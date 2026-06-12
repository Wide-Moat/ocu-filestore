// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// errBadScopeName — a session's filesystem_id is unfit for a socket filename
// (empty, or a path component that would escape the host-owned directory). A
// provision with such a scope fails loud rather than minting a socket path
// outside the 0700 directory. Match it with errors.Is.
var errBadScopeName = errors.New("southface: filesystem scope unfit for a socket path")

// syscallConner is the net.Conn slice the peer-cred extractor needs: the
// underlying file descriptor reachable via SyscallConn. *net.UnixConn
// satisfies it; the test counting conn delegates it so real extraction still
// reaches the socket fd.
type syscallConner interface {
	SyscallConn() (syscall.RawConn, error)
}

// peerScopeKeyType is the unexported context-key type for the channel-bound
// PeerScope; using a private type keeps the value unreachable from any other
// package (no key collision, no external read).
type peerScopeKeyType struct{}

var peerScopeKey peerScopeKeyType

// PeerScope is the host-attested session identity stashed in every request's
// connection context: the channel-bound filesystem scope and intent grant,
// plus the kernel-attested peer uid/pid. The dispatch spine reads it from the
// context — never from a request field — to build caller evidence and to
// cross-check the body filesystem_id (NFR-SEC-43).
type PeerScope struct {
	// FilesystemID is the host-attested scope bound to the session channel
	// at provision time.
	FilesystemID string
	// GrantedIntents is the exhaustive intent grant set for the session.
	GrantedIntents []Intent
	// UID is the kernel-attested peer uid that passed the accept gate.
	UID uint32
	// PID is the kernel-attested peer pid.
	PID int32
}

// peerScopeFromContext returns the PeerScope stashed by the session server's
// ConnContext, ok=false when none is present (a handler reached without the
// channel binding is a wiring fault and fails closed).
func peerScopeFromContext(ctx context.Context) (PeerScope, bool) {
	ps, ok := ctx.Value(peerScopeKey).(PeerScope)
	return ps, ok
}

// contextWithPeerScope returns ctx carrying ps under the private key.
func contextWithPeerScope(ctx context.Context, ps PeerScope) context.Context {
	return context.WithValue(ctx, peerScopeKey, ps)
}

// peerChecker extracts the kernel-attested peer uid/pid of a connection. The
// build-tagged extractPeerCred satisfies it on each platform; tests inject a
// fake.
type peerChecker func(net.Conn) (uint32, int32, error)

// gatedListener is the SEC-76 accept gate: a net.Listener wrapper whose Accept
// loops, extracting each accepted connection's peer credentials and closing —
// without reading a single byte — any peer whose uid is not the broker's host
// uid. Only a host-peer connection is ever handed to http.Server.
type gatedListener struct {
	inner     net.Listener
	checkPeer peerChecker
	hostUID   uint32
}

// Accept returns the next host-peer connection, closing and skipping any
// connection whose peer-cred extraction fails or whose uid is not the host
// uid. No byte is read from a rejected connection (NFR-SEC-76).
func (g *gatedListener) Accept() (net.Conn, error) {
	for {
		conn, err := g.inner.Accept()
		if err != nil {
			return nil, err
		}
		uid, _, err := g.checkPeer(conn)
		if err != nil || uid != g.hostUID {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

// Close closes the inner listener.
func (g *gatedListener) Close() error { return g.inner.Close() }

// Addr returns the inner listener's address.
func (g *gatedListener) Addr() net.Addr { return g.inner.Addr() }

// session is one per-session south-face server: a unix-socket HTTP/1.1 server
// bound to a single filesystem scope, gated by peer credentials, with the
// scope stashed into every request's context. It honours the frozen
// southface.Server seam (Serve/Close).
type session struct {
	socketPath string
	reg        *SessionRegistry
	listener   *gatedListener
	srv        *http.Server
}

// compile-time proof a session honours the frozen Server seam.
var _ Server = (*session)(nil)

// SocketPath returns the unix-socket path this session serves on.
func (s *session) SocketPath() string { return s.socketPath }

// provisionSession mints a per-session south-face server for entry's scope:
// it ensures dir exists at mode 0700 (umask-independent), derives the socket
// path from the scope, removes any stale socket at that path before bind,
// binds the scope in reg keyed by the socket path, wraps the listener in the
// peer-cred accept gate, and builds an HTTP/1.1 server whose ConnContext
// stashes the bound PeerScope into every connection's context. The server does
// not serve until Serve is called.
func provisionSession(dir string, entry SessionEntry, reg *SessionRegistry, handler http.Handler, checkPeer peerChecker, hostUID uint32) (*session, error) {
	socketPath, err := socketPathForScope(dir, entry.FilesystemID)
	if err != nil {
		return nil, err
	}

	// Host-owned 0700 directory: MkdirAll honours umask, so chmod after to
	// pin the mode regardless of the process umask.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}

	// A stale socket from a crashed predecessor must not block bind
	// (Pitfall 1). Remove unconditionally; ignore a not-exist result.
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	if err := reg.Provision(socketPath, entry); err != nil {
		_ = ln.Close()
		return nil, err
	}

	gl := &gatedListener{inner: ln, checkPeer: checkPeer, hostUID: hostUID}

	s := &session{
		socketPath: socketPath,
		reg:        reg,
		listener:   gl,
	}

	// HTTP/1.1 only — do NOT set srv.Protocols. ConnContext stashes the
	// channel-bound scope so every handler reads identity from the context,
	// never from a request field (NFR-SEC-43).
	s.srv = &http.Server{
		Handler: handler,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			bound, ok := reg.Lookup(socketPath)
			if !ok {
				// Binding released mid-flight: carry an empty scope; the
				// dispatch spine fails closed when the scope is absent.
				return ctx
			}
			return contextWithPeerScope(ctx, PeerScope{
				FilesystemID:   bound.FilesystemID,
				GrantedIntents: bound.GrantedIntents,
			})
		},
	}
	return s, nil
}

// socketPathForScope derives the per-session socket path from the scope,
// refusing a scope unfit for a single filename (empty, or one that contains a
// path separator or a parent reference) so the path can never escape dir.
func socketPathForScope(dir, scope string) (string, error) {
	if scope == "" || strings.ContainsRune(scope, '/') || strings.ContainsRune(scope, filepath.Separator) || scope == ".." || strings.Contains(scope, "..") {
		return "", fmt.Errorf("%w: %q", errBadScopeName, scope)
	}
	return filepath.Join(dir, scope+".sock"), nil
}

// Serve accepts host-peer connections until Close shuts the server down. A
// clean shutdown returns nil (http.ErrServerClosed is collapsed to nil).
func (s *session) Serve() error {
	err := s.srv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close shuts the server down, releases the scope binding, and unlinks the
// socket. In-flight operations finish or fail fail-closed, never
// half-acknowledged. The unix listener's default SetUnlinkOnClose removes the
// socket on listener close; Close also removes it explicitly to cover the
// shutdown-before-serve path.
func (s *session) Close() error {
	shutdownErr := s.srv.Shutdown(context.Background())
	s.reg.Release(s.socketPath)
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		if shutdownErr == nil {
			shutdownErr = err
		}
	}
	return shutdownErr
}
