// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
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

// credConn is a host-peer connection carrying the kernel-attested peer
// credentials the accept gate extracted, so ConnContext can stamp the REAL
// uid/pid into the PeerScope (and from there into every audit record's
// actor) without a second extraction. Only the gate mints it: a connection
// reaching ConnContext as anything else is a wiring fault and fails closed
// (no PeerScope, the dispatch spine denies).
type credConn struct {
	net.Conn
	uid uint32
	pid int32
}

// SyscallConn delegates to the inner connection so anything needing the raw
// fd still reaches the real socket.
func (c *credConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.Conn.(syscallConner)
	if !ok {
		return nil, errors.New("southface: inner connection does not expose SyscallConn")
	}
	return sc.SyscallConn()
}

// gatedListener is the SEC-76 accept gate: a net.Listener wrapper whose Accept
// loops, extracting each accepted connection's peer credentials and closing —
// without reading a single byte — any peer whose uid is not the broker's host
// uid. Only a host-peer connection is ever handed to http.Server.
type gatedListener struct {
	inner     net.Listener
	checkPeer peerChecker
	hostUID   uint32
	// onPeerDrop is an optional callback invoked BEFORE conn.Close() on each
	// rejected connection. It receives the extracted uid, pid, and a reason
	// string ("uid_mismatch" or "peercred_error"). A nil value is a no-op —
	// existing tests that construct gatedListener by literal need not supply
	// one and continue to compile and pass unchanged.
	onPeerDrop func(uid uint32, pid int32, reason string)
}

// Accept returns the next host-peer connection, closing and skipping any
// connection whose peer-cred extraction fails or whose uid is not the host
// uid. No byte is read from a rejected connection (NFR-SEC-76). An admitted
// connection is wrapped in credConn so the attested (uid, pid) survive to
// ConnContext and into the audit actor — the gate is the ONE extraction
// point; nothing downstream re-derives identity.
func (g *gatedListener) Accept() (net.Conn, error) {
	for {
		conn, err := g.inner.Accept()
		if err != nil {
			return nil, err
		}
		uid, pid, err := g.checkPeer(conn)
		if err != nil {
			if g.onPeerDrop != nil {
				g.onPeerDrop(0, 0, "peercred_error")
			}
			_ = conn.Close()
			continue
		}
		if uid != g.hostUID {
			if g.onPeerDrop != nil {
				g.onPeerDrop(uid, pid, "uid_mismatch")
			}
			_ = conn.Close()
			continue
		}
		return &credConn{Conn: conn, uid: uid, pid: pid}, nil
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
//
// logger is used to wire the peer-drop WARN callback on the accept gate and
// to route the http.Server's internal error log into the JSON stream. A nil
// logger produces a discard-all logger (the caller must ensure non-nil; Serve
// normalises the Logger field before calling here).
func provisionSession(dir string, entry SessionEntry, reg *SessionRegistry, handler http.Handler, checkPeer peerChecker, hostUID uint32, logger *slog.Logger) (*session, error) {
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

	gl := &gatedListener{
		inner:     ln,
		checkPeer: checkPeer,
		hostUID:   hostUID,
		onPeerDrop: func(uid uint32, pid int32, reason string) {
			logger.Warn("peer-cred gate: connection dropped",
				slog.String(observ.KeyReason, reason),
				slog.Uint64(observ.KeyPeerUID, uint64(uid)),
				slog.Int64(observ.KeyPeerPID, int64(pid)),
			)
		},
	}

	s := &session{
		socketPath: socketPath,
		reg:        reg,
		listener:   gl,
	}

	// HTTP/1.1 only — do NOT set srv.Protocols. ConnContext stashes the
	// channel-bound scope AND the gate-attested peer (uid, pid) so every
	// handler — and every audit record's actor — reads identity from the
	// context, never from a request field (NFR-SEC-43/76).
	//
	// Timeouts (NFR-SEC-46): ReadHeaderTimeout bounds a peer that connects
	// and never finishes its headers; IdleTimeout reaps idle keep-alive
	// connections. ReadTimeout stays UNSET on purpose — it would cap a whole
	// legitimate chunked upload; the per-frame read deadline inside the
	// streaming handler covers a stalled body instead. ReadHeaderTimeout
	// also re-arms the connection deadline per request, so a handler-set
	// body deadline never poisons the next request on the connection.
	s.srv = &http.Server{
		Handler:           handler,
		ErrorLog:          observ.ErrorLog(logger),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			cc, ok := c.(*credConn)
			if !ok {
				// The connection did not come through the accept gate: a
				// wiring fault. Carry no scope; the dispatch spine fails
				// closed — an audit actor must never default to uid 0.
				return ctx
			}
			bound, ok := reg.Lookup(socketPath)
			if !ok {
				// Binding released mid-flight: carry an empty scope; the
				// dispatch spine fails closed when the scope is absent.
				return ctx
			}
			return contextWithPeerScope(ctx, PeerScope{
				FilesystemID:   bound.FilesystemID,
				GrantedIntents: bound.GrantedIntents,
				UID:            cc.uid,
				PID:            cc.pid,
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

// shutdownDrainTimeout bounds the graceful drain in Close: in-flight
// operations get this long to finish before stragglers are force-closed. A
// wedged peer must never hold the session open indefinitely — the caller's
// teardown (erase-before-reuse, NFR-SEC-54) runs AFTER Close returns, so an
// unbounded drain would be an unbounded teardown delay. The bound is
// deliberately under typical service-manager stop grace periods (30s) so the
// drain, the force-close, AND the scope erase all fit before a SIGKILL.
const shutdownDrainTimeout = 25 * time.Second

// Close shuts the server down with a BOUNDED drain, releases the scope
// binding, and unlinks the socket. In-flight operations get up to
// shutdownDrainTimeout to finish or fail fail-closed, never
// half-acknowledged; stragglers past the bound are force-closed so teardown
// can always proceed. Every failure on the way down surfaces via errors.Join
// — a drain expiry never hides a force-close or unlink error. The unix
// listener's default SetUnlinkOnClose removes the socket on listener close;
// Close also removes it explicitly to cover the shutdown-before-serve path.
func (s *session) Close() error {
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), shutdownDrainTimeout)
	defer cancelDrain()
	shutdownErr := s.srv.Shutdown(drainCtx)
	if shutdownErr != nil {
		// The bounded drain expired (or shutdown itself failed): force-close
		// the straggling connections. Both errors surface.
		shutdownErr = errors.Join(shutdownErr, s.srv.Close())
	}
	s.reg.Release(s.socketPath)
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		shutdownErr = errors.Join(shutdownErr, err)
	}
	return shutdownErr
}
