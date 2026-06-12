// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
)

// countingConn counts every byte the server side reads from the wire, so
// the accept-gate tests can assert that a rejected peer had ZERO bytes
// parsed (NFR-SEC-76). It delegates SyscallConn so real peer-cred
// extraction still reaches the underlying unix socket fd.
type countingConn struct {
	net.Conn
	reads *int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	atomic.AddInt64(c.reads, int64(n))
	return n, err
}

func (c *countingConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.Conn.(syscallConner)
	if !ok {
		return nil, errors.New("countingConn: inner conn has no SyscallConn")
	}
	return sc.SyscallConn()
}

// countingListener wraps every accepted conn in a countingConn.
type countingListener struct {
	net.Listener
	reads *int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: c, reads: l.reads}, nil
}

// shortSocketDir returns a short-pathed temp directory cleaned up at test
// end. The platform unix-socket path limit (sun_path: 104 bytes on darwin,
// 108 on linux) is below the length of a typical t.TempDir() path, so socket
// tests mint their directory here instead. The accept-gate and lifecycle
// assertions are platform-independent; only the path budget differs.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sf")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// unixHTTPClient returns an http.Client that dials the given unix socket.
func unixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}
}

// TestGatedListenerRejectsNonHostPeer pins the SEC-76 gate at the unit
// level: a gatedListener whose peer check reports a non-host uid closes the
// connection inside Accept — http.Server never receives it and reads zero
// bytes; the client sees EOF.
func TestGatedListenerRejectsNonHostPeer(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "gate.sock")
	inner, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	var reads int64
	gl := &gatedListener{
		inner:     &countingListener{Listener: inner, reads: &reads},
		checkPeer: func(net.Conn) (uint32, int32, error) { return 12345, 1, nil },
		hostUID:   999, // never matches the fake peer uid
	}
	srv := &http.Server{Handler: http.NotFoundHandler()}
	go srv.Serve(gl)
	defer srv.Close()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	// The write may land in the socket buffer before the server closes;
	// the decisive assertions are the EOF and the zero server-side reads.
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("Read after rejected accept: got data, want EOF/reset")
	}
	if n := atomic.LoadInt64(&reads); n != 0 {
		t.Fatalf("server read %d bytes from a rejected peer, want 0 (SEC-76)", n)
	}
}

// TestGatedListenerAcceptsHostPeer pins the positive path: a host-uid peer
// passes the gate and the request is served.
func TestGatedListenerAcceptsHostPeer(t *testing.T) {
	socketPath := filepath.Join(shortSocketDir(t), "ok.sock")
	inner, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	gl := &gatedListener{
		inner:     inner,
		checkPeer: func(net.Conn) (uint32, int32, error) { return 777, 1, nil },
		hostUID:   777,
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	go srv.Serve(gl)
	defer srv.Close()

	resp, err := unixHTTPClient(socketPath).Get("http://session/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

// TestAcceptGateLinuxReal exercises the REAL kernel peer-credential
// extraction (SO_PEERCRED): a gate expecting a uid the connecting process
// does not have drops the connection before any HTTP byte is parsed, and a
// gate expecting our own uid serves. Linux CI is the enforcement target.
func TestAcceptGateLinuxReal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("peer-cred gate is Linux-CI only; darwin has no SO_PEERCRED equivalent in this build")
	}

	// Forged non-host peer: the gate expects uid+1, real extraction
	// returns our uid — dropped with zero bytes read.
	socketPath := filepath.Join(shortSocketDir(t), "real.sock")
	inner, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	var reads int64
	gl := &gatedListener{
		inner:     &countingListener{Listener: inner, reads: &reads},
		checkPeer: extractPeerCred,
		hostUID:   uint32(os.Getuid()) + 1,
	}
	srv := &http.Server{Handler: http.NotFoundHandler()}
	go srv.Serve(gl)
	defer srv.Close()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("Read after rejected accept: got data, want EOF/reset")
	}
	conn.Close()
	if n := atomic.LoadInt64(&reads); n != 0 {
		t.Fatalf("server read %d bytes from a non-host peer, want 0 (SEC-76)", n)
	}

	// Host peer: gate expects our real uid — served.
	okPath := filepath.Join(shortSocketDir(t), "real-ok.sock")
	innerOK, err := net.Listen("unix", okPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	glOK := &gatedListener{
		inner:     innerOK,
		checkPeer: extractPeerCred,
		hostUID:   uint32(os.Getuid()),
	}
	srvOK := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	go srvOK.Serve(glOK)
	defer srvOK.Close()

	resp, err := unixHTTPClient(okPath).Get("http://session/")
	if err != nil {
		t.Fatalf("Get (host peer): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

// scopeEchoHandler proves the ConnContext stash is real: it writes the
// channel-bound FilesystemID from the request context.
func scopeEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps, ok := peerScopeFromContext(r.Context())
		if !ok {
			http.Error(w, "no peer scope", http.StatusInternalServerError)
			return
		}
		io.WriteString(w, ps.FilesystemID)
	})
}

// allowAllPeer is the test peer check for darwin-portable lifecycle tests:
// every peer reports the test host uid.
func allowAllPeer(net.Conn) (uint32, int32, error) { return 4242, 99, nil }

// TestProvisionLifecycle pins the per-session socket lifecycle: Provision
// mints the socket in the configured directory (removing a stale socket
// first), binds the scope in the registry, serves with the scope stashed in
// the connection context, and Close shuts down, unlinks the socket, and
// releases the binding so a second Provision rebinds cleanly.
func TestProvisionLifecycle(t *testing.T) {
	dir := filepath.Join(shortSocketDir(t), "sessions")
	reg := NewSessionRegistry()
	entry := SessionEntry{FilesystemID: "fs-life", GrantedIntents: []Intent{IntentRead}}

	// Stale socket: a leftover file at the minted path must not block bind.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	stale := filepath.Join(dir, "fs-life.sock")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatalf("WriteFile stale: %v", err)
	}

	s, err := provisionSession(dir, entry, reg, scopeEchoHandler(), allowAllPeer, 4242)
	if err != nil {
		t.Fatalf("provisionSession: %v", err)
	}
	if s.SocketPath() != stale {
		t.Fatalf("SocketPath = %q, want %q", s.SocketPath(), stale)
	}
	if _, ok := reg.Lookup(s.SocketPath()); !ok {
		t.Fatalf("registry has no binding for %q after Provision", s.SocketPath())
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve() }()

	resp, err := unixHTTPClient(s.SocketPath()).Get("http://session/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "fs-life" {
		t.Fatalf("ConnContext scope echo = %q, want %q", body, "fs-life")
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve returned %v after Close, want nil", err)
	}
	if _, err := os.Stat(s.SocketPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still present after Close: %v", err)
	}
	if _, ok := reg.Lookup(s.SocketPath()); ok {
		t.Fatalf("registry binding survives Close, want released")
	}

	// Second Provision after Close rebinds cleanly.
	s2, err := provisionSession(dir, entry, reg, scopeEchoHandler(), allowAllPeer, 4242)
	if err != nil {
		t.Fatalf("second provisionSession after Close: %v", err)
	}
	go s2.Serve()
	defer s2.Close()
	resp2, err := unixHTTPClient(s2.SocketPath()).Get("http://session/")
	if err != nil {
		t.Fatalf("Get after re-provision: %v", err)
	}
	resp2.Body.Close()
}

// credEchoHandler writes the channel-bound peer uid:pid from the request
// context, proving the accept gate's extracted credentials survive
// ConnContext into the PeerScope.
func credEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps, ok := peerScopeFromContext(r.Context())
		if !ok {
			http.Error(w, "no peer scope", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%d:%d", ps.UID, ps.PID)
	})
}

// TestPeerCredsRetainedThroughConnContext pins COMP-01: the (uid, pid) the
// accept gate extracts are NOT discarded — they ride the credConn wrapper
// into ConnContext and land in the PeerScope every handler (and audit
// record) reads. Before the fix the PeerScope carried zero values and the
// audit actor read as uid "0".
func TestPeerCredsRetainedThroughConnContext(t *testing.T) {
	dir := filepath.Join(shortSocketDir(t), "creds")
	reg := NewSessionRegistry()
	entry := SessionEntry{FilesystemID: "fs-creds", GrantedIntents: []Intent{IntentRead}}
	checker := func(net.Conn) (uint32, int32, error) { return 4242, 99, nil }

	s, err := provisionSession(dir, entry, reg, credEchoHandler(), checker, 4242)
	if err != nil {
		t.Fatalf("provisionSession: %v", err)
	}
	go s.Serve()
	defer s.Close()

	resp, err := unixHTTPClient(s.SocketPath()).Get("http://session/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "4242:99" {
		t.Fatalf("PeerScope uid:pid = %q, want %q (gate credentials must survive to the context)", body, "4242:99")
	}
}

// TestPeerCredsLinuxReal pins the kernel-real half of COMP-01: with the REAL
// SO_PEERCRED extractor, a same-process dial yields OUR uid and pid in the
// PeerScope — the values the audit actor records. darwin loud-skips (no
// SO_PEERCRED equivalent in this build; Linux CI is the enforcement target).
func TestPeerCredsLinuxReal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("peer-cred extraction is Linux-real; darwin has no SO_PEERCRED equivalent in this build")
	}
	dir := filepath.Join(shortSocketDir(t), "creds-real")
	reg := NewSessionRegistry()
	entry := SessionEntry{FilesystemID: "fs-creds-real", GrantedIntents: []Intent{IntentRead}}

	s, err := provisionSession(dir, entry, reg, credEchoHandler(), extractPeerCred, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("provisionSession: %v", err)
	}
	go s.Serve()
	defer s.Close()

	resp, err := unixHTTPClient(s.SocketPath()).Get("http://session/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	want := fmt.Sprintf("%d:%d", os.Getuid(), os.Getpid())
	if string(body) != want {
		t.Fatalf("kernel-attested uid:pid = %q, want %q", body, want)
	}
}

// TestAuditActorCarriesGatePeerCreds drives the REAL dispatcher over a real
// session socket and pins that the durable audit record's actor carries the
// gate-attested (uid, pid) — the end-to-end COMP-01 witness: gate ->
// credConn -> ConnContext -> PeerScope -> auditEvent -> OCSF actor.
func TestAuditActorCarriesGatePeerCreds(t *testing.T) {
	dir := filepath.Join(shortSocketDir(t), "creds-audit")
	reg := NewSessionRegistry()
	entry := SessionEntry{FilesystemID: "fs-creds-audit", GrantedIntents: []Intent{IntentRead, IntentWrite}}
	g := &fakeGuard{}
	d := newDispatcherWithEngine(&fakeResolver{}, g, okCeilings(), 1<<20, newFakeEngine())
	checker := func(net.Conn) (uint32, int32, error) { return 1717, 4242, nil }

	s, err := provisionSession(dir, entry, reg, d, checker, 1717)
	if err != nil {
		t.Fatalf("provisionSession: %v", err)
	}
	go s.Serve()
	defer s.Close()

	body := `{"filesystem_id":"fs-creds-audit","path":"/x","authorization_metadata":{"intent":"write","downloadable":false}}`
	req, err := http.NewRequest(http.MethodPost, "http://session"+servicePrefix+"makeDirectory", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set(connectProtocolVersionHeader, connectProtocolVersion)
	req.Header.Set("Content-Type", contentTypeJSON)
	resp, err := unixHTTPClient(s.SocketPath()).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory status = %d, want 200", resp.StatusCode)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.events) == 0 {
		t.Fatal("no audit event mandated")
	}
	ev, ok := g.events[0].(auditgate.FileActivityEvent)
	if !ok {
		t.Fatalf("audit event is %T, want auditgate.FileActivityEvent", g.events[0])
	}
	if ev.Actor.UserUID != "1717" {
		t.Fatalf("audit actor user_uid = %q, want %q (the gate-attested uid, never a zero default)", ev.Actor.UserUID, "1717")
	}
	if ev.Actor.ProcessPID != 4242 {
		t.Fatalf("audit actor process_pid = %d, want 4242 (the gate-attested pid)", ev.Actor.ProcessPID)
	}
}

// TestSocketDirMode pins that the session socket directory is created and
// held at mode 0700, umask-independent.
func TestSocketDirMode(t *testing.T) {
	dir := filepath.Join(shortSocketDir(t), "host-owned")
	reg := NewSessionRegistry()
	s, err := provisionSession(dir, SessionEntry{FilesystemID: "fs-mode"}, reg, scopeEchoHandler(), allowAllPeer, 4242)
	if err != nil {
		t.Fatalf("provisionSession: %v", err)
	}
	defer s.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("socket dir mode = %o, want 0700", got)
	}
}

// TestProvisionRejectsBadScopeName pins that a scope unfit for a socket
// filename (empty or path-traversing) refuses loud instead of minting a
// path outside the host-owned directory.
func TestProvisionRejectsBadScopeName(t *testing.T) {
	dir := filepath.Join(shortSocketDir(t), "d")
	reg := NewSessionRegistry()
	for _, fsid := range []string{"", "a/b", "../escape"} {
		if _, err := provisionSession(dir, SessionEntry{FilesystemID: fsid}, reg, scopeEchoHandler(), allowAllPeer, 4242); err == nil {
			t.Fatalf("provisionSession(%q): got nil error, want refusal", fsid)
		}
	}
}
