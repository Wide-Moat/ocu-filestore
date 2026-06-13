// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestServerTimeoutsConfigured pins the CONC-05 server half: every
// provisioned session server carries a header-read timeout and an idle
// timeout (a connect-and-stall peer cannot hold a connection open forever),
// while ReadTimeout stays unset so a long legitimate chunked upload is not
// capped (the per-frame deadline covers the body).
func TestServerTimeoutsConfigured(t *testing.T) {
	dir := filepath.Join(shortSocketDir(t), "timeouts")
	reg := NewSessionRegistry()
	s, err := provisionSession(dir, SessionEntry{FilesystemID: "fs-to"}, reg, scopeEchoHandler(), allowAllPeer, 4242, discardLogger())
	if err != nil {
		t.Fatalf("provisionSession: %v", err)
	}
	defer s.Close()

	if s.srv.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout unset: a header-stalling peer pins a connection forever")
	}
	if s.srv.IdleTimeout <= 0 {
		t.Fatal("IdleTimeout unset: idle keep-alive connections are never reaped")
	}
	if s.srv.ReadTimeout != 0 {
		t.Fatal("ReadTimeout set: it would cap a whole legitimate chunked upload (the per-frame deadline owns the body)")
	}
}

// TestStalledUploadStreamAborts pins the CONC-05 stream half over a REAL
// socket: a client that sends the params frame and then stalls mid-stream is
// aborted by the per-frame read deadline — the framed abort trailer arrives
// well within the test budget, the connection closes, and the fd/bytes
// ceilings are released (gauge balanced). Pre-fix, the stream pinned its
// goroutine and fd slot forever.
func TestStalledUploadStreamAborts(t *testing.T) {
	dir := filepath.Join(shortSocketDir(t), "stall")
	reg := NewSessionRegistry()
	entry := SessionEntry{FilesystemID: "fs-stall", GrantedIntents: []Intent{IntentRead, IntentWrite}}

	sess := &recordingCeilingsSession{}
	d := newDispatcherWithEngine(&fakeResolver{}, &fakeGuard{}, &recordingRegistry{sess: sess}, 1<<20, newFakeEngine())
	d.maxFileSize = 1 << 20
	d.frameReadTimeout = 200 * time.Millisecond // shrink the budget for the test

	s, err := provisionSession(dir, entry, reg, d, allowAllPeer, 4242, discardLogger())
	if err != nil {
		t.Fatalf("provisionSession: %v", err)
	}
	go s.Serve()
	defer s.Close()

	conn, err := net.Dial("unix", s.SocketPath())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Raw HTTP/1.1 chunked request: headers, then the params frame as one
	// chunk, then STALL (no further chunks, no terminal chunk).
	params := paramsFrame(t, "fs-stall", "/stalled.bin", 64)
	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "POST %sfileUpload HTTP/1.1\r\n", servicePrefix)
	fmt.Fprintf(&reqBuf, "Host: session\r\n")
	fmt.Fprintf(&reqBuf, "Content-Type: %s\r\n", connContentTypeStream)
	fmt.Fprintf(&reqBuf, "%s: %s\r\n", connectProtocolVersionHeader, connectProtocolVersion)
	fmt.Fprintf(&reqBuf, "Transfer-Encoding: chunked\r\n\r\n")
	fmt.Fprintf(&reqBuf, "%x\r\n", len(params))
	reqBuf.Write(params)
	reqBuf.WriteString("\r\n")
	if _, err := conn.Write(reqBuf.Bytes()); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// The abort trailer must arrive within a small multiple of the 200ms
	// frame budget; 5s is the hard test failure line.
	deadline := time.Now().Add(5 * time.Second)
	_ = conn.SetReadDeadline(deadline)
	start := time.Now()
	var resp bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, rerr := conn.Read(buf)
		resp.Write(buf[:n])
		if rerr != nil {
			break // server closed the aborted connection (or deadline)
		}
		if bytes.Contains(resp.Bytes(), []byte(`"code"`)) {
			break // the framed verdict arrived
		}
	}
	elapsed := time.Since(start)

	if !bytes.Contains(resp.Bytes(), []byte("HTTP/1.1 200")) {
		t.Fatalf("stalled stream produced no HTTP 200 framed response within %v; got %q", elapsed, resp.String())
	}
	if !bytes.Contains(resp.Bytes(), []byte(`"aborted"`)) {
		t.Fatalf("stalled stream trailer does not carry the aborted verdict; got %q", resp.String())
	}
	if elapsed > 4*time.Second {
		t.Fatalf("stalled stream aborted after %v, want well under the 5s budget (frame deadline 200ms)", elapsed)
	}
	if !sess.balanced() {
		t.Fatalf("ceilings gauge unbalanced after a stalled-stream abort: bytes %d/%d fd %d/%d",
			sess.acquired, sess.released, sess.fdAcquired, sess.fdReleased)
	}
}
