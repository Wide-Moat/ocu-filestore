// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// The stall-timeout suite proves NFR-SEC-46 on the two data-plane streaming
// handlers: a guest that opens an upload/download and then STALLS mid-stream
// must NOT pin the goroutine, its fd-ceiling slot, and its in-flight-bytes
// reservation forever. The upload handler re-arms a read deadline before every
// body read; the download handler re-arms a write deadline before every flush.
// A slow-but-progressing transfer keeps pushing its deadline out, while a stall
// (no byte for the frame timeout) trips it and aborts the operation fail-closed.
//
// These tests REQUIRE a real socket: http.NewResponseController's per-iteration
// SetReadDeadline/SetWriteDeadline are only honoured over a net.Conn-backed
// ResponseWriter (an in-memory httptest.ResponseRecorder returns
// http.ErrNotSupported, which the handlers tolerate but which would never fire
// the timeout). So each test stands the production router up behind an
// httptest.NewServer and drives it across the loopback, with the dispatcher's
// frameReadTimeout/frameWriteTimeout shrunk to keep the test fast.

// peerScopeInjector wraps a handler, stashing a fixed PeerScope on every request
// context so the dispatcher's unix-fallback identity source (peerScopeFromContext,
// used when no credential extractor is wired) resolves a scope. It is the live
// equivalent of the contextWithPeerScope the in-process handler tests use.
type peerScopeInjector struct {
	inner http.Handler
	ps    PeerScope
}

func (p peerScopeInjector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.inner.ServeHTTP(w, r.WithContext(contextWithPeerScope(r.Context(), p.ps)))
}

// newStallServer stands the production REST router (over an engine-backed,
// recording-ceilings dispatcher) up behind an httptest.NewServer with the frame
// read/write timeouts shrunk to d. The PeerScope source is the unix-fallback
// context injector (no credential extractor), so the scope/intents are fixed to
// scope+okIntents. It returns the server, the engine, and the recording session
// the caller asserts the ceilings balance on.
func newStallServer(t *testing.T, scope string, frameTimeout time.Duration) (*httptest.Server, *fakeEngine, *recordingCeilingsSession) {
	t.Helper()
	eng := newFakeEngine()
	sess := &recordingCeilingsSession{}
	res := &fakeResolver{grant: Grant{Downloadable: true}}
	reg := &recordingRegistry{sess: sess}
	d := newDispatcherWithEngine(res, &fakeGuard{}, reg, 1<<20, eng)
	d.maxFileSize = 1 << 24
	d.frameReadTimeout = frameTimeout
	d.frameWriteTimeout = frameTimeout

	h := peerScopeInjector{
		inner: newRESTRouter(d),
		ps:    PeerScope{FilesystemID: scope, GrantedIntents: okIntents(), UID: 4242, PID: 7},
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, eng, sess
}

// stallingBody is an io.Reader that yields a prefix of bytes and then BLOCKS
// (never returning a byte or an error) until release is closed or the read's
// context-driven deadline expires. It models a guest that begins an upload and
// then stalls mid-stream: the server's re-armed read deadline must trip on the
// next read rather than hanging forever. Read returns from the blocked state
// only when release is closed (test teardown), so a server that FAILED to bound
// the read would hang here and the test would time out — a hang is itself a
// failure signal.
type stallingBody struct {
	prefix  []byte
	off     int
	release chan struct{}
}

func (s *stallingBody) Read(p []byte) (int, error) {
	if s.off < len(s.prefix) {
		n := copy(p, s.prefix[s.off:])
		s.off += n
		return n, nil
	}
	// Prefix exhausted: STALL. Block until the test releases us (teardown). On a
	// correctly-bounded server the request has already been aborted by the read
	// deadline by the time we are unblocked here.
	<-s.release
	return 0, io.EOF
}

// TestUploadStallTripsReadDeadline proves a stalled multipart upload trips the
// re-armed inbound read deadline (NFR-SEC-46) and aborts fail-closed — the
// fd/bytes ceilings are released and no torn object is staged — rather than
// pinning the handler forever.
func TestUploadStallTripsReadDeadline(t *testing.T) {
	const scope = "fs-stall-up"
	srv, eng, sess := newStallServer(t, scope, 150*time.Millisecond)

	// Build a multipart prefix: the complete "params" field plus the OPENING of
	// the "file" part (its header and a few content bytes) but NOT the closing
	// boundary, so the server reads the params, opens the file part, reads the
	// initial bytes, then STALLS waiting for the rest of the file body that never
	// comes. declared is larger than the prefix bytes so the handler is mid-stream
	// (neither over- nor under-declared yet) when the stall hits.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	params := uploadParamsFixture{
		FilesystemID:          scope,
		Path:                  "/stall.bin",
		DeclaredSizeBytes:     4096,
		AuthorizationMetadata: writeMeta(),
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	if err := mw.WriteField(multipartParamsFieldName, string(raw)); err != nil {
		t.Fatalf("write params field: %v", err)
	}
	fw, err := mw.CreateFormFile(multipartFileFieldName, multipartFileFilename)
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := fw.Write([]byte("PARTIAL-")); err != nil {
		t.Fatalf("write partial file bytes: %v", err)
	}
	// Intentionally do NOT call mw.Close(): the closing boundary never arrives,
	// so after the prefix the server's filePart.Read blocks and the deadline must
	// trip.
	contentType := mw.FormDataContentType()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	body := &stallingBody{prefix: buf.Bytes(), release: release}

	req, err := http.NewRequest(http.MethodPost, srv.URL+restBase+string(OpFileUpload), body)
	if err != nil {
		t.Fatalf("build upload request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)

	// A generous client-side ceiling: many multiples of the server's frame
	// timeout. If the server's deadline fires, the request returns well within
	// this; if the server hung, this is what fails the test instead of hanging
	// the whole suite.
	client := &http.Client{Timeout: 5 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// The server aborting a stalled upload may surface client-side as a reset
		// rather than a response, depending on timing — either way the point is the
		// request did NOT hang. A nil-response error well under the client ceiling
		// is an acceptable proof the stall was bounded.
		if elapsed := time.Since(start); elapsed >= 5*time.Second {
			t.Fatalf("stalled upload was not bounded: client errored only at the ceiling (%v): %v", elapsed, err)
		}
		assertUploadAbortedFailClosed(t, eng, sess, scope, "stall.bin")
		return
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)
	if elapsed >= 5*time.Second {
		t.Fatalf("stalled upload hung past the client ceiling (%v)", elapsed)
	}
	// The handler aborted the stalled upload fail-closed with a deny status, not a
	// 200. A 2xx would mean the partial/stalled body was accepted.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		t.Fatalf("stalled upload returned success status %d, want a fail-closed deny", resp.StatusCode)
	}
	assertUploadAbortedFailClosed(t, eng, sess, scope, "stall.bin")
}

// assertUploadAbortedFailClosed waits briefly for the server-side handler defers
// to run, then asserts the fail-closed contract: the ceilings gauge balances (no
// leaked fd slot or in-flight bytes) and no torn object is staged at the path.
func assertUploadAbortedFailClosed(t *testing.T, eng *fakeEngine, sess *recordingCeilingsSession, scope, rel string) {
	t.Helper()
	// The client may observe the response/abort a hair before the server-side
	// ReleaseFD/ReleaseBytes defers complete; poll briefly for the balance.
	deadline := time.Now().Add(2 * time.Second)
	for !sess.balanced() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !sess.balanced() {
		bAcq, bRel, fdAcq, fdRel := sess.gauges()
		t.Fatalf("ceilings gauge unbalanced after a stalled upload: bytes %d/%d fd %d/%d (leaked slot)",
			bAcq, bRel, fdAcq, fdRel)
	}
	assertNoObject(t, eng, scope, rel)
}

// TestDownloadStallTripsWriteDeadline proves a stalled download (a reader that
// stops draining the body) trips the re-armed outbound write deadline and
// TERMINATES the stream, releasing the fd slot, rather than blocking the
// download goroutine forever on a wedged client.
func TestDownloadStallTripsWriteDeadline(t *testing.T) {
	const scope = "fs-stall-down"
	srv, eng, sess := newStallServer(t, scope, 150*time.Millisecond)

	// Seed a LARGE object so the engine.ReadRange copy makes several flush writes:
	// the first writes fill the client socket + kernel buffers, then the stalled
	// reader makes a subsequent flush block until the write deadline trips. The
	// payload must exceed the socket/window buffering so a write actually blocks.
	payload := bytes.Repeat([]byte("STALLPAYLOAD-"), 2_000_000) // ~26 MiB
	eng.putBytes(scope, "big.bin", payload)

	// Mint the broker-held uuid for the seeded object through the SAME store the
	// download handler resolves through (the dispatcher is reachable via the
	// router; reach its id store the same way the live harness does).
	// newStallServer hid the dispatcher, so rebuild the uuid the store would mint:
	// the store is keyed off (scope, guestPath). We need the dispatcher's store;
	// fetch it back through a typed handler accessor.
	uuid := stallServerMintUUID(t, srv, scope, "/big.bin")

	body := downloadJSONBodyRaw(t, scope, uuid)

	// Dial the server with a RAW socket so we control the read pace precisely.
	addr := srv.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial stall server: %v", err)
	}
	defer conn.Close()

	// Write the HTTP/1.1 request by hand (httptest.NewServer speaks HTTP/1.1 on a
	// plain socket). A single request, Connection: close.
	reqLine := "POST " + restBase + string(OpFileDownload) + " HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Content-Type: " + contentTypeJSON + "\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n"
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := conn.Write([]byte(reqLine)); err != nil {
		t.Fatalf("write request head: %v", err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatalf("write request body: %v", err)
	}

	// Read the status line + headers, then read only a SMALL slice of the body and
	// STALL: do not read another byte. The server's send buffer fills and the next
	// flush write trips the write deadline.
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !bytes.Contains([]byte(statusLine), []byte(" 200 ")) {
		t.Fatalf("download status line = %q, want 200 (the stream commits 200 before the first byte)", statusLine)
	}
	// Drain headers up to the blank line.
	for {
		line, herr := br.ReadString('\n')
		if herr != nil {
			t.Fatalf("read headers: %v", herr)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	// Read a small prefix of the body, then STALL by never reading again. The
	// server must trip its write deadline and terminate; we then assert the fd was
	// released. We do NOT close the connection yet — the stall is the reader simply
	// not reading.
	small := make([]byte, 4096)
	_, _ = br.Read(small) // best-effort: grab a little, then stop reading entirely

	// Wait for the server to trip its write deadline and run its ReleaseFD defer.
	// Poll the recording session for the fd balance: the download handler released
	// the fd slot on its (terminated) exit path. The poll ceiling is many frame
	// timeouts so a correctly-bounded server always balances well within it; a
	// server that never tripped the deadline would still hold the fd and fail.
	deadline := time.Now().Add(5 * time.Second)
	var acquired, released int
	for time.Now().Before(deadline) {
		acquired, released = sess.fdBalance()
		if released >= 1 && acquired == released {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	acquired, released = sess.fdBalance()
	if acquired == 0 {
		t.Fatalf("download never acquired an fd slot (the stream never committed); test misconfigured")
	}
	if released != acquired {
		t.Fatalf("fd slot leaked after a stalled download: acquired %d, released %d (the write deadline did not terminate the stream)",
			acquired, released)
	}
}

// downloadJSONBodyRaw builds the fileDownload JSON request body for the stall
// test without the *testing.T-helper marshalling indirection the parity tests
// use (it carries no rangeFixture dependency).
func downloadJSONBodyRaw(t *testing.T, scope, uuid string) []byte {
	t.Helper()
	body := fileDownloadRequest{
		FilesystemID: scope,
		UUID:         uuid,
	}
	body.AuthorizationMetadata.Intent = IntentRead
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal download body: %v", err)
	}
	return raw
}

// itoa is the base-10 Content-Length value for the hand-built request head.
func itoa(n int) string { return strconv.Itoa(n) }

// stallServerMintUUID mints the broker-held uuid for a seeded object directly on
// the dispatcher's objectIDStore — the same way the live download harness plants
// a handle without a prior listing round-trip. The production router does not
// expose the store, so the test unwraps the dispatcher the stall server serves.
func stallServerMintUUID(t *testing.T, srv *httptest.Server, scope, guestPath string) string {
	t.Helper()
	d := dispatcherOf(srv)
	if d == nil {
		t.Fatalf("could not reach the dispatcher behind the stall server (handler chain changed)")
	}
	return d.ids.idFor(scope, guestPath)
}

// dispatcherOf unwraps the dispatcher the stall server serves: the server's
// handler is a peerScopeInjector wrapping the production restRouter, which holds
// the dispatcher. This in-package accessor lets the download stall test reach the
// id store to mint a valid handle. A handler-chain refactor surfaces here (nil)
// rather than silently skipping the timeout proof.
func dispatcherOf(srv *httptest.Server) *dispatcher {
	if inj, ok := srv.Config.Handler.(peerScopeInjector); ok {
		if rt, ok := inj.inner.(*restRouter); ok {
			return rt.dispatcher
		}
	}
	return nil
}
