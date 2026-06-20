// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
)

const streamScope = "fs-stream"

// fataler is the minimal test-handle surface the frame helpers need. Both
// *testing.T and *rapid.T satisfy it (testing.TB cannot be used because its
// sealed private() method excludes *rapid.T), so the property tests reuse the
// same frame builders.
type fataler interface {
	Helper()
	Fatalf(format string, args ...any)
}

// frameBytes encodes a single data frame (flag 0x00) carrying payload.
func frameBytes(t fataler, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := writeFrame(&buf, dataFlag, payload); err != nil {
		t.Fatalf("frameBytes: %v", err)
	}
	return buf.Bytes()
}

// endFrame encodes the client half-close (end-stream) frame.
func endFrame(t fataler) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := writeFrame(&buf, endStreamFlag, []byte("{}")); err != nil {
		t.Fatalf("endFrame: %v", err)
	}
	return buf.Bytes()
}

// paramsFrame encodes an upload params frame.
func paramsFrame(t fataler, scope, path string, declared int64) []byte {
	t.Helper()
	body := fmt.Sprintf(
		`{"filesystem_id":%q,"path":%q,"declared_size_bytes":%d,"authorization_metadata":{"intent":"write","downloadable":false}}`,
		scope, path, declared)
	return frameBytes(t, []byte(body))
}

// chunkFrame encodes a chunk data frame carrying raw bytes (base64 under JSON).
func chunkFrame(t fataler, raw []byte) []byte {
	t.Helper()
	payload, err := json.Marshal(uploadChunkFrame{Chunk: raw})
	if err != nil {
		t.Fatalf("chunkFrame marshal: %v", err)
	}
	return frameBytes(t, payload)
}

// concat joins frames into a single stream body.
func concat(frames ...[]byte) []byte {
	var out []byte
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}

// chunkCountingReader wraps a body and counts bytes read PAST a marked offset, so a
// test can assert that zero CHUNK bytes were read after the params frame
// (Pitfall 5). markParamsEnd is called with the params frame length once the
// caller knows it.
type chunkCountingReader struct {
	r            io.Reader
	total        int
	paramsEnd    int
	afterParams  int
	markedParams bool
}

func (c *chunkCountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.total += n
	if c.markedParams && c.total > c.paramsEnd {
		// Count only the bytes beyond the params frame boundary.
		past := c.total - c.paramsEnd
		if past > n {
			past = n
		}
		c.afterParams += past
	}
	return n, err
}

// streamRequest builds a streaming POST: connect+json, the version header, NO
// Content-Length (the body is "chunked" — a plain reader with ContentLength
// -1), the framed body, and a PeerScope context. The returned request drives
// d.ServeHTTP; the framed response is read off the recorder afterwards.
func streamRequest(op Op, body io.Reader, scope string, intents []Intent) *http.Request {
	r := httptest.NewRequest(http.MethodPost, restBase+string(op), body)
	r.Header.Set(streamProtocolVersionHeader, streamProtocolVersion)
	r.Header.Set("Content-Type", connContentTypeStream)
	r.ContentLength = -1 // chunked / unknown length
	ps := PeerScope{FilesystemID: scope, GrantedIntents: intents, UID: 4242, PID: 7}
	return r.WithContext(contextWithPeerScope(r.Context(), ps))
}

// serveStream drives a streaming op end-to-end and returns the recorder.
func serveStream(d *dispatcher, op Op, body io.Reader, scope string, intents []Intent) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	d.ServeHTTP(w, streamRequest(op, body, scope, intents))
	return w
}

// streamTrailer reads the framed response off the recorder and returns the
// LAST frame's flag + parsed end-stream body. A streaming response is always
// HTTP 200; the verdict rides in the final 0x02 trailer.
func streamTrailer(t fataler, w *httptest.ResponseRecorder) (flag byte, resp endStreamResponse) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("stream status = %d, want 200 (verdict rides in the trailer); body %x", w.Code, w.Body.Bytes())
	}
	rdr := bytes.NewReader(w.Body.Bytes())
	var lastFlag byte
	var lastPayload []byte
	for {
		f, payload, err := readFrame(rdr)
		if err != nil {
			break
		}
		lastFlag = f
		lastPayload = payload
	}
	if lastFlag != endStreamFlag {
		t.Fatalf("last frame flag = %#x, want end-stream %#x; body %x", lastFlag, endStreamFlag, w.Body.Bytes())
	}
	if err := json.Unmarshal(lastPayload, &resp); err != nil {
		t.Fatalf("trailer body not JSON: %v (%s)", err, lastPayload)
	}
	return lastFlag, resp
}

// assertSuccessTrailer asserts the trailer is the success {} (nil error).
func assertSuccessTrailer(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	_, resp := streamTrailer(t, w)
	if resp.Error != nil {
		t.Fatalf("trailer = error %+v, want success {}", resp.Error)
	}
}

// assertErrorTrailer asserts the trailer carries the wanted Connect code.
func assertErrorTrailer(t *testing.T, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	_, resp := streamTrailer(t, w)
	if resp.Error == nil {
		t.Fatalf("trailer = success, want error code %q", wantCode)
	}
	if resp.Error.Code != wantCode {
		t.Fatalf("trailer code = %q, want %q (msg %q)", resp.Error.Code, wantCode, resp.Error.Message)
	}
}

// recordingCeilingsSession is an instrumented CeilingsSession: it counts the
// total AcquireBytes/ReleaseBytes (to assert the gauge nets to zero on every
// exit, Pitfall 6) and the fd acquire/release, and can fail AcquireBytes after
// a configured number of successful calls (the mid-stream-reject driver).
type recordingCeilingsSession struct {
	mu            sync.Mutex
	opErr         error
	fdErr         error
	bytesErr      error
	bytesErrAfter int // return bytesErr on the (bytesErrAfter+1)th AcquireBytes
	acquired      int64
	released      int64
	acquireCalls  int
	fdAcquired    int
	fdReleased    int
}

func (s *recordingCeilingsSession) TryConsumeOp() error { return s.opErr }

func (s *recordingCeilingsSession) AcquireBytes(n int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bytesErr != nil && s.acquireCalls >= s.bytesErrAfter {
		s.acquireCalls++
		return s.bytesErr
	}
	s.acquireCalls++
	s.acquired += n
	return nil
}

func (s *recordingCeilingsSession) ReleaseBytes(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.released += n
}

func (s *recordingCeilingsSession) TryAcquireFD() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fdErr != nil {
		return s.fdErr
	}
	s.fdAcquired++
	return nil
}

func (s *recordingCeilingsSession) ReleaseFD() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fdReleased++
}

func (s *recordingCeilingsSession) balanced() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acquired == s.released && s.fdAcquired == s.fdReleased
}

// fdCounts returns the fd acquire/release tallies under the lock so a test that
// polls the gauge while the handler goroutine still runs reads them race-free.
func (s *recordingCeilingsSession) fdCounts() (acquired, released int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fdAcquired, s.fdReleased
}

// recordingRegistry returns a fixed recording session for every key and
// records the keys requested (the channel-scope-keying witness).
type recordingRegistry struct {
	sess *recordingCeilingsSession
	mu   sync.Mutex
	keys []string
}

func (r *recordingRegistry) Session(key string) CeilingsSession {
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.mu.Unlock()
	return r.sess
}
func (r *recordingRegistry) Release(string) {}

var _ CeilingsSession = (*recordingCeilingsSession)(nil)
var _ CeilingsRegistry = (*recordingRegistry)(nil)

// newStreamDispatcher builds an engine-backed dispatcher with a recording
// ceilings session and a small whole-object ceiling for the size tests.
func newStreamDispatcher(eng Engine, g Guard, sess *recordingCeilingsSession, maxFile int64) *dispatcher {
	reg := &recordingRegistry{sess: sess}
	d := newDispatcherWithEngine(&fakeResolver{}, g, reg, 1<<20, eng)
	d.maxFileSize = maxFile
	return d
}

// TestFileUploadRouting pins Pitfall 1/4: fileUpload routes to serveStreaming
// (connect+json is admitted), a unary op with connect+json still hits the
// unary content-type reject, and fileDownload routes to streaming with an
// unimplemented trailer.
func TestFileUploadRouting(t *testing.T) {
	t.Run("fileUpload_admitted_to_stream", func(t *testing.T) {
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)
		body := concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertSuccessTrailer(t, w) // proves it reached the upload handler, not a unary reject
	})

	t.Run("unary_op_with_connect_json_still_unary_rejected", func(t *testing.T) {
		eng := newFakeEngine()
		d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)
		// readFile is unary; sending connect+json must hit the unary
		// content-type reject (the streaming branch is keyed on isStreamingOp,
		// not the content-type).
		r := httptest.NewRequest(http.MethodPost, restBase+string(OpReadFile), bytes.NewReader([]byte(`{}`)))
		r.Header.Set(streamProtocolVersionHeader, streamProtocolVersion)
		r.Header.Set("Content-Type", connContentTypeStream)
		r.ContentLength = 2
		ps := PeerScope{FilesystemID: streamScope, GrantedIntents: okIntents()}
		w := httptest.NewRecorder()
		d.ServeHTTP(w, r.WithContext(contextWithPeerScope(r.Context(), ps)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("readFile + connect+json status = %d, want 400 (unary content-type reject)", w.Code)
		}
	})

	t.Run("fileDownload_routes_to_streaming_handler", func(t *testing.T) {
		// fileDownload is now a real server-stream; confirm it routes to the
		// streaming branch (HTTP 200 + framed trailer) rather than a unary reject.
		// A nil body with no params frame is malformed, but the trailer must be
		// a framed error (not a unary 400/500), proving the streaming branch ran.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)
		w := serveStream(d, OpFileDownload, bytes.NewReader(nil), streamScope, okIntents())
		// A nil body means no params frame: the streaming handler returns a
		// framed error trailer (invalid_argument — malformed params frame).
		assertErrorTrailer(t, w, wireCodeInvalidArgument)
	})
}

// TestFileUploadNoContentLength pins Pitfall 2: a chunked upload (no
// Content-Length) is NOT refused with "requires Content-Length"; it proceeds.
func TestFileUploadNoContentLength(t *testing.T) {
	eng := newFakeEngine()
	sess := &recordingCeilingsSession{}
	d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)
	body := concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
	w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
	assertSuccessTrailer(t, w)
}

// TestFileUploadParamsGate pins the params-frame gate cases.
func TestFileUploadParamsGate(t *testing.T) {
	mk := func() *dispatcher {
		return newStreamDispatcher(newFakeEngine(), &fakeGuard{}, &recordingCeilingsSession{}, 1<<20)
	}

	t.Run("leading_end_stream_is_expected_params", func(t *testing.T) {
		d := mk()
		w := serveStream(d, OpFileUpload, bytes.NewReader(endFrame(t)), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodeInvalidArgument)
	})

	t.Run("missing_declared_size", func(t *testing.T) {
		d := mk()
		// declared_size_bytes 0 (<=0) -> invalid_argument, no escape hatch.
		w := serveStream(d, OpFileUpload, bytes.NewReader(paramsFrame(t, streamScope, "/up.bin", 0)), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodeInvalidArgument)
	})

	t.Run("unknown_field_rejected", func(t *testing.T) {
		d := mk()
		body := frameBytes(t, []byte(`{"filesystem_id":"fs-stream","path":"/up.bin","declared_size_bytes":8,"metadata_retention_days":7,"authorization_metadata":{"intent":"write","downloadable":false}}`))
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodeInvalidArgument)
	})

	t.Run("scope_mismatch", func(t *testing.T) {
		d := mk()
		// params filesystem_id disagrees with the channel scope.
		body := concat(paramsFrame(t, "fs-other", "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodePermissionDenied)
	})
}

// TestFileUploadHappyPath pins the success reassembly: the object is stored
// with the exact bytes (overwrite=false), the trailer is success, and an allow
// audit event preceded it.
func TestFileUploadHappyPath(t *testing.T) {
	eng := newFakeEngine()
	sess := &recordingCeilingsSession{}
	g := &fakeGuard{}
	d := newStreamDispatcher(eng, g, sess, 1<<20)

	body := concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
	w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
	assertSuccessTrailer(t, w)

	// The object is stored with the exact bytes.
	var buf bytes.Buffer
	if err := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 8, &buf); err != nil || buf.String() != "ABCDEFGH" {
		t.Fatalf("stored object = %q,%v want ABCDEFGH,nil", buf.String(), err)
	}
	// An allow audit event was Mandated (audit-before-ack).
	if len(g.events) == 0 {
		t.Fatalf("no allow audit event on a successful upload")
	}
	// The gauge balances.
	if !sess.balanced() {
		t.Fatalf("ceilings gauge unbalanced after success: bytes %d/%d fd %d/%d", sess.acquired, sess.released, sess.fdAcquired, sess.fdReleased)
	}
}

// TestFileUploadOversizeNoRead pins Pitfall 5/SEC-46: an over-ceiling
// declaration rejects BEFORE any chunk byte is read (zero chunk bytes), and
// WriteStream is never started (no object staged).
func TestFileUploadOversizeNoRead(t *testing.T) {
	eng := newFakeEngine()
	sess := &recordingCeilingsSession{}
	d := newStreamDispatcher(eng, &fakeGuard{}, sess, 4) // tiny whole-object ceiling

	params := paramsFrame(t, streamScope, "/up.bin", 1000) // declared >> ceiling
	chunk := chunkFrame(t, []byte("ABCDEFGH"))
	cr := &chunkCountingReader{r: bytes.NewReader(concat(params, chunk, endFrame(t))), paramsEnd: len(params), markedParams: true}

	w := serveStream(d, OpFileUpload, cr, streamScope, okIntents())
	assertErrorTrailer(t, w, wireCodeInvalidArgument)

	if cr.afterParams != 0 {
		t.Fatalf("read %d bytes past the params frame on an oversize declaration, want 0 (pre-buffer reject)", cr.afterParams)
	}
	// No object staged.
	var sink bytes.Buffer
	if err := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 1, &sink); err == nil {
		t.Fatalf("an object was staged on an oversize-declaration reject")
	}
	if !sess.balanced() {
		t.Fatalf("gauge unbalanced after oversize reject")
	}
}

// TestFileUploadSizeMismatch pins n2/Pitfall 4: over- and under-declaration
// both abort invalid_argument staging nothing; the matching case commits.
func TestFileUploadSizeMismatch(t *testing.T) {
	cases := []struct {
		name        string
		declared    int64
		chunk       []byte
		wantSuccess bool
	}{
		{"over_declaration", 8, []byte("ABCDEFGHIJ"), false}, // 10 actual > 8 declared
		{"under_declaration", 8, []byte("ABCD"), false},      // 4 actual < 8 declared
		{"matching", 8, []byte("ABCDEFGH"), true},            // positive control
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eng := newFakeEngine()
			sess := &recordingCeilingsSession{}
			d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)
			body := concat(paramsFrame(t, streamScope, "/up.bin", c.declared), chunkFrame(t, c.chunk), endFrame(t))
			w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())

			var staged bytes.Buffer
			readErr := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 1, &staged)
			if c.wantSuccess {
				assertSuccessTrailer(t, w)
				if readErr != nil {
					t.Fatalf("matching upload did not stage the object: %v", readErr)
				}
			} else {
				assertErrorTrailer(t, w, wireCodeInvalidArgument)
				if readErr == nil {
					t.Fatalf("%s staged an object (must stage nothing)", c.name)
				}
			}
			if !sess.balanced() {
				t.Fatalf("%s: gauge unbalanced", c.name)
			}
		})
	}
}

// TestFileUploadMalformedFrameHardAbort pins WIRE-LESSONS #1: a malformed
// chunk frame (undecodable JSON) and a truncated frame both hard-abort with an
// error trailer and stage nothing.
func TestFileUploadMalformedFrameHardAbort(t *testing.T) {
	t.Run("undecodable_chunk_json", func(t *testing.T) {
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)
		// A data frame whose payload is not a uploadChunkFrame object.
		bad := frameBytes(t, []byte(`["not","a","chunk"]`))
		body := concat(paramsFrame(t, streamScope, "/up.bin", 8), bad, endFrame(t))
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodeInvalidArgument)
		var sink bytes.Buffer
		if err := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 1, &sink); err == nil {
			t.Fatalf("malformed-frame abort staged an object")
		}
		if !sess.balanced() {
			t.Fatalf("gauge unbalanced after malformed-frame abort")
		}
	})

	t.Run("truncated_frame", func(t *testing.T) {
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)
		// params, then a header declaring len=8 with only 2 payload bytes (no
		// end-stream): readFrame errors mid-loop.
		var trunc bytes.Buffer
		var hdr [frameHeaderLen]byte
		hdr[4] = 8
		trunc.Write(hdr[:])
		trunc.Write([]byte("ab"))
		body := concat(paramsFrame(t, streamScope, "/up.bin", 8), trunc.Bytes())
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		// A truncated/aborted frame maps to aborted.
		assertErrorTrailer(t, w, wireCodeAborted)
		var sink bytes.Buffer
		if err := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 1, &sink); err == nil {
			t.Fatalf("truncated-frame abort staged an object")
		}
	})
}

// TestFileUploadTrailerBeforeClose pins WIRE-LESSONS #2: a mid-stream byte
// ceiling reject writes a well-formed 0x02 resource_exhausted trailer (HTTP
// 200) — the verdict reaches the recorder, not a transport error — and the
// gauge balances.
func TestFileUploadTrailerBeforeClose(t *testing.T) {
	eng := newFakeEngine()
	// Fail AcquireBytes on the FIRST chunk.
	sess := &recordingCeilingsSession{bytesErr: ErrBytesExceeded, bytesErrAfter: 0}
	g := &fakeGuard{}
	d := newStreamDispatcher(eng, g, sess, 1<<20)

	// Two chunks so a mid-stream reject is meaningful; the first AcquireBytes
	// fails.
	body := concat(
		paramsFrame(t, streamScope, "/up.bin", 16),
		chunkFrame(t, []byte("ABCDEFGH")),
		chunkFrame(t, []byte("IJKLMNOP")),
		endFrame(t),
	)
	w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
	assertErrorTrailer(t, w, wireCodeResourceExhausted)

	// A deny audit event was Mandated before the trailer (the allow + the
	// deny are both present; the deny is last).
	if len(g.events) < 2 {
		t.Fatalf("want an allow then a deny audit event, got %d", len(g.events))
	}
	var sink bytes.Buffer
	if err := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 1, &sink); err == nil {
		t.Fatalf("mid-stream byte-ceiling reject staged an object")
	}
	if !sess.balanced() {
		t.Fatalf("gauge unbalanced after mid-stream reject")
	}
}

// TestFileUploadPerFrameMaxInbound pins that a per-frame length over
// maxInboundFrame is a TRANSPORT reject (resource_exhausted), distinct from the
// policy size deny (invalid_argument).
func TestFileUploadPerFrameMaxInbound(t *testing.T) {
	eng := newFakeEngine()
	sess := &recordingCeilingsSession{}
	d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<30) // large policy ceiling

	// params (declared modest), then a data frame header declaring a length
	// over maxInboundFrame — readFrame returns errFrameTooLarge.
	var over bytes.Buffer
	var hdr [frameHeaderLen]byte
	hdr[0] = dataFlag
	// length = maxInboundFrame + 1, big-endian.
	putUint32BE(hdr[1:frameHeaderLen], uint32(maxInboundFrame+1))
	over.Write(hdr[:])
	body := concat(paramsFrame(t, streamScope, "/up.bin", 100), over.Bytes())
	w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
	assertErrorTrailer(t, w, wireCodeResourceExhausted)
}

// putUint32BE is a tiny local big-endian writer for the per-frame test header.
func putUint32BE(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// TestFileUploadMandateBeforeTrailer pins SEC-79 on the stream: on success the
// allow Mandate precedes the success trailer; on a mid-stream reject a deny
// Mandate precedes the error trailer. (The recorder records Mandate order; the
// trailer is the stream's "ack".)
func TestFileUploadMandateBeforeTrailer(t *testing.T) {
	t.Run("allow_before_success", func(t *testing.T) {
		eng := newFakeEngine()
		rec := &callRecorder{}
		g := &fakeGuard{rec: rec}
		sess := &recordingCeilingsSession{}
		d := newDispatcherWithEngine(&fakeResolver{rec: rec}, g, &recordingRegistry{sess: sess}, 1<<20, eng)
		d.maxFileSize = 1 << 20

		body := concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertSuccessTrailer(t, w)
		calls := rec.snapshot()
		// The last recorded pipeline call must be the allow Mandate (the
		// success trailer is written after it; nothing is recorded after).
		if len(calls) == 0 || calls[len(calls)-1] != "mandate" {
			t.Fatalf("call order = %v, want a mandate as the final pipeline call before the success trailer", calls)
		}
	})

	t.Run("deny_before_error", func(t *testing.T) {
		eng := newFakeEngine()
		g := &fakeGuard{}
		// Reject before any chunk: oversize declaration -> deny Mandate then
		// trailer.
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, g, sess, 4)
		body := paramsFrame(t, streamScope, "/up.bin", 1000)
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodeInvalidArgument)
		// A deny audit event was Mandated.
		if len(g.events) == 0 {
			t.Fatalf("no deny audit event on the size reject")
		}
		ev, ok := g.events[len(g.events)-1].(auditgate.FileActivityEvent)
		if !ok {
			t.Fatalf("audit event is not auditgate.FileActivityEvent: %T", g.events[len(g.events)-1])
		}
		if ev.Outcome.XDenyReason != denySizeExceeded {
			t.Fatalf("deny audit reason = %q, want %q", ev.Outcome.XDenyReason, denySizeExceeded)
		}
	})
}

// TestFileUploadAlreadyExists pins A1: overwrite=false against an existing path
// refuses already_exists in the trailer.
func TestFileUploadAlreadyExists(t *testing.T) {
	eng := newFakeEngine()
	eng.putBytes(streamScope, "up.bin", []byte("OLDBYTES"))
	sess := &recordingCeilingsSession{}
	d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

	body := concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
	w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
	assertErrorTrailer(t, w, wireCodeAlreadyExists)

	// The original bytes are unchanged.
	var buf bytes.Buffer
	if err := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 8, &buf); err != nil || buf.String() != "OLDBYTES" {
		t.Fatalf("existing object changed by a refused overwrite: %q,%v", buf.String(), err)
	}
	if !sess.balanced() {
		t.Fatalf("gauge unbalanced after already_exists")
	}
}

// paramsFrameOverwrite encodes an upload params frame with the given
// overwrite_existing value.
func paramsFrameOverwrite(t fataler, scope, path string, declared int64, overwrite bool) []byte {
	t.Helper()
	body := fmt.Sprintf(
		`{"filesystem_id":%q,"path":%q,"declared_size_bytes":%d,"overwrite_existing":%t,"authorization_metadata":{"intent":"write","downloadable":false}}`,
		scope, path, declared, overwrite)
	return frameBytes(t, []byte(body))
}

// TestFileUploadOverwriteExisting pins BL-P2: the overwrite_existing param
// controls whether an upload onto an existing path succeeds or refuses.
//
//   - overwrite_existing=true onto an existing path REPLACES the content (no
//     already_exists error, new bytes are readable).
//   - overwrite_existing=false (or absent — the zero value) refuses
//     already_exists, leaving the original bytes intact.
//   - The strict-decode discipline is preserved: overwrite_existing is
//     accepted as a known field (no rejection), while unknown fields still
//     cause invalid_argument.
func TestFileUploadOverwriteExisting(t *testing.T) {
	const (
		path    = "/ow.bin"
		engPath = "ow.bin"
	)
	newContent := []byte("NEWBYTES")

	t.Run("overwrite_true_replaces_existing", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putBytes(streamScope, engPath, []byte("OLDBYTES"))
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		body := concat(
			paramsFrameOverwrite(t, streamScope, path, int64(len(newContent)), true),
			chunkFrame(t, newContent),
			endFrame(t),
		)
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertSuccessTrailer(t, w)

		// The new bytes are readable; old bytes are gone.
		var buf bytes.Buffer
		if err := eng.ReadRange(t.Context(), streamScope, engPath, 0, int64(len(newContent)), &buf); err != nil {
			t.Fatalf("overwrite=true: ReadRange failed: %v", err)
		}
		if got := buf.String(); got != string(newContent) {
			t.Fatalf("overwrite=true: stored bytes = %q, want %q", got, newContent)
		}
		if !sess.balanced() {
			t.Fatalf("overwrite=true: ceilings gauge unbalanced")
		}
	})

	t.Run("overwrite_false_refuses_already_exists", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putBytes(streamScope, engPath, []byte("OLDBYTES"))
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		body := concat(
			paramsFrameOverwrite(t, streamScope, path, int64(len(newContent)), false),
			chunkFrame(t, newContent),
			endFrame(t),
		)
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodeAlreadyExists)

		// Original bytes are intact.
		var buf bytes.Buffer
		if err := eng.ReadRange(t.Context(), streamScope, engPath, 0, 8, &buf); err != nil || buf.String() != "OLDBYTES" {
			t.Fatalf("overwrite=false: existing bytes changed: %q, %v", buf.String(), err)
		}
		if !sess.balanced() {
			t.Fatalf("overwrite=false: ceilings gauge unbalanced")
		}
	})

	t.Run("overwrite_absent_defaults_false", func(t *testing.T) {
		// A params frame that omits overwrite_existing entirely must behave
		// as overwrite=false (JSON zero value — today's behaviour preserved).
		eng := newFakeEngine()
		eng.putBytes(streamScope, engPath, []byte("OLDBYTES"))
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		// Use paramsFrame (no overwrite field) onto an existing path.
		body := concat(
			paramsFrame(t, streamScope, path, int64(len(newContent))),
			chunkFrame(t, newContent),
			endFrame(t),
		)
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodeAlreadyExists)

		// Original bytes still intact.
		var buf bytes.Buffer
		if err := eng.ReadRange(t.Context(), streamScope, engPath, 0, 8, &buf); err != nil || buf.String() != "OLDBYTES" {
			t.Fatalf("overwrite_absent: existing bytes changed: %q, %v", buf.String(), err)
		}
	})
}

// TestFileUploadKeysChannelScope pins that ceilings key on the CHANNEL scope
// (PeerScope.FilesystemID), never the params body value.
func TestFileUploadKeysChannelScope(t *testing.T) {
	eng := newFakeEngine()
	sess := &recordingCeilingsSession{}
	reg := &recordingRegistry{sess: sess}
	d := newDispatcherWithEngine(&fakeResolver{}, &fakeGuard{}, reg, 1<<20, eng)
	d.maxFileSize = 1 << 20

	// params filesystem_id matches the channel scope (a mismatch denies
	// earlier); confirm the ceilings registry was keyed on the channel scope.
	body := concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
	w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
	assertSuccessTrailer(t, w)
	for _, k := range reg.keys {
		if k != streamScope {
			t.Fatalf("ceilings keyed on %q, want the channel scope %q", k, streamScope)
		}
	}
	if len(reg.keys) == 0 {
		t.Fatalf("ceilings registry never keyed (throttle bypassed)")
	}
}
