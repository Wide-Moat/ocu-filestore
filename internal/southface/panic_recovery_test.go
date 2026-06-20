// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// panicEngine is a fault-injection Engine whose verbs panic unconditionally.
// It implements the full Engine seam so the panicking-fake can be injected
// into a real dispatcher without any special wiring.
//
// This is fault injection, not a mock of a real dependency: we need to verify
// that the panic containment layer (T2-4, RES-02) catches panics before they
// propagate to the HTTP server layer as a goroutine crash or a naked connection
// drop.
type panicEngine struct{}

func (panicEngine) List(_ context.Context, _, _ string) ([]FileInfo, error) {
	panic("panicEngine: List panicked")
}
func (panicEngine) Stat(_ context.Context, _, _ string) (FileInfo, error) {
	panic("panicEngine: Stat panicked")
}
func (panicEngine) MakeDir(_ context.Context, _, _ string) error {
	panic("panicEngine: MakeDir panicked")
}
func (panicEngine) MoveDir(_ context.Context, _, _, _ string, _ bool) error {
	panic("panicEngine: MoveDir panicked")
}
func (panicEngine) RemoveDir(_ context.Context, _, _ string) error {
	panic("panicEngine: RemoveDir panicked")
}
func (panicEngine) CopyFile(_ context.Context, _, _, _ string, _ bool) error {
	panic("panicEngine: CopyFile panicked")
}
func (panicEngine) MoveFile(_ context.Context, _, _, _ string, _ bool) error {
	panic("panicEngine: MoveFile panicked")
}
func (panicEngine) RemoveFile(_ context.Context, _, _ string) error {
	panic("panicEngine: RemoveFile panicked")
}
func (panicEngine) ReadRange(_ context.Context, _, _ string, _, _ int64, _ io.Writer) error {
	panic("panicEngine: ReadRange panicked")
}
func (panicEngine) WriteStream(_ context.Context, _, _ string, r io.Reader, _ bool) error {
	panic("panicEngine: WriteStream panicked")
}

// Compile-time proof the fake satisfies the seam.
var _ Engine = panicEngine{}

// TestPanicContainmentUnaryPath drives a panicking-fake-engine on the UNARY
// dispatch path (list_directory, which calls the registered handler that in
// turn calls panicEngine.List). Asserts:
//
//   - The dispatcher returns a structured deny (not a crash / naked connection
//     drop — the test would deadlock or panic itself if the server goroutine
//     was not recovered).
//   - The deny audit (best-effort Mandate) was attempted (guard.events is
//     non-empty after the call).
//   - The wire response carries the internal Connect code.
func TestPanicContainmentUnaryPath(t *testing.T) {
	g := &fakeGuard{}
	d := newDispatcherWithEngine(
		&fakeResolver{grant: Grant{Downloadable: true}},
		g,
		okCeilings(),
		1<<20,
		panicEngine{},
	)

	const scope = "fs-panic-unary"
	body := listBody(scope, "/", 0, "", false)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, scopedRequest(OpListDirectory, body, scope, okIntents()))

	// Panic was contained: the recorder has a response (not a crash).
	if w.Code == 0 {
		t.Fatal("response code is 0 — panic was not recovered (server crashed)")
	}

	// The wire deny is the structured REST BoundedReason body.
	ce := decodeErrBody(t, w)
	if ce.Code != wireCodeInternal {
		t.Fatalf("wire code = %q, want %q (internal)", ce.Code, wireCodeInternal)
	}

	// A best-effort deny audit was attempted (guard received at least one Mandate
	// event — the pre-handler allow-Mandate from STAGE 3 and/or the recovery
	// deny). The key invariant: the guard was called, so the audit chain has
	// a record that something happened for this request.
	g.mu.Lock()
	evCount := len(g.events)
	g.mu.Unlock()
	if evCount == 0 {
		t.Fatal("guard.Mandate was never called — deny audit was not attempted (NFR-SEC-79)")
	}
}

// TestPanicContainmentStreamUploadPath drives a panicking-fake-engine on the
// STREAMING UPLOAD path (fileUpload → WriteStream). Asserts:
//
//   - The stream response is HTTP 200 (always, per the streaming contract).
//   - The trailer carries a deny error code (not a success — the upload did
//     not commit).
//   - No goroutine leak: the test completes without hanging (if the pipe
//     goroutine leaked the test would deadlock waiting on writeErrCh).
//   - A deny audit was attempted (guard.Mandate called).
func TestPanicContainmentStreamUploadPath(t *testing.T) {
	g := &fakeGuard{}
	d := newDispatcherWithEngine(
		&fakeResolver{grant: Grant{Downloadable: true}},
		g,
		okCeilings(),
		1<<20,
		panicEngine{},
	)
	// Inject a generous maxFileSize so the pre-buffer size reject does not
	// fire before the engine is reached.
	d.maxFileSize = 1 << 30

	const (
		scope   = "fs-panic-stream"
		path    = "/upload-panic.bin"
		content = "hello panic"
	)
	declared := int64(len(content))

	// Build a valid upload stream: params + one chunk + end-stream.
	var buf bytes.Buffer
	if err := writeFrame(&buf, dataFlag, []byte(
		`{"filesystem_id":"`+scope+`","path":"`+path+`","declared_size_bytes":`+
			itoa(declared)+`,"authorization_metadata":{"intent":"write","downloadable":false}}`,
	)); err != nil {
		t.Fatalf("params frame: %v", err)
	}
	chunk, _ := json.Marshal(uploadChunkFrame{Chunk: []byte(content)})
	if err := writeFrame(&buf, dataFlag, chunk); err != nil {
		t.Fatalf("chunk frame: %v", err)
	}
	if err := writeFrame(&buf, endStreamFlag, []byte("{}")); err != nil {
		t.Fatalf("end-stream frame: %v", err)
	}

	w := httptest.NewRecorder()
	serveStreamingShim(d, w, streamRequest(OpFileUpload, &buf, scope, okIntents()))

	// Always HTTP 200 on the streaming path.
	if w.Code != 200 {
		t.Fatalf("streaming response status = %d, want 200", w.Code)
	}

	// The trailer must be an error (the engine panicked, the upload did not
	// commit). The exact code may be internal or unavailable depending on
	// whether the Mandate call also failed.
	_, resp := streamTrailer(t, w)
	if resp.Error == nil {
		t.Fatal("trailer = success, want an error (engine panicked)")
	}

	// Guard was called at least once (the allow Mandate at STAGE 3 fired).
	g.mu.Lock()
	evCount := len(g.events)
	g.mu.Unlock()
	if evCount == 0 {
		t.Fatal("guard.Mandate was never called — deny audit was not attempted (NFR-SEC-79)")
	}
}

// TestPanicContainmentStreamDownloadPath drives a panicking-fake-engine on the
// STREAMING DOWNLOAD path (fileDownload → ReadRange). To reach ReadRange we
// need a valid UUID in the objectIDStore, which requires a prior listing or
// readFile to mint one. We seed the store directly (the store is package-
// accessible) and build a valid download request.
func TestPanicContainmentStreamDownloadPath(t *testing.T) {
	g := &fakeGuard{}
	d := newDispatcherWithEngine(
		&fakeResolver{grant: Grant{Downloadable: true}},
		g,
		okCeilings(),
		1<<20,
		panicEngine{},
	)

	const (
		scope    = "fs-panic-download"
		filePath = "panic-file.bin"
	)

	// Obtain a UUID from the objectIDStore (engine-relative path, no leading
	// slash — the store is keyed on the guest-convention path emitted by the
	// listing handler, which is the engine path with "/" prepended).
	uuid := d.ids.idFor(scope, "/"+filePath)

	// Build a valid download request: params frame carrying the uuid. A RANGE
	// is supplied so the handler skips the whole-object Stat size probe and
	// drives straight to ReadRange — the verb whose pipe-goroutine panic
	// containment (recoverReadStream) this test exercises.
	paramsJSON := `{"filesystem_id":"` + scope + `","uuid":"` + uuid + `","range":{"offset":0,"length":16},"authorization_metadata":{"intent":"read","downloadable":true}}`
	var buf bytes.Buffer
	if err := writeFrame(&buf, dataFlag, []byte(paramsJSON)); err != nil {
		t.Fatalf("params frame: %v", err)
	}

	w := httptest.NewRecorder()
	serveStreamingShim(d, w, streamRequest(OpFileDownload, &buf, scope, []Intent{IntentRead, IntentWrite}))

	// Always HTTP 200 on the streaming path.
	if w.Code != 200 {
		t.Fatalf("streaming response status = %d, want 200", w.Code)
	}

	// Trailer must carry an error.
	_, resp := streamTrailer(t, w)
	if resp.Error == nil {
		t.Fatal("trailer = success, want error (engine ReadRange panicked)")
	}

	// Guard was called (allow Mandate fired before the engine goroutine).
	g.mu.Lock()
	evCount := len(g.events)
	g.mu.Unlock()
	if evCount == 0 {
		t.Fatal("guard.Mandate was never called — deny audit was not attempted (NFR-SEC-79)")
	}
}

// TestPanicContainmentStreamDownloadStatPath drives a panicking-fake-engine on
// the WHOLE-OBJECT download path, where the handler runs engine.Stat on the
// MAIN goroutine to resolve the read length (a nil Range = whole object). A
// Stat panic must be contained INTO a framed end-stream error trailer — never
// escape to recoverDispatch and surface as a unary error after the HTTP-200
// stream header is already committed (the streaming always-framed-trailer
// contract). The deny audit must still be attempted (NFR-SEC-79).
func TestPanicContainmentStreamDownloadStatPath(t *testing.T) {
	g := &fakeGuard{}
	d := newDispatcherWithEngine(
		&fakeResolver{grant: Grant{Downloadable: true}},
		g,
		okCeilings(),
		1<<20,
		panicEngine{},
	)

	const (
		scope    = "fs-panic-stat"
		filePath = "panic-stat.bin"
	)
	uuid := d.ids.idFor(scope, "/"+filePath)

	// NO range field → whole-object read → the handler calls engine.Stat, which
	// panics on panicEngine.
	paramsJSON := `{"filesystem_id":"` + scope + `","uuid":"` + uuid + `","authorization_metadata":{"intent":"read","downloadable":true}}`
	var buf bytes.Buffer
	if err := writeFrame(&buf, dataFlag, []byte(paramsJSON)); err != nil {
		t.Fatalf("params frame: %v", err)
	}

	w := httptest.NewRecorder()
	serveStreamingShim(d, w, streamRequest(OpFileDownload, &buf, scope, []Intent{IntentRead, IntentWrite}))

	if w.Code != 200 {
		t.Fatalf("streaming response status = %d, want 200", w.Code)
	}

	// The verdict must be a framed END-STREAM (0x02) error trailer, proving the
	// Stat panic was contained inside the stream rather than escaping to the
	// unary recoverDispatch net.
	flag, resp := streamTrailer(t, w)
	if flag != endStreamFlag {
		t.Fatalf("last frame flag = %#x, want end-stream %#x (Stat panic escaped the stream)", flag, endStreamFlag)
	}
	if resp.Error == nil {
		t.Fatal("trailer = success, want error (engine Stat panicked)")
	}

	// Deny audit was attempted (the contained panic flows through
	// denyDownloadTrailer → guard.Mandate before the trailer).
	g.mu.Lock()
	evCount := len(g.events)
	g.mu.Unlock()
	if evCount == 0 {
		t.Fatal("guard.Mandate was never called — deny audit was not attempted (NFR-SEC-79)")
	}
}

// itoa is a minimal int64-to-string helper used in the test body literal so
// the test has no import on strconv (it stays in the southface test package
// without pulling in extra packages).
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// TestDispatcherRecoveryDoesNotReorderPipeline verifies that adding the panic
// recovery defer does NOT alter the LOCKED STAGE 0->4 call order recorded by
// the callRecorder — the ordering pins in TestMandateBeforeAck and
// TestPipelineOrder must still hold when a non-panicking engine is in play.
func TestDispatcherRecoveryDoesNotReorderPipeline(t *testing.T) {
	rec := &callRecorder{}
	d := newTestDispatcher(
		&fakeResolver{rec: rec},
		&fakeGuard{rec: rec},
		&fakeCeilingsRegistry{session: &fakeCeilingsSession{rec: rec}},
	)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, scopedRequest(OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead}))

	calls := rec.snapshot()
	want := []string{"ceilings_op", "resolve", "mandate"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("call order with recovery = %v, want %v (STAGE 0->4 must be unchanged)", calls, want)
	}
}
