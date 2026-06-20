// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"io"
	"net/http"
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

// TestPanicContainmentMultipartUploadPath drives a panicking-fake-engine on the
// REST multipart fileUpload path (WriteStream panics inside the pipe
// goroutine). recoverWriteStream must contain the panic: the reassembly loop's
// blocked pw.Write unblocks (the read end is closed with errInternalPanic), the
// upload aborts cleanly, no goroutine leaks (the test would deadlock on
// writeErrCh otherwise), and the engine's temp+rename atomicity guarantees no
// torn object. The pre-byte allow audit was already Mandated, so the guard was
// called (NFR-SEC-79).
func TestPanicContainmentMultipartUploadPath(t *testing.T) {
	g := &fakeGuard{}
	sess := &recordingCeilingsSession{}
	d := newStreamDispatcher(panicEngine{}, g, sess, 1<<20)
	// The resolver must grant write so the upload reaches the engine WriteStream.
	d.resolver = &fakeResolver{grant: Grant{Downloadable: true}}

	content := []byte("PANIC-DURING-WRITESTREAM")
	w := serveUpload(t, d, uploadBodyOpts{
		scope: "fs-panic-upload", path: "/boom.bin", declared: int64(len(content)), fileBytes: content,
	}, "fs-panic-upload", okIntents())

	// The panic was contained: the handler returned a structured response, not a
	// crash (a leaked pipe goroutine would have hung this test on writeErrCh).
	if w.Code == 0 {
		t.Fatal("response code is 0 — the WriteStream panic was not contained (goroutine crash)")
	}
	if w.Code == http.StatusOK {
		t.Fatalf("status = %d, want a deny (the upload must not commit on a WriteStream panic)", w.Code)
	}
	// The deny audit was attempted (the allow Mandate fired before the engine
	// goroutine ran).
	g.mu.Lock()
	evCount := len(g.events)
	g.mu.Unlock()
	if evCount == 0 {
		t.Fatal("guard.Mandate was never called — audit was not attempted (NFR-SEC-79)")
	}
	// The ceilings gauge balances even on the panic-abort path (every acquire
	// released).
	if !sess.balanced() {
		t.Fatalf("ceilings gauge unbalanced after a contained WriteStream panic: bytes %d/%d fd %d/%d",
			sess.acquired, sess.released, sess.fdAcquired, sess.fdReleased)
	}
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
