// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

// drainErrEngine is a fault-injection Engine that fully drains the WriteStream
// reader (as the real local engine's io.Copy does) and records the TERMINAL
// error the reader returned. It lets a unit test observe whether the upload
// handler closed the engine pipe with a clean io.EOF (which io.Copy would treat
// as a successful commit) or with a real abort error. Only WriteStream is
// meaningful; the other verbs are unused here.
type drainErrEngine struct {
	termErr error // the error the reader returned after the last byte
	n       int64 // bytes drained
}

func (e *drainErrEngine) WriteStream(ctx context.Context, _, _ string, r io.Reader, _ bool) error {
	buf := make([]byte, 512)
	for {
		nn, err := r.Read(buf)
		e.n += int64(nn)
		if err != nil {
			e.termErr = err
			// Mirror io.Copy semantics: io.EOF is a clean end (nil), any other
			// error propagates as the WriteStream error.
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (e *drainErrEngine) List(context.Context, string, string) ([]FileInfo, error) {
	return nil, errors.New("unused")
}
func (e *drainErrEngine) Stat(context.Context, string, string) (FileInfo, error) {
	return FileInfo{}, errors.New("unused")
}
func (e *drainErrEngine) MakeDir(context.Context, string, string) error { return errors.New("unused") }
func (e *drainErrEngine) MoveDir(context.Context, string, string, string, bool) error {
	return errors.New("unused")
}
func (e *drainErrEngine) RemoveDir(context.Context, string, string) error {
	return errors.New("unused")
}
func (e *drainErrEngine) CopyFile(context.Context, string, string, string, bool) error {
	return errors.New("unused")
}
func (e *drainErrEngine) MoveFile(context.Context, string, string, string, bool) error {
	return errors.New("unused")
}
func (e *drainErrEngine) RemoveFile(context.Context, string, string) error {
	return errors.New("unused")
}
func (e *drainErrEngine) ReadRange(context.Context, string, string, int64, int64, io.Writer) error {
	return errors.New("unused")
}

var _ Engine = (*drainErrEngine)(nil)

// TestUploadTruncatedStreamClosesPipeWithAbortError pins the torn-commit fix at
// the handler layer with no mock of the real engine's atomicity: a fileUpload
// that sends params + one chunk and then TRUNCATES (the body returns io.EOF
// before the explicit end-stream half-close, exactly the mid-stream connection
// drop) must close the engine pipe with a NON-EOF abort error. A clean io.EOF
// would make the engine's io.Copy treat the partial bytes as a complete stream
// and commit a torn object (temp+rename). The drainErrEngine records the
// terminal error its reader saw; the test asserts it is NOT io.EOF, so the real
// engine would discard the temp.
func TestUploadTruncatedStreamClosesPipeWithAbortError(t *testing.T) {
	eng := &drainErrEngine{}
	sess := &recordingCeilingsSession{}
	d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

	// params declaring 64 bytes + one 13-byte chunk, then NO end-stream frame:
	// the body simply ends, so the handler's next readFrame returns io.EOF.
	body := concat(
		paramsFrame(t, streamScope, "/torn.bin", 64),
		chunkFrame(t, []byte("partial-bytes")),
	)
	w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())

	// The verdict is an abort error trailer (never success).
	assertErrorTrailer(t, w, wireCodeAborted)

	// The engine's reader saw a NON-EOF terminal error — the load-bearing
	// assertion: a clean io.EOF here is the torn-commit bug.
	if eng.termErr == nil {
		t.Fatal("engine WriteStream reader saw no terminal error; the pipe was clean-closed (torn-commit bug)")
	}
	if errors.Is(eng.termErr, io.EOF) {
		t.Fatalf("engine WriteStream reader terminal error = io.EOF; a truncated upload MUST close the pipe with a non-EOF abort error so the engine discards the temp (got %v)", eng.termErr)
	}
	if !errors.Is(eng.termErr, errStreamAborted) {
		t.Fatalf("engine WriteStream reader terminal error = %v, want errStreamAborted", eng.termErr)
	}
	// The 13 partial bytes were drained but the stream aborted before commit.
	if eng.n != 13 {
		t.Fatalf("engine drained %d bytes, want the 13 partial bytes", eng.n)
	}
	// Ceilings balance on the abort path.
	if !sess.balanced() {
		t.Fatalf("ceilings unbalanced after truncated-upload abort: acq=%d rel=%d", sess.acquired, sess.released)
	}
}

// TestDenyClassForDecodeErrArms pins the two decode-class arms the route/
// envelope happy paths do not reach: the declared-size sentinel maps to
// size_exceeded, and a non-sentinel error falls through to the internal class.
// The malformed family is already exercised by the envelope tests; this closes
// the size and default arms so the mapper's whole switch is covered.
func TestDenyClassForDecodeErrArms(t *testing.T) {
	if got := denyClassForDecodeErr(errDeclaredSizeExceeded); got != denySizeExceeded {
		t.Fatalf("denyClassForDecodeErr(size) = %q, want %q", got, denySizeExceeded)
	}
	// A wrapped declared-size sentinel still matches under errors.Is.
	wrapped := errors.Join(errors.New("context"), errDeclaredSizeExceeded)
	if got := denyClassForDecodeErr(wrapped); got != denySizeExceeded {
		t.Fatalf("denyClassForDecodeErr(wrapped size) = %q, want %q", got, denySizeExceeded)
	}
	// An unrecognised error is the default (internal) — never silently malformed.
	if got := denyClassForDecodeErr(errors.New("not a decode sentinel")); got != denyInternal {
		t.Fatalf("denyClassForDecodeErr(unknown) = %q, want %q", got, denyInternal)
	}
}

// TestCtxOrBackground pins both arms of the handlerCtx context accessor: a
// handler built with a real context returns it verbatim, and one built without
// (the direct unit-test construction) falls back to context.Background rather
// than returning a nil context that would panic the first engine call.
func TestCtxOrBackground(t *testing.T) {
	type ctxKey string
	const k ctxKey = "marker"

	hcNil := handlerCtx{}
	if got := hcNil.ctxOrBackground(); got == nil {
		t.Fatal("ctxOrBackground() on a nil-ctx handlerCtx returned nil, want context.Background")
	}

	want := context.WithValue(context.Background(), k, "v")
	hcSet := handlerCtx{ctx: want}
	if got := hcSet.ctxOrBackground(); got.Value(k) != "v" {
		t.Fatal("ctxOrBackground() did not return the supplied request context verbatim")
	}
}

// TestStatSizeContained pins the whole-object download size probe in all three
// arms: a present object returns its size; a missing object surfaces the
// engine's not_found error (classified to denyNotFound by the caller); and a
// panicking engine is RECOVERED into errInternalPanic so a Stat fault on the
// main handler goroutine never escapes the streaming contract.
func TestStatSizeContained(t *testing.T) {
	const scope = "fs-stat-contained"

	t.Run("present", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(scope, "dir/obj.bin", 4096)
		size, err := statSizeContained(context.Background(), eng, scope, "dir/obj.bin")
		if err != nil {
			t.Fatalf("statSizeContained(present) err = %v, want nil", err)
		}
		if size != 4096 {
			t.Fatalf("statSizeContained(present) size = %d, want 4096", size)
		}
	})

	t.Run("missing", func(t *testing.T) {
		eng := newFakeEngine()
		size, err := statSizeContained(context.Background(), eng, scope, "ghost.bin")
		if err == nil {
			t.Fatal("statSizeContained(missing) err = nil, want a not_found error")
		}
		if size != 0 {
			t.Fatalf("statSizeContained(missing) size = %d, want 0", size)
		}
		if got := denyClassForEngineErr(err); got != denyNotFound {
			t.Fatalf("statSizeContained(missing) classifies as %q, want %q", got, denyNotFound)
		}
	})

	t.Run("panic_contained", func(t *testing.T) {
		size, err := statSizeContained(context.Background(), panicEngine{}, scope, "boom.bin")
		if !errors.Is(err, errInternalPanic) {
			t.Fatalf("statSizeContained(panicking) err = %v, want errInternalPanic", err)
		}
		if size != 0 {
			t.Fatalf("statSizeContained(panicking) size = %d, want 0", size)
		}
		if got := denyClassForEngineErr(err); got != denyInternal {
			t.Fatalf("statSizeContained(panicking) classifies as %q, want %q", got, denyInternal)
		}
	})
}
