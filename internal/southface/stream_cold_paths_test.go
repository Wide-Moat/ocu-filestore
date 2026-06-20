// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"testing"
)

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
// main handler goroutine never escapes into a half-written octet-stream
// response.
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
