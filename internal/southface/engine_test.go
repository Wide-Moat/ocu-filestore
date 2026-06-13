// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
)

// TestEnginePath pins the guest leading-slash -> engine relative translation,
// the single highest-risk helper (Pitfall 1). Every row is asserted.
func TestEnginePath(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"/", "."},
		{"", "."},
		{"/a/b", "a/b"},
		{"/golden-dir", "golden-dir"},
		{"a/b", "a/b"},      // already-relative passes through
		{"/a/b/c", "a/b/c"}, // deeper path
		{"relative", "relative"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := enginePath(tc.in); got != tc.want {
				t.Fatalf("enginePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestGuestPath pins the inverse used in listing-response emission: the engine
// relative path is stamped back into the guest's leading-slash convention.
func TestGuestPath(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{".", "/"},
		{"", "/"},
		{"a/b", "/a/b"},
		{"golden-dir", "/golden-dir"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := guestPathFromRel(tc.in); got != tc.want {
				t.Fatalf("guestPathFromRel(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDenyClassForEngineErr pins the order-sensitive engine-error
// classification (Pitfall 2 / D4). The EEXIST and ENOENT rows are the order
// regression guard: both are *fs.PathError, which isPathEscape also matches,
// so testing the fs sentinels FIRST is what keeps a benign already-exists or
// missing-parent from being misrecorded as a security escape.
func TestDenyClassForEngineErr(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{
			// ORDER REGRESSION GUARD: EEXIST as a *fs.PathError must NOT
			// fall through to isPathEscape (which would also match it).
			name: "PathError wrapping fs.ErrExist -> already_exists (not escape)",
			err:  &fs.PathError{Op: "mkdir", Path: "d", Err: fs.ErrExist},
			want: denyAlreadyExists,
		},
		{
			// ORDER REGRESSION GUARD: missing-parent ENOENT as a
			// *fs.PathError must classify not_found, not escape.
			name: "PathError wrapping fs.ErrNotExist -> not_found (not escape)",
			err:  &fs.PathError{Op: "open", Path: "a/b", Err: fs.ErrNotExist},
			want: denyNotFound,
		},
		{
			name: "errAlreadyExists sentinel -> already_exists",
			err:  errAlreadyExists,
			want: denyAlreadyExists,
		},
		{
			name: "fmt-wrapped errAlreadyExists -> already_exists (errors.Is chains)",
			err:  fmt.Errorf("move failed: %w", errAlreadyExists),
			want: denyAlreadyExists,
		},
		{
			name: "pure containment escape (*fs.PathError, neither EEXIST nor ENOENT) -> not_found degraded",
			err:  &fs.PathError{Op: "openat", Path: "x", Err: errors.New("path escapes from parent")},
			want: denyNotFound,
		},
		{
			name: "containment escape via *os.LinkError -> not_found degraded",
			err:  &os.LinkError{Op: "rename", Old: "a", New: "b", Err: errors.New("escapes root")},
			want: denyNotFound,
		},
		{
			name: "errInvalidPath sentinel -> not_found degraded",
			err:  errInvalidPath,
			want: denyNotFound,
		},
		{
			name: "unrelated error -> internal",
			err:  errors.New("disk on fire"),
			want: denyInternal,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := denyClassForEngineErr(tc.err); got != tc.want {
				t.Fatalf("denyClassForEngineErr(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestFakeEngineSemantics pins that the in-memory tree fake mirrors the engine
// sentinel contract the deny-mapping tests bind to, and that mutations are
// visible in subsequent listings (the real-tree requirement, Q2).
func TestFakeEngineSemantics(t *testing.T) {
	ctx := context.Background()
	const scope = "fs-1"

	t.Run("MakeDir on existing dir -> fs.ErrExist", func(t *testing.T) {
		e := newFakeEngine()
		if err := e.MakeDir(ctx, scope, "d"); err != nil {
			t.Fatalf("first MakeDir: %v", err)
		}
		err := e.MakeDir(ctx, scope, "d")
		if !errors.Is(err, fs.ErrExist) {
			t.Fatalf("MakeDir existing: err %v, want fs.ErrExist", err)
		}
		// And it classifies as already_exists, not escape.
		if c := denyClassForEngineErr(err); c != denyAlreadyExists {
			t.Fatalf("EEXIST class = %q, want already_exists", c)
		}
	})

	t.Run("MakeDir missing parent -> fs.ErrNotExist", func(t *testing.T) {
		e := newFakeEngine()
		err := e.MakeDir(ctx, scope, "a/b")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("MakeDir missing parent: err %v, want fs.ErrNotExist", err)
		}
	})

	t.Run("Move to existing dst overwrite=false -> errAlreadyExists", func(t *testing.T) {
		e := newFakeEngine()
		e.putFile(scope, "src.txt", 3)
		e.putFile(scope, "dst.txt", 7)
		err := e.MoveFile(ctx, scope, "src.txt", "dst.txt", false)
		if !errors.Is(err, errAlreadyExists) {
			t.Fatalf("Move collision: err %v, want errAlreadyExists", err)
		}
	})

	t.Run("RemoveDir of missing path is a no-op (nil)", func(t *testing.T) {
		e := newFakeEngine()
		if err := e.RemoveDir(ctx, scope, "nope"); err != nil {
			t.Fatalf("RemoveDir missing: %v, want nil", err)
		}
	})

	t.Run("List/Stat of missing path -> fs.ErrNotExist", func(t *testing.T) {
		e := newFakeEngine()
		if _, err := e.List(ctx, scope, "ghost"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("List missing: %v, want fs.ErrNotExist", err)
		}
		if _, err := e.Stat(ctx, scope, "ghost"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Stat missing: %v, want fs.ErrNotExist", err)
		}
	})

	t.Run("MakeDir then List shows the new entry (real tree, not scripted)", func(t *testing.T) {
		e := newFakeEngine()
		if err := e.MakeDir(ctx, scope, "fresh"); err != nil {
			t.Fatalf("MakeDir: %v", err)
		}
		entries, err := e.List(ctx, scope, ".")
		if err != nil {
			t.Fatalf("List root: %v", err)
		}
		found := false
		for _, en := range entries {
			if en.Name == "fresh" && en.IsDir {
				found = true
			}
		}
		if !found {
			t.Fatalf("List root = %+v, want a dir entry 'fresh'", entries)
		}
	})

	t.Run("lexical reject -> errInvalidPath", func(t *testing.T) {
		e := newFakeEngine()
		if _, err := e.List(ctx, scope, "a//b"); !errors.Is(err, errInvalidPath) {
			t.Fatalf("List a//b: %v, want errInvalidPath", err)
		}
	})
}

// TestDenyClassForEngineErr_BackendRows pins the W1 backend resilience rows
// in the engine-error classifier: throttle -> throttle (resource_exhausted
// downstream), transient -> backend_unavailable (unavailable downstream) —
// including fmt-wrapped forms, the shape the broker adapter hands the spine.
// The order non-regression and non-vacuity rows re-assert that inserting the
// two branches did not disturb the load-bearing fs-sentinels-before-escape
// ordering or widen the default.
func TestDenyClassForEngineErr_BackendRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{
			name: "errBackendThrottled -> throttle",
			err:  errBackendThrottled,
			want: denyThrottle,
		},
		{
			name: "fmt-wrapped errBackendThrottled -> throttle (errors.Is chains)",
			err:  fmt.Errorf("write failed: %w", errBackendThrottled),
			want: denyThrottle,
		},
		{
			name: "errBackendTransient -> backend_unavailable",
			err:  errBackendTransient,
			want: denyBackendUnavailable,
		},
		{
			name: "fmt-wrapped errBackendTransient -> backend_unavailable (errors.Is chains)",
			err:  fmt.Errorf("read failed: %w", errBackendTransient),
			want: denyBackendUnavailable,
		},
		{
			// ORDER NON-REGRESSION: EEXIST as a *fs.PathError still classifies
			// already_exists after the branch insertion — never escape, never
			// a backend row.
			name: "PathError wrapping fs.ErrExist still -> already_exists",
			err:  &fs.PathError{Op: "mkdir", Path: "d", Err: fs.ErrExist},
			want: denyAlreadyExists,
		},
		{
			// NON-VACUITY: a plain unrelated error still falls to internal —
			// the new branches widened nothing.
			name: "plain error still -> internal",
			err:  errors.New("boom"),
			want: denyInternal,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := denyClassForEngineErr(tc.err); got != tc.want {
				t.Fatalf("denyClassForEngineErr(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
