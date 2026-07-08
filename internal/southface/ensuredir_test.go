// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// hasDirAt reports whether the fake engine holds a directory at engine-relative
// rel (its parent lists it as a dir). It drives the real in-memory tree, so a
// pass proves EnsureDir's MakeDir actually landed the level.
func hasDirAt(t *testing.T, e *fakeEngine, scope, rel string) bool {
	t.Helper()
	parent, leaf := ".", rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		parent, leaf = rel[:i], rel[i+1:]
	}
	entries, err := e.List(context.Background(), scope, parent)
	if err != nil {
		return false
	}
	for _, en := range entries {
		if en.Name == leaf && en.IsDir {
			return true
		}
	}
	return false
}

// TestEnsureDir pins the shared dir-marker walker both the south make_parents
// spine and the north create compose over (ADR-0029).
func TestEnsureDir(t *testing.T) {
	ctx := context.Background()

	t.Run("makes every level root to leaf", func(t *testing.T) {
		e := newFakeEngine()
		if err := EnsureDir(ctx, e, opScope, "a/b/c"); err != nil {
			t.Fatalf("EnsureDir(a/b/c) = %v, want nil", err)
		}
		for _, lvl := range []string{"a", "a/b", "a/b/c"} {
			if !hasDirAt(t, e, opScope, lvl) {
				t.Fatalf("level %q not created", lvl)
			}
		}
	})

	t.Run("idempotent — a repeat call converges, leaf EEXIST tolerated", func(t *testing.T) {
		e := newFakeEngine()
		if err := EnsureDir(ctx, e, opScope, "uploads"); err != nil {
			t.Fatalf("first EnsureDir(uploads) = %v, want nil", err)
		}
		// The second call re-MakeDirs the SAME leaf; the engine surfaces EEXIST, which
		// EnsureDir must tolerate as success (unlike make_parents' caller-visible leaf).
		if err := EnsureDir(ctx, e, opScope, "uploads"); err != nil {
			t.Fatalf("repeat EnsureDir(uploads) = %v, want nil (idempotent)", err)
		}
		if !hasDirAt(t, e, opScope, "uploads") {
			t.Fatal("uploads missing after idempotent ensure")
		}
	})

	t.Run("tolerates a pre-existing intermediate level", func(t *testing.T) {
		e := newFakeEngine()
		e.mkdirSeed(opScope, "a") // "a" already exists; EnsureDir must not abort on its EEXIST
		if err := EnsureDir(ctx, e, opScope, "a/b"); err != nil {
			t.Fatalf("EnsureDir over a pre-existing intermediate = %v, want nil", err)
		}
		if !hasDirAt(t, e, opScope, "a/b") {
			t.Fatal("a/b not created past the pre-existing intermediate")
		}
	})

	t.Run("empty dir is a no-op success (static-path mode)", func(t *testing.T) {
		e := newFakeEngine()
		if err := EnsureDir(ctx, e, opScope, ""); err != nil {
			t.Fatalf("EnsureDir(\"\") = %v, want nil (static-path no-op)", err)
		}
		if got := e.mutations(); len(got) != 0 {
			t.Fatalf("empty-dir ensure touched the engine: %v, want no MakeDir", got)
		}
	})

	t.Run("depth cap refuses an over-deep dir before any engine call", func(t *testing.T) {
		e := newFakeEngine()
		deep := strings.Repeat("x/", maxWalkDepth) + "x" // maxWalkDepth+1 components
		if err := EnsureDir(ctx, e, opScope, deep); !errors.Is(err, errInvalidPath) {
			t.Fatalf("EnsureDir(over-deep) = %v, want errInvalidPath", err)
		}
		if got := e.mutations(); len(got) != 0 {
			t.Fatalf("over-deep ensure called MakeDir %v before the cap; the guard must precede any engine call", got)
		}
	})

	t.Run("propagates a genuine engine error (missing intermediate parent)", func(t *testing.T) {
		// A single-level MakeDir whose parent is absent must ENOENT out, not be
		// swallowed: EnsureDir tolerates only EEXIST, never ErrNotExist. Drive it by
		// asking the engine (via the private makeDirs make_parents=false path) — here
		// we assert EnsureDir does NOT mask a non-EEXIST error by feeding a leaf whose
		// walk the fake rejects lexically (an invalid path segment).
		e := newFakeEngine()
		if err := EnsureDir(ctx, e, opScope, "bad//seg"); err == nil {
			t.Fatal("EnsureDir over a lexically-invalid path returned nil; a non-EEXIST error must propagate")
		}
	})
}
