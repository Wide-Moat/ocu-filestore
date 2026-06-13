// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// TestPropLexicalNeverEscapes asserts that any path ValidatePath accepts is
// local (no absolute, no ".." escape), carries no NUL byte, and was not
// URL-shaped — for arbitrary byte strings, whose default rune table already
// includes '\x00', '/', '\\', '.', and control characters
// (PATH-01, NFR-SEC-25 lexical stage).
func TestPropLexicalNeverEscapes(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		p := rapid.String().Draw(rt, "path")
		clean, err := ValidatePath(p)
		if err != nil {
			// Rejection is always acceptable.
			return
		}
		if !filepath.IsLocal(clean) {
			rt.Fatalf("ValidatePath accepted non-local path: input=%q clean=%q", p, clean)
		}
		if strings.ContainsRune(clean, '\x00') {
			rt.Fatalf("ValidatePath accepted NUL-containing path: input=%q clean=%q", p, clean)
		}
		if hasURLScheme(p) {
			rt.Fatalf("ValidatePath accepted URL-shaped path: input=%q clean=%q", p, clean)
		}
	})
}

// TestPropSymlinkNeverEscapes builds an adversarial symlink topology in a
// fresh temp scope each iteration — direct link-out, chained link (link →
// link → outside), link in the middle of a traversed path, absolute symlink
// — and asserts that no fd ScopeRoot.Open ever yields resolves to the marker
// outside the scope (PATH-01, NFR-SEC-25 symlink stage).
//
// Two guards keep the property non-vacuous:
//
//  1. Every iteration unconditionally opens the planted escape entry for the
//     active topology and requires the os.Root escape class — a nil error, a
//     plain ENOENT (topology never reached), or the lexical sentinel each
//     fail the property. A run can therefore never regress to all-ENOENT.
//  2. The fuzz arm draws from a biased generator: the four planted entry
//     paths with probability ~1/2, random `[a-z_/]` strings otherwise, so
//     the random arm also exercises the refusal branch with high
//     probability while keeping genuine fuzz value.
//
// Intra-scope opens may succeed — only escapes are refused. The refusal
// count is logged and must be non-zero across the run.
func TestPropSymlinkNeverEscapes(t *testing.T) {
	// Escape entry path per topology arm, indexed by the topology draw.
	plantedPaths := []string{"escape", "a/escape", "mid/secret", "abs_escape"}

	var escapeRefusals int
	rapid.Check(t, func(rt *rapid.T) {
		base := t.TempDir()

		// Sibling dir OUTSIDE the scope with a secret marker.
		outside := filepath.Join(filepath.Dir(base), "outside")
		if err := os.MkdirAll(outside, 0o755); err != nil {
			rt.Fatalf("mkdir outside: %v", err)
		}
		defer os.RemoveAll(outside)
		secretPath := filepath.Join(outside, "secret")
		if err := os.WriteFile(secretPath, []byte("escaped"), 0o644); err != nil {
			rt.Fatalf("write secret: %v", err)
		}

		// The scope root, with one legitimate file the generator can reach.
		scope := filepath.Join(base, "scope")
		if err := os.MkdirAll(filepath.Join(scope, "a"), 0o755); err != nil {
			rt.Fatalf("mkdir scope: %v", err)
		}
		if err := os.WriteFile(filepath.Join(scope, "f"), []byte("inside"), 0o644); err != nil {
			rt.Fatalf("write scope file: %v", err)
		}

		// One of four adversarial topologies per iteration.
		topology := rapid.IntRange(0, 3).Draw(rt, "topology")
		switch topology {
		case 0: // direct symlink to the outside dir: escape -> outside
			if err := os.Symlink(outside, filepath.Join(scope, "escape")); err != nil {
				rt.Fatalf("symlink: %v", err)
			}
		case 1: // chained: a/escape -> ../hop (relative, in scope) -> outside
			if err := os.Symlink(outside, filepath.Join(scope, "hop")); err != nil {
				rt.Fatalf("symlink: %v", err)
			}
			if err := os.Symlink("../hop", filepath.Join(scope, "a", "escape")); err != nil {
				rt.Fatalf("symlink: %v", err)
			}
		case 2: // link in the middle of a traversed path: mid/secret
			if err := os.Symlink(outside, filepath.Join(scope, "mid")); err != nil {
				rt.Fatalf("symlink: %v", err)
			}
		case 3: // absolute symlink pointing out of the scope
			if err := os.Symlink("/tmp", filepath.Join(scope, "abs_escape")); err != nil {
				rt.Fatalf("symlink: %v", err)
			}
		}

		sr, err := OpenScopeRoot(base, ScopeID("scope"))
		if err != nil {
			rt.Fatalf("OpenScopeRoot on an existing scope dir: %v", err)
		}
		defer sr.Close()

		// Unconditional vacuity guard: the planted escape entry for the
		// ACTIVE topology must be refused with the os.Root escape class —
		// never opened, never ENOENT, never the lexical sentinel.
		planted := plantedPaths[topology]
		if ef, err := sr.Open(planted); err == nil {
			efi, statErr := ef.Stat()
			ef.Close()
			secretInfo, outErr := os.Stat(secretPath)
			if statErr == nil && outErr == nil && os.SameFile(efi, secretInfo) {
				rt.Fatalf("Open(%q): opened fd resolves OUTSIDE the scope root", planted)
			}
			rt.Fatalf("Open(%q): planted escape link must be refused, got nil error", planted)
		} else {
			if errors.Is(err, fs.ErrNotExist) {
				rt.Fatalf("Open(%q): refused with ENOENT — topology %d never reached, property is vacuous: %v", planted, topology, err)
			}
			if errors.Is(err, ErrInvalidPath) {
				rt.Fatalf("Open(%q): escape refusal must not be the lexical sentinel ErrInvalidPath: %v", planted, err)
			}
			var pe *fs.PathError
			if !errors.As(err, &pe) {
				rt.Fatalf("Open(%q): want the *fs.PathError escape class from os.Root, got %T: %v", planted, err, err)
			}
			escapeRefusals++
		}

		// Fuzz arm: biased draw — planted adversarial names mixed with
		// random strings, so the refusal branch stays hot under random
		// exploration too.
		p := rapid.OneOf(
			rapid.SampledFrom(plantedPaths),
			rapid.StringMatching(`[a-z_/]{1,20}`),
		).Draw(rt, "path")
		clean, err := ValidatePath(p)
		if err != nil {
			return // lexically rejected — always acceptable
		}

		f, err := sr.Open(clean)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				escapeRefusals++
			}
			return // refused at open — acceptable (escape or nonexistent)
		}
		defer f.Close()

		// Any successfully opened fd must NOT be the outside marker.
		fi, err := f.Stat()
		if err != nil {
			return
		}
		secretInfo, err := os.Stat(secretPath)
		if err == nil && os.SameFile(fi, secretInfo) {
			rt.Fatalf("opened fd resolves OUTSIDE the scope root: path=%q clean=%q", p, clean)
		}
	})
	t.Logf("os.Root escape refusals exercised across the run: %d", escapeRefusals)
	if escapeRefusals == 0 {
		t.Fatal("property completed without exercising a single escape refusal — vacuous run")
	}
}
