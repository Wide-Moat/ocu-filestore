// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
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
// fresh temp scope each iteration — direct link-out, chained link, link in
// the middle of a traversed path, absolute symlink — and asserts that no fd
// ScopeRoot.Open ever yields resolves to the marker outside the scope
// (PATH-01, NFR-SEC-25 symlink stage). The path generator's character class
// includes '_' so the "escape"/"abs_escape" link names are reachable.
// Intra-scope opens may succeed — only escapes are refused.
func TestPropSymlinkNeverEscapes(t *testing.T) {
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
		switch rapid.IntRange(0, 3).Draw(rt, "topology") {
		case 0: // direct symlink to the outside dir
			if err := os.Symlink(outside, filepath.Join(scope, "escape")); err != nil {
				rt.Fatalf("symlink: %v", err)
			}
		case 1: // chained: scope/a/escape -> outside
			if err := os.Symlink(outside, filepath.Join(scope, "a", "escape")); err != nil {
				rt.Fatalf("symlink: %v", err)
			}
		case 2: // link in the middle of a traversed path: scope/mid/<rest>
			if err := os.Symlink(outside, filepath.Join(scope, "mid")); err != nil {
				rt.Fatalf("symlink: %v", err)
			}
		case 3: // absolute symlink pointing out of the scope
			if err := os.Symlink("/tmp", filepath.Join(scope, "abs_escape")); err != nil {
				rt.Fatalf("symlink: %v", err)
			}
		}

		p := rapid.StringMatching(`[a-z_/]{1,20}`).Draw(rt, "path")
		clean, err := ValidatePath(p)
		if err != nil {
			return // lexically rejected — always acceptable
		}

		sr, err := OpenScopeRoot(base, ScopeID("scope"))
		if err != nil {
			rt.Fatalf("OpenScopeRoot on an existing scope dir: %v", err)
		}
		defer sr.Close()

		f, err := sr.Open(clean)
		if err != nil {
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
}
