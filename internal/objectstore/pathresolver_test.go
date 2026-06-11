// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestValidatePath pins every lexical rejection class — NUL byte, absolute
// path, ".." traversal, URL-shaped handle, empty path — and the accept side:
// clean relative paths pass, "." segments are cleaned, percent-encoded
// sequences and unicode dot-lookalikes pass through as literal bytes because
// decoding is the wire layer's job (PATH-01, NFR-SEC-25).
func TestValidatePath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		// Rejection classes — caught by the pure function, pre-syscall.
		{"nul", "a\x00b", "", ErrInvalidPath},
		{"nul_trailing", "file.txt\x00", "", ErrInvalidPath},
		{"absolute", "/etc/passwd", "", ErrInvalidPath},
		{"traversal", "a/../../etc/passwd", "", ErrInvalidPath},
		{"traversal_plain", "../escape", "", ErrInvalidPath},
		{"traversal_bare", "..", "", ErrInvalidPath},
		{"url_scheme_s3", "s3://bucket/key", "", ErrInvalidPath},
		{"url_scheme_https", "https://x/y", "", ErrInvalidPath},
		{"empty", "", "", ErrInvalidPath},
		{"dot_bare", ".", "", ErrInvalidPath},
		{"dot_via_clean", "a/..", "", ErrInvalidPath},
		// Accept side — cleaned form returned, no error.
		{"accept_normal", "normal/path", "normal/path", nil},
		{"accept_dot_segment", "a/./b", "a/b", nil},
		{"accept_percent_encoded_literal", "%2e%2e/x", "%2e%2e/x", nil},
		{"accept_unicode_lookalike", "a․․/b", "a․․/b", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clean, err := ValidatePath(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ValidatePath(%q): got err %v, want ErrInvalidPath", tc.in, err)
				}
				if clean != "" {
					t.Fatalf("ValidatePath(%q): rejected path returned clean %q, want empty", tc.in, clean)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidatePath(%q): got err %v, want nil", tc.in, err)
			}
			if clean != tc.want {
				t.Fatalf("ValidatePath(%q): got clean %q, want %q", tc.in, clean, tc.want)
			}
		})
	}
}

// TestScopeRootContainment pins the symlink stage (PATH-01, NFR-SEC-25):
// a file inside the scope opens and resolves to the same inode (os.SameFile,
// never string-path compare — t.TempDir sits under the /var → /private/var
// symlink on darwin); an intra-scope symlink IS followed (the invariant is
// "no escape", not "no symlinks"); symlinks pointing outside the scope are
// refused with the os.Root escape error, which stays distinct from the
// lexical sentinel ErrInvalidPath.
func TestScopeRootContainment(t *testing.T) {
	base := t.TempDir()
	scope := filepath.Join(base, "fs_alpha")
	if err := os.MkdirAll(filepath.Join(scope, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	realPath := filepath.Join(scope, "sub", "data.txt")
	if err := os.WriteFile(realPath, []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sibling dir OUTSIDE the scope holding a secret marker.
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(outside, "secret")
	if err := os.WriteFile(secretPath, []byte("escaped"), 0o644); err != nil {
		t.Fatal(err)
	}
	secretInfo, err := os.Stat(secretPath)
	if err != nil {
		t.Fatal(err)
	}

	// Adversarial links inside the scope pointing out, and one intra-scope
	// link that must keep working.
	if err := os.Symlink(secretPath, filepath.Join(scope, "escape_file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(scope, "escape_dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub/data.txt", filepath.Join(scope, "intra")); err != nil {
		t.Fatal(err)
	}

	sr, err := OpenScopeRoot(base, ScopeID("fs_alpha"))
	if err != nil {
		t.Fatalf("OpenScopeRoot: %v", err)
	}
	defer sr.Close()

	// Containment positive: the opened fd is the real file (same inode).
	f, err := sr.Open("sub/data.txt")
	if err != nil {
		t.Fatalf("Open(sub/data.txt): %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fi, want) {
		t.Fatalf("Open(sub/data.txt): opened fd is not the scope file")
	}

	// Intra-scope symlink positive: followed, resolves to the scope file.
	lf, err := sr.Open("intra")
	if err != nil {
		t.Fatalf("Open(intra): intra-scope symlink must be followed, got %v", err)
	}
	defer lf.Close()
	lfi, err := lf.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(lfi, want) {
		t.Fatalf("Open(intra): fd does not resolve to the intra-scope target")
	}

	// Escapes: refused, distinct from the lexical sentinel, and never an
	// fd that matches the outside secret.
	for _, name := range []string{"escape_file", "escape_dir/secret"} {
		ef, err := sr.Open(name)
		if err == nil {
			efi, statErr := ef.Stat()
			ef.Close()
			if statErr == nil && os.SameFile(efi, secretInfo) {
				t.Fatalf("Open(%q): opened fd resolves OUTSIDE the scope", name)
			}
			t.Fatalf("Open(%q): escape symlink must be refused, got nil error", name)
		}
		if errors.Is(err, ErrInvalidPath) {
			t.Fatalf("Open(%q): symlink-stage escape must not be ErrInvalidPath (classes stay distinct), got %v", name, err)
		}
		var pe *fs.PathError
		if !errors.As(err, &pe) {
			t.Fatalf("Open(%q): want *fs.PathError from os.Root, got %T: %v", name, err, err)
		}
	}

	// Lexical class still rejected at the seam: Open runs ValidatePath first.
	if _, err := sr.Open("../fs_alpha/sub/data.txt"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Open(../...): want ErrInvalidPath from the lexical stage, got %v", err)
	}
}

// TestScopeRootID pins PATH-02 (NFR-SEC-43): the scope is the host-attested
// constructor argument, never parsed out of the caller-supplied path — a
// path whose first component LOOKS like another scope id still opens inside
// the constructor's scope and does not change ID().
func TestScopeRootID(t *testing.T) {
	base := t.TempDir()
	scope := filepath.Join(base, "fs_a")
	// A directory inside fs_a that is NAMED like a different scope.
	if err := os.MkdirAll(filepath.Join(scope, "fs_b"), 0o755); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(scope, "fs_b", "data")
	if err := os.WriteFile(inner, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	sr, err := OpenScopeRoot(base, ScopeID("fs_a"))
	if err != nil {
		t.Fatalf("OpenScopeRoot: %v", err)
	}
	defer sr.Close()

	if got := sr.ID(); got != ScopeID("fs_a") {
		t.Fatalf("ID(): got %q, want the constructor argument \"fs_a\"", got)
	}

	f, err := sr.Open("fs_b/data")
	if err != nil {
		t.Fatalf("Open(fs_b/data): %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(inner)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fi, want) {
		t.Fatalf("Open(fs_b/data): fd is not base/fs_a/fs_b/data — path must resolve under the attested scope")
	}
	if got := sr.ID(); got != ScopeID("fs_a") {
		t.Fatalf("ID() after Open: got %q — scope must never be re-derived from the path", got)
	}
}
