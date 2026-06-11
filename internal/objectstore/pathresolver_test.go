// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"errors"
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
