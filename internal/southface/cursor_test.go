// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/base64"
	"errors"
	"testing"
)

// TestCursorRoundTrip pins byte-identical round-trip for representative
// relpaths (the P2 seed). encodeCursor mints exactly what decodeCursor
// reverses.
func TestCursorRoundTrip(t *testing.T) {
	for _, p := range []string{
		"",
		"a",
		"a/b/c",
		"a/b/", // trailing slash preserved verbatim
		"golden-dir/x",
		"dir with space/f",
	} {
		t.Run(p, func(t *testing.T) {
			tok := encodeCursor(p)
			if tok == "" {
				t.Fatalf("encodeCursor(%q) minted an empty token", p)
			}
			got, err := decodeCursor(tok)
			if err != nil {
				t.Fatalf("decodeCursor(%q): %v", tok, err)
			}
			if got != p {
				t.Fatalf("round-trip %q -> %q, want identity", p, got)
			}
		})
	}
}

// TestCursorEmptyAndMalformed pins the empty/last-page case and the rejection
// cases (bad base64, empty-after-decode, wrong version byte).
func TestCursorEmptyAndMalformed(t *testing.T) {
	t.Run("empty token decodes to empty (first page / last page)", func(t *testing.T) {
		got, err := decodeCursor("")
		if err != nil || got != "" {
			t.Fatalf("decodeCursor(\"\") = (%q,%v), want (\"\",nil)", got, err)
		}
	})

	t.Run("non-base64url token -> errMalformedCursor", func(t *testing.T) {
		if _, err := decodeCursor("!!!not base64!!!"); !errors.Is(err, errMalformedCursor) {
			t.Fatalf("err = %v, want errMalformedCursor", err)
		}
	})

	t.Run("zero-byte payload -> errMalformedCursor", func(t *testing.T) {
		// A valid base64url encoding of zero bytes is the empty string,
		// which is the first-page case; a token that decodes to zero bytes
		// but is non-empty cannot exist for RawURLEncoding, so feed a token
		// that decodes to an empty slice via an explicit empty encode is not
		// possible — instead assert a single-but-wrong-version byte rejects.
		tok := base64.RawURLEncoding.EncodeToString([]byte{0x09})
		if _, err := decodeCursor(tok); !errors.Is(err, errMalformedCursor) {
			t.Fatalf("wrong single byte: err = %v, want errMalformedCursor", err)
		}
	})

	t.Run("wrong version byte -> errMalformedCursor", func(t *testing.T) {
		// Version 2 prefix; phase-9 must reject it so a future cursor shape
		// is distinguishable rather than silently mis-walked.
		tok := base64.RawURLEncoding.EncodeToString(append([]byte{cursorV1 + 1}, "a/b"...))
		if _, err := decodeCursor(tok); !errors.Is(err, errMalformedCursor) {
			t.Fatalf("wrong version: err = %v, want errMalformedCursor", err)
		}
	})

	t.Run("correct version byte alone decodes to empty after-path", func(t *testing.T) {
		got, err := decodeCursor(encodeCursor(""))
		if err != nil || got != "" {
			t.Fatalf("version-only token = (%q,%v), want (\"\",nil)", got, err)
		}
	})
}
