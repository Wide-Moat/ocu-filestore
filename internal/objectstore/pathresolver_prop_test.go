// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
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
