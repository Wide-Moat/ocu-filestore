// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"errors"
	"path/filepath"
	"strings"
)

// ScopeID is the host-attested filesystem_id scope. It is given to the
// resolver by its caller — the face that terminates the connection — and is
// never parsed out of the caller-supplied path string (NFR-SEC-43, PATH-02).
type ScopeID string

// ErrInvalidPath is the lexical-stage sentinel: the caller-supplied path is
// rejected before any filesystem syscall (NUL byte, URL-shaped handle,
// absolute path, ".." escape, or empty path). Match it with errors.Is.
var ErrInvalidPath = errors.New("objectstore: invalid or unsafe path")

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// hasURLScheme reports whether s begins with an RFC-3986 scheme followed by
// "://" (scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )). It is purely
// lexical — it does not validate the rest of the string as a URL. It must
// run on the raw input BEFORE filepath.Clean, because Clean deduplicates
// "//" to "/" and hides the scheme shape.
func hasURLScheme(s string) bool {
	i := 0
	if i >= len(s) || !isAlpha(s[i]) {
		return false
	}
	i++
	for i < len(s) && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '+' || s[i] == '-' || s[i] == '.') {
		i++
	}
	return i+2 < len(s) && s[i] == ':' && s[i+1] == '/' && s[i+2] == '/'
}

// ValidatePath returns the cleaned, lexically safe form of p for use under a
// ScopeRoot, or ErrInvalidPath. It is a pure function: no filesystem access,
// so every rejection here happens before any backend call (PATH-01,
// NFR-SEC-25 lexical stage).
//
// Rejection classes, checked in this order:
//
//  1. NUL byte (\x00) — must be first: filepath.Clean and filepath.IsLocal
//     both pass NUL through, so relying on them would defer the rejection
//     to the syscall layer.
//  2. URL-shaped handle ("scheme://...") — must run before filepath.Clean,
//     which deduplicates "//" and would hide the scheme; blocks smuggling a
//     backend address (e.g. "s3://bucket/key") through the path field.
//  3. After filepath.Clean: anything not filepath.IsLocal — absolute paths
//     and ".." escapes — plus any input that cleans to "." (the empty path,
//     ".", "a/.." ...): filepath.Clean("") returns ".", which IS local, so
//     IsLocal alone misses it; a path must name an object inside the scope,
//     never the scope root itself.
//
// Percent-encoded sequences ("%2e%2e") and unicode dot-lookalikes are NOT
// decoded here and pass through as literal bytes — they are valid filename
// bytes, not traversal; decoding, where a wire format requires it, is the
// wire layer's job and must happen before calling ValidatePath.
func ValidatePath(p string) (string, error) {
	if strings.ContainsRune(p, '\x00') {
		return "", ErrInvalidPath
	}
	if hasURLScheme(p) {
		return "", ErrInvalidPath
	}
	clean := filepath.Clean(p)
	if clean == "." || !filepath.IsLocal(clean) {
		return "", ErrInvalidPath
	}
	return clean, nil
}
