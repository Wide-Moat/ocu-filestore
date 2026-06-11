// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"errors"
)

// ScopeID is the host-attested filesystem_id scope. It is given to the
// resolver by its caller — the face that terminates the connection — and is
// never parsed out of the caller-supplied path string (NFR-SEC-43, PATH-02).
type ScopeID string

// ErrInvalidPath is the lexical-stage sentinel: the caller-supplied path is
// rejected before any filesystem syscall (NUL byte, URL-shaped handle,
// absolute path, ".." escape, or empty path). Match it with errors.Is.
var ErrInvalidPath = errors.New("objectstore: invalid or unsafe path")

// hasURLScheme reports whether s begins with an RFC-3986 scheme followed by
// "://". Stub: implemented against the failing tests.
func hasURLScheme(s string) bool {
	return false
}

// ValidatePath returns the cleaned, lexically safe form of p, or
// ErrInvalidPath. Stub: implemented against the failing tests.
func ValidatePath(p string) (string, error) {
	return p, nil
}
