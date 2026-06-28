// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectid

import "testing"

// TestNewShapeIsHex pins the handle shape: exactly 32 characters, all
// lowercase hex. This is the byte-shape every consumer (the south-face
// object-id store, the durable handle store) depends on.
func TestNewShapeIsHex(t *testing.T) {
	id := New()
	if len(id) != 32 {
		t.Fatalf("New() len = %d, want exactly 32", len(id))
	}
	for i, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("New()[%d] = %q, not lowercase hex (id=%q)", i, c, id)
		}
	}
}

// TestNewLengthExactly32 isolates the length invariant so a regression that
// changed the byte count (e.g. 8 or 32 random bytes) fails loudly on its own.
func TestNewLengthExactly32(t *testing.T) {
	if got := len(New()); got != 32 {
		t.Fatalf("New() length = %d, want 32", got)
	}
}

// TestNewDistinct pins that two consecutive mints differ — the handle is drawn
// fresh from the CSPRNG, never a fixed or counter value.
func TestNewDistinct(t *testing.T) {
	a, b := New(), New()
	if a == b {
		t.Fatalf("two New() calls returned the same handle %q (want distinct)", a)
	}
}
