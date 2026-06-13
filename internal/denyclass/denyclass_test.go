// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package denyclass_test

import (
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
)

// TestAllPrependsNoneSentinel verifies All() is the deny vocabulary preceded by
// the allow sentinel, and that it returns a defensive copy (mutating the result
// does not corrupt the shared source).
func TestAllPrependsNoneSentinel(t *testing.T) {
	all := denyclass.All()
	classes := denyclass.DenyClasses()

	if len(all) != len(classes)+1 {
		t.Fatalf("All() = %d entries, want DenyClasses()+1 = %d", len(all), len(classes)+1)
	}
	if all[0] != denyclass.None {
		t.Fatalf("All()[0] = %q, want None sentinel %q", all[0], denyclass.None)
	}
	for i, c := range classes {
		if all[i+1] != c {
			t.Fatalf("All()[%d] = %q, want %q", i+1, all[i+1], c)
		}
	}

	// Mutating a returned slice must not affect a fresh call (copy semantics).
	all[0] = "tampered"
	if denyclass.All()[0] != denyclass.None {
		t.Fatal("All() returned a slice aliasing shared state — mutation leaked")
	}
}

// TestDenyClassesIsACopy verifies DenyClasses() hands back a defensive copy and
// contains no duplicate tokens.
func TestDenyClassesIsACopy(t *testing.T) {
	a := denyclass.DenyClasses()
	if len(a) == 0 {
		t.Fatal("DenyClasses() is empty")
	}
	a[0] = "tampered"
	if denyclass.DenyClasses()[0] == "tampered" {
		t.Fatal("DenyClasses() returned a slice aliasing shared state — mutation leaked")
	}

	seen := make(map[string]bool, len(a))
	for _, c := range denyclass.DenyClasses() {
		if c == denyclass.None {
			t.Fatalf("DenyClasses() must not contain the allow sentinel %q", denyclass.None)
		}
		if seen[c] {
			t.Fatalf("DenyClasses() has a duplicate token %q", c)
		}
		seen[c] = true
	}
}
