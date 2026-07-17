// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"errors"
	"testing"
)

// mustFamily builds the family or fails the test -- the constructor shape
// guards have their own tests below.
func mustFamily(t *testing.T, base string) ScopeFamily {
	t.Helper()
	f, err := NewScopeFamily(ScopeID(base))
	if err != nil {
		t.Fatalf("NewScopeFamily(%q): %v", base, err)
	}
	return f
}

// mustLazy wraps eng in the lazy-provision decorator over base's family or
// fails the test -- construction fail-closed has its own test.
func mustLazy(t *testing.T, eng Engine, base string, scaffold func(ctx context.Context, scope ScopeID) error) Engine {
	t.Helper()
	wrapped, err := NewLazyProvisionEngine(eng, mustFamily(t, base), scaffold)
	if err != nil {
		t.Fatalf("NewLazyProvisionEngine(base=%q): %v", base, err)
	}
	return wrapped
}

// TestScopeFamilyRefusesDerivedShapedBase pins the disjointness keystone: a
// base that is itself derived-shaped ("...-<16 hex>") is refused at
// construction, so no deployment's base can sit inside another deployment's
// family and the two families can never overlap.
func TestScopeFamilyRefusesDerivedShapedBase(t *testing.T) {
	if _, err := NewScopeFamily(ScopeID("fs-fleet-aaaaaaaaaaaaaaaa")); !errors.Is(err, ErrInvalidScopeID) {
		t.Fatalf("derived-shaped base accepted (err=%v); families of distinct deployments could overlap", err)
	}
	// A malformed base is refused by the shared scope-id shape guard.
	for _, bad := range []string{"", ".", "..", "a/b", "a\\b"} {
		if _, err := NewScopeFamily(ScopeID(bad)); err == nil {
			t.Fatalf("NewScopeFamily(%q) accepted a malformed base", bad)
		}
	}
	// A 15-hex suffix is NOT derived-shaped: it is a legal (if odd) base.
	if _, err := NewScopeFamily(ScopeID("fs-fleet-aaaaaaaaaaaaaaa")); err != nil {
		t.Fatalf("15-hex-suffixed base refused (%v); the refusal must match the member shape exactly", err)
	}
}

// TestScopeFamilyContainsBoundary walks the membership boundary: exactly the
// base and "<base>-<16 lowercase hex>" are in; every near-miss is out.
func TestScopeFamilyContainsBoundary(t *testing.T) {
	f := mustFamily(t, "fs-fleet")

	for _, in := range []string{
		"fs-fleet",
		"fs-fleet-0123456789abcdef",
		"fs-fleet-ffffffffffffffff",
	} {
		if !f.Contains(ScopeID(in)) {
			t.Fatalf("Contains(%q) = false, want member", in)
		}
	}
	for _, out := range []string{
		"fs-other",                                   // unrelated base
		"fs-other-0123456789abcdef",                  // another family's member
		"fs-fleet-0123456789abcde",                   // 15-hex suffix
		"fs-fleet-0123456789abcdef0",                 // 17-hex suffix
		"fs-fleet-0123456789ABCDEF",                  // uppercase hex
		"fs-fleet-0123456789abcdeg",                  // non-hex byte
		"fs-fleet-0123456789abcd\u0435f",             // unicode confusable in the suffix (cyrillic-e escape, looks like ascii e)
		"fs-fleetx-0123456789abcdef",                 // base prefix-extension
		"fs-fleet2",                                  // sibling base
		"fs-fleet0123456789abcdef",                   // missing separator
		"fs-fleet-",                                  // bare separator
		"fs-fleet-0123456789abcdef-deadbeef00112233", // double suffix
		"fs-fleet/../fs-other",                       // traversal-shaped
		"",                                           // empty
	} {
		if f.Contains(ScopeID(out)) {
			t.Fatalf("Contains(%q) = true, want refused", out)
		}
	}
}

// TestScopeFamilyZeroValueContainsNothing pins the fail-closed zero value: a
// family that did not come from NewScopeFamily admits no scope at all.
func TestScopeFamilyZeroValueContainsNothing(t *testing.T) {
	var zero ScopeFamily
	for _, s := range []string{"", "fs-fleet", "fs-fleet-0123456789abcdef"} {
		if zero.Contains(ScopeID(s)) {
			t.Fatalf("zero-value family Contains(%q) = true; must contain nothing", s)
		}
	}
}
