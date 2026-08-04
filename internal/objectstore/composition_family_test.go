// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// composedStack mirrors the cmd wiring EXACTLY (one ScopeFamily built at
// compose; confinement wraps the raw engine first; the lazy decorator wraps
// the confined engine and scaffolds THROUGH it): lazy(confined(raw)),
// scaffold = ProvisionScope + a marker MakeDir against the confined engine.
// This is the stack every real verb crosses, and the seam no per-decorator
// suite composes -- which is how the exact-match guard shipped green while
// killing every derived-scope first touch.
func composedStack(t *testing.T, base string) Engine {
	t.Helper()
	fam := mustFamily(t, base)
	confined, err := NewScopeConfinedEngine(NewLocalVolumeEngine(t.TempDir()), fam)
	if err != nil {
		t.Fatalf("NewScopeConfinedEngine: %v", err)
	}
	scaffold := func(ctx context.Context, s ScopeID) error {
		if perr := confined.ProvisionScope(ctx, s); perr != nil {
			return perr
		}
		return confined.MakeDir(ctx, s, "outputs/")
	}
	wrapped, err := NewLazyProvisionEngine(confined, fam, scaffold)
	if err != nil {
		t.Fatalf("NewLazyProvisionEngine: %v", err)
	}
	return wrapped
}

// TestComposedConfinedLazy_DerivedScopeScaffoldsAndWrites is the composition
// keystone (D5, ADR-0030 x engine confinement, ADR-0013/0029): on the composed
// confined-plus-lazy stack a legitimately-derived per-chat scope
// ("<base>-<16 lowercase hex>") must lazily scaffold on first touch and serve
// the data verb. Each decorator passes its own suite in isolation; only this
// composed test catches a confinement predicate that refuses what the lazy
// decorator legitimizes -- which is exactly the wiring the daemon ships.
func TestComposedConfinedLazy_DerivedScopeScaffoldsAndWrites(t *testing.T) {
	eng := composedStack(t, "fs-fleet")
	ctx := context.Background()
	derived := ScopeID("fs-fleet-0123456789abcdef")

	if _, err := eng.WriteStream(ctx, derived, "outputs/first.txt", strings.NewReader("hi"), false); err != nil {
		t.Fatalf("first-touch write on a derived scope must lazily scaffold and succeed; got: %v", err)
	}
	info, err := eng.Stat(ctx, derived, "outputs/first.txt")
	if err != nil {
		t.Fatalf("Stat after first-touch write: %v", err)
	}
	if info.Size != 2 {
		t.Fatalf("derived-scope object size = %d, want 2", info.Size)
	}
	// The base scope keeps serving on the SAME composed stack.
	if err := eng.ProvisionScope(ctx, ScopeID("fs-fleet")); err != nil {
		t.Fatalf("base ProvisionScope on the composed stack: %v", err)
	}
	if _, err := eng.WriteStream(ctx, ScopeID("fs-fleet"), "outputs/base.txt", strings.NewReader("b"), false); err != nil {
		t.Fatalf("base write on the composed stack: %v", err)
	}
}

// TestComposedConfinedLazy_ForeignScopeStillRefused pins that widening the
// confinement to the scope family never admits anything else: on the SAME
// composed stack every scope outside {base, base-<16 lowercase hex>} stays
// ErrForeignScope on a write, a read, and a lifecycle verb, and the lazy
// decorator never scaffolds it.
func TestComposedConfinedLazy_ForeignScopeStillRefused(t *testing.T) {
	eng := composedStack(t, "fs-fleet")
	ctx := context.Background()

	for _, foreign := range []ScopeID{
		"fs-other",                                   // unrelated base
		"fs-other-0123456789abcdef",                  // another family's member
		"fs-fleet-0123456789ABCDEF",                  // uppercase hex suffix
		"fs-fleet-0123456789abcde",                   // 15-hex suffix
		"fs-fleet-0123456789abcdef0",                 // 17-hex suffix
		"fs-fleet-0123456789abcdeg",                  // non-hex byte
		"fs-fleetx-0123456789abcdef",                 // base prefix-extension
		"fs-fleet2",                                  // sibling base
		"fs-fleet0123456789abcdef",                   // missing separator
		"fs-fleet-",                                  // bare separator
		"fs-fleet-0123456789abcdef-deadbeef00112233", // double suffix
	} {
		if _, err := eng.WriteStream(ctx, foreign, "outputs/x", strings.NewReader("x"), false); !errors.Is(err, ErrForeignScope) {
			t.Fatalf("WriteStream(%q) = %v, want ErrForeignScope", foreign, err)
		}
		if _, err := eng.Stat(ctx, foreign, "outputs/x"); !errors.Is(err, ErrForeignScope) {
			t.Fatalf("Stat(%q) = %v, want ErrForeignScope", foreign, err)
		}
		if err := eng.TeardownScope(ctx, foreign); !errors.Is(err, ErrForeignScope) {
			t.Fatalf("TeardownScope(%q) = %v, want ErrForeignScope", foreign, err)
		}
	}
}
