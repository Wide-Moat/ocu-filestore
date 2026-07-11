// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"testing"
)

// lazyMarkers is the marker subtree list the boot scaffold seeds; the lazy
// decorator seeds the SAME list on first touch of a derived scope.
var lazyMarkers = []string{"uploads", "outputs"}

// newLazyDeployment returns a bare local engine over a fresh base dir and a
// lazy-provision decorator over the SAME engine, sharing the bootBase and the
// marker list. The bare engine is returned so a test can drive the un-wrapped
// path (the red-probe: no lazy scaffold, so a fresh derived scope faults).
func newLazyDeployment(t *testing.T, bootBase string) (bare Engine, wrapped Engine, base string) {
	t.Helper()
	base = t.TempDir()
	bare = NewLocalVolumeEngine(base)
	// scaffoldScope mirrors the boot scaffold: provision the scope, then seed
	// each distinct marker dir (idempotent, ErrExist == success). It runs
	// against the SAME bare engine the decorator wraps.
	scaffold := func(ctx context.Context, scope ScopeID) error {
		return scaffoldMarkers(ctx, bare, scope, lazyMarkers)
	}
	wrapped = NewLazyProvisionEngine(bare, bootBase, scaffold)
	return bare, wrapped, base
}

// scaffoldMarkers is the test-local mirror of cmd/ocu-filestored.scaffoldScope:
// ProvisionScope + a MakeDir per distinct marker, ErrExist treated as success.
// The production helper lives in the daemon binary; this keeps the unit
// hermetic to the objectstore package while exercising the identical verbs.
func scaffoldMarkers(ctx context.Context, eng Engine, scope ScopeID, markers []string) error {
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	for _, sub := range markers {
		if sub == "" {
			continue
		}
		if _, dup := seen[sub]; dup {
			continue
		}
		seen[sub] = struct{}{}
		if err := eng.MakeDir(ctx, scope, sub); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}

// TestLazyScaffoldOnFirstSouthWrite pins the primary two-mount flow: a FRESH
// derived scope "<base>-<16hex>" the engine has never seen, whose FIRST
// operation is a south write-intent write to outputs/f.txt, SUCCEEDS through
// the decorator (the markers are lazily scaffolded on first touch), and the
// object is then listable under "<derived>/outputs/".
//
// Red-probe (NON-VACUOUS): drive the SAME first write on the BARE engine
// (decorator removed). The fresh derived scope has no scaffold, so the write
// faults on the absent scope/marker -> RED. Restore the wrap -> GREEN.
func TestLazyScaffoldOnFirstSouthWrite(t *testing.T) {
	ctx := context.Background()
	const bootBase = "fs-fleet"
	derived := ScopeID(bootBase + "-0123456789abcdef")

	_, wrapped, _ := newLazyDeployment(t, bootBase)

	data := []byte("agent output written first")
	// FIRST op on a never-seen derived scope is a write to the write-subtree.
	if _, err := wrapped.WriteStream(ctx, derived, "outputs/f.txt", bytes.NewReader(data), false); err != nil {
		t.Fatalf("first south write to fresh derived scope: got err %v, want success (lazy scaffold)", err)
	}

	// The object is listable under the derived scope's outputs/ subtree.
	entries, err := wrapped.List(ctx, derived, "outputs")
	if err != nil {
		t.Fatalf("List(%q, outputs): %v", derived, err)
	}
	var found bool
	for _, e := range entries {
		if e.Name == "f.txt" && !e.IsDir {
			found = true
		}
	}
	if !found {
		t.Fatalf("wrote outputs/f.txt but it is not listable under %q/outputs; entries=%v", derived, entries)
	}
}

// TestLazyScaffoldFirstWriteFaultsOnBareEngine is the STANDING red-probe for
// the primary keystone: it proves the bare engine (no decorator) faults on the
// SAME first write. If the fault ever stops happening the decorator is doing
// nothing and TestLazyScaffoldOnFirstSouthWrite is vacuous, so this guards the
// non-vacuity in-tree.
func TestLazyScaffoldFirstWriteFaultsOnBareEngine(t *testing.T) {
	ctx := context.Background()
	const bootBase = "fs-fleet"
	derived := ScopeID(bootBase + "-0123456789abcdef")

	bare, _, _ := newLazyDeployment(t, bootBase)

	data := []byte("agent output written first")
	if _, err := bare.WriteStream(ctx, derived, "outputs/f.txt", bytes.NewReader(data), false); err == nil {
		t.Fatalf("bare engine first write to un-provisioned derived scope: got success, want fault (no scaffold)")
	}
}

// TestLazyScaffoldRefusesForeignScope pins fail-closed: a scope that is NOT the
// base and NOT "<base>-<16hex>" is NOT scaffolded, so the op refuses exactly as
// the bare engine does today (the decorator never widens what the engine
// accepts).
//
// Red-probe: forcing the derived-shape predicate always-true would scaffold a
// foreign scope and let the write succeed; this asserts it must NOT.
func TestLazyScaffoldRefusesForeignScope(t *testing.T) {
	ctx := context.Background()
	const bootBase = "fs-fleet"

	_, wrapped, _ := newLazyDeployment(t, bootBase)

	foreign := []ScopeID{
		ScopeID("fs-attacker"),                   // unrelated base
		ScopeID(bootBase + "-XYZ"),               // right prefix, non-hex suffix
		ScopeID(bootBase + "-0123456789abcde"),   // 15 hex, too short
		ScopeID(bootBase + "-0123456789abcdefa"), // 17 hex, too long
	}
	for _, scope := range foreign {
		data := []byte("attacker write")
		if _, err := wrapped.WriteStream(ctx, scope, "outputs/f.txt", bytes.NewReader(data), false); err == nil {
			t.Fatalf("foreign scope %q: got success, want refuse (must NOT be scaffolded)", scope)
		}
	}
}

// TestLazyScaffoldBaseScopeScaffolds pins that the bootBase itself is a legal
// derived scope: a first write to the base scaffolds and succeeds.
func TestLazyScaffoldBaseScopeScaffolds(t *testing.T) {
	ctx := context.Background()
	const bootBase = "fs-fleet"

	_, wrapped, _ := newLazyDeployment(t, bootBase)

	data := []byte("base scope write")
	if _, err := wrapped.WriteStream(ctx, ScopeID(bootBase), "outputs/f.txt", bytes.NewReader(data), false); err != nil {
		t.Fatalf("first write to base scope: got err %v, want success", err)
	}
}

// TestLazyScaffoldConcurrentFirstTouchScaffoldsOnce pins the thread-safety
// contract: many concurrent first-touches of the SAME fresh derived scope
// scaffold exactly once and all succeed.
func TestLazyScaffoldConcurrentFirstTouchScaffoldsOnce(t *testing.T) {
	ctx := context.Background()
	const bootBase = "fs-fleet"
	derived := ScopeID(bootBase + "-abcdefabcdef0123")

	// One shared bare engine backs the writes; the counting scaffold provisions
	// on it and increments under a mutex so the assertion sees the true count.
	bare := NewLocalVolumeEngine(t.TempDir())
	var calls int
	var mu sync.Mutex
	scaffold := func(ctx context.Context, scope ScopeID) error {
		mu.Lock()
		calls++
		mu.Unlock()
		return scaffoldMarkers(ctx, bare, scope, lazyMarkers)
	}
	wrapped := NewLazyProvisionEngine(bare, bootBase, scaffold)

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = wrapped.WriteStream(ctx, derived, "outputs/f.txt", bytes.NewReader([]byte("x")), true)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent write %d: %v", i, err)
		}
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("scaffold ran %d times under %d concurrent first-touches, want exactly 1", got, n)
	}
}

// TestLazyScaffoldTransientFailureIsRetriedOnNextTouch pins the recovery
// contract: a scaffold attempt that fails with a TRANSIENT backend refusal
// (e.g. an S3 storage-full 5xx mapped to ErrTransient) fails THAT caller's
// verb but is NOT memoized — the next touch of the same scope re-runs the
// scaffold and, with the backend healthy again, succeeds. Success IS
// memoized: a third touch runs no further scaffold.
//
// Red-probe: memoizing the first attempt's error (the terminal-cache
// behaviour) leaves the second write failing forever and this test RED.
func TestLazyScaffoldTransientFailureIsRetriedOnNextTouch(t *testing.T) {
	ctx := context.Background()
	const bootBase = "fs-fleet"
	derived := ScopeID(bootBase + "-00ff00ff00ff00ff")

	bare := NewLocalVolumeEngine(t.TempDir())
	var mu sync.Mutex
	var calls int
	scaffold := func(ctx context.Context, scope ScopeID) error {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			// The backend refuses the marker write transiently (the live class:
			// a 5xx storage refusal surfaces wrapped around ErrTransient).
			return fmt.Errorf("scaffold subtree %q: objectstore: s3 mkdir: %w", "uploads", ErrTransient)
		}
		return scaffoldMarkers(ctx, bare, scope, lazyMarkers)
	}
	wrapped := NewLazyProvisionEngine(bare, bootBase, scaffold)

	// First touch: the scaffold fails; the verb surfaces the transient error.
	if _, err := wrapped.WriteStream(ctx, derived, "outputs/f.txt", bytes.NewReader([]byte("x")), false); !errors.Is(err, ErrTransient) {
		t.Fatalf("first touch during backend refusal: err = %v, want ErrTransient", err)
	}

	// Second touch after the backend recovered: the scaffold MUST re-run and
	// the verb MUST succeed. A terminal error cache leaves this failing until
	// process restart — the defect this test pins closed.
	if _, err := wrapped.WriteStream(ctx, derived, "outputs/f.txt", bytes.NewReader([]byte("x")), false); err != nil {
		t.Fatalf("second touch after backend recovery: err = %v, want success (scaffold retried)", err)
	}

	// Third touch: success is memoized; no further scaffold runs.
	if _, err := wrapped.WriteStream(ctx, derived, "outputs/g.txt", bytesReader("y"), false); err != nil {
		t.Fatalf("third touch: %v", err)
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 2 {
		t.Fatalf("scaffold ran %d times, want exactly 2 (fail, retry-success, then memoized)", got)
	}
}

// bytesReader is a tiny helper so the third-touch line stays readable.
func bytesReader(s string) *bytes.Reader { return bytes.NewReader([]byte(s)) }

// TestLazyScaffoldCanceledFirstTouchDoesNotPoison pins the same recovery
// contract for the caller-context class: a first touch whose request context
// is already canceled fails THAT verb with the ctx error, and a later touch
// with a live context scaffolds and succeeds. The first toucher's canceled
// request must never wedge the scope for every subsequent caller.
func TestLazyScaffoldCanceledFirstTouchDoesNotPoison(t *testing.T) {
	const bootBase = "fs-fleet"
	derived := ScopeID(bootBase + "-11aa11aa11aa11aa")

	bare := NewLocalVolumeEngine(t.TempDir())
	scaffold := func(ctx context.Context, scope ScopeID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return scaffoldMarkers(ctx, bare, scope, lazyMarkers)
	}
	wrapped := NewLazyProvisionEngine(bare, bootBase, scaffold)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := wrapped.WriteStream(canceled, derived, "outputs/f.txt", bytes.NewReader([]byte("x")), false); err == nil {
		t.Fatal("first touch with canceled ctx: got success, want the ctx error")
	}

	if _, err := wrapped.WriteStream(context.Background(), derived, "outputs/f.txt", bytes.NewReader([]byte("x")), false); err != nil {
		t.Fatalf("second touch with live ctx: err = %v, want success (canceled first touch must not poison)", err)
	}
}
