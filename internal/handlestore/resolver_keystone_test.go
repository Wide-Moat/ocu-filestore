// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"errors"
	"testing"
)

// TestGetKeystoneScopeBinding is the ADR-0023 KEYSTONE: Get resolves a file_id
// ONLY under the scope it was minted in. A cross-scope Get and an unknown-id Get
// return the IDENTICAL ErrNotFound sentinel and a ZERO Record — cross-scope is
// indistinguishable from absent (anti-enumeration). The scope assertion lives
// INSIDE Get (below the Store seam), never in the caller.
//
// THREE MUTATIONS that MUST turn this test RED — the keystone is only load-
// bearing if each of these regressions fails the suite:
//
//	(a) DELETE the scope check in DiskStore.Get
//	    (`if rec.Scope != attestedScope { return Record{}, ErrNotFound }`):
//	    Get(id,"fs-B") would then RESOLVE the fs-A record — a cross-scope read.
//	    The "cross-scope errors" and "zero record" assertions below go RED.
//
//	(b) INVERT the comparison to `==`
//	    (`if rec.Scope == attestedScope { return Record{}, ErrNotFound }`):
//	    the SAME-scope Get(id,"fs-A") would then return ErrNotFound — the
//	    "same-scope resolves" assertion goes RED.
//
//	(c) `return rec, nil` REGARDLESS of scope (drop both the ok-check and the
//	    scope-check guards): Get(id,"fs-B") and Get(unknown,"fs-A") would both
//	    return a record — the cross-scope and unknown-id assertions go RED.
func TestGetKeystoneScopeBinding(t *testing.T) {
	_, s := newTestStore(t)

	rec, err := s.Put(context.Background(), samplePut("fs-A", "secret"))
	if err != nil {
		t.Fatalf("Put under fs-A: %v", err)
	}
	id := rec.FileID

	// Cross-scope: ErrNotFound AND a zero Record (no field leaks).
	got, err := s.Get(context.Background(), id, "fs-B")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(id, fs-B) = %v, want ErrNotFound (mutation (a)/(c) would break this)", err)
	}
	if got != (Record{}) {
		t.Fatalf("Get(id, fs-B) leaked a non-zero Record: %+v (cross-scope must reveal nothing)", got)
	}

	// Same scope: resolves to the exact record.
	got, err = s.Get(context.Background(), id, "fs-A")
	if err != nil {
		t.Fatalf("Get(id, fs-A) = %v, want the record (mutation (b) would break this)", err)
	}
	if got != rec {
		t.Fatalf("Get(id, fs-A) = %+v, want %+v", got, rec)
	}

	// Unknown id under the right scope: ErrNotFound, zero record.
	got, err = s.Get(context.Background(), "never-minted", "fs-A")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(unknown, fs-A) = %v, want ErrNotFound (mutation (c) would break this)", err)
	}
	if got != (Record{}) {
		t.Fatalf("Get(unknown, fs-A) leaked a non-zero Record: %+v", got)
	}
}

// TestGetCrossScopeAndUnknownAreIdenticalSentinel pins the anti-enumeration
// core: the cross-scope error and the unknown-id error are the IDENTICAL
// sentinel — same errors.Is target AND the same error string — so a probe
// cannot tell "this id exists in another scope" from "this id never existed".
func TestGetCrossScopeAndUnknownAreIdenticalSentinel(t *testing.T) {
	_, s := newTestStore(t)
	rec, _ := s.Put(context.Background(), samplePut("fs-A", "secret"))

	_, crossErr := s.Get(context.Background(), rec.FileID, "fs-B")
	_, unknownErr := s.Get(context.Background(), "never-minted", "fs-B")

	if !errors.Is(crossErr, ErrNotFound) || !errors.Is(unknownErr, ErrNotFound) {
		t.Fatalf("cross=%v unknown=%v, want both to be ErrNotFound", crossErr, unknownErr)
	}
	if crossErr.Error() != unknownErr.Error() {
		t.Fatalf("cross-scope and unknown-id errors differ:\n cross=%q\n unknown=%q (must be byte-identical for anti-enumeration)", crossErr.Error(), unknownErr.Error())
	}
}
