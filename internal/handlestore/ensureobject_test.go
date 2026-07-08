// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"errors"
	"testing"
)

// sampleEnsure is a representative EnsureInput under the given scope and ref.
func sampleEnsure(scope, ref string) EnsureInput {
	return EnsureInput{
		Scope:                 scope,
		ObjectRef:             ref,
		Filename:              "report.pdf",
		Mime:                  "application/pdf",
		Size:                  123,
		DownloadablePolicyRef: "",
	}
}

// TestEnsureObject_Idempotent is the anti-dup keystone at the store layer:
// EnsureObject twice for the SAME (scope, ref) returns the SAME FileID and mints
// exactly ONE record; a DIFFERENT ref mints a DIFFERENT FileID; the SAME ref in a
// DIFFERENT scope mints a DIFFERENT record (scope-keyed). Mutation: dropping the
// refIndex put-if-absent lookup (always mint) makes the two same-ref calls return
// different FileIDs -> this test goes RED (the red-probe below proves it).
func TestEnsureObject_Idempotent(t *testing.T) {
	_, s := newTestStore(t)
	ctx := context.Background()

	r1, err := s.EnsureObject(ctx, sampleEnsure("fs-A", "outputs/report.pdf"))
	if err != nil {
		t.Fatalf("EnsureObject #1: %v", err)
	}
	r2, err := s.EnsureObject(ctx, sampleEnsure("fs-A", "outputs/report.pdf"))
	if err != nil {
		t.Fatalf("EnsureObject #2: %v", err)
	}
	if r1.FileID != r2.FileID {
		t.Fatalf("same (scope, ref) minted two file_ids %q and %q — the anti-dup invariant is broken", r1.FileID, r2.FileID)
	}

	// Exactly one record for that (scope, ref): the List page carries one entry.
	page, err := s.List(ctx, ListInput{Scope: "fs-A"})
	if err != nil {
		t.Fatalf("List(fs-A): %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("List(fs-A) has %d records, want exactly 1 (idempotent ensure)", len(page.Records))
	}

	// A DIFFERENT ref -> a DIFFERENT file_id.
	other, err := s.EnsureObject(ctx, sampleEnsure("fs-A", "outputs/other.pdf"))
	if err != nil {
		t.Fatalf("EnsureObject other ref: %v", err)
	}
	if other.FileID == r1.FileID {
		t.Fatalf("distinct refs shared a file_id %q", other.FileID)
	}

	// The SAME ref in a DIFFERENT scope -> a DIFFERENT record (scope-keyed).
	crossScope, err := s.EnsureObject(ctx, sampleEnsure("fs-B", "outputs/report.pdf"))
	if err != nil {
		t.Fatalf("EnsureObject cross-scope: %v", err)
	}
	if crossScope.FileID == r1.FileID {
		t.Fatalf("same ref across scopes shared a file_id %q — the key is not scope-bound", crossScope.FileID)
	}
	if crossScope.Scope != "fs-B" {
		t.Fatalf("cross-scope record scope = %q, want fs-B", crossScope.Scope)
	}
}

// TestEnsureObject_LeadingSlashNormalization pins ADR-0029 inv-5: an ObjectRef
// stored with NO leading slash (the create convention) and the same ref WITH a
// leading slash key to the SAME handle. A byte-mismatch here is the most likely
// first bug (the design flags it), so this test guards the normalization
// directly. Mutation: dropping normalizeRef's TrimPrefix mints two handles for
// "outputs/x" vs "/outputs/x" -> RED.
func TestEnsureObject_LeadingSlashNormalization(t *testing.T) {
	_, s := newTestStore(t)
	ctx := context.Background()

	noSlash, err := s.EnsureObject(ctx, sampleEnsure("fs-A", "outputs/report.pdf"))
	if err != nil {
		t.Fatalf("EnsureObject no-slash: %v", err)
	}
	withSlash, err := s.EnsureObject(ctx, sampleEnsure("fs-A", "/outputs/report.pdf"))
	if err != nil {
		t.Fatalf("EnsureObject with-slash: %v", err)
	}
	if noSlash.FileID != withSlash.FileID {
		t.Fatalf("leading-slash and no-leading-slash refs minted two handles %q / %q — inv-5 normalization broken",
			noSlash.FileID, withSlash.FileID)
	}
}

// TestEnsureObject_TombstonedRefNotReminted is the tombstone-mask keystone: a
// Put'd then Deleted ref is NOT re-minted by EnsureObject (it returns the
// ErrNotFound sentinel) and does NOT reappear in a List. Mutation: dropping the
// tombstonedRefs check in EnsureObject re-mints the deleted object -> RED (the
// red-probe below proves it).
func TestEnsureObject_TombstonedRefNotReminted(t *testing.T) {
	_, s := newTestStore(t)
	ctx := context.Background()

	// Put a handle for the ref (the normal north-create path), then Delete it.
	put, err := s.Put(ctx, PutInput{Scope: "fs-A", ObjectRef: "outputs/gone.pdf", Filename: "gone.pdf", Size: 9})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, put.FileID, "fs-A"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// EnsureObject for the SAME ref must NOT re-mint: it returns ErrNotFound.
	_, eerr := s.EnsureObject(ctx, sampleEnsure("fs-A", "outputs/gone.pdf"))
	if !errors.Is(eerr, ErrNotFound) {
		t.Fatalf("EnsureObject of a tombstoned ref = %v, want ErrNotFound (the delete-mask must not re-mint)", eerr)
	}

	// The deleted object does not reappear in the list.
	page, err := s.List(ctx, ListInput{Scope: "fs-A"})
	if err != nil {
		t.Fatalf("List(fs-A): %v", err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("List(fs-A) has %d records after delete+ensure, want 0 (tombstoned ref reappeared)", len(page.Records))
	}
}

// TestEnsureObject_PutRevivesTombstonedRef pins that a fresh Put of a
// previously-deleted ref REVIVES it (the operator re-created what they deleted):
// a subsequent EnsureObject then finds the revived handle instead of the mask.
func TestEnsureObject_PutRevivesTombstonedRef(t *testing.T) {
	_, s := newTestStore(t)
	ctx := context.Background()

	p1, err := s.Put(ctx, PutInput{Scope: "fs-A", ObjectRef: "outputs/x.pdf", Filename: "x.pdf", Size: 1})
	if err != nil {
		t.Fatalf("Put #1: %v", err)
	}
	if err := s.Delete(ctx, p1.FileID, "fs-A"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Re-create the same ref: a fresh Put must clear the tombstone.
	p2, err := s.Put(ctx, PutInput{Scope: "fs-A", ObjectRef: "outputs/x.pdf", Filename: "x.pdf", Size: 2})
	if err != nil {
		t.Fatalf("Put #2 (recreate): %v", err)
	}
	// EnsureObject now finds the revived handle, not the mask.
	got, eerr := s.EnsureObject(ctx, sampleEnsure("fs-A", "outputs/x.pdf"))
	if eerr != nil {
		t.Fatalf("EnsureObject after re-create = %v, want the revived handle", eerr)
	}
	if got.FileID != p2.FileID {
		t.Fatalf("EnsureObject returned %q, want the re-created handle %q (Put must revive the tombstone)", got.FileID, p2.FileID)
	}
}

// TestEnsureObject_LatchedFailsClosed pins the mutation fail-closed contract: on a
// latched store EnsureObject returns ErrStoreUnavailable without minting. It
// latches via the package's canonical faultSyncer (the same helper the Put/Delete
// latch tests use).
func TestEnsureObject_LatchedFailsClosed(t *testing.T) {
	_, s := newTestStore(t)
	fault := faultSyncer{ws: s.f, failWrite: true}
	s.w = &fault
	_, _ = s.Put(context.Background(), samplePut("fs-A", "a.txt")) // latches the store
	if !s.Latched() {
		t.Fatal("store did not latch on a faulting write")
	}
	_, eerr := s.EnsureObject(context.Background(), sampleEnsure("fs-A", "outputs/report.pdf"))
	if !errors.Is(eerr, ErrStoreUnavailable) {
		t.Fatalf("EnsureObject on a latched store = %v, want ErrStoreUnavailable", eerr)
	}
}

// TestEnsureObject_ReplayRebuildsIndex pins the replay derivation: after a Put and
// a Delete on one store, a FRESH store reopened on the same log rebuilds BOTH the
// ref index (a surviving ref dedups) AND the tombstone mask (a deleted ref stays
// masked) from the existing opPut/opDelete log — no new record shape.
func TestEnsureObject_ReplayRebuildsIndex(t *testing.T) {
	ctx := context.Background()
	path := newTempLog(t)

	s1, err := NewDiskStore(path)
	if err != nil {
		t.Fatalf("NewDiskStore #1: %v", err)
	}
	// A surviving ensured ref, and a Put+Delete'd ref (tombstoned).
	survivor, err := s1.EnsureObject(ctx, sampleEnsure("fs-A", "outputs/live.pdf"))
	if err != nil {
		t.Fatalf("EnsureObject survivor: %v", err)
	}
	gone, err := s1.Put(ctx, PutInput{Scope: "fs-A", ObjectRef: "outputs/gone.pdf", Filename: "gone.pdf", Size: 3})
	if err != nil {
		t.Fatalf("Put gone: %v", err)
	}
	if err := s1.Delete(ctx, gone.FileID, "fs-A"); err != nil {
		t.Fatalf("Delete gone: %v", err)
	}
	_ = s1.Close()

	// Reopen: replay must rebuild the index and the mask.
	s2, err := NewDiskStore(path)
	if err != nil {
		t.Fatalf("NewDiskStore #2 (replay): %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	// The surviving ref dedups to the SAME file_id (index rebuilt).
	again, err := s2.EnsureObject(ctx, sampleEnsure("fs-A", "outputs/live.pdf"))
	if err != nil {
		t.Fatalf("EnsureObject survivor after replay: %v", err)
	}
	if again.FileID != survivor.FileID {
		t.Fatalf("survivor ref minted a new file_id after replay (%q != %q) — ref index not rebuilt", again.FileID, survivor.FileID)
	}
	// The deleted ref stays masked (mask rebuilt).
	_, eerr := s2.EnsureObject(ctx, sampleEnsure("fs-A", "outputs/gone.pdf"))
	if !errors.Is(eerr, ErrNotFound) {
		t.Fatalf("deleted ref re-minted after replay = %v, want ErrNotFound — tombstone mask not rebuilt", eerr)
	}
}
