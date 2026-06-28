// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// deleteSetup wires a delete handler over a store with one in-scope record.
func deleteSetup(guard *fakeGuard) (*Handler, *fakeStore) {
	store := newFakeStore()
	store.put("fid-known", "fs-alpha", handlestore.Record{Filename: "doc", ObjectRef: "obj/doc"})
	h := newTestHandler(Deps{
		Store: store,
		Guard: guard,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	return h, store
}

// TestDeleteSuccessIs204AndGetThenDelete pins the happy path: a known in-scope
// file_id is deleted (204) with the ALLOW audit landing AFTER the Get and BEFORE
// the tombstone (Get-then-audit-then-Delete, Default 2).
func TestDeleteSuccessIs204AndGetThenDelete(t *testing.T) {
	guard := &fakeGuard{}
	h, store := deleteSetup(guard)
	w := doReq(h, http.MethodDelete, "/v1/files/fid-known")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	// The tombstone ran (the record is gone) AND exactly one record was deleted.
	if _, present := store.recs["fid-known"]; present {
		t.Fatal("record still present after a successful delete")
	}
	if len(store.deleted) != 1 || store.deleted[0] != "fid-known" {
		t.Fatalf("Delete called with %v, want [fid-known]", store.deleted)
	}
	// The ALLOW audit landed and named the backend ObjectRef, not the file_id.
	if len(guard.events) != 1 || guard.events[0].Outcome.DispositionID != auditgate.DispositionAllow {
		t.Fatalf("expected one ALLOW audit, got %+v", guard.events)
	}
	if guard.events[0].ActivityID != auditgate.ActivityDelete {
		t.Fatalf("audit activity = %d, want Delete", guard.events[0].ActivityID)
	}
	if guard.events[0].ObjectHandle != "obj/doc" {
		t.Fatalf("ObjectHandle = %q, want obj/doc (never the public file_id)", guard.events[0].ObjectHandle)
	}
}

// TestDeleteAuditFailsBeforeTombstone pins audit-before-ack: an ALLOW Mandate
// failure denies 503 and the tombstone is NEVER written (the record survives).
func TestDeleteAuditFailsBeforeTombstone(t *testing.T) {
	guard := &fakeGuard{err: auditgate.ErrAuditUnavailable}
	h, store := deleteSetup(guard)
	w := doReq(h, http.MethodDelete, "/v1/files/fid-known")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if _, present := store.recs["fid-known"]; !present {
		t.Fatal("record deleted despite a failed pre-tombstone audit")
	}
	if len(store.deleted) != 0 {
		t.Fatalf("Delete invoked %d times after a failed audit; want 0", len(store.deleted))
	}
}

// TestDeleteLatchedStoreIs503 pins Default 2: a latched store (mutation-path
// fault on Delete) denies 503 AFTER the ALLOW audit, with a best-effort DENY
// audit recorded.
func TestDeleteLatchedStoreIs503(t *testing.T) {
	guard := &fakeGuard{}
	store := newFakeStore()
	store.put("fid-known", "fs-alpha", handlestore.Record{ObjectRef: "obj/doc"})
	store.deleteErr = handlestore.ErrStoreUnavailable
	h := newTestHandler(Deps{
		Store: store,
		Guard: guard,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	w := doReq(h, http.MethodDelete, "/v1/files/fid-known")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (latched store)", w.Code)
	}
	// An ALLOW preceded the Delete attempt, then a DENY audit followed.
	if len(guard.events) != 2 {
		t.Fatalf("expected ALLOW then DENY audit (2 events), got %d: %+v", len(guard.events), guard.events)
	}
	if guard.events[0].Outcome.DispositionID != auditgate.DispositionAllow ||
		guard.events[1].Outcome.DispositionID != auditgate.DispositionDeny {
		t.Fatalf("audit order = %+v, want ALLOW then DENY", guard.events)
	}
}

// TestDeleteKeystone404 pins that an unknown OR cross-scope file_id on the
// delete path is the header-less keystone 404 — no tombstone, no audit.
func TestDeleteKeystone404(t *testing.T) {
	guard := &fakeGuard{}
	store := newFakeStore()
	store.put("fid-foreign", "fs-other", handlestore.Record{ObjectRef: "obj/x"})
	h := newTestHandler(Deps{
		Store: store,
		Guard: guard,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	unknown := doReq(h, http.MethodDelete, "/v1/files/nope")
	cross := doReq(h, http.MethodDelete, "/v1/files/fid-foreign")
	if unknown.Code != http.StatusNotFound || cross.Code != http.StatusNotFound {
		t.Fatalf("statuses unknown=%d cross=%d, want both 404", unknown.Code, cross.Code)
	}
	if unknown.Body.String() != cross.Body.String() {
		t.Fatal("keystone bodies differ on delete path")
	}
	if unknown.Header().Get(denywire.DenyReasonHeader) != "" || cross.Header().Get(denywire.DenyReasonHeader) != "" {
		t.Fatal("keystone 404 carries x-deny-reason on the delete path")
	}
	if len(guard.events) != 0 {
		t.Fatalf("a keystone-404 delete recorded %d audits; want 0 (no resolved object)", len(guard.events))
	}
	if len(store.deleted) != 0 {
		t.Fatal("a keystone-404 delete invoked the tombstone")
	}
}
