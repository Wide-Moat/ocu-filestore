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

// deleteAxisHandler wires a delete handler over one in-scope record with the
// programmable guard, resolver and ceilings the three-axis tests drive. The
// attested scope grants ONLY read intent — exactly what the shipped F9
// ScopeSource stamps — so a delete that presented the scope's grant set verbatim
// to the Resolver would be denied on the intent axis.
func deleteAxisHandler(guard *fakeGuard, resolver southface.Resolver, ceilings southface.CeilingsRegistry) (*Handler, *fakeStore) {
	store := newFakeStore()
	store.put("fid-known", "fs-alpha", handlestore.Record{Filename: "doc", ObjectRef: "obj/doc"})
	h := newTestHandler(Deps{
		Store:    store,
		Guard:    guard,
		Resolver: resolver,
		Ceilings: ceilings,
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})
	return h, store
}

// TestDeleteChargesOpsBucket pins that DELETE /v1/files/{id} charges the
// per-session ops ceiling (NFR-SEC-46) BEFORE it resolves the file_id: an
// exhausted bucket is a 429 with the handle store never read, never tombstoned,
// and no activity recorded. Asserting the zero side effect is what proves the
// charge PRECEDES the work.
func TestDeleteChargesOpsBucket(t *testing.T) {
	ceilings := newFakeCeilings()
	ceilings.sess.opErr = southface.ErrThrottleExceeded
	guard := &fakeGuard{}
	h, store := deleteAxisHandler(guard, &fakeResolver{}, ceilings)

	w := doReq(h, http.MethodDelete, "/v1/files/fid-known")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (ops ceiling exhausted); body %s", w.Code, w.Body.String())
	}
	if store.getCalls != 0 {
		t.Fatalf("store resolved %d file_ids after a refused op charge; want 0", store.getCalls)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("the tombstone ran %d times after a refused op charge; want 0", len(store.deleted))
	}
	if len(guard.events) != 0 {
		t.Fatalf("a throttled delete recorded %d audits; want 0 (no object was resolved)", len(guard.events))
	}
}

// TestDeleteResolvesWriteIntentAtObjectRef pins WHICH question the broker
// re-derives for a delete: the WRITE axis (a delete is a namespace mutation —
// the repo's closed route-op map puts removeFile in the write class and the
// delete audit event already stamps intent=write), at the resolved record's
// backend reference, in the attested scope.
//
// The load-bearing leg is the evidence: the shipped F9 ScopeSource stamps ONLY
// read intent, so a delete that handed ps.GrantedIntents to the Resolver
// verbatim would 403 EVERY live delete. The write verb adds write intent to the
// evidence exactly as the create verb does, rather than widening the scope
// source's grant for every plane.
func TestDeleteResolvesWriteIntentAtObjectRef(t *testing.T) {
	resolver := &recordingResolver{}
	h, store := deleteAxisHandler(&fakeGuard{}, resolver, newFakeCeilings())

	w := doReq(h, http.MethodDelete, "/v1/files/fid-known")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body %s", w.Code, w.Body.String())
	}
	if resolver.calls != 1 {
		t.Fatalf("Resolve called %d times, want exactly 1 (re-derived per request)", resolver.calls)
	}
	if resolver.lastReq.Intent != southface.IntentWrite {
		t.Fatalf("resolved intent = %q, want %q (a delete is a namespace mutation)", resolver.lastReq.Intent, southface.IntentWrite)
	}
	if resolver.lastReq.Path != "obj/doc" {
		t.Fatalf("resolved path = %q, want the record's backend reference obj/doc", resolver.lastReq.Path)
	}
	if resolver.lastReq.Filesystem != "fs-alpha" {
		t.Fatalf("resolved filesystem = %q, want fs-alpha", resolver.lastReq.Filesystem)
	}
	if resolver.lastEvidence.Scope != "fs-alpha" {
		t.Fatalf("evidence scope = %q, want the attested fs-alpha", resolver.lastEvidence.Scope)
	}
	if !hasIntent(resolver.lastEvidence.GrantedIntents, southface.IntentWrite) {
		t.Fatalf("evidence intents = %v; the write verb must present write intent, or every live delete 403s under the read-only F9 grant", resolver.lastEvidence.GrantedIntents)
	}
	if len(store.deleted) != 1 {
		t.Fatalf("Delete called %d times, want 1", len(store.deleted))
	}
}

// TestDeleteResolverDenyRefusesTombstone pins deny-by-default on the delete
// verb: a resolver deny on a RESOLVED record is a 403 with exactly one DENY
// audit naming the object, and the tombstone is NEVER written — the record
// survives. This is not a file_id-resolution leak: the record already resolved
// in scope, so the verdict is a downstream authorization decision, never the
// keystone's absent-vs-foreign distinction.
func TestDeleteResolverDenyRefusesTombstone(t *testing.T) {
	guard := &fakeGuard{}
	h, store := deleteAxisHandler(guard, &recordingResolver{err: southface.ErrIntentDenied}, newFakeCeilings())

	w := doReq(h, http.MethodDelete, "/v1/files/fid-known")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (resolver intent deny); body %s", w.Code, w.Body.String())
	}
	if len(guard.events) != 1 || guard.events[0].Outcome.DispositionID != auditgate.DispositionDeny {
		t.Fatalf("expected exactly one DENY audit, got %+v", guard.events)
	}
	if guard.events[0].ActivityID != auditgate.ActivityDelete {
		t.Fatalf("audit activity = %d, want Delete(4)", guard.events[0].ActivityID)
	}
	if guard.events[0].ObjectHandle != "obj/doc" {
		t.Fatalf("ObjectHandle = %q, want obj/doc (never the public file_id)", guard.events[0].ObjectHandle)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("the tombstone ran %d times after an authorization deny; want 0", len(store.deleted))
	}
	if _, present := store.recs["fid-known"]; !present {
		t.Fatal("the record was removed despite an authorization deny")
	}
}

// TestDeleteResolverDenyAuditDownIs503 is the fail-closed twin of the deny path
// (NFR-SEC-79): when the DENY record itself cannot durably land, the verdict the
// caller sees degrades to audit-down (503), not the authorization 403 — a
// refusal the chain does not carry is not a refusal the wire may assert. The
// tombstone still never runs.
func TestDeleteResolverDenyAuditDownIs503(t *testing.T) {
	guard := &fakeGuard{err: auditgate.ErrAuditUnavailable}
	h, store := deleteAxisHandler(guard, &recordingResolver{err: southface.ErrIntentDenied}, newFakeCeilings())

	w := doReq(h, http.MethodDelete, "/v1/files/fid-known")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (the deny record did not land); body %s", w.Code, w.Body.String())
	}
	if len(store.deleted) != 0 {
		t.Fatalf("the tombstone ran %d times after an audit-down deny; want 0", len(store.deleted))
	}
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
