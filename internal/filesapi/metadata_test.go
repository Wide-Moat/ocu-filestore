// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// metadataHandler wires a store seeded with one in-scope record and a scope
// source bound to that scope.
func metadataHandler(t *testing.T) (*Handler, *fakeStore) {
	t.Helper()
	store := newFakeStore()
	store.put("fid-known", "fs-alpha", handlestore.Record{
		Filename:  "doc.txt",
		Mime:      "text/plain",
		Size:      10,
		ObjectRef: "obj/doc.txt",
		CreatedAt: "2026-06-23T00:00:00Z",
	})
	h := newTestHandler(Deps{
		Store: store,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})
	return h, store
}

// TestMetadataKnownReturnsFileObject pins the happy path: a known in-scope
// file_id returns 200 with the FileObject, downloadable omitted.
func TestMetadataKnownReturnsFileObject(t *testing.T) {
	h, _ := metadataHandler(t)
	w := doReq(h, http.MethodGet, "/v1/files/fid-known")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var fo FileObject
	if err := json.Unmarshal(w.Body.Bytes(), &fo); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fo.ID != "fid-known" || fo.Filename != "doc.txt" {
		t.Fatalf("FileObject = %+v", fo)
	}
}

// TestMetadataKeystoneByteIdentical404 is the keystone proof for the metadata
// path: an UNKNOWN file_id and a CROSS-SCOPE file_id (a real handle in a
// DIFFERENT scope) MUST produce byte-identical 404 responses — same status,
// same body, no x-deny-reason on either. The handler cannot distinguish them
// because the store collapses both into ErrNotFound and the handler has one
// not_found deny token.
func TestMetadataKeystoneByteIdentical404(t *testing.T) {
	store := newFakeStore()
	// A record that EXISTS but in a foreign scope.
	store.put("fid-foreign", "fs-other", handlestore.Record{Filename: "secret", ObjectRef: "obj/secret"})
	h := newTestHandler(Deps{
		Store: store,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})

	unknown := doReq(h, http.MethodGet, "/v1/files/fid-does-not-exist")
	crossScope := doReq(h, http.MethodGet, "/v1/files/fid-foreign")

	if unknown.Code != http.StatusNotFound || crossScope.Code != http.StatusNotFound {
		t.Fatalf("statuses = unknown %d, cross-scope %d; want both 404", unknown.Code, crossScope.Code)
	}
	if unknown.Body.String() != crossScope.Body.String() {
		t.Fatalf("bodies differ:\n unknown:     %q\n cross-scope: %q", unknown.Body.String(), crossScope.Body.String())
	}
	if unknown.Header().Get(denywire.DenyReasonHeader) != "" || crossScope.Header().Get(denywire.DenyReasonHeader) != "" {
		t.Fatal("a 404 carries x-deny-reason; the keystone 404 must be header-less")
	}
	// And neither is ever a 403.
	if unknown.Code == http.StatusForbidden || crossScope.Code == http.StatusForbidden {
		t.Fatal("metadata resolution returned 403; no forbidden on any file_id path")
	}
}

// TestMetadataStoreUnavailableIs503 pins that a store-latch fault on Get is a
// broker-internal 503, never a client deny.
func TestMetadataStoreUnavailableIs503(t *testing.T) {
	store := newFakeStore()
	store.getErr = handlestore.ErrStoreUnavailable
	h := newTestHandler(Deps{
		Store: store,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	w := doReq(h, http.MethodGet, "/v1/files/fid-known")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

// metadataAxisHandler wires a metadata handler over one in-scope record with the
// programmable guard, resolver and ceilings the three-axis tests drive.
func metadataAxisHandler(guard *fakeGuard, resolver southface.Resolver, ceilings southface.CeilingsRegistry) (*Handler, *fakeStore) {
	store := newFakeStore()
	store.put("fid-known", "fs-alpha", handlestore.Record{
		Filename:  "doc.txt",
		Mime:      "text/plain",
		Size:      10,
		ObjectRef: "obj/doc.txt",
		CreatedAt: "2026-06-23T00:00:00Z",
	})
	h := newTestHandler(Deps{
		Store:    store,
		Guard:    guard,
		Resolver: resolver,
		Ceilings: ceilings,
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})
	return h, store
}

// assertNoFileObject fails when the response body carries a FileObject: a
// refused metadata request must hand back a deny, never the record it refused.
func assertNoFileObject(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		return // a header-less/empty deny body carries no FileObject either
	}
	if _, present := body["filename"]; present {
		t.Fatalf("a refused metadata request returned the FileObject: %q", w.Body.String())
	}
}

// TestMetadataChargesOpsBucket pins that GET /v1/files/{id} charges the
// per-session ops ceiling (NFR-SEC-46) BEFORE it resolves the file_id: an
// exhausted bucket is a 429 with the handle store never touched. Asserting the
// zero Store.Get is what proves the charge PRECEDES the work.
func TestMetadataChargesOpsBucket(t *testing.T) {
	ceilings := newFakeCeilings()
	ceilings.sess.opErr = southface.ErrThrottleExceeded
	h, store := metadataAxisHandler(&fakeGuard{}, &fakeResolver{}, ceilings)

	w := doReq(h, http.MethodGet, "/v1/files/fid-known")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (ops ceiling exhausted); body %s", w.Code, w.Body.String())
	}
	if store.getCalls != 0 {
		t.Fatalf("store resolved %d file_ids after a refused op charge; want 0", store.getCalls)
	}
}

// TestMetadataResolverDenyIsForbidden pins that the three axes are re-derived
// broker-side for the metadata verb: a resolver deny on a RESOLVED record is a
// 403 with exactly one DENY audit and no FileObject on the wire. This is not a
// file_id-resolution leak — the record already resolved in scope, so the verdict
// is a downstream authorization decision, never the keystone's absent-vs-foreign
// distinction.
func TestMetadataResolverDenyIsForbidden(t *testing.T) {
	guard := &fakeGuard{}
	h, _ := metadataAxisHandler(guard, &fakeResolver{err: southface.ErrIntentDenied}, newFakeCeilings())

	w := doReq(h, http.MethodGet, "/v1/files/fid-known")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (resolver intent deny); body %s", w.Code, w.Body.String())
	}
	if len(guard.events) != 1 || guard.events[0].Outcome.DispositionID != auditgate.DispositionDeny {
		t.Fatalf("expected exactly one DENY audit, got %+v", guard.events)
	}
	assertNoFileObject(t, w)
}

// TestMetadataEmitsReadClassAllowAudit pins that a successful metadata read
// records one Read-class ALLOW naming the backend object reference, never the
// public file_id. The contract puts listFiles and getManifest in the Read class
// alongside download, so a metadata read is activity_id Read(2).
func TestMetadataEmitsReadClassAllowAudit(t *testing.T) {
	guard := &fakeGuard{}
	h, _ := metadataAxisHandler(guard, &fakeResolver{}, newFakeCeilings())

	w := doReq(h, http.MethodGet, "/v1/files/fid-known")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if len(guard.events) != 1 {
		t.Fatalf("expected exactly one ALLOW audit for a metadata read, got %d: %+v", len(guard.events), guard.events)
	}
	ev := guard.events[0]
	if ev.Outcome.DispositionID != auditgate.DispositionAllow {
		t.Fatalf("disposition = %q, want allow", ev.Outcome.DispositionID)
	}
	if ev.ActivityID != auditgate.ActivityRead {
		t.Fatalf("activity_id = %d, want %d (Read)", ev.ActivityID, auditgate.ActivityRead)
	}
	if ev.ObjectHandle != "obj/doc.txt" {
		t.Fatalf("object_handle = %q, want obj/doc.txt (never the public file_id)", ev.ObjectHandle)
	}
	if ev.Intent != string(southface.IntentRead) {
		t.Fatalf("intent = %q, want %q", ev.Intent, southface.IntentRead)
	}
}

// TestMetadataAuditFailureDeniesWithNoFileObject is the fail-closed twin
// (audit-before-ack, SEC-79): when the audit gate is down the metadata read
// denies 503 and the FileObject never reaches the caller. The record is the
// precondition for the answer, not a side note appended to it.
func TestMetadataAuditFailureDeniesWithNoFileObject(t *testing.T) {
	guard := &fakeGuard{err: auditgate.ErrAuditUnavailable}
	h, _ := metadataAxisHandler(guard, &fakeResolver{}, newFakeCeilings())

	w := doReq(h, http.MethodGet, "/v1/files/fid-known")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (audit gate down); body %s", w.Code, w.Body.String())
	}
	assertNoFileObject(t, w)
}

// TestMetadataKeystone404RecordsNoAudit is the REGRESSION guard for the
// repo-pinned convention the delete path already asserts: an unresolved file_id
// is not a file activity. It named no object in this scope (absent or foreign
// are the same sentinel), so there is nothing honest to record — and recording
// one would build a durable oracle out of the very distinction the keystone
// erases on the wire.
func TestMetadataKeystone404RecordsNoAudit(t *testing.T) {
	guard := &fakeGuard{}
	store := newFakeStore()
	store.put("fid-foreign", "fs-other", handlestore.Record{ObjectRef: "obj/secret"})
	h := newTestHandler(Deps{
		Store: store,
		Guard: guard,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	unknown := doReq(h, http.MethodGet, "/v1/files/nope")
	cross := doReq(h, http.MethodGet, "/v1/files/fid-foreign")
	if unknown.Code != http.StatusNotFound || cross.Code != http.StatusNotFound {
		t.Fatalf("statuses unknown=%d cross=%d, want both 404", unknown.Code, cross.Code)
	}
	if len(guard.events) != 0 {
		t.Fatalf("a keystone-404 metadata read recorded %d audits; want 0 (no resolved object)", len(guard.events))
	}
}

// TestMetadataDirtyObjectRefIs404 pins that a stored ObjectRef which does not
// normalise into the engine's relative convention is a not_found-class refusal
// with no audit — the same defence-in-depth the content verb already applies to
// the same class of record. Such a reference names no in-tree object, so the
// metadata verb must not describe it either.
func TestMetadataDirtyObjectRefIs404(t *testing.T) {
	guard := &fakeGuard{}
	store := newFakeStore()
	store.put("fid-dirty", "fs-alpha", handlestore.Record{Filename: "x", ObjectRef: "../escape"})
	h := newTestHandler(Deps{
		Store: store,
		Guard: guard,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files/fid-dirty")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a non-normalising ObjectRef; body %s", w.Code, w.Body.String())
	}
	if len(guard.events) != 0 {
		t.Fatalf("a non-normalising ObjectRef recorded %d audits; want 0", len(guard.events))
	}
	assertNoFileObject(t, w)
}
