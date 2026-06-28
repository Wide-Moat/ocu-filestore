// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// contentSetup wires a content handler over a store with one in-scope record
// ("fid-known" -> engine path "obj/doc"), a fake engine holding the bytes, a
// resolver returning the given grant, and the given guard.
func contentSetup(grant southface.Grant, guard *fakeGuard) (*Handler, *fakeEngine, *fakeStore) {
	store := newFakeStore()
	store.put("fid-known", "fs-alpha", handlestore.Record{
		Filename: "doc", ObjectRef: "obj/doc", Size: 5,
	})
	eng := newFakeEngine()
	eng.bytesByPath["obj/doc"] = []byte("hello")
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Resolver: &fakeResolver{grant: grant},
		Guard:    guard,
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})
	return h, eng, store
}

// TestContentSuccessStreamsBytes pins the happy path: a downloadable object
// streams 200 + octet-stream + the raw bytes, with an ALLOW audit preceding the
// first byte.
func TestContentSuccessStreamsBytes(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, _ := contentSetup(southface.Grant{Downloadable: true}, guard)
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != contentTypeOctetStream {
		t.Fatalf("Content-Type = %q, want octet-stream", ct)
	}
	if w.Body.String() != "hello" {
		t.Fatalf("body = %q, want hello", w.Body.String())
	}
	if eng.readRangeCalls != 1 {
		t.Fatalf("ReadRange called %d times, want 1", eng.readRangeCalls)
	}
	// The ALLOW audit landed and it preceded the read (audit-before-ack).
	if len(guard.events) == 0 || guard.events[0].Outcome.DispositionID != auditgate.DispositionAllow {
		t.Fatalf("expected a leading ALLOW audit, got %+v", guard.events)
	}
	if guard.events[0].ActivityID != auditgate.ActivityRead {
		t.Fatalf("audit activity = %d, want Read", guard.events[0].ActivityID)
	}
	// ObjectHandle is the backend ref, never the public file_id.
	if guard.events[0].ObjectHandle != "obj/doc" {
		t.Fatalf("ObjectHandle = %q, want the backend ref obj/doc", guard.events[0].ObjectHandle)
	}
}

// TestContentNonDownloadableIs403AndEngineNeverCalled pins downloadable-at-read
// (NFR-SEC-73): a non-downloadable grant denies 403 and engine.ReadRange is
// NEVER reached.
func TestContentNonDownloadableIs403AndEngineNeverCalled(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, _ := contentSetup(southface.Grant{Downloadable: false}, guard)
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("ReadRange called %d times on a non-downloadable object; want 0", eng.readRangeCalls)
	}
	if eng.statCalls != 0 {
		t.Fatalf("Stat called %d times before the downloadable check; want 0", eng.statCalls)
	}
	// The deny carries the not_downloadable truth in the x-deny-reason header
	// (this is a downstream authorization verdict on a RESOLVED object, not a
	// file_id-resolution leak).
	if w.Header().Get(denywire.DenyReasonHeader) != "not_downloadable" {
		t.Fatalf("x-deny-reason = %q, want not_downloadable", w.Header().Get(denywire.DenyReasonHeader))
	}
}

// TestContentNilRangeStatsBeforeAudit pins that a whole-object read (no range
// params) resolves the size via Stat BEFORE the ALLOW audit — a Stat fault
// records a single deny, never allow-then-deny.
func TestContentNilRangeStatsBeforeAudit(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, _ := contentSetup(southface.Grant{Downloadable: true}, guard)
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if eng.statCalls != 1 {
		t.Fatalf("Stat called %d times for a whole-object read, want 1", eng.statCalls)
	}
	if w.Body.String() != "hello" {
		t.Fatalf("body = %q, want the whole object", w.Body.String())
	}
}

// TestContentVanishedObjectIsSingleDeny pins that a whole-object read whose Stat
// fails (the object vanished after the handle was minted) records a SINGLE deny
// (404), never an allow-then-deny pair — the ALLOW audit must not have landed.
func TestContentVanishedObjectIsSingleDeny(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, _ := contentSetup(southface.Grant{Downloadable: true}, guard)
	eng.statErr = southface.ErrInvalidPath // the object is gone
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a vanished object", w.Code)
	}
	// Exactly one audit event, and it is a DENY (no prior ALLOW).
	allows := 0
	for _, e := range guard.events {
		if e.Outcome.DispositionID == auditgate.DispositionAllow {
			allows++
		}
	}
	if allows != 0 {
		t.Fatalf("a vanished-object read recorded %d ALLOW events; want 0 (single deny)", allows)
	}
}

// TestContentNegativeRangeIs400 pins that a negative offset or length is a
// malformed window (400), refused before the audit/engine.
func TestContentNegativeRangeIs400(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, _ := contentSetup(southface.Grant{Downloadable: true}, guard)
	for _, q := range []string{"offset=-1", "length=-1", "offset=-5&length=2"} {
		w := doReq(h, http.MethodGet, "/v1/files/fid-known/content?"+q)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("range %q -> status %d, want 400", q, w.Code)
		}
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("ReadRange called on a negative range; want 0")
	}
}

// TestContentExplicitRangeReadsWindow pins that an explicit offset/length reads
// the half-open window WITHOUT a whole-object Stat.
func TestContentExplicitRangeReadsWindow(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, _ := contentSetup(southface.Grant{Downloadable: true}, guard)
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content?offset=1&length=3")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "ell" {
		t.Fatalf("ranged body = %q, want ell", w.Body.String())
	}
	if eng.statCalls != 0 {
		t.Fatalf("Stat called %d times for an explicit-range read; want 0", eng.statCalls)
	}
}

// TestContentOffsetOnlyReadsToEOF pins the offset-only window: a request with an
// offset but NO length param reads [offset, EOF) — NOT an empty body. The handler
// must Stat the size and resolve length = info.Size - offset when the length param
// is absent (the nil-range whole-object formula at offset 0 generalised). A bare
// offset that skips the Stat and passes length=0 to the engine silently returns an
// empty 200 (data loss) -> this goes RED.
func TestContentOffsetOnlyReadsToEOF(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, _ := contentSetup(southface.Grant{Downloadable: true}, guard)
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content?offset=2")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != "llo" {
		t.Fatalf("offset-only body = %q, want %q (bytes [offset, EOF))", w.Body.String(), "llo")
	}
	// The length param is absent, so the handler must Stat to learn info.Size.
	if eng.statCalls != 1 {
		t.Fatalf("Stat called %d times for an offset-only read; want 1 (length resolved by Stat)", eng.statCalls)
	}
}

// TestContentOffsetOnlyAtEOF pins the EOF edge: an offset equal to the object size
// (no length param) is a correct empty 200 — distinct from the offset-only data
// loss bug. offset==Size reads zero bytes legitimately; the body is empty AND the
// status is 200.
func TestContentOffsetOnlyAtEOF(t *testing.T) {
	guard := &fakeGuard{}
	h, _, _ := contentSetup(southface.Grant{Downloadable: true}, guard)
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content?offset=5")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (offset==Size is a legitimate empty read)", w.Code)
	}
	if w.Body.String() != "" {
		t.Fatalf("offset-at-EOF body = %q, want empty (offset==Size reads zero bytes)", w.Body.String())
	}
}

// TestContentAuditBeforeAckMandateFailsIs503ZeroBytes pins audit-before-ack: an
// ALLOW Mandate failure (audit down) denies 503 with ZERO bytes and
// engine.ReadRange NEVER called.
func TestContentAuditBeforeAckMandateFailsIs503ZeroBytes(t *testing.T) {
	guard := &fakeGuard{err: auditgate.ErrAuditUnavailable}
	h, eng, _ := contentSetup(southface.Grant{Downloadable: true}, guard)
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	// ZERO OBJECT bytes: the deny carries a diagnostic BoundedReason body, but
	// NONE of the object's bytes ("hello") may leak before the audit lands.
	if strings.Contains(w.Body.String(), "hello") {
		t.Fatalf("object bytes leaked on an audit-down deny: %q", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct == contentTypeOctetStream {
		t.Fatal("octet-stream Content-Type committed on an audit-down deny; want the deny JSON body")
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("ReadRange called %d times after a failed allow audit; want 0", eng.readRangeCalls)
	}
}

// TestContentKeystone404 pins that an unknown OR cross-scope file_id on the
// content path is the header-less keystone 404 with engine never touched.
func TestContentKeystone404(t *testing.T) {
	store := newFakeStore()
	store.put("fid-foreign", "fs-other", handlestore.Record{ObjectRef: "obj/x"})
	eng := newFakeEngine()
	h := newTestHandler(Deps{
		Store:  store,
		Engine: eng,
		Scope:  fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	unknown := doReq(h, http.MethodGet, "/v1/files/nope/content")
	cross := doReq(h, http.MethodGet, "/v1/files/fid-foreign/content")
	if unknown.Code != http.StatusNotFound || cross.Code != http.StatusNotFound {
		t.Fatalf("statuses unknown=%d cross=%d, want both 404", unknown.Code, cross.Code)
	}
	if unknown.Body.String() != cross.Body.String() {
		t.Fatalf("keystone bodies differ on content path")
	}
	if eng.readRangeCalls != 0 || eng.statCalls != 0 {
		t.Fatal("engine touched on a keystone 404")
	}
}

// TestContentMidStreamEngineFaultKeeps200 pins that an engine fault AFTER the
// 200 header is committed cannot change the status — the stream just terminates.
func TestContentMidStreamEngineFaultKeeps200(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, _ := contentSetup(southface.Grant{Downloadable: true}, guard)
	eng.readErr = southface.ErrBackendTransient // faults inside ReadRange after 200
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (committed before the mid-stream fault)", w.Code)
	}
}

// TestContentOpCeilingExhaustedIs429 pins the ops/s ceiling: an exhausted op
// token denies 429 before the store is touched.
func TestContentOpCeilingExhaustedIs429(t *testing.T) {
	store := newFakeStore()
	store.put("fid-known", "fs-alpha", handlestore.Record{ObjectRef: "obj/doc"})
	ceil := newFakeCeilings()
	ceil.sess.opErr = southface.ErrThrottleExceeded
	h := newTestHandler(Deps{
		Store:    store,
		Ceilings: ceil,
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
}

// TestContentFDCeilingExhaustedIs429 pins the fd ceiling: an exhausted fd slot
// denies 429 with no bytes streamed.
func TestContentFDCeilingExhaustedIs429(t *testing.T) {
	guard := &fakeGuard{}
	store := newFakeStore()
	store.put("fid-known", "fs-alpha", handlestore.Record{ObjectRef: "obj/doc", Size: 5})
	eng := newFakeEngine()
	eng.bytesByPath["obj/doc"] = []byte("hello")
	ceil := newFakeCeilings()
	ceil.sess.fdErr = southface.ErrFDExceeded
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Guard:    guard,
		Ceilings: ceil,
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (fd ceiling)", w.Code)
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("ReadRange called %d times after fd-ceiling reject; want 0", eng.readRangeCalls)
	}
}
