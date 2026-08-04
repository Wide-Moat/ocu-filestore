// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// TestListEnvelopeShape pins GET /v1/files: the {data, has_more, first_id,
// last_id, next_cursor} envelope built from the store page.
func TestListEnvelopeShape(t *testing.T) {
	store := newFakeStore()
	store.listPage = handlestore.ListPage{
		Records: []handlestore.Record{
			{FileID: "f1", Filename: "a", ObjectRef: "o1"},
			{FileID: "f2", Filename: "b", ObjectRef: "o2"},
		},
		HasMore:    true,
		FirstID:    "f1",
		LastID:     "f2",
		NextCursor: "cur-f2",
	}
	h := newTestHandler(Deps{
		Store: store,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var env ListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Data) != 2 || !env.HasMore || env.FirstID != "f1" || env.LastID != "f2" || env.NextCursor != "cur-f2" {
		t.Fatalf("envelope = %+v", env)
	}
}

// pagingStore is a two-page fake: the first List (empty cursor) returns page 1
// with a next cursor; the second List (that cursor) returns page 2, final.
type pagingStore struct {
	*fakeStore
	page1, page2 handlestore.ListPage
	gotCursor    string // the Cursor the most recent List call received
}

func (s *pagingStore) List(_ context.Context, in handlestore.ListInput) (handlestore.ListPage, error) {
	s.gotCursor = in.Cursor
	if in.Cursor == "" {
		return s.page1, nil
	}
	return s.page2, nil
}

// TestListTwoPageCursorPagination pins ?after=<next_cursor> pagination: the first
// page carries an opaque next_cursor + has_more; passing that token back as
// ?after fetches the final page (has_more=false, no next_cursor). It also pins
// the round-trip: the token the client sends as ?after reaches the store as the
// opaque Cursor verbatim (the wire never substitutes the bare boundary id).
func TestListTwoPageCursorPagination(t *testing.T) {
	ps := &pagingStore{
		fakeStore: newFakeStore(),
		page1: handlestore.ListPage{
			Records:    []handlestore.Record{{FileID: "f1", ObjectRef: "o1"}},
			HasMore:    true,
			FirstID:    "f1",
			LastID:     "f1",
			NextCursor: "cur-1",
		},
		page2: handlestore.ListPage{
			Records: []handlestore.Record{{FileID: "f2", ObjectRef: "o2"}},
			HasMore: false,
			FirstID: "f2",
			LastID:  "f2",
		},
	}
	h := newTestHandler(Deps{
		Store: ps,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})

	w1 := doReq(h, http.MethodGet, "/v1/files")
	var e1 ListResponse
	_ = json.Unmarshal(w1.Body.Bytes(), &e1)
	if !e1.HasMore || e1.NextCursor != "cur-1" || len(e1.Data) != 1 || e1.Data[0].ID != "f1" {
		t.Fatalf("page1 = %+v", e1)
	}

	// Pass the opaque next_cursor back as ?after; it must reach the store verbatim.
	w2 := doReq(h, http.MethodGet, "/v1/files?after=cur-1")
	var e2 ListResponse
	_ = json.Unmarshal(w2.Body.Bytes(), &e2)
	if e2.HasMore || e2.NextCursor != "" || len(e2.Data) != 1 || e2.Data[0].ID != "f2" {
		t.Fatalf("page2 = %+v", e2)
	}
	if ps.gotCursor != "cur-1" {
		t.Fatalf("store received cursor %q, want the opaque next_cursor cur-1 passed via ?after", ps.gotCursor)
	}
}

// TestListInvalidLimitIs400 pins that a non-integer or negative limit query
// parameter is a malformed client request (400).
func TestListInvalidLimitIs400(t *testing.T) {
	h := newTestHandler(Deps{
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	for _, limit := range []string{"abc", "-5"} {
		w := doReq(h, http.MethodGet, "/v1/files?limit="+limit)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("limit=%q -> status %d, want 400", limit, w.Code)
		}
	}
}

// TestListStoreErrorIs503 pins that a store List error is a broker-internal 503.
func TestListStoreErrorIs503(t *testing.T) {
	store := newFakeStore()
	store.listErr = handlestore.ErrStoreUnavailable
	h := newTestHandler(Deps{
		Store: store,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

// TestListMalformedCursorIs400 pins that a malformed ?after cursor is a CLIENT
// fault mapped to 400 invalid_argument (denyclass.Malformed), NOT a retryable
// 503. The store surfaces the malformed token as handlestore.ErrMalformedCursor
// (proven end-to-end against the real keyset walk in
// handlestore.TestListMalformedCursorRejected); this pins the wire layer's
// classification of that sentinel — a bare last_id or any undecodable token
// must not invite an infinite client retry loop.
func TestListMalformedCursorIs400(t *testing.T) {
	store := newFakeStore()
	store.listErr = handlestore.ErrMalformedCursor
	h := newTestHandler(Deps{
		Store: store,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	w := doReq(h, http.MethodGet, "/v1/files?after=not-a-real-cursor")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a malformed cursor (client fault, not retryable)", w.Code)
	}
}

// listAxisHandler wires a list handler over a seeded engine namespace (so the
// reconcile really walks and really mints) plus the programmable guard,
// resolver and ceilings the three-axis tests drive.
func listAxisHandler(guard *fakeGuard, resolver southface.Resolver, ceilings southface.CeilingsRegistry) (*Handler, *fakeStore, *fakeEngine) {
	store := newFakeStore()
	eng := newFakeEngine()
	eng.seedObject("outputs/report.pdf", []byte("pdf"))
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Guard:    guard,
		Resolver: resolver,
		Ceilings: ceilings,
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})
	return h, store, eng
}

// TestListChargesOpsBucket pins that GET /v1/files charges the per-session ops
// ceiling (NFR-SEC-46) BEFORE it touches the engine or the store: an exhausted
// bucket is a 429 with the reconcile walk never started and no handle minted.
// Asserting the zero side effect — not merely the status — is what proves the
// charge PRECEDES the work rather than merely happening somewhere.
func TestListChargesOpsBucket(t *testing.T) {
	ceilings := newFakeCeilings()
	ceilings.sess.opErr = southface.ErrThrottleExceeded
	h, store, eng := listAxisHandler(&fakeGuard{}, &fakeResolver{}, ceilings)

	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (ops ceiling exhausted); body %s", w.Code, w.Body.String())
	}
	if eng.listCalls != 0 {
		t.Fatalf("engine walked %d levels after a refused op charge; want 0", eng.listCalls)
	}
	if store.ensureMints != 0 {
		t.Fatalf("the reconcile minted %d handles after a refused op charge; want 0", store.ensureMints)
	}
}

// TestListResolverDenyRefusesPage pins that the three axes are re-derived
// broker-side for the list verb: a resolver deny refuses the whole page (403),
// records exactly one DENY audit, and leaves ZERO side effect — the engine
// namespace is never walked and no durable handle is minted.
func TestListResolverDenyRefusesPage(t *testing.T) {
	guard := &fakeGuard{}
	h, store, eng := listAxisHandler(guard, &fakeResolver{err: southface.ErrIntentDenied}, newFakeCeilings())

	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (resolver intent deny); body %s", w.Code, w.Body.String())
	}
	if len(guard.events) != 1 || guard.events[0].Outcome.DispositionID != auditgate.DispositionDeny {
		t.Fatalf("expected exactly one DENY audit, got %+v", guard.events)
	}
	if eng.listCalls != 0 {
		t.Fatalf("engine walked %d levels after an authorization deny; want 0", eng.listCalls)
	}
	if store.ensureMints != 0 {
		t.Fatalf("the reconcile minted %d handles after an authorization deny; want 0", store.ensureMints)
	}
}

// TestListEmitsReadClassAllowAudit pins the two audit fields the frozen wire
// contract constrains for a list: activity_id is Read(2) (the contract's
// "list maps to Read(2)") and object_handle is the non-empty scope-root
// RelativePath the listing names (RelativePath carries minLength 1, so an empty
// handle would be off-contract). Intent is the read axis.
func TestListEmitsReadClassAllowAudit(t *testing.T) {
	guard := &fakeGuard{}
	h, _, _ := listAxisHandler(guard, &fakeResolver{}, newFakeCeilings())

	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if len(guard.events) != 1 {
		t.Fatalf("expected exactly one ALLOW audit for a list, got %d: %+v", len(guard.events), guard.events)
	}
	ev := guard.events[0]
	if ev.Outcome.DispositionID != auditgate.DispositionAllow {
		t.Fatalf("disposition = %q, want allow", ev.Outcome.DispositionID)
	}
	if ev.ActivityID != auditgate.ActivityRead {
		t.Fatalf("activity_id = %d, want %d (Read: the contract maps list to Read(2))", ev.ActivityID, auditgate.ActivityRead)
	}
	if ev.ObjectHandle == "" {
		t.Fatal("object_handle is empty; the contract's RelativePath has minLength 1")
	}
	if ev.ObjectHandle != "." {
		t.Fatalf("object_handle = %q, want %q (the scope root the listing walks)", ev.ObjectHandle, ".")
	}
	if ev.Intent != string(southface.IntentRead) {
		t.Fatalf("intent = %q, want %q", ev.Intent, southface.IntentRead)
	}
	if ev.FilesystemID != "fs-alpha" {
		t.Fatalf("filesystem_id = %q, want fs-alpha", ev.FilesystemID)
	}
}
