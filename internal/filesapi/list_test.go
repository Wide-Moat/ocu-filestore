// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

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
