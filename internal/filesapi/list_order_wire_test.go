// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// orderCapturingStore records the ListInput.Order the handler passed, mirroring
// pagingStore's gotCursor capture. It is the discriminator for #182: the wire
// ?order= param must reach ListInput.Order, else the descending walk the engine
// already implements is unreachable from the north face and a just-written
// deliverable stays stranded off page 1.
type orderCapturingStore struct {
	*fakeStore
	gotOrder handlestore.ListOrder
}

func (s *orderCapturingStore) List(_ context.Context, in handlestore.ListInput) (handlestore.ListPage, error) {
	s.gotOrder = in.Order
	return handlestore.ListPage{}, nil
}

// TestListWireOrderReachesStore pins the #182 handler wiring: ?order=desc reaches
// the store as ListOrderDesc, an omitted param defaults to ascending, and any
// other value is ascending too (an old caller keeps its historical order). This
// is the seam that was missing — the engine (a832aa8) walks descending, but
// serveList set only {Scope, Cursor, Limit}, dropping the direction. Without the
// fix the desc case fails: gotOrder stays the zero value (Asc).
func TestListWireOrderReachesStore(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  handlestore.ListOrder
	}{
		{"desc param -> descending", "/v1/files?order=desc", handlestore.ListOrderDesc},
		{"omitted -> ascending default", "/v1/files", handlestore.ListOrderAsc},
		{"unknown value -> ascending default", "/v1/files?order=sideways", handlestore.ListOrderAsc},
		{"asc explicit -> ascending", "/v1/files?order=asc", handlestore.ListOrderAsc},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &orderCapturingStore{fakeStore: newFakeStore()}
			h := newTestHandler(Deps{
				Store: store,
				Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
			})
			w := doReq(h, http.MethodGet, tc.query)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
			}
			if store.gotOrder != tc.want {
				t.Fatalf("store received Order = %d, want %d (the ?order= param did not reach ListInput.Order)", store.gotOrder, tc.want)
			}
		})
	}
}
