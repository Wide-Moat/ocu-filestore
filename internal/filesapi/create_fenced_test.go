// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// TestCreateIsFenced501 pins that POST /v1/files is fenced: it returns 501
// unimplemented (the upload body is TBD pending ADR-0025; inventing one is
// forbidden) and touches nothing — no store, no engine.
func TestCreateIsFenced501(t *testing.T) {
	store := newFakeStore()
	h := newTestHandler(Deps{
		Store: store,
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})
	r := httptest.NewRequest(http.MethodPost, "/v1/files", strings.NewReader(`{"any":"body"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 (create is fenced)", w.Code)
	}
	if len(store.deleted) != 0 {
		t.Fatal("fenced create touched the store")
	}
}
