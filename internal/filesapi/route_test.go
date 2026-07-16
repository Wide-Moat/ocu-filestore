// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
)

// doReq drives the handler with a fresh recorder and returns it. The default
// test handler has an ok scope, so the route boundary is exercised without the
// scope fail-closed path unless overridden.
func doReq(h *Handler, method, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestRouteUnknownPathIsAntiEnum404 pins that a path the handler does not serve
// is a header-less 404 (anti-enumeration) — never a 403 or a 405.
func TestRouteUnknownPathIsAntiEnum404(t *testing.T) {
	h := newTestHandler(Deps{})
	for _, target := range []string{
		"/",
		"/v1",
		"/v1/other",
		"/v1/files/abc/unknown",
		"/v1/files/abc/content/extra",
		"/v2/files",
	} {
		t.Run(target, func(t *testing.T) {
			w := doReq(h, http.MethodGet, target)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 for unknown path %q", w.Code, target)
			}
			if w.Header().Get(denywire.DenyReasonHeader) != "" {
				t.Fatalf("unknown path carries x-deny-reason; must be header-less")
			}
		})
	}
}

// TestRouteUnsupportedMethodIs405WithAllow pins that an unsupported method on a
// KNOWN route is a 405 with an Allow header listing the accepted methods — an
// HTTP-method fault, not an authorization verdict, decided on the route before
// any store lookup.
func TestRouteUnsupportedMethodIs405WithAllow(t *testing.T) {
	h := newTestHandler(Deps{})
	for _, tc := range []struct {
		method, target string
		wantAllow      []string
	}{
		{http.MethodPut, "/v1/files", []string{"GET", "POST"}},
		{http.MethodDelete, "/v1/files", []string{"GET", "POST"}},
		{http.MethodPost, "/v1/files/abc", []string{"GET", "DELETE"}},
		{http.MethodPut, "/v1/files/abc", []string{"GET", "DELETE"}},
		{http.MethodDelete, "/v1/files/abc/content", []string{"GET"}},
		{http.MethodPost, "/v1/files/abc/content", []string{"GET"}},
	} {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			w := doReq(h, tc.method, tc.target)
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", w.Code)
			}
			allow := w.Header().Get("Allow")
			for _, m := range tc.wantAllow {
				if !strings.Contains(allow, m) {
					t.Fatalf("Allow = %q, want it to contain %q", allow, m)
				}
			}
			if w.Header().Get(denywire.DenyReasonHeader) != "" {
				t.Fatal("405 carries x-deny-reason; a method fault is not an authorization verdict")
			}
		})
	}
}

// TestRouteScopeAbsentFailsClosed pins that a request whose ScopeSource returns
// ok=false is refused (5xx) BEFORE any store lookup — and never with a 403 that
// could leak a scope distinction.
func TestRouteScopeAbsentFailsClosed(t *testing.T) {
	store := newFakeStore()
	h := newTestHandler(Deps{
		Scope: fakeScope{ok: false},
		Store: store,
	})
	w := doReq(h, http.MethodGet, "/v1/files/abc")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for absent attested scope", w.Code)
	}
	if w.Code == http.StatusForbidden {
		t.Fatal("absent scope returned 403; must never leak a scope distinction")
	}
}

// TestNorthScopeShapeGuard is the north choke-point wire keystone (ADR-0030
// north face, open question #348). Driving the REAL fenced header source over
// the route, it pins that:
//
//   - a shape-legal filesystem_id ("fs-fleet-abcdef0123456789") resolves and
//     reaches the store (a plain "fs-fleet" is likewise accepted, backward
//     compatible: no chat suffix required);
//   - a traversal-shaped id ("fs-fleet-abc/123", "fs-fleet-../etc") is refused
//     at the north edge with the existing 503 fail-closed deny (NEVER a 403 that
//     would leak a scope distinction) BEFORE the store is ever read.
//
// The non-vacuous leg is getCalls: a refused traversal id must NOT reach the
// store. This is a cooperative shape guard (single legal path element), not a
// per-chat authorization point.
func TestNorthScopeShapeGuard(t *testing.T) {
	reqWithScope := func(h *Handler, id string) (*httptest.ResponseRecorder, *fakeStore) {
		store := newFakeStore()
		store.put("fid-x", id, handlestore.Record{Filename: "f", ObjectRef: "obj/f", Size: 1})
		h = newTestHandler(Deps{Scope: NewFencedScopeSource(), Store: store})
		r := httptest.NewRequest(http.MethodGet, "/v1/files/fid-x", nil)
		r.Header.Set(fencedScopeHeader, id)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w, store
	}

	t.Run("legal chat-suffixed id resolves and reads the store", func(t *testing.T) {
		w, store := reqWithScope(nil, "fs-fleet-abcdef0123456789")
		if w.Code != http.StatusOK {
			t.Fatalf("legal scope -> %d, want 200", w.Code)
		}
		if store.getCalls == 0 {
			t.Fatal("legal scope never reached the store; the guard must not block a shape-legal id")
		}
	})

	t.Run("plain base is backward compatible", func(t *testing.T) {
		w, store := reqWithScope(nil, "fs-fleet")
		if w.Code != http.StatusOK {
			t.Fatalf("plain base scope -> %d, want 200", w.Code)
		}
		if store.getCalls == 0 {
			t.Fatal("plain base never reached the store")
		}
	})

	for _, id := range []string{"fs-fleet-abc/123", "fs-fleet-../etc"} {
		t.Run("traversal id refused at the edge: "+id, func(t *testing.T) {
			w, store := reqWithScope(nil, id)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("traversal scope %q -> %d, want 503 (shape guard fail-closed)", id, w.Code)
			}
			if w.Code == http.StatusForbidden {
				t.Fatalf("traversal scope %q -> 403; must never leak a scope distinction", id)
			}
			if store.getCalls != 0 {
				t.Fatalf("traversal scope %q reached the store (%d Get calls); the guard must refuse at the north edge",
					id, store.getCalls)
			}
		})
	}
}

// TestRouteEmptyFileIDIs404 pins that a bare "/v1/files/" (empty file_id) is a
// header-less 404, not a 500 or a panic.
func TestRouteEmptyFileIDIs404(t *testing.T) {
	h := newTestHandler(Deps{})
	w := doReq(h, http.MethodGet, "/v1/files/")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for empty file_id", w.Code)
	}
}

// TestRouteStampsRequestID pins that every response carries the x-request-id
// correlation header (allow and deny alike).
func TestRouteStampsRequestID(t *testing.T) {
	h := newTestHandler(Deps{})
	w := doReq(h, http.MethodGet, "/v1/files/unknown")
	if w.Header().Get(requestIDHeader) == "" {
		t.Fatal("response missing x-request-id")
	}
}
