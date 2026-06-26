// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
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
