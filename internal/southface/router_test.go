// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// routedRequest builds a POST REST request for op carrying body and the
// application/json Content-Type, with a PeerScope bound to scope/intents in the
// request context (the unix-fallback identity source the dispatcher reads when
// no credential extractor is wired). It mirrors scopedRequest but is driven
// through the router rather than straight at the dispatcher.
func routedRequest(op Op, body string, scope string, intents []Intent) *http.Request {
	return scopedRequest(op, body, scope, intents)
}

// TestRouter pins the A1 route boundary: a known op reached with POST is
// delegated to the dispatcher (200 on the clear path); a known op reached with
// a non-POST method is 405 with Allow: POST; a path naming an unknown op (or one
// outside restBase) is 404.
func TestRouter(t *testing.T) {
	t.Run("POST to a known op is delegated (200)", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(boundScope, "p", 7)
		d := newEngineDispatcher(
			&fakeResolver{grant: Grant{Downloadable: true}},
			&fakeGuard{},
			okCeilings(),
			eng,
		)
		rt := newRESTRouter(d)

		w := httptest.NewRecorder()
		rt.ServeHTTP(w, routedRequest(OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead}))
		if w.Code != http.StatusOK {
			t.Fatalf("POST readFile through router: status = %d, want 200; body %s", w.Code, w.Body.String())
		}
		// The dispatcher minted and stamped the per-request id on the delegated
		// response — the router never strips it.
		if w.Header().Get(requestIDHeader) == "" {
			t.Fatal("delegated response missing x-request-id")
		}
	})

	t.Run("non-POST to a known op is 405 with Allow: POST", func(t *testing.T) {
		rt := newRESTRouter(newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings()))
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(method, restBase+"readFile", nil)
			rt.ServeHTTP(w, r)
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s readFile: status = %d, want 405", method, w.Code)
			}
			if w.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("%s readFile: Allow = %q, want POST", method, w.Header().Get("Allow"))
			}
			// The 405 body is the REST BoundedReason diagnostic, not a naked drop.
			ce := decodeErrBody(t, w)
			if ce.Code == "" {
				t.Fatalf("%s readFile: 405 body has no reason_code", method)
			}
		}
	})

	t.Run("unknown op is 404", func(t *testing.T) {
		rt := newRESTRouter(newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings()))
		for _, path := range []string{
			restBase + "noSuchOp",
			restBase, // bare prefix: trailing segment is empty, not a known op
			"/other/readFile",
			"/v1/filestore/readFile", // outside restBase
		} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			rt.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound {
				t.Fatalf("POST %q: status = %d, want 404", path, w.Code)
			}
		}
	})

	t.Run("404 precedes 405 for an unknown op with a non-POST method", func(t *testing.T) {
		// A non-POST to an UNKNOWN op is 404 (the op does not exist), not 405:
		// the route-boundary order resolves op membership before method.
		rt := newRESTRouter(newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings()))
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, restBase+"noSuchOp", nil)
		rt.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("GET noSuchOp: status = %d, want 404 (404 before 405)", w.Code)
		}
	})
}

// TestRouteOp pins the router-boundary op resolver: every frozen op resolves;
// an empty segment, an unknown op, and a path outside restBase do not.
func TestRouteOp(t *testing.T) {
	for op := range knownOps {
		got, ok := routeOp(restBase + string(op))
		if !ok || got != op {
			t.Errorf("routeOp(%q) = (%q,%v), want (%q,true)", restBase+string(op), got, ok, op)
		}
	}
	for _, path := range []string{restBase, restBase + "noSuchOp", "/other/x", "/v1/filestore/x"} {
		if _, ok := routeOp(path); ok {
			t.Errorf("routeOp(%q) reported known, want unknown", path)
		}
	}
}

// TestNegotiatedRequestClass pins the route-boundary content negotiation:
// fileUpload carrying multipart/form-data is the multipart class; every other
// op (and a fileUpload without multipart, which the dispatcher gate refuses) is
// the JSON class.
func TestNegotiatedRequestClass(t *testing.T) {
	mp := httptest.NewRequest(http.MethodPost, restBase+"fileUpload", nil)
	mp.Header.Set("Content-Type", "multipart/form-data; boundary=abc123")
	if got := negotiatedRequestClass(OpFileUpload, mp); got != multipartContentType {
		t.Errorf("fileUpload multipart class = %q, want %q", got, multipartContentType)
	}

	jsonUpload := httptest.NewRequest(http.MethodPost, restBase+"fileUpload", nil)
	jsonUpload.Header.Set("Content-Type", "application/json")
	if got := negotiatedRequestClass(OpFileUpload, jsonUpload); got != contentTypeJSON {
		t.Errorf("fileUpload non-multipart class = %q, want %q (dispatcher gate refuses)", got, contentTypeJSON)
	}

	rd := httptest.NewRequest(http.MethodPost, restBase+"readFile", nil)
	rd.Header.Set("Content-Type", "application/json")
	if got := negotiatedRequestClass(OpReadFile, rd); got != contentTypeJSON {
		t.Errorf("readFile class = %q, want %q", got, contentTypeJSON)
	}
}
