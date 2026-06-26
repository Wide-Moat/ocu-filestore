// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// keystoneHandler wires a handler whose store holds one record in a FOREIGN
// scope ("fs-other") while the attested scope is "fs-alpha", so a probe of that
// file_id is a cross-scope resolution and a probe of any other id is an absent
// resolution. Both MUST be byte-identical.
func keystoneHandler() *Handler {
	store := newFakeStore()
	store.put("fid-foreign", "fs-other", handlestore.Record{Filename: "secret", ObjectRef: "obj/secret", Size: 3})
	eng := newFakeEngine()
	eng.bytesByPath["obj/secret"] = []byte("xxx")
	return newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})
}

// stripRequestID returns the response header without the per-request x-request-id
// (which is random per call and so legitimately differs); every OTHER header
// must match for the keystone byte-identity claim.
func stripRequestID(h http.Header) http.Header {
	out := h.Clone()
	out.Del(requestIDHeader)
	return out
}

// assertByteIdentical fails unless the two recorders are byte-identical in
// status, body, and every header except the random x-request-id.
func assertByteIdentical(t *testing.T, label string, a, b *httptest.ResponseRecorder) {
	t.Helper()
	if a.Code != b.Code {
		t.Fatalf("%s: status unknown=%d cross-scope=%d, want identical", label, a.Code, b.Code)
	}
	if a.Body.String() != b.Body.String() {
		t.Fatalf("%s: bodies differ\n unknown:     %q\n cross-scope: %q", label, a.Body.String(), b.Body.String())
	}
	ha, hb := stripRequestID(a.Header()), stripRequestID(b.Header())
	if len(ha) != len(hb) {
		t.Fatalf("%s: header sets differ: unknown=%v cross-scope=%v", label, ha, hb)
	}
	for k, va := range ha {
		vb := hb[k]
		if len(va) != len(vb) {
			t.Fatalf("%s: header %q differs: unknown=%v cross-scope=%v", label, k, va, vb)
		}
		for i := range va {
			if va[i] != vb[i] {
				t.Fatalf("%s: header %q[%d]: unknown=%q cross-scope=%q", label, k, i, va[i], vb[i])
			}
		}
	}
	// No x-deny-reason on either (the keystone 404 is header-less).
	if a.Header().Get(denywire.DenyReasonHeader) != "" || b.Header().Get(denywire.DenyReasonHeader) != "" {
		t.Fatalf("%s: a keystone 404 carries x-deny-reason", label)
	}
}

// TestKeystoneByteIdentical404 is the consolidated keystone proof: on metadata,
// content, AND delete, an UNKNOWN file_id and a CROSS-SCOPE file_id produce
// byte-identical 404 responses (status, body, headers sans x-request-id), with
// no x-deny-reason on either. This is THE load-bearing anti-enumeration
// invariant — the handler is structurally incapable of distinguishing the two.
func TestKeystoneByteIdentical404(t *testing.T) {
	for _, route := range []struct {
		name           string
		method, suffix string
	}{
		{"metadata", http.MethodGet, ""},
		{"content", http.MethodGet, "/content"},
		{"delete", http.MethodDelete, ""},
	} {
		t.Run(route.name, func(t *testing.T) {
			h := keystoneHandler()
			unknown := doReq(h, route.method, "/v1/files/fid-absent"+route.suffix)
			cross := doReq(h, route.method, "/v1/files/fid-foreign"+route.suffix)

			if unknown.Code != http.StatusNotFound {
				t.Fatalf("unknown -> %d, want 404", unknown.Code)
			}
			assertByteIdentical(t, route.name, unknown, cross)
		})
	}
}

// TestKeystoneNoForbiddenOnAnyResolutionPath pins that NO file_id-resolution
// path ever returns 403: a cross-scope probe (which on a naive design would be a
// scope_mismatch 403) is a 404 on metadata, content, and delete. A 403 here
// would leak that the handle exists in another scope.
func TestKeystoneNoForbiddenOnAnyResolutionPath(t *testing.T) {
	for _, route := range []struct {
		name           string
		method, suffix string
	}{
		{"metadata", http.MethodGet, ""},
		{"content", http.MethodGet, "/content"},
		{"delete", http.MethodDelete, ""},
	} {
		t.Run(route.name, func(t *testing.T) {
			h := keystoneHandler()
			for _, id := range []string{"fid-absent", "fid-foreign"} {
				w := doReq(h, route.method, "/v1/files/"+id+route.suffix)
				if w.Code == http.StatusForbidden {
					t.Fatalf("%s %s returned 403 on a file_id-resolution path; must be 404", route.name, id)
				}
				if w.Code != http.StatusNotFound {
					t.Fatalf("%s %s -> %d, want 404", route.name, id, w.Code)
				}
			}
		})
	}
}
