// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"encoding/json"
	"net/http"
	"testing"

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
