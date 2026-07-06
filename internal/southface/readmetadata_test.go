// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// readMetadataBody builds a readMetadata request body.
func readMetadataBody(scope, path string) string {
	return fmt.Sprintf(
		`{"filesystem_id":%q,"path":%q,"authorization_metadata":{"intent":"read","downloadable":false}}`,
		scope, path)
}

func decodeReadMetadata(t *testing.T, w *httptest.ResponseRecorder) readMetadataResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("readMetadata status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	var resp readMetadataResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("readMetadata body not JSON: %v (%s)", err, w.Body.String())
	}
	return resp
}

// TestHandlerReadMetadataFileArm pins the read/resolve plane the guest mount
// runs on every Open: readMetadata Stats a file and returns the file arm with
// the guest-read field names and a broker-minted uuid handle. Without this the
// op is 501 and no object round-trips back through the mount.
func TestHandlerReadMetadataFileArm(t *testing.T) {
	eng := newFakeEngine()
	eng.putFile(opScope, "report.pdf", 2048)
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	w := serveOp(d, OpReadMetadata, readMetadataBody(opScope, "/report.pdf"), opScope, okIntents())
	resp := decodeReadMetadata(t, w)

	if resp.File == nil {
		t.Fatalf("readMetadata of a file returned no file arm: %s", w.Body.String())
	}
	if resp.Directory != nil {
		t.Fatalf("readMetadata of a file also set the directory arm: %+v", resp.Directory)
	}
	if resp.File.Path != "/report.pdf" {
		t.Fatalf("file path = %q, want guest-convention /report.pdf", resp.File.Path)
	}
	if resp.File.Size != 2048 {
		t.Fatalf("file size = %d, want the real Stat size 2048", resp.File.Size)
	}
	if resp.File.MTime == "" || resp.File.MIME == "" || resp.File.UUID == "" {
		t.Fatalf("file arm missing a guest-read field: %+v", resp.File)
	}
}

// TestHandlerReadMetadataDirectoryArm pins that a directory target resolves to
// the directory arm (path/mtime), NOT a not_found — unlike readFile, resolve is
// a metadata op and a directory is a first-class result.
func TestHandlerReadMetadataDirectoryArm(t *testing.T) {
	eng := newFakeEngine()
	eng.mkdirSeed(opScope, "outputs")
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	w := serveOp(d, OpReadMetadata, readMetadataBody(opScope, "/outputs"), opScope, okIntents())
	resp := decodeReadMetadata(t, w)

	if resp.Directory == nil {
		t.Fatalf("readMetadata of a directory returned no directory arm: %s", w.Body.String())
	}
	if resp.File != nil {
		t.Fatalf("readMetadata of a directory also set the file arm: %+v", resp.File)
	}
	if resp.Directory.Path != "/outputs" {
		t.Fatalf("dir path = %q, want guest-convention /outputs", resp.Directory.Path)
	}
	if resp.Directory.MTime == "" {
		t.Fatalf("directory arm missing mtime: %+v", resp.Directory)
	}
}

// TestHandlerReadMetadataAbsentIsNotFound pins the anti-enumeration keystone on
// the resolve plane: an absent path surfaces the engine's not_found (404), not a
// distinguishable oracle. The guest classifies both arms absent / 404 as
// "object not found".
func TestHandlerReadMetadataAbsentIsNotFound(t *testing.T) {
	eng := newFakeEngine()
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	w := serveOp(d, OpReadMetadata, readMetadataBody(opScope, "/nope.txt"), opScope, okIntents())
	if w.Code != http.StatusNotFound {
		t.Fatalf("readMetadata of an absent path = %d, want 404; body %s", w.Code, w.Body.String())
	}
}

// TestReadMetadataUUIDMatchesListing is the round-trip handle-consistency proof:
// the uuid readMetadata mints for a path is the SAME uuid a listDirectory of the
// parent mints for that entry. The guest resolves a handle via readMetadata and
// must reach the same object a listing named — a divergent uuid would break the
// mount's read-back.
func TestReadMetadataUUIDMatchesListing(t *testing.T) {
	eng := newFakeEngine()
	eng.putFile(opScope, "a.txt", 5)
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	// Resolve the file's uuid via readMetadata.
	rm := decodeReadMetadata(t, serveOp(d, OpReadMetadata, readMetadataBody(opScope, "/a.txt"), opScope, okIntents()))
	if rm.File == nil {
		t.Fatalf("readMetadata returned no file arm")
	}
	resolveUUID := rm.File.UUID

	// The same file listed from the root must carry the same uuid.
	list := decodeList(t, serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents()))
	var listUUID string
	for _, e := range list.Entries {
		if e.File != nil && e.File.Path == "/a.txt" {
			listUUID = e.File.UUID
		}
	}
	if listUUID == "" {
		t.Fatalf("listing did not contain /a.txt")
	}
	if resolveUUID != listUUID {
		t.Fatalf("resolve uuid %q != listing uuid %q — the mount would resolve a handle the listing never named", resolveUUID, listUUID)
	}
}
