// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// TestCreateThenList_SurfacesContentSha256 is the D6 content-hash keystone
// (PARITY-LEDGER-147): the engine computes a SHA-256 of the bytes it writes,
// the create path threads it into the durable handle record, and the north list
// surfaces it as the FileObject `sha256` field. The upload client dedups by this
// digest, so an edited same-size file (a new digest) is re-uploaded.
//
// It wires a REAL handlestore.DiskStore so the digest survives write -> record ->
// list end to end, not against a fake that could paper over a lost field. The
// recordingEngine computes the SAME single-pass digest the real engines do, so
// the assertion is against the precomputed hex SHA-256 of the exact bytes, never
// a value the engine echoed from the request.
func TestCreateThenList_SurfacesContentSha256(t *testing.T) {
	const scope = "fs-fleet"
	const subtree = "uploads"

	eng := newFakeEngine()
	store, err := handlestore.NewDiskStore(t.TempDir() + "/handles.jsonl")
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	recEng := &recordingEngine{fakeEngine: eng}
	h := newTestHandler(Deps{
		Engine:        recEng,
		Store:         store,
		CreateSubtree: subtree,
		Resolver:      &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Scope:         fakeScope{ps: southface.PeerScope{FilesystemID: scope, GrantedIntents: []southface.Intent{southface.IntentRead, southface.IntentWrite}}, ok: true},
	})

	payload := []byte("D6 content-hash manifest payload \x00\x01\x02 edit-and-reshare")
	want := hex.EncodeToString(func() []byte { s := sha256.Sum256(payload); return s[:] }())

	// CREATE: the response FileObject carries the digest.
	createdID := createDoc(t, h, "/report.txt", payload)

	// LIST: the list FileObject surfaces the SAME digest, read from the durable
	// record (no per-object backend HEAD/tag lookup).
	list := listFiles(t, h)
	var got string
	found := false
	for _, fo := range list {
		if fo.ID == createdID {
			got = fo.Sha256
			found = true
		}
	}
	if !found {
		t.Fatalf("created file_id %q did not surface in the north list", createdID)
	}
	if got != want {
		t.Fatalf("list FileObject sha256 = %q, want the precomputed content hash %q", got, want)
	}
	if len(want) != 64 {
		t.Fatalf("precomputed hex sha256 length = %d, want 64", len(want))
	}
}

// TestOldRecordWithoutSha256_ListsCleanly_NoKey is the D6 back-compat keystone:
// a durable Record persisted BEFORE the sha256 field existed (empty Sha256)
// lists cleanly, and its marshalled JSON carries NO `sha256` key at all
// (omitempty). Clients then fall back to name+size - the designed compat window.
func TestOldRecordWithoutSha256_ListsCleanly_NoKey(t *testing.T) {
	rec := handlestore.Record{
		FileID:    "old-fid",
		Scope:     "fs-alpha",
		ObjectRef: "uploads/legacy.bin",
		Filename:  "legacy.bin",
		Mime:      "application/octet-stream",
		Size:      12,
		CreatedAt: "2026-06-01T00:00:00Z",
		// Sha256 deliberately empty: a record from before the field existed.
	}
	fo := newFileObject(rec)
	if fo.Sha256 != "" {
		t.Fatalf("newFileObject copied a non-empty sha256 %q from an old record", fo.Sha256)
	}
	raw, err := json.Marshal(fo)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "sha256") {
		t.Fatalf("old-record FileObject JSON emitted a sha256 key (want it absent via omitempty): %s", raw)
	}
	// The rest of the object still marshals - the empty digest omits ONE field,
	// it does not break the record.
	if !strings.Contains(string(raw), `"id":"old-fid"`) {
		t.Fatalf("old-record FileObject lost its id: %s", raw)
	}
}

// TestFileObject_Sha256_PresentWhenSet pins the positive marshal leg: a record
// carrying a digest emits the `sha256` key with the hex value, alongside the
// six frozen fields.
func TestFileObject_Sha256_PresentWhenSet(t *testing.T) {
	digest := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("x")); return s[:] }())
	rec := handlestore.Record{
		FileID:    "fid-1",
		Scope:     "fs-a",
		ObjectRef: "uploads/x",
		Filename:  "x",
		Mime:      "text/plain",
		Size:      1,
		CreatedAt: "2026-06-01T00:00:00Z",
		Sha256:    digest,
	}
	fo := newFileObject(rec)
	if fo.Sha256 != digest {
		t.Fatalf("newFileObject sha256 = %q, want %q", fo.Sha256, digest)
	}
	raw, _ := json.Marshal(fo)
	if !strings.Contains(string(raw), `"sha256":"`+digest+`"`) {
		t.Fatalf("FileObject JSON missing the sha256 field: %s", raw)
	}
}
