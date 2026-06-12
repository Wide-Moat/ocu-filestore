// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"fmt"
	"testing"
)

// storeSize returns the forward/reverse record counts under the store lock.
func storeSize(s *objectIDStore) (keys, ids int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byKey), len(s.byID)
}

// uuidForPath drives a listing and returns the minted uuid of the named
// guest path ("" when absent from the listing).
func uuidForPath(t *testing.T, d *dispatcher, scope, listPath, wantPath string, recursive bool) string {
	t.Helper()
	resp := decodeList(t, serveOp(d, OpListDirectory, listBody(scope, listPath, 0, "", recursive), scope, okIntents()))
	for _, e := range resp.Entries {
		if e.File != nil && e.File.Path == wantPath {
			return e.File.UUID
		}
	}
	return ""
}

// TestObjectIDEvictOnRemoveFile pins CONC-04: removeFile evicts BOTH the
// forward and the reverse record for the removed path; a re-created object
// at the same path mints a fresh id.
func TestObjectIDEvictOnRemoveFile(t *testing.T) {
	eng := newFakeEngine()
	eng.putFile(opScope, "doomed.txt", 3)
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	id := uuidForPath(t, d, opScope, "/", "/doomed.txt", false)
	if id == "" {
		t.Fatal("listing did not mint a uuid for /doomed.txt")
	}
	if _, ok := d.ids.lookup(id); !ok {
		t.Fatal("reverse record absent before the remove")
	}

	body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/doomed.txt","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
	assertBareAck(t, serveOp(d, OpRemoveFile, body, opScope, okIntents()))

	if _, ok := d.ids.lookup(id); ok {
		t.Fatal("reverse record survives removeFile, want evicted")
	}
	if keys, ids := storeSize(d.ids); keys != 0 || ids != 0 {
		t.Fatalf("store after remove = %d keys / %d ids, want 0/0 (forward+reverse evicted)", keys, ids)
	}

	// Re-creation mints a FRESH id (identity follows the object version).
	eng.putFile(opScope, "doomed.txt", 5)
	if id2 := uuidForPath(t, d, opScope, "/", "/doomed.txt", false); id2 == "" || id2 == id {
		t.Fatalf("re-created object uuid = %q (old %q), want a fresh mint", id2, id)
	}
}

// TestObjectIDEvictOnMoveFile pins that moveFile evicts the SOURCE record
// while leaving unrelated records intact.
func TestObjectIDEvictOnMoveFile(t *testing.T) {
	eng := newFakeEngine()
	eng.putFile(opScope, "mv.txt", 3)
	eng.putFile(opScope, "stay.txt", 3)
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	mvID := uuidForPath(t, d, opScope, "/", "/mv.txt", false)
	stayID := uuidForPath(t, d, opScope, "/", "/stay.txt", false)
	if mvID == "" || stayID == "" {
		t.Fatal("listing did not mint the seed uuids")
	}

	body := fmt.Sprintf(`{"filesystem_id":%q,"source":"/mv.txt","destination":"/mv-dst.txt","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
	assertBareAck(t, serveOp(d, OpMoveFile, body, opScope, okIntents()))

	if _, ok := d.ids.lookup(mvID); ok {
		t.Fatal("moved-away source record survives moveFile, want evicted")
	}
	if _, ok := d.ids.lookup(stayID); !ok {
		t.Fatal("unrelated record was evicted by moveFile")
	}
}

// TestObjectIDEvictTreeOnRemoveDirectory pins the directory-shaped evict:
// removing a directory evicts every record under it and nothing outside it;
// moveDirectory does the same for the moved-away source subtree.
func TestObjectIDEvictTreeOnRemoveDirectory(t *testing.T) {
	eng := newFakeEngine()
	eng.putFile(opScope, "dir/a.txt", 1)
	eng.putFile(opScope, "dir/sub/b.txt", 2)
	eng.putFile(opScope, "dirx/outside.txt", 3) // shares the "dir" prefix STRING, not the path boundary
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	inA := uuidForPath(t, d, opScope, "/", "/dir/a.txt", true)
	inB := uuidForPath(t, d, opScope, "/", "/dir/sub/b.txt", true)
	out := uuidForPath(t, d, opScope, "/", "/dirx/outside.txt", true)
	if inA == "" || inB == "" || out == "" {
		t.Fatal("recursive listing did not mint the seed uuids")
	}

	body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/dir","recursive":true,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
	assertBareAck(t, serveOp(d, OpRemoveDirectory, body, opScope, okIntents()))

	if _, ok := d.ids.lookup(inA); ok {
		t.Fatal("/dir/a.txt record survives removeDirectory, want evicted")
	}
	if _, ok := d.ids.lookup(inB); ok {
		t.Fatal("/dir/sub/b.txt record survives removeDirectory, want evicted")
	}
	if _, ok := d.ids.lookup(out); !ok {
		t.Fatal("/dirx/outside.txt was evicted by a path-boundary-violating prefix match")
	}

	// moveDirectory evicts the moved-away subtree too.
	mvBody := fmt.Sprintf(`{"filesystem_id":%q,"source":"/dirx","destination":"/diry","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
	assertBareAck(t, serveOp(d, OpMoveDirectory, mvBody, opScope, okIntents()))
	if _, ok := d.ids.lookup(out); ok {
		t.Fatal("/dirx subtree record survives moveDirectory, want evicted")
	}
}

// TestObjectIDStoreBoundedAcrossMutations pins the CONC-04 growth bound: a
// long-lived session cycling create -> list -> remove over DISTINCT paths
// ends with an EMPTY store — pre-fix every cycle leaked a forward+reverse
// pair for the session's lifetime.
func TestObjectIDStoreBoundedAcrossMutations(t *testing.T) {
	eng := newFakeEngine()
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	const cycles = 50
	for i := 0; i < cycles; i++ {
		rel := fmt.Sprintf("obj-%03d.bin", i)
		eng.putFile(opScope, rel, int64(i))
		if id := uuidForPath(t, d, opScope, "/", "/"+rel, false); id == "" {
			t.Fatalf("cycle %d: listing did not mint a uuid", i)
		}
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":%q,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope, "/"+rel)
		assertBareAck(t, serveOp(d, OpRemoveFile, body, opScope, okIntents()))
	}

	if keys, ids := storeSize(d.ids); keys != 0 || ids != 0 {
		t.Fatalf("store after %d create/remove cycles = %d keys / %d ids, want 0/0 (unbounded growth)", cycles, keys, ids)
	}
}
