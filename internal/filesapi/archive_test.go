// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// archiveSetup wires an archive handler over a store seeded with the given
// records, a fake engine holding the seeded bytes, a resolver returning the given
// grant, and the given guard. Records seeded with scope != "fs-alpha" are
// cross-scope (keystone-excluded) relative to the attested scope the handler runs
// under.
func archiveSetup(grant southface.Grant, guard *fakeGuard) (*Handler, *fakeEngine, *fakeStore) {
	store := newFakeStore()
	eng := newFakeEngine()
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Resolver: &fakeResolver{grant: grant},
		Guard:    guard,
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})
	return h, eng, store
}

// seedFile seeds an in-scope-or-cross-scope record and its bytes: a record bound
// to scope, with engine path objRef holding body.
func seedFile(store *fakeStore, eng *fakeEngine, fileID, scope, objRef, filename, body string) {
	store.put(fileID, scope, handlestore.Record{
		Filename: filename, ObjectRef: objRef, Size: int64(len(body)),
	})
	eng.bytesByPath[objRef] = []byte(body)
}

// readZipEntries opens body as a zip and returns a map of entry-name -> content.
// It fails the test if the body is not a valid zip.
func readZipEntries(t *testing.T, body []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("response body is not a valid zip: %v", err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, oerr := f.Open()
		if oerr != nil {
			t.Fatalf("open zip entry %q: %v", f.Name, oerr)
		}
		data, rerr := io.ReadAll(rc)
		_ = rc.Close()
		if rerr != nil {
			t.Fatalf("read zip entry %q: %v", f.Name, rerr)
		}
		out[f.Name] = string(data)
	}
	return out
}

// TestArchiveHappyPathStreamsZip pins the happy path: two in-scope downloadable
// files stream a 200 application/zip attachment whose body is a valid zip
// containing both files' bytes under their filenames.
func TestArchiveHappyPathStreamsZip(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, store := archiveSetup(southface.Grant{Downloadable: true}, guard)
	seedFile(store, eng, "fid-a", "fs-alpha", "obj/a", "alpha.txt", "AAA")
	seedFile(store, eng, "fid-b", "fs-alpha", "obj/b", "beta.txt", "BBBB")

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-a&file_id=fid-b")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != contentTypeZip {
		t.Fatalf("Content-Type = %q, want application/zip", ct)
	}
	cd := w.Header().Get("Content-Disposition")
	if cd == "" || !bytes.Contains([]byte(cd), []byte("attachment")) {
		t.Fatalf("Content-Disposition = %q, want an attachment disposition", cd)
	}

	entries := readZipEntries(t, w.Body.Bytes())
	if len(entries) != 2 {
		t.Fatalf("zip has %d entries, want 2: %v", len(entries), entries)
	}
	if entries["alpha.txt"] != "AAA" {
		t.Fatalf("alpha.txt = %q, want AAA", entries["alpha.txt"])
	}
	if entries["beta.txt"] != "BBBB" {
		t.Fatalf("beta.txt = %q, want BBBB", entries["beta.txt"])
	}
	// Two members, two engine reads.
	if eng.readRangeCalls != 2 {
		t.Fatalf("ReadRange called %d times, want 2", eng.readRangeCalls)
	}
	// An ALLOW audit landed for each member.
	allows := 0
	for _, e := range guard.events {
		if e.Outcome.DispositionID == auditgate.DispositionAllow && e.ActivityID == auditgate.ActivityRead {
			allows++
		}
	}
	if allows != 2 {
		t.Fatalf("recorded %d ALLOW read audits, want 2", allows)
	}
}

// TestArchiveKeystoneSilentExclusion pins the keystone: a cross-scope id in the
// requested set is SILENTLY excluded — the zip carries only the in-scope member,
// the response is a plain 200, and the cross-scope id leaks nothing (no error, no
// header difference).
func TestArchiveKeystoneSilentExclusion(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, store := archiveSetup(southface.Grant{Downloadable: true}, guard)
	seedFile(store, eng, "fid-mine", "fs-alpha", "obj/mine", "mine.txt", "MINE")
	// A record that exists but is bound to ANOTHER scope: keystone-excluded.
	seedFile(store, eng, "fid-foreign", "fs-other", "obj/foreign", "foreign.txt", "FOREIGN")

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-mine&file_id=fid-foreign")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the in-scope member resolves)", w.Code)
	}
	entries := readZipEntries(t, w.Body.Bytes())
	if len(entries) != 1 {
		t.Fatalf("zip has %d entries, want 1 (only the in-scope member): %v", len(entries), entries)
	}
	if entries["mine.txt"] != "MINE" {
		t.Fatalf("mine.txt = %q, want MINE", entries["mine.txt"])
	}
	if _, present := entries["foreign.txt"]; present {
		t.Fatal("cross-scope member leaked into the archive")
	}
	// The cross-scope id was NOT probed onto the engine: only the in-scope member
	// was read.
	if eng.readRangeCalls != 1 {
		t.Fatalf("ReadRange called %d times, want 1 (cross-scope id never read)", eng.readRangeCalls)
	}
}

// TestArchiveNoneResolveIs404 pins the anti-enumeration keystone for the
// collection verb: when NO named id resolves in scope (all cross-scope or unknown)
// the response is 404 — never 403, never a 200 empty zip.
func TestArchiveNoneResolveIs404(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, store := archiveSetup(southface.Grant{Downloadable: true}, guard)
	seedFile(store, eng, "fid-foreign", "fs-other", "obj/foreign", "foreign.txt", "FOREIGN")

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-foreign&file_id=fid-unknown")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no named id resolves in scope)", w.Code)
	}
	if w.Code == http.StatusForbidden {
		t.Fatal("none-resolve returned 403; must be the header-less keystone 404")
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("ReadRange called %d times on a none-resolve archive; want 0", eng.readRangeCalls)
	}
	// No ALLOW audit lands when nothing resolves.
	for _, e := range guard.events {
		if e.Outcome.DispositionID == auditgate.DispositionAllow {
			t.Fatal("an ALLOW audit landed when no id resolved")
		}
	}
}

// TestArchiveNonDownloadableExcluded pins that a resolvable file whose grant is
// !Downloadable is excluded from the archive — not a 403 for the whole archive.
// When it is the ONLY named id, the empty set degrades to the keystone 404.
func TestArchiveNonDownloadableExcluded(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, store := archiveSetup(southface.Grant{Downloadable: false}, guard)
	seedFile(store, eng, "fid-locked", "fs-alpha", "obj/locked", "locked.txt", "LOCKED")

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-locked")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (the only member is non-downloadable -> empty set)", w.Code)
	}
	if w.Code == http.StatusForbidden {
		t.Fatal("a non-downloadable-only archive returned 403; must degrade to the keystone 404")
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("ReadRange called %d times on a non-downloadable member; want 0", eng.readRangeCalls)
	}
}

// TestArchiveNonDownloadableExcludedFromMixedSet pins that a non-downloadable
// member is excluded from an archive that still has an accessible member: the zip
// carries only the downloadable file, at a plain 200.
func TestArchiveNonDownloadableExcludedFromMixedSet(t *testing.T) {
	guard := &fakeGuard{}
	store := newFakeStore()
	eng := newFakeEngine()
	seedFile(store, eng, "fid-ok", "fs-alpha", "obj/ok", "ok.txt", "OK")
	seedFile(store, eng, "fid-locked", "fs-alpha", "obj/locked", "locked.txt", "LOCKED")
	// The resolver returns downloadable only for the "obj/ok" path.
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Resolver: &pathGrantResolver{downloadable: map[string]bool{"obj/ok": true, "obj/locked": false}},
		Guard:    guard,
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-ok&file_id=fid-locked")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (one accessible member)", w.Code)
	}
	entries := readZipEntries(t, w.Body.Bytes())
	if len(entries) != 1 || entries["ok.txt"] != "OK" {
		t.Fatalf("entries = %v, want only ok.txt=OK", entries)
	}
	if _, present := entries["locked.txt"]; present {
		t.Fatal("non-downloadable member leaked into the mixed-set archive")
	}
}

// pathGrantResolver returns a per-path downloadable grant so a test can mix a
// downloadable and a non-downloadable member in one set.
type pathGrantResolver struct {
	downloadable map[string]bool
}

func (p *pathGrantResolver) Resolve(_ context.Context, _ any, req southface.ResolveRequest) (southface.Grant, error) {
	return southface.Grant{Downloadable: p.downloadable[req.Path]}, nil
}

// TestArchiveEmptyFileIDListIs404 pins that a request with NO file_id parameter
// resolves nothing and is the keystone 404 (never 403, never a 200 empty zip).
func TestArchiveEmptyFileIDListIs404(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, _ := archiveSetup(southface.Grant{Downloadable: true}, guard)
	w := doReq(h, http.MethodGet, "/v1/files/archive")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an empty file_id list", w.Code)
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("ReadRange called on an empty file_id list; want 0")
	}
}

// TestArchiveStoreUnavailableIs503 pins that a backend fault on Get (store
// latched -> ErrStoreUnavailable) fails the WHOLE request 503 — a backend fault
// is never a per-id skip that would hand back a partial archive.
func TestArchiveStoreUnavailableIs503(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, store := archiveSetup(southface.Grant{Downloadable: true}, guard)
	seedFile(store, eng, "fid-a", "fs-alpha", "obj/a", "a.txt", "AAA")
	store.getErr = handlestore.ErrStoreUnavailable

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-a")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (store unavailable is a backend fault, not a skip)", w.Code)
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("ReadRange called %d times on a store-unavailable archive; want 0", eng.readRangeCalls)
	}
}

// TestArchiveAuditBeforeAckAllMandatesPrecedeBytes pins audit-before-ack for the
// collection verb: EVERY member's ALLOW is Mandated BEFORE any zip byte / any
// engine read. Using the shared-trace guard+engine, all audit:allow entries must
// precede the first engine:read.
func TestArchiveAuditBeforeAckAllMandatesPrecedeBytes(t *testing.T) {
	var trace []string
	store := newFakeStore()
	base := newFakeEngine()
	seedFile(store, base, "fid-a", "fs-alpha", "obj/a", "a.txt", "AAA")
	seedFile(store, base, "fid-b", "fs-alpha", "obj/b", "b.txt", "BBB")
	eng := &tracingEngine{fakeEngine: base, trace: &trace}
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:    &orderingGuard{trace: &trace},
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-a&file_id=fid-b")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Every audit:allow must precede every engine:read (all-up-front audit).
	firstRead := -1
	lastAllow := -1
	allows := 0
	for i, e := range trace {
		switch e {
		case "audit:allow":
			allows++
			lastAllow = i
		case "engine:read":
			if firstRead == -1 {
				firstRead = i
			}
		}
	}
	if allows != 2 {
		t.Fatalf("recorded %d ALLOW audits, want 2; trace = %v", allows, trace)
	}
	if firstRead == -1 {
		t.Fatalf("no engine read ran; trace = %v", trace)
	}
	if lastAllow > firstRead {
		t.Fatalf("an ALLOW audit ran AFTER the first engine read; trace = %v", trace)
	}
}

// TestArchiveAuditDownIs503NoZipBytes pins that an ALLOW Mandate failure (audit
// down) BEFORE the 200 fails the whole request 503 with ZERO zip bytes and the
// engine never read.
func TestArchiveAuditDownIs503NoZipBytes(t *testing.T) {
	guard := &fakeGuard{err: auditgate.ErrAuditUnavailable}
	h, eng, store := archiveSetup(southface.Grant{Downloadable: true}, guard)
	seedFile(store, eng, "fid-a", "fs-alpha", "obj/a", "a.txt", "AAA")

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-a")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (audit down before 200)", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct == contentTypeZip {
		t.Fatal("application/zip Content-Type committed on an audit-down deny; want the deny JSON body")
	}
	if bytes.Contains(w.Body.Bytes(), []byte("AAA")) {
		t.Fatalf("object bytes leaked on an audit-down deny: %q", w.Body.String())
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("ReadRange called %d times after a failed allow audit; want 0", eng.readRangeCalls)
	}
}

// TestArchiveMethodNotGetIs405 pins that a non-GET method on /v1/files/archive is
// a 405 with Allow: GET — a method fault decided on the route before any store
// lookup.
func TestArchiveMethodNotGetIs405(t *testing.T) {
	h := newTestHandler(Deps{})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		w := doReq(h, method, "/v1/files/archive")
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s -> status %d, want 405", method, w.Code)
		}
		if allow := w.Header().Get("Allow"); allow != http.MethodGet {
			t.Fatalf("%s -> Allow = %q, want GET", method, allow)
		}
	}
}

// TestArchiveDuplicateFilenamesDeduped pins that two accessible members with the
// SAME filename both survive in the zip under distinct entry names, so no member
// silently overwrites another.
func TestArchiveDuplicateFilenamesDeduped(t *testing.T) {
	guard := &fakeGuard{}
	h, eng, store := archiveSetup(southface.Grant{Downloadable: true}, guard)
	seedFile(store, eng, "fid-1", "fs-alpha", "obj/1", "dup.txt", "ONE")
	seedFile(store, eng, "fid-2", "fs-alpha", "obj/2", "dup.txt", "TWO")

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-1&file_id=fid-2")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	entries := readZipEntries(t, w.Body.Bytes())
	if len(entries) != 2 {
		t.Fatalf("zip has %d entries, want 2 (both dup-named members survive): %v", len(entries), entries)
	}
	// Both bodies are present across the two distinct entry names.
	bodies := map[string]bool{}
	for _, v := range entries {
		bodies[v] = true
	}
	if !bodies["ONE"] || !bodies["TWO"] {
		t.Fatalf("deduped entries lost a member body: %v", entries)
	}
}

// TestDedupeEntryName pins the entry-name deduper directly: first-seen names
// pass through, an empty name becomes a synthetic base, a plain collision gets a
// "-N" suffix, and a suffix that itself collides with a literal member walks
// forward until it is free. No branch fabricates a path separator.
func TestDedupeEntryName(t *testing.T) {
	used := map[string]int{}
	if got := dedupeEntryName(used, "a.txt"); got != "a.txt" {
		t.Fatalf("first a.txt -> %q, want a.txt", got)
	}
	if got := dedupeEntryName(used, "a.txt"); got != "a.txt-1" {
		t.Fatalf("second a.txt -> %q, want a.txt-1", got)
	}
	if got := dedupeEntryName(used, ""); got != "file" {
		t.Fatalf("empty name -> %q, want the synthetic file", got)
	}
	// Force the secondary-collision walk: "b" and a LITERAL "b-1" are already
	// used, so a third "b" must skip "b-1" and land on "b-2".
	used2 := map[string]int{"b": 1, "b-1": 1}
	if got := dedupeEntryName(used2, "b"); got != "b-2" {
		t.Fatalf("collision walk -> %q, want b-2 (b-1 is taken)", got)
	}
	// No deduped name ever carries a path separator (no archive-root escape).
	for name := range used {
		if bytes.ContainsRune([]byte(name), '/') {
			t.Fatalf("deduped entry name %q carries a path separator", name)
		}
	}
}

// TestArchiveFDCeilingMidStreamKeeps200 pins that an fd-ceiling exhaustion
// MID-STREAM (after the 200 is committed) cannot change the status — the archive
// stream terminates at 200, it never becomes a 429.
func TestArchiveFDCeilingMidStreamKeeps200(t *testing.T) {
	guard := &fakeGuard{}
	store := newFakeStore()
	eng := newFakeEngine()
	seedFile(store, eng, "fid-a", "fs-alpha", "obj/a", "a.txt", "AAA")
	ceil := newFakeCeilings()
	ceil.sess.fdErr = southface.ErrFDExceeded
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Guard:    guard,
		Ceilings: ceil,
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-a")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fd ceiling exhausted AFTER the 200 commit)", w.Code)
	}
}
