// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// putAt writes a record under scope with a fixed CreatedAt by stamping the
// store clock, so a test can control the (CreatedAt, FileID) sort order.
func putAt(t *testing.T, s *DiskStore, scope, name string, created time.Time) Record {
	t.Helper()
	s.now = func() time.Time { return created }
	rec, err := s.Put(context.Background(), samplePut(scope, name))
	if err != nil {
		t.Fatalf("Put(%s,%s): %v", scope, name, err)
	}
	return rec
}

// TestListScopeConfined asserts a record under another scope NEVER appears in a
// List of a different scope. Mutation: dropping the `rec.Scope == in.Scope`
// filter in List leaks the foreign record -> this test goes RED.
func TestListScopeConfined(t *testing.T) {
	_, s := newTestStore(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mine := putAt(t, s, "fs-A", "a.txt", base)
	_ = putAt(t, s, "fs-B", "b.txt", base.Add(time.Second))

	page, err := s.List(context.Background(), ListInput{Scope: "fs-A"})
	if err != nil {
		t.Fatalf("List(fs-A): %v", err)
	}
	if len(page.Records) != 1 || page.Records[0].FileID != mine.FileID {
		t.Fatalf("List(fs-A) = %+v, want exactly the fs-A record %s", page.Records, mine.FileID)
	}
	for _, r := range page.Records {
		if r.Scope != "fs-A" {
			t.Fatalf("List(fs-A) leaked a %q-scope record: %+v", r.Scope, r)
		}
	}
}

// TestListStableTotalOrder asserts the page order is (CreatedAt, FileID) and is
// the deterministic tiebreak when CreatedAt collides. Mutation: removing the
// FileID tiebreak in recordLess makes same-CreatedAt order map-dependent -> the
// equal-timestamp ordering assertion flaps RED under -count.
func TestListStableTotalOrder(t *testing.T) {
	_, s := newTestStore(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Three at the SAME timestamp (FileID is the only tiebreak) + one later.
	a := putAt(t, s, "fs-A", "a", t0)
	b := putAt(t, s, "fs-A", "b", t0)
	c := putAt(t, s, "fs-A", "c", t0)
	d := putAt(t, s, "fs-A", "d", t0.Add(time.Hour))

	page, err := s.List(context.Background(), ListInput{Scope: "fs-A"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Records) != 4 {
		t.Fatalf("got %d records, want 4", len(page.Records))
	}
	// The three same-timestamp records sort by FileID; d (later) sorts last.
	want := []string{a.FileID, b.FileID, c.FileID}
	// Sort want by file_id to mirror the deterministic tiebreak.
	for i := 0; i < len(want); i++ {
		for j := i + 1; j < len(want); j++ {
			if want[j] < want[i] {
				want[i], want[j] = want[j], want[i]
			}
		}
	}
	want = append(want, d.FileID)
	for i, id := range want {
		if page.Records[i].FileID != id {
			t.Fatalf("record[%d] = %s, want %s (order must be (CreatedAt,FileID))", i, page.Records[i].FileID, id)
		}
	}
}

// TestListCursorRoundTripsAndPages walks every record across pages of size 1,
// asserting each page has FirstID==LastID==the single record, HasMore until the
// last page, and the union is the full set in stable order with no repeats.
// Mutation: an off-by-one resume (i instead of i+1) repeats the cursor record
// -> the no-repeat assertion goes RED.
func TestListCursorRoundTripsAndPages(t *testing.T) {
	_, s := newTestStore(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const n = 5
	for i := 0; i < n; i++ {
		putAt(t, s, "fs-A", "f", t0.Add(time.Duration(i)*time.Second))
	}

	var walked []string
	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages <= n+1; pages++ {
		page, err := s.List(context.Background(), ListInput{Scope: "fs-A", Cursor: cursor, Limit: 1})
		if err != nil {
			t.Fatalf("List page: %v", err)
		}
		if len(page.Records) == 0 {
			break
		}
		if len(page.Records) != 1 {
			t.Fatalf("Limit=1 page returned %d records", len(page.Records))
		}
		r := page.Records[0]
		if page.FirstID != r.FileID || page.LastID != r.FileID {
			t.Fatalf("single-record page bounds First=%s Last=%s want %s", page.FirstID, page.LastID, r.FileID)
		}
		if seen[r.FileID] {
			t.Fatalf("record %s repeated across pages (off-by-one resume?)", r.FileID)
		}
		seen[r.FileID] = true
		walked = append(walked, r.FileID)
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Fatalf("HasMore=false but NextCursor=%q", page.NextCursor)
			}
			cursor = ""
			break
		}
		if page.NextCursor == "" {
			t.Fatalf("HasMore=true but NextCursor empty")
		}
		cursor = page.NextCursor
	}
	if len(walked) != n {
		t.Fatalf("walked %d records across pages, want %d", len(walked), n)
	}

	// The walked order equals a single full-page List (stable order).
	full, _ := s.List(context.Background(), ListInput{Scope: "fs-A"})
	if len(full.Records) != n {
		t.Fatalf("full page = %d, want %d", len(full.Records), n)
	}
	for i, r := range full.Records {
		if walked[i] != r.FileID {
			t.Fatalf("paged order[%d]=%s != full order %s", i, walked[i], r.FileID)
		}
	}
}

// TestListMalformedCursorRejected asserts a non-mintable cursor -> errMalformed
// Cursor. Mutation: skipping the decodeCursor error return makes the garbage
// token silently page from the start -> this goes RED.
func TestListMalformedCursorRejected(t *testing.T) {
	_, s := newTestStore(t)
	putAt(t, s, "fs-A", "a", time.Now())

	bad := []string{
		"!!!not-base64!!!",
		"",  // handled below separately — empty is the genuine first page
		"A", // base64url "A" decodes to a single 0x00 byte -> wrong version
	}
	// Empty is NOT malformed (first page); test it resolves cleanly.
	if _, err := s.List(context.Background(), ListInput{Scope: "fs-A", Cursor: ""}); err != nil {
		t.Fatalf("empty cursor should be the first page, got %v", err)
	}
	for _, tok := range bad {
		if tok == "" {
			continue
		}
		_, err := s.List(context.Background(), ListInput{Scope: "fs-A", Cursor: tok})
		if !errors.Is(err, errMalformedCursor) {
			t.Fatalf("List(cursor=%q) = %v, want errMalformedCursor", tok, err)
		}
	}
}

// TestListFirstLastMatchBounds asserts FirstID/LastID equal the page's actual
// first/last record file_ids. Mutation: swapping FirstID/LastID assignment ->
// RED.
func TestListFirstLastMatchBounds(t *testing.T) {
	_, s := newTestStore(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		putAt(t, s, "fs-A", "f", t0.Add(time.Duration(i)*time.Second))
	}
	page, err := s.List(context.Background(), ListInput{Scope: "fs-A", Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if page.FirstID != page.Records[0].FileID {
		t.Fatalf("FirstID=%s, want %s", page.FirstID, page.Records[0].FileID)
	}
	if page.LastID != page.Records[len(page.Records)-1].FileID {
		t.Fatalf("LastID=%s, want %s", page.LastID, page.Records[len(page.Records)-1].FileID)
	}
}

// TestListLimitClamped asserts Limit is clamped to maxListLimit and a single
// page never exceeds it even when more records exist.
func TestListLimitClamped(t *testing.T) {
	_, s := newTestStore(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < maxListLimit+5; i++ {
		putAt(t, s, "fs-A", "f", t0.Add(time.Duration(i)*time.Second))
	}
	page, err := s.List(context.Background(), ListInput{Scope: "fs-A", Limit: maxListLimit + 1000})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Records) != maxListLimit {
		t.Fatalf("page size = %d, want clamped to %d", len(page.Records), maxListLimit)
	}
	if !page.HasMore {
		t.Fatal("HasMore=false but more than a page of records exist")
	}
}

// TestAuditObjectHandleReturnsObjectRef pins honesty-fix (a): the audit handle
// is the backend ObjectRef, NEVER the public FileID. The record is constructed
// with DISTINCT ObjectRef and FileID; a mutation returning r.FileID turns this
// RED (the assertion that the handle != FileID when they differ).
func TestAuditObjectHandleReturnsObjectRef(t *testing.T) {
	r := Record{FileID: "fid-public-1234", ObjectRef: "backend/obj/secret-9999"}
	if got := r.AuditObjectHandle(); got != r.ObjectRef {
		t.Fatalf("AuditObjectHandle() = %q, want ObjectRef %q", got, r.ObjectRef)
	}
	if r.AuditObjectHandle() == r.FileID {
		t.Fatalf("AuditObjectHandle() returned the public FileID %q; the file_id must NEVER populate object_handle (honesty-fix a)", r.FileID)
	}
}

// TestListReplayStableAcrossRestart is the rapid-style stability property: the
// List order BEFORE a Close/reopen replay equals the List order AFTER. The
// cursor walk is only stable across a restart if the (CreatedAt, FileID) order
// is replay-independent. Mutation: ordering by map/append order (no sort) makes
// the pre/post-restart orders diverge -> RED.
func TestListReplayStableAcrossRestart(t *testing.T) {
	path, s := newTestStore(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Mixed timestamps incl. collisions, two scopes interleaved.
	specs := []struct {
		scope string
		dt    time.Duration
	}{
		{"fs-A", 0}, {"fs-B", 0}, {"fs-A", 0}, {"fs-A", time.Second},
		{"fs-A", 2 * time.Second}, {"fs-B", time.Second}, {"fs-A", 2 * time.Second},
	}
	for _, sp := range specs {
		putAt(t, s, sp.scope, "f", t0.Add(sp.dt))
	}
	before, err := s.List(context.Background(), ListInput{Scope: "fs-A", Limit: maxListLimit})
	if err != nil {
		t.Fatalf("List before: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewDiskStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	after, err := s2.List(context.Background(), ListInput{Scope: "fs-A", Limit: maxListLimit})
	if err != nil {
		t.Fatalf("List after: %v", err)
	}

	if len(before.Records) != len(after.Records) {
		t.Fatalf("page size changed across restart: before=%d after=%d", len(before.Records), len(after.Records))
	}
	for i := range before.Records {
		if before.Records[i].FileID != after.Records[i].FileID {
			t.Fatalf("order diverged across restart at [%d]: before=%s after=%s", i, before.Records[i].FileID, after.Records[i].FileID)
		}
	}
}

// TestListEmptyScopeEmptyPage is the followup-2 List leg: List with Scope=""
// returns an empty page even when a record with Scope="" exists. Mutation:
// removing the empty-scope guard makes the empty-scope record leak -> RED.
func TestListEmptyScopeEmptyPage(t *testing.T) {
	_, s := newTestStore(t)
	// Persist a record under an EMPTY scope (Put does not reject it).
	if _, err := s.Put(context.Background(), samplePut("", "ghost")); err != nil {
		t.Fatalf("Put empty-scope: %v", err)
	}
	page, err := s.List(context.Background(), ListInput{Scope: ""})
	if err != nil {
		t.Fatalf("List(scope=\"\"): %v", err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("List(scope=\"\") returned %d records, want empty (empty scope authorizes nothing)", len(page.Records))
	}
}
