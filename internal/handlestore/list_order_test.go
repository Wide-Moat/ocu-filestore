// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// K1 for the #182 list-order defect: the internal handlestore descending walk.
// The wire `?order=` parameter, the OpenAPI OrderQuery, and the pane request are
// the ADR-0031 wire half (owner-gated); this file covers the internal keyset
// correctness the ADR decision rests on -- the tiebreak, the direction-aware
// cursor version byte, and the provable zero-diff on the ascending default.

// TestListDescendingPage1ContainsNewestDefectShaped ties K1 to #182: seed the page
// cap plus one, with the NEWEST record created last; the descending page-1 contains
// it (so a pane requesting desc shows a just-created file), while the ascending
// page-1 does NOT (the live defect: the newest sorts past the ascending page). This
// is the exact condition #182's j8 acceptance keystone exercises, at the store.
func TestListDescendingPage1ContainsNewestDefectShaped(t *testing.T) {
	_, s := newTestStore(t)
	// maxListLimit older records, then one newest.
	for i := 0; i < maxListLimit; i++ {
		seedRec(s, fmt.Sprintf("%032x", i), "fs-K", fmt.Sprintf("2026-01-01T00:00:%02dZ", i%60))
	}
	newest := "ffffffffffffffffffffffffffffffff"
	seedRec(s, newest, "fs-K", "2026-12-31T23:59:59Z") // strictly the latest CreatedAt

	desc, err := s.List(context.Background(), ListInput{Scope: "fs-K", Order: ListOrderDesc})
	if err != nil {
		t.Fatalf("desc List: %v", err)
	}
	if len(desc.Records) == 0 || desc.Records[0].FileID != newest {
		t.Fatalf("desc page-1[0] = %v, want the newest %s on top", firstID(desc.Records), newest)
	}

	asc, err := s.List(context.Background(), ListInput{Scope: "fs-K"}) // zero Order = asc
	if err != nil {
		t.Fatalf("asc List: %v", err)
	}
	for _, r := range asc.Records {
		if r.FileID == newest {
			t.Fatalf("asc page-1 unexpectedly contained the newest record -- the "+
				"page cap is %d and the newest must sort past it (this is the #182 defect)", maxListLimit)
		}
	}
}

// TestListDescendingPage1ContainsNewestAtDefectScale is the defect-SCALE acceptance
// evidence for #182 (Fable-ruled): reproduce the exact live-observed condition -- a
// scope holding MORE than the page cap (the live fs-fleet scope held 117 objects when
// the pane went blind) -- at the store, and assert the fix. With the newest record
// created last: (1) desc page-1 CONTAINS it (so a pane sending order=desc shows a
// just-created file), and (2) asc page-1 REPRODUCES the blindness (the newest is
// absent, exactly the live pane behaviour: page-1 is the oldest maxListLimit records).
// This is the internal proof the order=desc fix resolves the pane blindness at real
// scale, standing in for the deployed-wire j8 keystone until ADR-0031 is signed.
func TestListDescendingPage1ContainsNewestAtDefectScale(t *testing.T) {
	// The live-reproduced scale: 117 objects (> maxListLimit=100). Parametrized on
	// maxListLimit+N so it tracks the cap, with N chosen to match the live count.
	const totalObjects = 117
	if totalObjects <= maxListLimit {
		t.Fatalf("test misconfigured: totalObjects %d must exceed the page cap %d to "+
			"reproduce the #182 blindness", totalObjects, maxListLimit)
	}
	_, s := newTestStore(t)
	// totalObjects-1 older records with strictly increasing CreatedAt, then the newest.
	for i := 0; i < totalObjects-1; i++ {
		// Spread CreatedAt across a wide window so the sort is unambiguous; the
		// %010d suffix keeps FileIDs 32 hex and unique.
		seedRec(s, fmt.Sprintf("%032x", i), "fs-S",
			fmt.Sprintf("2026-01-%02dT%02d:%02d:%02dZ", (i/86400)%28+1, (i/3600)%24, (i/60)%60, i%60))
	}
	newest := "ffffffffffffffffffffffffffffffff"
	seedRec(s, newest, "fs-S", "2026-12-31T23:59:59Z") // strictly the latest CreatedAt

	// (1) desc page-1 contains the newest on top (the fix).
	desc, err := s.List(context.Background(), ListInput{Scope: "fs-S", Order: ListOrderDesc})
	if err != nil {
		t.Fatalf("desc List: %v", err)
	}
	if len(desc.Records) != maxListLimit {
		t.Fatalf("desc page-1 len = %d, want the full page cap %d at %d objects",
			len(desc.Records), maxListLimit, totalObjects)
	}
	if desc.Records[0].FileID != newest {
		t.Fatalf("desc page-1[0] = %v, want the newest %s on top at %d-object scale "+
			"(this is the order=desc fix that unblinds the pane)", firstID(desc.Records), newest, totalObjects)
	}

	// (2) asc page-1 reproduces the live blindness: the newest is NOT on page-1.
	asc, err := s.List(context.Background(), ListInput{Scope: "fs-S"}) // zero Order = asc
	if err != nil {
		t.Fatalf("asc List: %v", err)
	}
	if len(asc.Records) != maxListLimit {
		t.Fatalf("asc page-1 len = %d, want the full page cap %d", len(asc.Records), maxListLimit)
	}
	for _, r := range asc.Records {
		if r.FileID == newest {
			t.Fatalf("asc page-1 unexpectedly contained the newest at %d objects -- the "+
				"live #182 defect is that it must NOT (page-1 is the oldest %d records)",
				totalObjects, maxListLimit)
		}
	}
}

// TestListDescendingFileIDTiebreak asserts equal-CreatedAt records order by
// DESCENDING FileID under desc (the mirror of the ascending tiebreak). A drift here
// makes same-timestamp order map-dependent under -count.
func TestListDescendingFileIDTiebreak(t *testing.T) {
	_, s := newTestStore(t)
	const t0 = "2026-01-01T00:00:00Z"
	a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	c := "cccccccccccccccccccccccccccccccc"
	seedRec(s, a, "fs-K", t0)
	seedRec(s, b, "fs-K", t0)
	seedRec(s, c, "fs-K", t0)

	page, err := s.List(context.Background(), ListInput{Scope: "fs-K", Order: ListOrderDesc})
	if err != nil {
		t.Fatalf("desc List: %v", err)
	}
	want := []string{c, b, a} // same timestamp -> descending FileID
	if len(page.Records) != 3 {
		t.Fatalf("got %d records, want 3", len(page.Records))
	}
	for i, id := range want {
		if page.Records[i].FileID != id {
			t.Fatalf("desc tiebreak record[%d] = %s, want %s (descending FileID on equal CreatedAt)", i, page.Records[i].FileID, id)
		}
	}
}

// TestListDescendingWalkReversesAscending asserts a full descending cursor walk is
// the element-wise REVERSE of the ascending walk (stronger than a set union), with
// no duplicate and no strand -- including across a deleted boundary record mid-walk,
// matching the ascending exactly-once guarantee.
func TestListDescendingWalkReversesAscending(t *testing.T) {
	_, s := newTestStore(t)
	ids := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("%032x", i)
		ids = append(ids, id)
		seedRec(s, id, "fs-K", fmt.Sprintf("2026-01-01T00:00:0%dZ", i))
	}
	// The ascending order is ids[0..4]; the descending order must be its reverse.
	wantDesc := []string{ids[4], ids[3], ids[2], ids[1], ids[0]}

	got := walkAll(t, s, ListOrderDesc, 2)
	if len(got) != len(wantDesc) {
		t.Fatalf("desc walk returned %d records, want %d: %v", len(got), len(wantDesc), got)
	}
	for i := range wantDesc {
		if got[i] != wantDesc[i] {
			t.Fatalf("desc walk[%d] = %s, want %s (element-wise reverse of asc)", i, got[i], wantDesc[i])
		}
	}

	// Deleted-boundary mid-walk: delete the record the page-1 cursor names, then
	// resume; every surviving record after it appears exactly once, none repeats.
	_, s2 := newTestStore(t)
	for i := 0; i < 5; i++ {
		seedRec(s2, fmt.Sprintf("%032x", i), "fs-K", fmt.Sprintf("2026-01-01T00:00:0%dZ", i))
	}
	p1, _ := s2.List(context.Background(), ListInput{Scope: "fs-K", Order: ListOrderDesc, Limit: 2})
	if !p1.HasMore || p1.NextCursor == "" {
		t.Fatalf("desc page1 HasMore=%v cursor=%q, want a continuation", p1.HasMore, p1.NextCursor)
	}
	boundary := p1.Records[len(p1.Records)-1].FileID
	s2.mu.Lock()
	delete(s2.recs, boundary)
	s2.mu.Unlock()
	rest := walkFrom(t, s2, ListOrderDesc, p1.NextCursor, 2)
	seen := map[string]int{}
	for _, r := range p1.Records {
		seen[r.FileID]++
	}
	for _, id := range rest {
		seen[id]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("record %s appeared %d times across the deleted-boundary desc walk, want exactly 1", id, n)
		}
	}
}

// TestListCursorDirectionMismatchRejected asserts a cursor minted under one order
// is ErrMalformedCursor under the other: a v1 (asc) token replayed with Order desc,
// and a v2 (desc) token replayed with Order asc. This is the fail-closed guard that
// a mis-directed resume cannot silently mis-walk.
func TestListCursorDirectionMismatchRejected(t *testing.T) {
	_, s := newTestStore(t)
	for i := 0; i < 4; i++ {
		seedRec(s, fmt.Sprintf("%032x", i), "fs-K", fmt.Sprintf("2026-01-01T00:00:0%dZ", i))
	}
	ascP1, _ := s.List(context.Background(), ListInput{Scope: "fs-K", Limit: 2})
	descP1, _ := s.List(context.Background(), ListInput{Scope: "fs-K", Order: ListOrderDesc, Limit: 2})
	if ascP1.NextCursor == "" || descP1.NextCursor == "" {
		t.Fatalf("need both cursors: asc=%q desc=%q", ascP1.NextCursor, descP1.NextCursor)
	}

	if _, err := s.List(context.Background(), ListInput{Scope: "fs-K", Order: ListOrderDesc, Cursor: ascP1.NextCursor}); !errors.Is(err, ErrMalformedCursor) {
		t.Fatalf("v1(asc) cursor under Order desc -> err=%v, want ErrMalformedCursor", err)
	}
	if _, err := s.List(context.Background(), ListInput{Scope: "fs-K", Cursor: descP1.NextCursor}); !errors.Is(err, ErrMalformedCursor) {
		t.Fatalf("v2(desc) cursor under Order asc -> err=%v, want ErrMalformedCursor", err)
	}
}

// TestListAscendingZeroDiffGolden pins that the ascending default is byte-identical
// to the pre-change behaviour: {Scope} with no Order yields a page and a NextCursor
// whose bytes equal the golden minted from HEAD before the Order field existed. If
// the zero-value default ever flips to desc, or the asc cursor bytes change, this
// reds -- proving default-asc is test-pinned, not accidental.
func TestListAscendingZeroDiffGolden(t *testing.T) {
	_, s := newTestStore(t)
	seedRec(s, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", "fs-G", "2026-01-01T00:00:01Z")
	seedRec(s, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2", "fs-G", "2026-01-01T00:00:02Z")

	page, err := s.List(context.Background(), ListInput{Scope: "fs-G", Limit: 1})
	if err != nil {
		t.Fatalf("asc List: %v", err)
	}
	// Golden minted from clean HEAD (list.go/handlestore.go pristine) before the
	// Order field was added: v1 byte + t1 + NUL + r1 file_id.
	const goldenAscCursor = "ATIwMjYtMDEtMDFUMDA6MDA6MDFaAGFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEx"
	if page.NextCursor != goldenAscCursor {
		t.Fatalf("asc NextCursor = %q, want the golden %q (asc must be byte-identical; a "+
			"default flip to desc or a cursor-byte change breaks this)", page.NextCursor, goldenAscCursor)
	}
	if len(page.Records) != 1 || page.Records[0].FileID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1" {
		t.Fatalf("asc page-1 = %v, want the OLDEST record on top", firstID(page.Records))
	}
}

// walkAll follows a cursor from the first page to the last, returning every FileID
// in walk order.
func walkAll(t *testing.T, s *DiskStore, order ListOrder, limit int) []string {
	t.Helper()
	return walkFrom(t, s, order, "", limit)
}

// walkFrom resumes a walk from an existing cursor to the last page.
func walkFrom(t *testing.T, s *DiskStore, order ListOrder, cursor string, limit int) []string {
	t.Helper()
	out := []string{}
	for i := 0; i < 128; i++ {
		p, err := s.List(context.Background(), ListInput{Scope: "fs-K", Order: order, Cursor: cursor, Limit: limit})
		if err != nil {
			t.Fatalf("walk List: %v", err)
		}
		for _, r := range p.Records {
			out = append(out, r.FileID)
		}
		if !p.HasMore || p.NextCursor == "" {
			return out
		}
		cursor = p.NextCursor
	}
	t.Fatalf("walk exceeded page budget")
	return out
}

// firstID projects the first record's FileID for readable failures.
func firstID(recs []Record) string {
	if len(recs) == 0 {
		return "<empty>"
	}
	return recs[0].FileID
}
