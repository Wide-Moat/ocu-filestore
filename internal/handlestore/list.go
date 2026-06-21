// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
)

// maxListLimit clamps ListInput.Limit: a caller may ask for fewer records but
// never more than this many per page, so a single List can neither exhaust
// memory nor amortize a full-scope dump into one response. A zero or negative
// Limit defaults to this value.
const maxListLimit = 100

// cursorV1 is the version prefix byte stamped on every minted handle-store
// cursor. A version byte keeps this phase's cursors distinguishable from any
// future cursor shape so a stale token decodes to a clean rejection rather than
// a silent mis-walk. The handle-store cursor is keyed on file_id (the stable
// per-record tiebreak), distinct from the south-face path-keyed cursor.
const cursorV1 byte = 1

// errMalformedCursor names a cursor token that is not a base64url-decodable,
// non-empty, correctly-versioned token the store minted. The store only ever
// decodes cursors it minted (the token is opaque to callers); a malformed
// token is a client fault the wire maps to 400. It is unexported: callers never
// branch on it directly, the wire layer maps it.
var errMalformedCursor = errors.New("handlestore: malformed cursor")

// encodeCursor mints an opaque keyset cursor encoding the file_id of the
// last-emitted record on a page. The wire form is
// base64url(version-byte || raw-file_id-bytes) with no padding; the store emits
// exactly the bytes it will later decode, so the round-trip is byte-identical.
// An empty afterFileID still mints a non-empty token (the version byte alone),
// distinct from the empty no-more-pages cursor.
func encodeCursor(afterFileID string) string {
	buf := make([]byte, 0, 1+len(afterFileID))
	buf = append(buf, cursorV1)
	buf = append(buf, afterFileID...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// decodeCursor reverses encodeCursor. An empty token is the genuine first-page
// / no-cursor case and returns ("", nil). A token that is not base64url-
// decodable, decodes to zero bytes, or carries the wrong version byte returns
// errMalformedCursor. Otherwise the bytes after the version prefix are the
// resume-after file_id (which the caller compares against the sorted order).
func decodeCursor(tok string) (string, error) {
	if tok == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(b) == 0 || b[0] != cursorV1 {
		return "", errMalformedCursor
	}
	return string(b[1:]), nil
}

// recordLess imposes the STABLE total order List pages walk: ascending
// CreatedAt, then ascending FileID as the deterministic tiebreak. FileID is the
// store's primary key (32 hex, globally unique per Put), so the order is total
// and independent of map iteration / append / replay order — two records with
// the same CreatedAt always sort the same way across a restart, which is what
// makes a cursor stable across a daemon replay.
func recordLess(a, b Record) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt < b.CreatedAt
	}
	return a.FileID < b.FileID
}

// List returns a scope-bound, opaque-cursor page of records in a STABLE total
// order. It is served from the in-memory map and works on a latched store
// (reads are never collateral-denied by a mutation-path latch).
//
// Ordering: records are sorted by (CreatedAt, FileID) with FileID the
// deterministic tiebreak, so the order is independent of map/append/replay
// order and identical across a daemon restart — a cursor minted before a
// restart resumes at the same boundary after the log is replayed.
//
// Cursoring: in.Cursor is an opaque base64url-versioned token keyed on file_id.
// An empty cursor starts at the first record; a non-empty cursor resumes
// strictly AFTER the record it names in the sorted order. A malformed cursor
// returns errMalformedCursor (the wire maps it to 400). in.Limit is clamped to
// maxListLimit; a non-positive Limit defaults to maxListLimit.
//
// Scope binding (Get's keystone, replicated): only records whose Scope
// byte-matches in.Scope appear. An empty in.Scope yields an empty page — an
// empty attested scope authorizes nothing (defense-in-depth, followup-2). A
// foreign scope yields an empty page, never another scope's records.
func (s *DiskStore) List(ctx context.Context, in ListInput) (ListPage, error) {
	// Empty attested scope authorizes nothing: do not let it resolve any
	// records (including a record persisted under an empty scope). This is the
	// List leg of the empty-scope reject; Get/Delete reject before the map
	// lookup. Decode the cursor first so a malformed cursor is still a 400 even
	// under an empty scope (a client fault is named regardless of scope).
	after, err := decodeCursor(in.Cursor)
	if err != nil {
		return ListPage{}, err
	}
	if in.Scope == "" {
		return ListPage{}, nil
	}

	limit := in.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = maxListLimit
	}

	s.mu.Lock()
	matched := make([]Record, 0, len(s.recs))
	for _, rec := range s.recs {
		if rec.Scope == in.Scope {
			matched = append(matched, rec)
		}
	}
	s.mu.Unlock()

	sort.Slice(matched, func(i, j int) bool {
		return recordLess(matched[i], matched[j])
	})

	// Resume strictly after the record the cursor names, in the FULL sorted
	// order. The cursor names the last record of the prior page; the next page
	// starts at the first record that sorts strictly after it.
	start := 0
	if in.Cursor != "" {
		start = resumeIndex(matched, after)
	}

	page := matched[start:]
	hasMore := false
	if len(page) > limit {
		page = page[:limit]
		hasMore = true
	}

	out := ListPage{Records: page}
	if len(page) > 0 {
		out.Records = append([]Record(nil), page...)
		first := page[0].FileID
		last := page[len(page)-1].FileID
		out.FirstID = first
		out.LastID = last
	}
	if hasMore {
		out.HasMore = true
		out.NextCursor = encodeCursor(out.LastID)
	}
	return out, nil
}

// resumeIndex returns the index in the (CreatedAt, FileID)-sorted slice at
// which a page resuming strictly after the record named by afterFileID should
// start. The cursor names the last record of the prior page by its globally
// unique file_id: locate that exact record and resume at the following index.
//
// If no record carries that file_id (it was deleted between pages), the walk
// must neither strand nor repeat: fall back to the first record whose file_id
// sorts strictly greater than the cursor's. Because file_id is unique and the
// boundary record is gone, this resumes at or after where the deleted record
// sat — every still-present record after the deletion boundary is emitted
// exactly once.
func resumeIndex(sorted []Record, afterFileID string) int {
	for i := range sorted {
		if sorted[i].FileID == afterFileID {
			return i + 1
		}
	}
	for i := range sorted {
		if sorted[i].FileID > afterFileID {
			return i
		}
	}
	return len(sorted)
}
