// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"bytes"
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
// a silent mis-walk. The handle-store cursor carries the FULL (CreatedAt,
// FileID) sort key — the same key recordLess orders on — so a resume is a strict
// tuple comparison, not a bare-FileID walk that mis-resumes against a
// CreatedAt-primary order (which repeats or strands a record on a deleted
// boundary). It is distinct from the south-face path-keyed cursor.
const cursorV1 byte = 1

// cursorFieldSep delimits the two cursor fields (CreatedAt then FileID) inside
// the encoded token. It is a NUL byte: an RFC-3339 timestamp and a 32-hex
// file_id can never contain one, so the split is unambiguous and neither field
// can forge a boundary.
const cursorFieldSep byte = 0

// ErrMalformedCursor names a cursor token that is not a base64url-decodable,
// non-empty, correctly-versioned token the store minted. The store only ever
// decodes cursors it minted (the token is opaque to callers); a malformed
// token — including a bare last_id that was never a valid cursor — is a client
// fault. It is EXPORTED so the wire layer (filesapi serveList) can classify it
// as a 400 invalid_argument (denyclass.Malformed) rather than misfiling it as a
// retryable backend-unavailable 503.
var ErrMalformedCursor = errors.New("handlestore: malformed cursor")

// encodeCursor mints an opaque keyset cursor encoding the FULL sort key
// (CreatedAt, FileID) of the last-emitted record on a page. The wire form is
// base64url(version-byte || createdAt || NUL || file_id) with no padding; the
// store emits exactly the bytes it will later decode, so the round-trip is
// byte-identical. Carrying both fields lets the resume be a strict tuple
// comparison matching recordLess, so a deleted boundary record neither repeats
// nor strands a surviving record.
func encodeCursor(afterCreatedAt, afterFileID string) string {
	buf := make([]byte, 0, 2+len(afterCreatedAt)+len(afterFileID))
	buf = append(buf, cursorV1)
	buf = append(buf, afterCreatedAt...)
	buf = append(buf, cursorFieldSep)
	buf = append(buf, afterFileID...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// decodeCursor reverses encodeCursor. An empty token is the genuine first-page
// / no-cursor case and returns ("", "", nil). A token that is not base64url-
// decodable, decodes to zero bytes, carries the wrong version byte, or lacks the
// single field separator returns ErrMalformedCursor. Otherwise it returns the
// (CreatedAt, FileID) sort key to resume strictly after.
func decodeCursor(tok string) (createdAt, fileID string, err error) {
	if tok == "" {
		return "", "", nil
	}
	b, derr := base64.RawURLEncoding.DecodeString(tok)
	if derr != nil || len(b) == 0 || b[0] != cursorV1 {
		return "", "", ErrMalformedCursor
	}
	sep := bytes.IndexByte(b[1:], cursorFieldSep)
	if sep < 0 {
		return "", "", ErrMalformedCursor
	}
	return string(b[1 : 1+sep]), string(b[1+sep+1:]), nil
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
// returns ErrMalformedCursor (the wire maps it to 400). in.Limit is clamped to
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
	afterCreatedAt, afterFileID, err := decodeCursor(in.Cursor)
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
		start = resumeIndex(matched, afterCreatedAt, afterFileID)
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
		// Mint the cursor from the FULL sort key of the last emitted record so
		// the next page resumes by a strict (CreatedAt, FileID) tuple comparison.
		boundary := page[len(page)-1]
		out.NextCursor = encodeCursor(boundary.CreatedAt, boundary.FileID)
	}
	return out, nil
}

// resumeIndex returns the index in the (CreatedAt, FileID)-sorted slice at which
// a page resuming strictly after the (afterCreatedAt, afterFileID) sort key
// should start. The cursor carries the FULL sort key of the prior page's last
// record, so the resume is a strict TUPLE comparison matching recordLess: the
// first record that sorts strictly AFTER the cursor key, i.e. the first record
// for which (CreatedAt > afterCreatedAt) OR (CreatedAt == afterCreatedAt AND
// FileID > afterFileID).
//
// Because the comparison is on the same key the order sorts by, the resume point
// is well-defined whether or not the boundary record still exists: if it was
// deleted between pages, the first record sorting after its key is exactly where
// the next page must begin — every surviving record after the boundary is
// emitted exactly once, with no repeat and no strand.
func resumeIndex(sorted []Record, afterCreatedAt, afterFileID string) int {
	for i := range sorted {
		if sortsAfter(sorted[i], afterCreatedAt, afterFileID) {
			return i
		}
	}
	return len(sorted)
}

// sortsAfter reports whether rec sorts strictly after the (createdAt, fileID)
// key under the recordLess order: ascending CreatedAt primary, ascending FileID
// tiebreak. It is the cursor-resume mirror of recordLess.
func sortsAfter(rec Record, createdAt, fileID string) bool {
	if rec.CreatedAt != createdAt {
		return rec.CreatedAt > createdAt
	}
	return rec.FileID > fileID
}
