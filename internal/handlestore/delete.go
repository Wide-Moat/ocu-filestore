// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import "context"

// var _ Store completes the interface conformance assertion here, with Delete —
// the last method of the Store interface. Keeping it in this file (not disk.go)
// lets the TASK-3 core compile before Delete exists and pins conformance the
// moment Delete lands.
var _ Store = (*DiskStore)(nil)

// Delete tombstones a file_id IFF the attested scope byte-matches the record's
// scope. It is SCOPE-BOUND exactly like Get: an absent file_id AND a cross-scope
// file_id both return ErrNotFound — the SAME sentinel — so a probe can neither
// confirm a handle's existence in another scope nor distinguish a failed delete
// from an absent one (anti-enumeration). On a scope-matching record it appends a
// del tombstone, fsyncs (fsync-before-ack, mirroring Put), and only THEN removes
// the record from the in-memory map.
//
// Replay applies the tombstone as delete(map, file_id), so a deleted handle does
// not reappear after a restart; combined with Put's last-write-wins put, the
// last op per file_id wins on replay. There is NO byte-erasure guarantee: this
// store carries no engine/byte dependency (structurally), so Delete removes the
// HANDLE, never the stored object's bytes — byte lifecycle belongs to the
// engine.
//
// The scope assertion lives HERE, below the Store seam, never in the caller. The
// canonical attested-scope source is southface.PeerScope.FilesystemID.
func (s *DiskStore) Delete(ctx context.Context, fileID, attestedScope string) error {
	if err := ctx.Err(); err != nil {
		return ErrStoreUnavailable
	}

	// Empty attested scope authorizes nothing: reject BEFORE the map lookup so
	// an empty scope can never tombstone a record — not even one persisted
	// under an empty Scope (defense-in-depth, keystone-wave followup-2; do not
	// rely only on the credscope sibling). ErrNotFound matches the
	// absent/cross-scope case (anti-enumeration).
	if attestedScope == "" {
		return ErrNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.closed {
		return ErrStoreUnavailable
	}

	rec, ok := s.recs[fileID]
	if !ok {
		// Absent: not found.
		return ErrNotFound
	}
	if rec.Scope != attestedScope {
		// Cross-scope is indistinguishable from absent: SAME sentinel, no
		// mutation. A foreign scope can neither delete nor probe the record.
		return ErrNotFound
	}

	if err := s.durableAppend(delEnvelope{Op: opDel, FileID: fileID, Scope: rec.Scope}); err != nil {
		return err
	}
	// Remove from the map AND the ref index, and mark the (scope, ref) tombstoned
	// so EnsureObject will not re-mint it on the next north-list reconcile (a
	// north-deleted object must not silently reappear). Only after the durable
	// tombstone acked.
	unindexRef(s.refIndex, s.tombstonedRefs, rec.Scope, rec.ObjectRef)
	delete(s.recs, fileID)
	return nil
}
