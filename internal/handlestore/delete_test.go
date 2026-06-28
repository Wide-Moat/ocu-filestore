// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"errors"
	"testing"

	"pgregory.net/rapid"
)

// TestDeleteThenReopenGone pins durability of the tombstone: a Put then Delete,
// after a restart, leaves the file_id gone (the del replays as a map deletion).
func TestDeleteThenReopenGone(t *testing.T) {
	path, s := newTestStore(t)
	rec, err := s.Put(context.Background(), samplePut("fs-A", "a"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(context.Background(), rec.FileID, "fs-A"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewDiskStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if _, err := s2.Get(context.Background(), rec.FileID, "fs-A"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted id resolved after restart: %v, want ErrNotFound", err)
	}
}

// TestDeleteUnknownIsNotFound pins that deleting an unminted file_id is
// ErrNotFound (never a silent success).
func TestDeleteUnknownIsNotFound(t *testing.T) {
	_, s := newTestStore(t)
	if err := s.Delete(context.Background(), "never-minted", "fs-A"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(unknown) = %v, want ErrNotFound", err)
	}
}

// TestDeleteCrossScopeIsNotFound pins the scope binding: deleting a record
// under the WRONG scope is ErrNotFound — NOT a success — and the record
// survives (a foreign scope cannot delete another scope's handle).
func TestDeleteCrossScopeIsNotFound(t *testing.T) {
	_, s := newTestStore(t)
	rec, err := s.Put(context.Background(), samplePut("fs-A", "a"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(context.Background(), rec.FileID, "fs-B"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete cross-scope = %v, want ErrNotFound (not success)", err)
	}
	// The record must survive a cross-scope delete attempt.
	if _, err := s.Get(context.Background(), rec.FileID, "fs-A"); err != nil {
		t.Fatalf("record removed by a cross-scope delete: %v, want it intact", err)
	}
}

// TestDeleteCrossScopeAndUnknownSameSentinel pins anti-enumeration: a
// cross-scope delete and an unknown-id delete return the IDENTICAL sentinel —
// indistinguishable, so a probe cannot learn that a handle exists in another
// scope.
func TestDeleteCrossScopeAndUnknownSameSentinel(t *testing.T) {
	_, s := newTestStore(t)
	rec, _ := s.Put(context.Background(), samplePut("fs-A", "a"))

	cross := s.Delete(context.Background(), rec.FileID, "fs-B")
	unknown := s.Delete(context.Background(), "never-minted", "fs-B")
	if !errors.Is(cross, ErrNotFound) || !errors.Is(unknown, ErrNotFound) {
		t.Fatalf("cross=%v unknown=%v, want both ErrNotFound", cross, unknown)
	}
	if cross.Error() != unknown.Error() {
		t.Fatalf("cross-scope and unknown delete differ:\n cross=%q\n unknown=%q (must be identical)", cross.Error(), unknown.Error())
	}
}

// TestPropLastOpWins asserts replay determinism under rapid interleaved
// Put/Delete on a fixed handle set: after a restart, a file_id is present IFF
// its last applied op was a put (last-write-wins per id).
func TestPropLastOpWins(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		path := newTempLog(t)
		s, err := NewDiskStore(path)
		if err != nil {
			rt.Fatalf("NewDiskStore: %v", err)
		}

		const scope = "fs-A"
		// A fixed pool of slots; each step re-puts or deletes one slot, so a
		// file_id can be churned and the LAST op per slot decides presence.
		type slot struct {
			id      string
			present bool
		}
		slots := make([]*slot, rapid.IntRange(1, 4).Draw(rt, "slots"))
		for i := range slots {
			slots[i] = &slot{}
		}

		steps := rapid.IntRange(1, 30).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			idx := rapid.IntRange(0, len(slots)-1).Draw(rt, "slot")
			sl := slots[idx]
			if rapid.Bool().Draw(rt, "put") || sl.id == "" {
				rec, err := s.Put(context.Background(), samplePut(scope, "f"))
				if err != nil {
					rt.Fatalf("Put: %v", err)
				}
				sl.id = rec.FileID
				sl.present = true
			} else {
				if err := s.Delete(context.Background(), sl.id, scope); err != nil && !errors.Is(err, ErrNotFound) {
					rt.Fatalf("Delete: %v", err)
				}
				sl.present = false
			}
		}
		if err := s.Close(); err != nil {
			rt.Fatalf("close: %v", err)
		}

		s2, err := NewDiskStore(path)
		if err != nil {
			rt.Fatalf("reopen: %v", err)
		}
		defer s2.Close()
		for _, sl := range slots {
			if sl.id == "" {
				continue
			}
			_, err := s2.Get(context.Background(), sl.id, scope)
			if sl.present && err != nil {
				rt.Fatalf("slot id=%s should be present after replay, got %v", sl.id, err)
			}
			if !sl.present && !errors.Is(err, ErrNotFound) {
				rt.Fatalf("slot id=%s should be absent after replay, got %v", sl.id, err)
			}
		}
	})
}
