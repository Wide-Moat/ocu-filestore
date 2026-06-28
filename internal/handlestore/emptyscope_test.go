// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"errors"
	"testing"
)

// TestGetEmptyScopeRejected is the followup-2 Get leg (defense-in-depth): a Get
// with attestedScope="" returns ErrNotFound EVEN IF a record with Scope=""
// exists in the map. The reject is BEFORE the map lookup — an empty attested
// scope authorizes nothing.
//
// Mutation: removing the `if attestedScope == "" { return ErrNotFound }` guard
// makes Get("",id) resolve the empty-scope record (rec.Scope=="" byte-matches
// attestedScope=="") -> the "no record" assertion goes RED.
func TestGetEmptyScopeRejected(t *testing.T) {
	_, s := newTestStore(t)
	// A record persisted under an empty scope (Put accepts it).
	rec, err := s.Put(context.Background(), samplePut("", "ghost"))
	if err != nil {
		t.Fatalf("Put empty-scope: %v", err)
	}

	got, err := s.Get(context.Background(), rec.FileID, "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(id, attestedScope=\"\") = %v, want ErrNotFound (empty scope authorizes nothing)", err)
	}
	if got != (Record{}) {
		t.Fatalf("Get with empty attested scope leaked a record: %+v", got)
	}
}

// TestDeleteEmptyScopeRejected is the followup-2 Delete leg: a Delete with
// attestedScope="" returns ErrNotFound even if a Scope="" record exists, and
// the record is NOT tombstoned (still resolvable under its real — empty —
// scope). The guard is before the map lookup.
//
// Mutation: removing the empty-scope guard in Delete makes Delete(id,"") match
// and tombstone the empty-scope record -> the "still present" assertion RED.
func TestDeleteEmptyScopeRejected(t *testing.T) {
	_, s := newTestStore(t)
	rec, err := s.Put(context.Background(), samplePut("", "ghost"))
	if err != nil {
		t.Fatalf("Put empty-scope: %v", err)
	}

	if err := s.Delete(context.Background(), rec.FileID, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(id, attestedScope=\"\") = %v, want ErrNotFound", err)
	}

	// The record was not tombstoned: it is still in the map (verified by a
	// direct map probe, since Get with an empty scope is itself rejected).
	s.mu.Lock()
	_, present := s.recs[rec.FileID]
	s.mu.Unlock()
	if !present {
		t.Fatal("Delete with an empty attested scope tombstoned the record; the guard must reject before the map mutation")
	}
}
