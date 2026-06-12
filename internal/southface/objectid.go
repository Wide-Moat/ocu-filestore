// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// idKey is the forward-map key: a (scope, path) pair uniquely names an object
// within a session.
type idKey struct {
	scope string
	path  string
}

// idVal is the reverse-map value: a minted uuid resolves back to the
// (scope, path) it names. The scope is carried in the value so phase 10 can
// compare the channel scope to the record scope and refuse a cross-scope
// presentation (audited scope_mismatch, wire not_found — D8); the resolution
// check lands with the uuid axis (phase 10), the store shape is fixed here
// (D7).
type idVal struct {
	scope string
	path  string
}

// objectIDStore is the session-scoped uuid record store: it mints a
// broker-held object handle (D7) the first time a (scope, path) is observed
// in a listing and reuses it on re-observation. It keys forward by
// (scope, path) and reverse by uuid; phase 10's getFileMetadata/fileDownload
// resolve through the SAME store. The store holds no durable retention — it
// lives and dies with the session, consistent with the ephemeral-workspace
// rule.
type objectIDStore struct {
	mu    sync.RWMutex
	byKey map[idKey]string
	byID  map[string]idVal
}

// newObjectIDStore returns an empty session-scoped object-id store.
func newObjectIDStore() *objectIDStore {
	return &objectIDStore{
		byKey: make(map[idKey]string),
		byID:  make(map[string]idVal),
	}
}

// idFor returns the uuid for a (scope, path), minting one lazily on first
// observation and reusing it on every subsequent observation of the same
// pair. It takes the read lock for the fast path and the write lock with a
// re-check for the mint, so concurrent observers race-cleanly converge on a
// single id per pair. Move/remove do NOT eagerly rewrite or delete records
// this phase — phase 10 re-validates (scope, path) existence at read time
// (Q5).
func (s *objectIDStore) idFor(scope, path string) string {
	k := idKey{scope: scope, path: path}
	s.mu.RLock()
	if id, ok := s.byKey[k]; ok {
		s.mu.RUnlock()
		return id
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byKey[k]; ok { // race re-check under the write lock
		return id
	}
	id := newObjectID()
	s.byKey[k] = id
	s.byID[id] = idVal{scope: scope, path: path}
	return id
}

// lookup resolves a uuid back to its (scope, path) record for phase-10
// id->scope resolution. ok is false when the uuid was never minted by this
// session. The cross-scope DENY decision is phase 10's; this only exposes the
// stored scope so that decision is possible.
func (s *objectIDStore) lookup(uuid string) (idVal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.byID[uuid]
	return v, ok
}

// newObjectID returns a 32-char lowercase hex object handle from 16 bytes of
// crypto/rand, reusing the spine's correlation-id shape (deny.go) — no uuid
// dependency, zero new packages (CLAUDE.md minimal shelf). A failing kernel
// CSPRNG is unrecoverable — fail loud.
func newObjectID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("southface: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
