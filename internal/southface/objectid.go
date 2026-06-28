// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"strings"
	"sync"

	"github.com/Wide-Moat/ocu-filestore/internal/objectid"
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
// single id per pair. Remove/move handlers EVICT the records their mutation
// orphans (evict/evictTree below) so the store stays bounded by the live
// namespace on a long-lived session; the read path still re-validates
// (scope, path) existence at resolution time (Q5) — eviction is a memory
// bound, never the authorization.
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

// evict removes the forward AND reverse record for one (scope, path) pair,
// if present (N8/CONC-04): a removed or moved-away object's record would
// otherwise live for the whole host_local_long_lived session, growing the
// store without bound across mutations. A re-created object at the same
// path mints a FRESH id on its next observation — identity follows the
// object version, and the read path re-validates existence anyway.
func (s *objectIDStore) evict(scope, path string) {
	k := idKey{scope: scope, path: path}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byKey[k]; ok {
		delete(s.byKey, k)
		delete(s.byID, id)
	}
}

// evictTree removes every record for scope whose guest path is gp or lies
// beneath it — the directory-shaped evict for removeDirectory/moveDirectory.
// Paths are the guest convention the store is keyed by ("/" is the scope
// root and matches everything). The scan is O(store) under the write lock,
// bounded by the session's live namespace.
func (s *objectIDStore) evictTree(scope, gp string) {
	prefix := gp
	if prefix != "/" {
		prefix += "/"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, id := range s.byKey {
		if k.scope != scope {
			continue
		}
		if k.path == gp || strings.HasPrefix(k.path, prefix) {
			delete(s.byKey, k)
			delete(s.byID, id)
		}
	}
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

// newObjectID returns a 32-char lowercase hex object handle. The mint body now
// lives in the shared zero-dependency internal/objectid package so the durable
// Files-API handle store reuses the IDENTICAL shape and CSPRNG-failure contract;
// this wrapper keeps the session-scoped objectIDStore's call site and byte-shape
// unchanged. A failing kernel CSPRNG is unrecoverable — objectid.New panics.
func newObjectID() string {
	return objectid.New()
}
