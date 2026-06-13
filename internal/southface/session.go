// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"errors"
	"sync"
)

// ErrSessionExists — a session is already provisioned for the socket path;
// a duplicate provision is a wiring mistake and fails loud, never silently
// rebinds a live channel to a different scope. Match it with errors.Is.
var ErrSessionExists = errors.New("southface: session already provisioned for socket path")

// SessionEntry is the scope binding a session-provision call establishes
// for one socket: the channel-derived identity every request on that socket
// is attributed to (NFR-SEC-43). The guest-supplied filesystem_id in a
// request body is only a hint cross-checked against this binding.
type SessionEntry struct {
	// FilesystemID is the host-attested scope bound to the socket.
	FilesystemID string
	// GrantedIntents is the exhaustive intent grant set for the session.
	GrantedIntents []Intent
}

// SessionRegistry is the in-process socket-path -> scope-binding map. The
// control plane provisions a binding before the socket serves; the listener
// reads it once per accepted connection; Release removes it at session
// teardown.
type SessionRegistry struct {
	mu      sync.RWMutex
	entries map[string]SessionEntry
}

// NewSessionRegistry returns an empty registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{entries: make(map[string]SessionEntry)}
}

// Provision binds entry to socketPath. A path that is already bound
// refuses with ErrSessionExists.
func (r *SessionRegistry) Provision(socketPath string, entry SessionEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[socketPath]; ok {
		return ErrSessionExists
	}
	r.entries[socketPath] = entry
	return nil
}

// Lookup returns the binding for socketPath, ok=false when none exists.
func (r *SessionRegistry) Lookup(socketPath string) (SessionEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[socketPath]
	return entry, ok
}

// Release removes the binding for socketPath. Releasing an unknown path is
// a no-op.
func (r *SessionRegistry) Release(socketPath string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, socketPath)
}
