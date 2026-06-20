// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import "context"

// PeerScope is the host-attested session identity the dispatch spine reads at
// STAGE 0 of every request: the channel-bound filesystem scope and intent
// grant, plus the actor uid/pid for the audit record. The spine reads it from
// the request context — never from a request field — to build caller evidence
// and to cross-check the body filesystem_id (NFR-SEC-43).
//
// On the REST transport the scope is derived from the edge-injected
// Authorization: Bearer (credscope.go); the UID/PID are credential-derived or
// zero (a REST transport has no kernel peer). The struct itself is
// transport-neutral: every handler and the audit mapping read the same fields
// regardless of where the scope was attested.
type PeerScope struct {
	// FilesystemID is the host-attested scope bound to the request's credential.
	FilesystemID string
	// GrantedIntents is the exhaustive intent grant set for the request.
	GrantedIntents []Intent
	// UID is the actor uid carried into every audit record's actor, or zero
	// when the credential carries none.
	UID uint32
	// PID is the actor pid, or zero when the credential carries none.
	PID int32
}

// peerScopeKeyType is the unexported context-key type for the request-bound
// PeerScope; using a private type keeps the value unreachable from any other
// package (no key collision, no external read).
type peerScopeKeyType struct{}

var peerScopeKey peerScopeKeyType

// peerScopeFromContext returns the PeerScope stashed on the request context,
// ok=false when none is present (a handler reached without the scope binding is
// a wiring fault and fails closed).
func peerScopeFromContext(ctx context.Context) (PeerScope, bool) {
	ps, ok := ctx.Value(peerScopeKey).(PeerScope)
	return ps, ok
}

// contextWithPeerScope returns ctx carrying ps under the private key. The
// credential-scope path and any test that injects a scope use it.
func contextWithPeerScope(ctx context.Context, ps PeerScope) context.Context {
	return context.WithValue(ctx, peerScopeKey, ps)
}
