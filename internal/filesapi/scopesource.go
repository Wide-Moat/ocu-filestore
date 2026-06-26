// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"

	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// ScopeSource derives the host-attested PeerScope for an F9 Files-API request.
// It is a narrow seam with exactly one method that reads the ratified ADR-0025
// scope-field transport: the attested filesystem_id presented as a request
// header on the trusted intra-deployment F9 channel (NFR-SEC-43 — scope is read
// from the attested channel, never from a request body). The shape is frozen
// (tracking issue #304 / ADR-0025 §Decision); the canon merge to origin/next/v1
// is owner-gated and still pending, so the binding is architect-ratified but not
// yet origin-canon-merged.
//
// Q-F9AUTH (architect ruling): the F9 HOST leg does NOT cross egress, so there
// is NO edge-injected Authorization: Bearer to read — the south credscope
// extractor is structurally WRONG here. The Web UI (component-08) has already
// done embed-token verification, the first-party session, and the three-axis
// authorization upstream (ADR-0015) before it makes this intra-deployment F9
// call; it presents the host-attested filesystem_id DIRECTLY as a scope field on
// the F9 request over the trusted intra-deployment channel. ScopeSource reads
// that field and returns PeerScope{FilesystemID}.
//
// ok=false is fail-closed: a request reaching the handler without a resolvable
// host-attested scope is a wiring fault (the F9 channel must attest one), and
// the route layer refuses it without consulting the store — no scope, no file_id
// resolution.
type ScopeSource interface {
	// Scope returns the host-attested PeerScope for r, or ok=false when the
	// request carries no resolvable attested scope (fail-closed).
	Scope(r *http.Request) (southface.PeerScope, bool)
}

// fencedScopeHeader is the request header the ScopeSource reads the host-attested
// filesystem_id from.
//
// This header IS the ADR-0025 scope-field transport (ratified in tracking issue
// #304 / ADR-0025 §Decision): on the F9 host leg the attested filesystem_id is
// carried as this request header over the trusted intra-deployment channel, and
// scope is taken from the attested channel, never from a request body
// (NFR-SEC-43). It is a wire commitment, not a throwaway placeholder; the shape
// is frozen, with the canon merge to origin/next/v1 still owner-gated and
// pending. The header name is deliberately host-attested-only: on the real F9
// host leg the trusted intra-deployment channel attests it; a guest never
// reaches this plane (Mount B is a separate listener, not the south guest path),
// so there is no guest-spoofing surface. This is NOT credscope reuse: there is no
// Bearer, no JWKS verification, no edge injection here.
const fencedScopeHeader = "X-OCU-Filesystem-Id"

// fencedGrantedIntents is the intent grant the placeholder ScopeSource stamps on
// the derived PeerScope.
//
// FENCED (pending ADR-0025): the read/delete Files-API endpoints exercise the
// read axis, so the placeholder grants read intent. The real F9 request shape
// will carry the attested intent grant from component-08's upstream
// authorization; until then this is the minimal grant the read plane needs. It
// is the broker-side Resolver that makes the actual allow/deny decision per
// request (deny-by-default), so this grant is an input to that re-derivation,
// never the decision itself.
var fencedGrantedIntents = []southface.Intent{southface.IntentRead}

// headerScopeSource is the ScopeSource that reads the ADR-0025 scope-field
// transport: it reads the host-attested filesystem_id from the fencedScopeHeader
// request header and, if present and non-empty, returns a PeerScope bound to it
// with the read intent grant. An absent or empty header is ok=false
// (fail-closed).
//
// The transport shape is ratified (tracking issue #304 / ADR-0025 §Decision);
// the canon merge to origin/next/v1 is owner-gated and still pending, so the
// binding is architect-ratified but not yet origin-canon-merged.
type headerScopeSource struct{}

// NewFencedScopeSource returns the ScopeSource Mount B wires this build: the
// reader of the ratified ADR-0025 scope-field transport (tracking issue #304),
// pending only the owner-gated canon merge to origin/next/v1.
func NewFencedScopeSource() ScopeSource { return headerScopeSource{} }

// Scope reads the host-attested filesystem_id from the fenced header and returns
// the bound PeerScope, or ok=false when the header is absent/empty (fail-closed).
// UID/PID are zero: the F9 host leg carries no kernel peer credential, exactly as
// the south REST transport carries none.
func (headerScopeSource) Scope(r *http.Request) (southface.PeerScope, bool) {
	fsid := r.Header.Get(fencedScopeHeader)
	if fsid == "" {
		return southface.PeerScope{}, false
	}
	return southface.PeerScope{
		FilesystemID:   fsid,
		GrantedIntents: fencedGrantedIntents,
	}, true
}
