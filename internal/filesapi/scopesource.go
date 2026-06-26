// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"

	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// ScopeSource derives the host-attested PeerScope for an F9 Files-API request.
// It is a narrow seam with exactly one method so the concrete binding is a
// one-file swap when ADR-0025 freezes the F9 request shape.
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

// fencedScopeHeader is the request header the PLACEHOLDER ScopeSource reads the
// host-attested filesystem_id from.
//
// FENCED (pending ADR-0025): this header is a STRUCTURAL PLACEHOLDER standing in
// for the real F9 request scope-field. It is NOT a wire commitment — when
// ADR-0025 freezes the F9 request shape, the concrete ScopeSource binding reads
// the attested filesystem_id from that shape and this header disappears. The
// header name is deliberately host-attested-only: on the real F9 host leg the
// trusted intra-deployment channel attests it; a guest never reaches this plane
// (Mount B is a separate listener, not the south guest path), so there is no
// guest-spoofing surface. This is NOT credscope reuse: there is no Bearer, no
// JWKS verification, no edge injection here.
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

// headerScopeSource is the FENCED placeholder ScopeSource: it reads the
// host-attested filesystem_id from the fencedScopeHeader request header and, if
// present and non-empty, returns a PeerScope bound to it with the read intent
// grant. An absent or empty header is ok=false (fail-closed).
//
// FENCED (pending ADR-0025): this is a structural placeholder for the real F9
// request scope-field binding. It is narrow by design — swapping it for the
// frozen-contract reader is a one-type change.
type headerScopeSource struct{}

// NewFencedScopeSource returns the FENCED placeholder ScopeSource. It is the
// binding Mount B wires this build, pending the ADR-0025 F9 request contract.
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
