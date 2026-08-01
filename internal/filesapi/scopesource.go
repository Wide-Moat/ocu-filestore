// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// ScopeSource derives the host-attested PeerScope for an F9 Files-API request.
// It is a narrow seam with exactly one method that reads the ADR-0025
// scope-field transport: the attested filesystem_id presented as a request
// header on the trusted intra-deployment F9 channel (NFR-SEC-43 — scope is read
// from the attested channel, never from a request body). The shape is
// architect-agreed (tracking issue #304 / ADR-0025 §Decision, status:proposed);
// the canon merge to origin/next/v1 is owner-gated and still pending, so the
// binding is architect-agreed-pending-canon-merge — NOT yet canon-ratified on
// origin/next/v1.
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
// This header IS the ADR-0025 scope-field transport (architect-agreed in
// tracking issue #304 / ADR-0025 §Decision, status:proposed): on the F9 host leg
// the attested filesystem_id is carried as this request header over the trusted
// intra-deployment channel, and scope is taken from the attested channel, never
// from a request body (NFR-SEC-43). It is a wire commitment, not a throwaway
// placeholder; the shape is architect-agreed, with the canon merge to
// origin/next/v1 still owner-gated and pending (so the binding is
// architect-agreed-pending-canon-merge, not yet canon-ratified). The header
// name is deliberately host-attested-only: on the real F9
// host leg the trusted intra-deployment channel attests it; a guest never
// reaches this plane (Mount B is a separate listener, not the south guest path),
// so there is no guest-spoofing surface. This is NOT credscope reuse: there is no
// Bearer, no JWKS verification, no edge injection here.
const fencedScopeHeader = "X-OCU-Filesystem-Id"

// fencedGrantedIntents is the intent grant the placeholder ScopeSource stamps on
// the derived PeerScope.
//
// FENCED (pending ADR-0025): the six served routes do NOT share one axis. Four
// are read-class — metadata, list, content and archive each Resolve with
// IntentRead.
// Two are WRITE-class: create is a content mutation and delete is a namespace
// mutation, the same split the repo's closed route-op map (southface's
// opRequiredIntent) gives createFile and removeFile. This placeholder grants
// read ONLY, so each write-class verb ADDS IntentWrite to its own evidence at
// its own call site (writeEvidenceIntents) rather than widening the grant for
// every plane. The real F9 request shape will carry the attested intent grant
// from component-08's upstream authorization; until then the grant a request
// reaches the Resolver with is this fixed read plus those two per-verb
// additions — never a per-verb grant derived from the caller.
//
// What that costs, stated here rather than left for a reader to derive: with
// this fixed grant, and against the resolver cmd/ocu-filestored actually wires,
// no Resolve call this package makes can return an error.
//
//   - Intent axis: a read verb asks read and presents read; a write verb asks
//     write and presents writeEvidenceIntents, which always contains write.
//     Satisfied by construction, on every verb.
//   - Scope axis: each handler builds ResolveRequest.Filesystem and
//     CallerEvidence.Scope from the same ps.FilesystemID, and Scope below has
//     already refused an absent or empty one, so neither the empty-scope nor the
//     request-disagrees-with-evidence branch is reachable.
//   - Downloadable axis: the shipped tag source
//     (broker.NewPrefixDownloadablePolicy) returns a nil error on every path, so
//     the resolver's fail-closed tag-error branch cannot fire either.
//
// So the resolver-error deny arms on this plane (denyList, denyDelete, and
// denyRead's authorization branch) are DEFENCE IN DEPTH against a future scope
// source, not refusals a deployment can produce today: no flag, prefix set, or
// request shape reaches them. They stay — the seams they guard (Deps.Resolver,
// Deps.Scope) are filled by composition, and the answer flips the moment the F9
// grant becomes real — but nothing should describe them as a live denial. What
// DOES refuse live on this plane is the ops/s ceiling, the keystone 404, and the
// downloadable egress gate on the two byte-emitting verbs; that gate reads
// Grant.Downloadable, a resolved VALUE, not a resolver error, and it refuses
// under the shipped prefix policy today. TestShippedGrantLeavesResolverNoAxisToFail
// pins the reachability so this paragraph cannot go stale in silence.
//
// It is still the broker-side Resolver that makes the allow/deny decision per
// request (deny-by-default); this grant is an input to that re-derivation, never
// the decision itself.
var fencedGrantedIntents = []southface.Intent{southface.IntentRead}

// validateScopeShape refuses a filesystem_id whose bytes are not a single,
// clean path element. It is the north face of ADR-0030 (open question #348): a
// COOPERATIVE shape + traversal guard, not a per-chat authorization point. The
// filesystem_id is entirely caller-supplied on this leg, so this check cannot
// (and does not) enforce which chat a caller may reach - the real per-chat
// isolation lives on the credential/south path. What it DOES enforce is that the
// value is a legal single directory element, so a scope id can never change which
// directory a downstream baseDir join resolves to.
//
// The rules mirror the storage engine's own scope-id validation (a defense in
// depth guard at the north edge, refusing a malformed scope BEFORE it reaches the
// engine): reject empty, "." / "..", any path separator or NUL, and any
// non-clean form. A shape-legal id is "<base>" or "<base>-<hex>" or any other
// single clean element; the guard does not require the chat suffix, so a plain
// scope stays backward compatible.
func validateScopeShape(id string) error {
	switch {
	case id == "" || id == "." || id == "..":
		return fmt.Errorf("filesapi: invalid scope shape: %q", id)
	case strings.ContainsAny(id, "/\\\x00"):
		return fmt.Errorf("filesapi: invalid scope shape: %q", id)
	case filepath.Clean(id) != id:
		return fmt.Errorf("filesapi: invalid scope shape: %q", id)
	}
	return nil
}

// headerScopeSource is the ScopeSource that reads the ADR-0025 scope-field
// transport: it reads the host-attested filesystem_id from the fencedScopeHeader
// request header and, if present and non-empty, returns a PeerScope bound to it
// with the read intent grant. An absent or empty header is ok=false
// (fail-closed).
//
// The transport shape is architect-agreed (tracking issue #304 / ADR-0025
// §Decision, status:proposed); the canon merge to origin/next/v1 is owner-gated
// and still pending, so the binding is architect-agreed-pending-canon-merge —
// NOT yet canon-ratified on origin/next/v1.
type headerScopeSource struct{}

// NewFencedScopeSource returns the ScopeSource Mount B wires this build: the
// reader of the architect-agreed ADR-0025 scope-field transport (tracking issue
// #304, ADR-0025 status:proposed), pending the owner-gated canon merge to
// origin/next/v1.
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
	// Shape-guard the resolved scope (ADR-0030 north face, open question #348): a
	// filesystem_id that is not a single, clean path element is refused
	// fail-closed (ok=false), so the route's existing 503 deny refuses it without
	// a scope-distinction leak. This is a cooperative shape guard, not authz.
	if validateScopeShape(fsid) != nil {
		return southface.PeerScope{}, false
	}
	return southface.PeerScope{
		FilesystemID:   fsid,
		GrantedIntents: fencedGrantedIntents,
	}, true
}
