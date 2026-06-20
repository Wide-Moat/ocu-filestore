// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"errors"
	"net/http"
	"strings"
)

// PENDING-PHASE-7(A5-credscope): the service receives ONLY the edge-injected
// real credential on Authorization: Bearer (never the guest weak JWT). It
// forwards that bearer to the engine unmodified; the engine enforces the
// filesystem_id scope on it — 403 on a foreign filesystem_id, 401 on a
// missing/expired credential — per the credential authority's contract. The
// scope check sits at the SERVICE/ROUTE layer feeding a thin engine (OQ-2
// option c). It does NOT JWKS-verify the bearer: the edge owns weak-JWT
// validation and has already validated+stripped the guest session JWT before
// injecting the real credential. Component-04 mints/signs nothing (invariant 3).
// Sibling-proven, frozen pending #292 — flips to "frozen @ canon-rev <sha>".
//
// This file is the credential-scope source: it replaces the unix-socket
// peer-cred PeerScope as the per-request host-attested-scope origin. It
// populates the SAME PeerScope struct the dispatch spine's STAGE-0
// peerScopeFromContext already reads and stashes it via the SAME
// contextWithPeerScope helper, so the dispatch spine and all seven handler
// algorithms compile and run unchanged. Only the SOURCE of the scope changes:
// kernel SO_PEERCRED becomes the edge-injected bearer. The UID/PID fields are
// credential-derived-or-zero (the kernel peer no longer exists on a REST
// transport); the audit actor reads whatever the extractor supplies.

// errMissingBearer — the request carried no usable Authorization: Bearer
// credential (header absent, wrong scheme, or an empty token after the scheme).
// The edge injects this credential on every admitted request, so its absence is
// an unauthenticated request: it maps to the lease-expired/unauthenticated deny
// class (401). Match it with errors.Is.
var errMissingBearer = errors.New("southface: missing or malformed Authorization: Bearer credential")

// authHeaderName is the only credential-bearing header the service reads: the
// edge injects the real credential here on every admitted request.
const authHeaderName = "Authorization"

// bearerScheme is the literal Authorization scheme prefix — "Bearer " (capital
// B, single trailing space) — followed by the injected real credential
// verbatim. The credential after the scheme is opaque and case-sensitive.
const bearerScheme = "Bearer "

// errCredentialRejected — the extractor could not derive a credential-bound
// filesystem scope from an otherwise-present bearer (an expired or
// authority-rejected credential). It maps to the same lease-expired/
// unauthenticated deny class (401) as a missing bearer: the broker cannot
// attribute the request to a scope, so it never reaches a handler. Match it
// with errors.Is.
var errCredentialRejected = errors.New("southface: credential rejected by the scope authority")

// CredentialScope is the credential-bound identity an extractor derives from
// the edge-injected bearer: the filesystem scope the credential authority bound
// the credential to, and the intent grant set it carries. It is the
// transport-neutral analogue of the unix SessionEntry — the host-attested
// binding a request is authorized against — sourced from the bearer rather than
// from a per-socket provision.
type CredentialScope struct {
	// FilesystemID is the scope the credential authority bound the injected
	// credential to. The request's top-level filesystem_id is cross-checked
	// against THIS value; a mismatch is a scope deny (403).
	FilesystemID string
	// GrantedIntents is the exhaustive intent grant set the credential carries.
	// An absent intent is denied by the resolver regardless of other fields.
	GrantedIntents []Intent
	// UID is the credential-derived actor uid for the audit record, or zero
	// when the credential carries none (a REST transport has no kernel peer).
	UID uint32
	// PID is the credential-derived actor pid for the audit record, or zero
	// when the credential carries none.
	PID int32
}

// CredentialScopeExtractor derives the credential-bound scope from the
// edge-injected bearer token. It is the swappable seam that isolates the exact
// injected-credential SHAPE — which is the credential authority's contract and
// is unpinned — from the structural scope-enforcement flow (read bearer ->
// derive bound fsid -> compare to request fsid -> 403/401), which is testable
// now.
//
// PENDING-PHASE-7(A5-credscope): the production extractor binds to the
// credential authority's contract for how the bound filesystem_id and the
// intent grant are carried on the injected credential. It does NOT JWKS-verify
// the bearer (the edge owns weak-JWT validation); it reads the authority's
// already-validated injected credential. No issuer/audience/alg is hardcoded
// here — those, if any, belong to the authority's contract and bind later.
//
// Extract returns the derived scope, or an error: errCredentialRejected when a
// present-but-unusable credential cannot be bound to a scope (expired/rejected),
// which the caller maps to 401. A return with an empty FilesystemID is treated
// as a rejection (no scope to enforce against), never as a wildcard.
type CredentialScopeExtractor interface {
	Extract(bearer string) (CredentialScope, error)
}

// bearerScopeExtractor is the default CredentialScopeExtractor: a clean seam
// implementation that lets the structural scope-enforcement flow be tested now
// while the exact injected-credential shape binds later. It carries no jwt/jwks
// dependency and verifies no signature — that is intentionally NOT this layer's
// job (the edge validated the weak JWT; the engine/service enforce only the
// authority's scope).
//
// PENDING-PHASE-7(A5-credscope): the bind function maps a verbatim bearer
// string to its credential-bound scope. The default bind is a structural
// placeholder, swapped for the authority's real extractor when the
// injected-credential contract pins; the daemon wiring injects the production
// bind. The default treats the bearer as the verbatim credential the authority
// issued and asks bind to return its bound scope; an empty result is a
// rejection. No issuer/audience/alg is assumed.
type bearerScopeExtractor struct {
	// bind maps a non-empty bearer token to its credential-bound scope. A nil
	// bind, or a bind returning an empty FilesystemID / a non-nil error, is a
	// rejection (the request cannot be attributed to a scope).
	bind func(bearer string) (CredentialScope, error)
}

// Extract derives the credential-bound scope from a non-empty bearer string. A
// nil bind, a bind error, or a bound scope with an empty FilesystemID is a
// rejection (errCredentialRejected) — the request cannot be attributed to a
// scope and is denied before any handler. The caller has already stripped the
// "Bearer " scheme and rejected an empty token, so a present-but-unbindable
// credential is the only failure this layer reports.
func (e bearerScopeExtractor) Extract(bearer string) (CredentialScope, error) {
	if e.bind == nil {
		return CredentialScope{}, errCredentialRejected
	}
	scope, err := e.bind(bearer)
	if err != nil {
		return CredentialScope{}, errCredentialRejected
	}
	if scope.FilesystemID == "" {
		return CredentialScope{}, errCredentialRejected
	}
	return scope, nil
}

// newBearerScopeExtractor returns the default extractor over bind. The daemon
// wiring supplies the production bind (the credential authority's contract);
// tests supply a fake. A nil bind yields an extractor that rejects every
// credential — an unwired credential source fails CLOSED.
func newBearerScopeExtractor(bind func(bearer string) (CredentialScope, error)) bearerScopeExtractor {
	return bearerScopeExtractor{bind: bind}
}

// bearerFromRequest extracts the verbatim credential from the request's
// Authorization header, stripping the "Bearer " scheme. It returns
// errMissingBearer when the header is absent, carries a different scheme, or
// leaves an empty token after the scheme. The scheme match is
// case-insensitive on the scheme word only; the token after the single space
// is returned verbatim (a credential is opaque and case-sensitive).
func bearerFromRequest(r *http.Request) (string, error) {
	h := r.Header.Get(authHeaderName)
	if h == "" {
		return "", errMissingBearer
	}
	// The scheme is the literal "Bearer " (one trailing space) per the wire
	// surface; match the scheme word case-insensitively and take the remainder
	// verbatim. A header that is only the scheme word (no token) is missing a
	// credential.
	const scheme = "Bearer"
	if len(h) <= len(scheme)+1 || !strings.EqualFold(h[:len(scheme)], scheme) || h[len(scheme)] != ' ' {
		return "", errMissingBearer
	}
	token := h[len(scheme)+1:]
	if strings.TrimSpace(token) == "" {
		return "", errMissingBearer
	}
	return token, nil
}

// deriveCredScope is the A5 credential-scope check at the SERVICE/ROUTE layer.
// It reads the edge-injected Authorization: Bearer, derives the
// credential-bound filesystem scope via the extractor, and enforces that the
// request's top-level filesystem_id matches the credential-bound scope. On
// success it returns the PeerScope the dispatch spine reads from context
// (FilesystemID + GrantedIntents drive authz; UID/PID feed the audit actor).
//
// PENDING-PHASE-7(A5-credscope): the scope-check flow is read bearer -> derive
// bound fsid -> compare to the request fsid -> allow / 403 / 401. It does NOT
// JWKS-verify the bearer. The deny mapping reuses the SURVIVING deny vocabulary
// — no new classes:
//
//   - a missing/malformed/expired/rejected bearer -> denyLeaseExpired
//     (unauthenticated, 401): the broker cannot attribute the request to any
//     scope.
//   - a request filesystem_id that does NOT match the credential-bound scope ->
//     denyScopeMismatch (permission_denied, 403). The wire MAY degrade this to
//     404 for anti-enumeration exactly as deny.go classes scope_mismatch
//     elsewhere — that degrade is applied by the caller's deny writer, not here;
//     this function names the broker-resolved TRUTH (scope_mismatch).
//
// ok=false carries the DenyVerdict the route layer writes; ok=true carries the
// PeerScope to stash via contextWithPeerScope. requestFsid is the top-level
// filesystem_id from the request body (A4: a sibling of authorization_metadata,
// never nested) — the route layer decodes it before calling here.
func deriveCredScope(r *http.Request, extractor CredentialScopeExtractor, requestFsid string) (PeerScope, DenyVerdict, bool) {
	bearer, err := bearerFromRequest(r)
	if err != nil {
		// No usable credential: unauthenticated. The wire is 401
		// (lease_expired -> unauthenticated) and carries no scope.
		return PeerScope{}, mapDeny(denyLeaseExpired), false
	}

	// PENDING-PHASE-7(A5-credscope): derive the credential-bound scope from the
	// injected bearer WITHOUT JWKS-verifying it — the extractor binds to the
	// authority's contract, which is unpinned. A rejected credential is treated
	// as unauthenticated (401), the same class as a missing bearer: the broker
	// has no scope to attribute the request to.
	scope, err := extractor.Extract(bearer)
	if err != nil {
		return PeerScope{}, mapDeny(denyLeaseExpired), false
	}

	// PENDING-PHASE-7(A5-credscope): scope enforcement at the route layer. The
	// request's top-level filesystem_id is an untrusted hint; a value that
	// disagrees with the credential-bound scope is a scope_mismatch deny
	// (permission_denied, 403). This MIRRORS the unix-transport STAGE-1b
	// channel-scope cross-check (env.FilesystemID != ps.FilesystemID) — the only
	// change is the source of the authoritative scope (the credential, not the
	// socket binding). The wire may anti-enumeration-degrade to 404 per the deny
	// table; the audited truth named here stays scope_mismatch.
	if requestFsid != scope.FilesystemID {
		return PeerScope{}, mapDeny(denyScopeMismatch), false
	}

	// The credential-bound scope is authoritative: build the PeerScope the
	// dispatch spine reads. GrantedIntents come from the credential, never from
	// a request field. UID/PID are credential-derived-or-zero.
	return PeerScope{
		FilesystemID:   scope.FilesystemID,
		GrantedIntents: scope.GrantedIntents,
		UID:            scope.UID,
		PID:            scope.PID,
	}, DenyVerdict{}, true
}
