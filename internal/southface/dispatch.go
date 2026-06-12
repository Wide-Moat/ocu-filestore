// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"net/http"
)

// connectError is the Connect unary error body: a Connect code and a human
// message. details are omitted in this build (the contract leaves them
// optional).
type connectError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeConnectError writes a Connect error response from a DenyVerdict: the
// derived HTTP status, the application/json body, and — only when the verdict
// gates it (permission_denied / unauthenticated, n3) — the x-deny-reason
// header carrying the audited truth. It is the single response path for every
// refusal the spine produces.
func writeConnectError(w http.ResponseWriter, v DenyVerdict, message string) {
	if v.WireHeader {
		w.Header().Set("x-deny-reason", v.AuditReason)
	}
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(v.WireStatus)
	_ = json.NewEncoder(w).Encode(connectError{Code: v.WireCode, Message: message})
}

// dispatcher is the south-face http.Handler: it runs the LOCKED fail-closed
// pipeline for every accepted request and routes the cleared request to the
// per-op handler. The seam dependencies (resolver, guard, ceilings) are
// injected so tests drive fakes and the composition phase binds the real
// packages.
type dispatcher struct {
	resolver Resolver
	guard    Guard
	ceilings CeilingsRegistry
	registry map[Op]opHandler
	// sizeCeiling is the per-request declared/streamed body ceiling
	// (NFR-SEC-78), applied pre-buffer on the Content-Length and as the
	// MaxBytesReader backstop.
	sizeCeiling int64
}

// newDispatcher builds a dispatcher with the default-unimplemented registry
// and the injected seams.
func newDispatcher(resolver Resolver, guard Guard, ceilings CeilingsRegistry, sizeCeiling int64) *dispatcher {
	return &dispatcher{
		resolver:    resolver,
		guard:       guard,
		ceilings:    ceilings,
		registry:    newHandlerRegistry(),
		sizeCeiling: sizeCeiling,
	}
}

// ServeHTTP runs the LOCKED pipeline. The order is load-bearing and must not
// be reordered:
//
//	STAGE 0 header gate (NO body byte read): route -> version -> Content-Type
//	  -> PeerScope from context -> declared-size pre-buffer on Content-Length
//	  -> ops/s throttle keyed on the CHANNEL scope (never the body)
//	STAGE 1 strict envelope decode (through the MaxBytesReader backstop)
//	STAGE 1b channel-scope cross-check on the DECODED body (D2)
//	STAGE 2 authz (Resolver.Resolve with caller evidence from the channel)
//	STAGE 3 audit Mandate BEFORE any 2xx (NFR-SEC-79)
//	STAGE 4 registry[op] (all unimplemented in this build)
//
// Every refusal flows through the deny.go mapper — one source of truth.
func (d *dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// STAGE 0: route. A non-POST to a valid-shaped route is a 405; an
	// unknown route or version/content-type fault is invalid_argument. No
	// body byte is read in this stage (SEC-76/78).
	op, err := parseRoute(r.Method, r.URL.Path)
	if err != nil {
		if err == errBadMethod {
			w.Header().Set("Allow", http.MethodPost)
			writeConnectError(w, mapDeny(denyMalformed).withStatus(http.StatusMethodNotAllowed), "method not allowed")
			return
		}
		writeConnectError(w, mapDeny(denyClassForDecodeErr(err)), "unknown route")
		return
	}

	// STAGE 0: version header (D1).
	if err := checkVersion(r); err != nil {
		writeConnectError(w, mapDeny(denyClassForDecodeErr(err)), "missing or wrong Connect-Protocol-Version")
		return
	}

	// STAGE 0: Content-Type.
	if err := checkContentType(r); err != nil {
		writeConnectError(w, mapDeny(denyClassForDecodeErr(err)), "Content-Type must be application/json")
		return
	}

	// STAGE 0: PeerScope from the connection context — the host-attested
	// channel identity. Its absence is a wiring fault: fail closed.
	ps, ok := peerScopeFromContext(r.Context())
	if !ok {
		writeConnectError(w, mapDeny(denyInternal), "no channel scope on connection")
		return
	}

	// STAGE 0: declared-size pre-buffer on the Content-Length (SEC-78). A
	// unary request carries a known-size body; an absent Content-Length is
	// refused before any body byte is read. An over-ceiling length is a size
	// deny.
	cl := r.ContentLength
	if cl < 0 {
		writeConnectError(w, mapDeny(denyMalformed), "unary request requires Content-Length")
		return
	}
	if cl > d.sizeCeiling {
		writeConnectError(w, mapDeny(denySizeExceeded), "declared body size exceeds ceiling")
		return
	}

	// STAGE 0: ops/s throttle, keyed on the CHANNEL scope (PeerScope), never
	// on any body field — nothing trusts the body before STAGE 1b. A throttle
	// is resource_exhausted with NO x-deny-reason (n3).
	sess := d.ceilings.Session(ps.FilesystemID)
	if err := sess.TryConsumeOp(); err != nil {
		writeConnectError(w, mapDeny(denyClassForErr(err)), "operation rate ceiling exceeded")
		return
	}

	// STAGE 1: strict envelope decode through the MaxBytesReader backstop.
	var env unaryEnvelope
	if err := decodeUnaryEnvelope(w, r, d.sizeCeiling, &env); err != nil {
		writeConnectError(w, mapDeny(denyClassForDecodeErr(err)), "malformed request envelope")
		return
	}

	// STAGE 1b: channel-scope cross-check on the DECODED body. The body
	// filesystem_id is an untrusted hint; a value that disagrees with the
	// channel-bound scope is a scope_mismatch deny (permission_denied +
	// x-deny-reason), and the handler is never reached (D2/NFR-SEC-43).
	if env.FilesystemID != ps.FilesystemID {
		writeConnectError(w, mapDeny(denyScopeMismatch), "request scope does not match the session channel")
		return
	}

	// STAGE 1b: route-vs-envelope op cross-check is implicit — the body
	// carries no op field in this build; the route op is authoritative and
	// the body scope/intent are the only cross-checked fields.

	// STAGE 2: authz. Caller evidence is built from the channel scope, never
	// from a request field. Deny sentinels map through the D4 table with the
	// header gated to authorization verdicts.
	evidence := CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: ps.GrantedIntents}
	req := ResolveRequest{
		Filesystem: env.FilesystemID,
		Path:       env.Path,
		Intent:     env.AuthorizationMetadata.Intent,
	}
	if _, err := d.resolver.Resolve(r.Context(), evidence, req); err != nil {
		writeConnectError(w, mapDeny(denyClassForErr(err)), "authorization denied")
		return
	}

	// STAGE 3: audit Mandate BEFORE any 2xx (NFR-SEC-79). The event carries
	// the broker-resolved truth; an unavailable audit gate denies the
	// operation and the handler is never invoked. No x-deny-reason on an
	// audit-down verdict (n3).
	if err := d.guard.Mandate(r.Context(), d.auditEvent(op, ps, req)); err != nil {
		writeConnectError(w, mapDeny(denyClassForErr(err)), "audit gate unavailable")
		return
	}

	// STAGE 4: the per-op handler. Every op is registered; all return Connect
	// unimplemented in this build. A route op absent from the registry is a
	// wiring fault and fails closed.
	h, ok := d.registry[op]
	if !ok {
		writeConnectError(w, mapDeny(denyUnimplemented), "operation not registered")
		return
	}
	h(w, r)
}

// auditEvent builds the broker-resolved-truth audit event for an operation.
// The concrete event encoding is the audit gate's (frozen on its branch); the
// spine passes an opaque value through the Guard.Mandate seam exactly as the
// real gate consumes it.
func (d *dispatcher) auditEvent(op Op, ps PeerScope, req ResolveRequest) auditEvent {
	return auditEvent{
		Op:         op,
		Scope:      ps.FilesystemID,
		Path:       req.Path,
		Intent:     req.Intent,
		PeerUID:    ps.UID,
		PeerPID:    ps.PID,
		AccessTime: nil,
	}
}

// auditEvent is the spine's broker-resolved-truth record passed to the audit
// gate. It is intentionally opaque to the gate (Mandate takes any); the gate's
// own encoding shapes the durable record in the composition phase.
type auditEvent struct {
	Op         Op
	Scope      string
	Path       string
	Intent     Intent
	PeerUID    uint32
	PeerPID    int32
	AccessTime *int64
}

// withStatus returns a copy of the verdict with an overridden HTTP status,
// used only for the 405 method-not-allowed path where the Connect code stays
// invalid_argument but the HTTP method semantics demand 405.
func (v DenyVerdict) withStatus(status int) DenyVerdict {
	v.WireStatus = status
	return v
}
