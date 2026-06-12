// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// OCSF File System Activity ids (class 1001). There is no rename/move id, so a
// move/copy is recorded as a Create on the produced (destination) handle
// (Q7). The set is the slice the namespace ops need; the auditgate branch owns
// the full enum, the wiring phase maps these onto it.
const (
	activityCreate = 1 // create / make / move-destination / copy-destination
	activityRead   = 2 // read / list
	activityDelete = 4 // delete / remove
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
	// engine is the consumer-side storage seam the seven phase-9 handlers
	// call; the wiring phase binds the real local-volume engine.
	engine Engine
	// ids is the session-scoped uuid record store the listing emitter mints
	// through and phase 10 resolves through.
	ids *objectIDStore
	// sizeCeiling is the per-request declared/streamed body ceiling
	// (NFR-SEC-78), applied pre-buffer on the Content-Length and as the
	// MaxBytesReader backstop.
	sizeCeiling int64
	// maxFileSize is the WHOLE-OBJECT upload ceiling (NFR-SEC-46): the
	// fileUpload pre-buffer reject compares declared_size_bytes against it
	// BEFORE reading any chunk. It is DISTINCT from sizeCeiling, which is the
	// per-RPC-message body ceiling (~4 MiB — the size of a single envelope or
	// frame). A whole object legitimately exceeds the per-message ceiling
	// while being streamed in many sub-ceiling frames, so the two ceilings
	// cannot be the same value.
	//
	// PHASE-11 PLACEHOLDER (W1): the real ceiling is the control-plane's
	// BrokerMaxFileSizeBytes, bound in the wiring phase. Until then this is
	// defaulted to sizeCeiling in newDispatcherWithEngine, so an unwired
	// deployment caps uploads at the per-message ceiling — conservative and
	// fail-closed, but not the real whole-object limit. Tests set a small
	// value directly (the package is in-package).
	maxFileSize int64
}

// newDispatcher builds a dispatcher with the seven phase-9 handlers wired over
// the injected engine seam (the other eleven ops stay unimplemented) and the
// injected authz/audit/ceilings seams. A nil engine leaves the registry
// fully unimplemented (the phase-8 spine tests construct the dispatcher
// without an engine).
func newDispatcher(resolver Resolver, guard Guard, ceilings CeilingsRegistry, sizeCeiling int64) *dispatcher {
	return newDispatcherWithEngine(resolver, guard, ceilings, sizeCeiling, nil)
}

// newDispatcherWithEngine builds a dispatcher binding the storage engine seam
// and a fresh session-scoped uuid store. When engine is non-nil it registers
// the seven phase-9 handlers, replacing their unimplemented entries; the other
// eleven ops stay unimplemented. The phase-8 spine ordering/registry tests use
// newDispatcher (engine nil) and continue to see every op unimplemented.
func newDispatcherWithEngine(resolver Resolver, guard Guard, ceilings CeilingsRegistry, sizeCeiling int64, engine Engine) *dispatcher {
	reg := newHandlerRegistry()
	if engine != nil {
		reg[OpListDirectory] = handleListDirectory
		reg[OpMakeDirectory] = handleMakeDirectory
		reg[OpMoveDirectory] = handleMoveDirectory
		reg[OpRemoveDirectory] = handleRemoveDirectory
		reg[OpCopyFile] = handleCopyFile
		reg[OpMoveFile] = handleMoveFile
		reg[OpRemoveFile] = handleRemoveFile
		// readFile (OPS-04) rides the unary dispatch unchanged. fileUpload
		// (OPS-05) is dispatched OUT-OF-BAND via serveStreaming and never read
		// from this registry, so its entry stays unimplemented (see
		// handler_stub.go).
		reg[OpReadFile] = handleReadFile
	}
	return &dispatcher{
		resolver:    resolver,
		guard:       guard,
		ceilings:    ceilings,
		registry:    reg,
		engine:      engine,
		ids:         newObjectIDStore(),
		sizeCeiling: sizeCeiling,
		// PHASE-11 PLACEHOLDER (W1): default the whole-object upload ceiling
		// to the per-message ceiling until the real BrokerMaxFileSizeBytes is
		// wired. See the maxFileSize field doc.
		maxFileSize: sizeCeiling,
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

	// STREAMING BRANCH (per-op flag, NOT content-type sniffing): a streaming
	// op (fileUpload, fileDownload) has its own STAGE-0 gate
	// (application/connect+json, no Content-Length pre-buffer reject) and
	// emits a framed HTTP-200 trailer for every verdict. It MUST branch HERE,
	// before the unary checkContentType (hard-equals application/json) and the
	// unary Content-Length pre-buffer reject would kill a chunked connect+json
	// upload (Pitfalls 1, 2). The unary path below is unchanged.
	if isStreamingOp(op) {
		d.serveStreaming(w, r, op)
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

	// STAGE 1: buffer the body once through the MaxBytesReader backstop, then
	// strict-decode the envelope from the buffer. The same bytes are handed to
	// the per-op handler so it re-decodes the op-specific fields without a
	// second network read; the size ceiling / MaxBytesReader backstop stays
	// intact on the single read.
	r.Body = http.MaxBytesReader(w, r.Body, d.sizeCeiling)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeConnectError(w, mapDeny(denySizeExceeded), "declared body size exceeds ceiling")
			return
		}
		writeConnectError(w, mapDeny(denyMalformed), "malformed request envelope")
		return
	}
	var env unaryEnvelope
	if err := decodeUnaryEnvelopeBytes(bodyBytes, &env); err != nil {
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

	// STAGE 2: route-op -> required-intent binding (NFR-SEC-49, invariant 4).
	// The route op is AUTHORITATIVE for what the request does; the wire
	// authorization_metadata.intent is an untrusted hint. The authz intent
	// passed to Resolve is DERIVED FROM THE ROUTE OP — never the wire — and a
	// wire intent that disagrees with the op's required intent is refused
	// (errRouteOpMismatch) before the resolver is consulted, so a read-only
	// grant can never reach a mutation handler by declaring intent=read on a
	// mutation route. An op absent from the closed map is a wiring fault and
	// fails closed.
	requiredIntent, ok := requiredIntentForOp(op)
	if !ok {
		writeConnectError(w, mapDeny(denyInternal), "no required intent bound to operation")
		return
	}
	if env.AuthorizationMetadata.Intent != requiredIntent {
		writeConnectError(w, mapDeny(denyClassForDecodeErr(errRouteOpMismatch)), "authorization intent does not match the operation")
		return
	}

	// STAGE 2: authz. Caller evidence is built from the channel scope, never
	// from a request field. Deny sentinels map through the D4 table with the
	// header gated to authorization verdicts.
	evidence := CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: ps.GrantedIntents}
	req := ResolveRequest{
		Filesystem: env.FilesystemID,
		Path:       env.Path,
		Intent:     requiredIntent,
	}
	grant, err := d.resolver.Resolve(r.Context(), evidence, req)
	if err != nil {
		writeConnectError(w, mapDeny(denyClassForErr(err)), "authorization denied")
		return
	}

	// STAGE 3: audit Mandate BEFORE any 2xx (NFR-SEC-79). The event is the
	// per-op, broker-resolved-truth allow record (ActivityID / ObjectHandle /
	// Intent / Downloadable per op); an unavailable audit gate denies the
	// operation and the handler is never invoked. No x-deny-reason on an
	// audit-down verdict (n3). This pre-handler allow-Mandate stays HERE,
	// before STAGE 4 — the phase-8 ordering test still passes; a handler-stage
	// refusal emits a SECOND deny event through the mandateDeny hook below.
	allowEvent := d.auditEvent(op, ps, req, grant, bodyBytes)
	if err := d.guard.Mandate(r.Context(), mapAuditEvent(allowEvent)); err != nil {
		writeConnectError(w, mapDeny(denyClassForErr(err)), "audit gate unavailable")
		return
	}

	// STAGE 4: the per-op handler. The seven phase-9 ops have real handlers;
	// the other eleven stay unimplemented. A route op absent from the registry
	// is a wiring fault and fails closed.
	h, ok := d.registry[op]
	if !ok {
		writeConnectError(w, mapDeny(denyUnimplemented), "operation not registered")
		return
	}

	// mandateDeny lets the handler emit a SECOND deny audit event (the
	// operational refusal, carrying the broker-resolved truth as the audit
	// reason) BEFORE the wire deny. The wire reason MAY degrade away from the
	// truth (D8). The Mandate ordering stays owned by the spine — the handler
	// only supplies the per-op deny event content.
	//
	// A deny-Mandate FAILURE degrades the verdict to audit_down (NFR-SEC-79,
	// invariant 8): if the deny record did not durably land, the durable
	// chain's last record would be the STAGE-3 allow — asserting allow for a
	// refused op — so the wire must say unavailable and carry NO x-deny-reason
	// (the truth header only ever accompanies a recorded truth), mirroring the
	// STAGE-3 allow-Mandate failure path above.
	mandateDeny := func(auditReason, wireClass, message string) {
		denyEvent := d.denyAuditEvent(op, ps, req, grant, bodyBytes, auditReason)
		if err := d.guard.Mandate(r.Context(), mapAuditEvent(denyEvent)); err != nil {
			writeConnectError(w, mapDeny(denyAuditDown), "audit gate unavailable")
			return
		}
		writeConnectError(w, mapDenyDegraded(auditReason, wireClass), message)
	}

	h(d.handlerDeps(), handlerCtx{
		ctx:         r.Context(),
		w:           w,
		op:          op,
		body:        bodyBytes,
		ps:          ps,
		grant:       grant,
		mandateDeny: mandateDeny,
	})
}

// activityForOp returns the OCSF ActivityID for an op (Q7): a listing is a
// Read, make/move/copy is a Create (no rename id), remove is a Delete. A
// non-namespace op defaults to Read — those ops stay unimplemented and never
// reach the audit builder in this build.
func activityForOp(op Op) int {
	switch op {
	case OpMakeDirectory, OpMoveDirectory, OpCopyFile, OpMoveFile:
		return activityCreate
	case OpRemoveDirectory, OpRemoveFile:
		return activityDelete
	default: // OpListDirectory and the rest
		return activityRead
	}
}

// objectHandleForOp derives the audited object handle for an op. For
// move/copy the handle is the DESTINATION (the produced object); for the
// others it is the envelope path. The destination is read from the buffered
// body so the audit record names the produced handle even though the spine
// envelope carries no destination field.
func objectHandleForOp(op Op, scope string, req ResolveRequest, body []byte) string {
	path := req.Path
	switch op {
	case OpMoveDirectory:
		var b moveDirectoryRequest
		if json.Unmarshal(body, &b) == nil {
			path = b.Destination
		}
	case OpCopyFile:
		var b copyFileRequest
		if json.Unmarshal(body, &b) == nil {
			path = b.Destination
		}
	case OpMoveFile:
		var b moveFileRequest
		if json.Unmarshal(body, &b) == nil {
			path = b.Destination
		}
	}
	return scope + ":" + path
}

// auditEvent builds the per-op broker-resolved-truth ALLOW event. The concrete
// durable encoding is the audit gate's (frozen on its branch); the spine
// passes an opaque value through Guard.Mandate exactly as the real gate
// consumes it. The op-aware fields (ActivityID, ObjectHandle, Intent,
// Downloadable) are populated per Q7; the committed envelope fields keep their
// meaning.
func (d *dispatcher) auditEvent(op Op, ps PeerScope, req ResolveRequest, grant Grant, body []byte) auditEvent {
	return auditEvent{
		Op:           op,
		Scope:        ps.FilesystemID,
		Path:         req.Path,
		Intent:       req.Intent,
		PeerUID:      ps.UID,
		PeerPID:      ps.PID,
		AccessTime:   nil,
		ActivityID:   activityForOp(op),
		ObjectHandle: objectHandleForOp(op, ps.FilesystemID, req, body),
		ByteCount:    0,
		Downloadable: grant.Downloadable,
	}
}

// denyAuditEvent builds the per-op DENY event for a handler-stage operational
// refusal: the same op-aware shape as the allow event, carrying the
// broker-resolved truth as the DenyReason. It is emitted through the spine's
// guard (via the mandateDeny hook) BEFORE the wire deny so the durable record
// captures that the op did not take effect (T-09-04 / NFR-SEC-79).
func (d *dispatcher) denyAuditEvent(op Op, ps PeerScope, req ResolveRequest, grant Grant, body []byte, auditReason string) auditEvent {
	e := d.auditEvent(op, ps, req, grant, body)
	e.DenyReason = auditReason
	return e
}

// handlerDeps returns the per-op handler dependencies (engine seam + uuid
// store). The dispatcher carries them so the wiring phase binds the real
// engine and a session-scoped store.
func (d *dispatcher) handlerDeps() *handlerDeps {
	return &handlerDeps{engine: d.engine, ids: d.ids}
}

// auditEvent is the spine's broker-resolved-truth record passed to the audit
// gate. It is intentionally opaque to the gate (Mandate takes any); the gate's
// own encoding shapes the durable record in the composition phase. The
// op-aware fields (ActivityID/ObjectHandle/ByteCount/Downloadable) and the
// handler-stage DenyReason extend the committed envelope shape in place so the
// package keeps ONE audit struct (the wiring phase maps it onto the real
// auditgate.FileActivityEvent).
type auditEvent struct {
	Op         Op
	Scope      string
	Path       string
	Intent     Intent
	PeerUID    uint32
	PeerPID    int32
	AccessTime *int64

	ActivityID   int
	ObjectHandle string
	ByteCount    int64
	Downloadable bool
	// DenyReason is set only on a handler-stage deny event; empty on an
	// allow event.
	DenyReason string
}

// withStatus returns a copy of the verdict with an overridden HTTP status,
// used only for the 405 method-not-allowed path where the Connect code stays
// invalid_argument but the HTTP method semantics demand 405.
func (v DenyVerdict) withStatus(status int) DenyVerdict {
	v.WireStatus = status
	return v
}
