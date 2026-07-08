// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// defaultFrameReadTimeout is the conservative per-frame inbound read budget
// for streaming ops: generous for any live peer writing a sub-4-MiB frame,
// fatal only to a stalled one.
const defaultFrameReadTimeout = 30 * time.Second

// defaultFrameWriteTimeout is the conservative per-frame OUTBOUND write budget
// for the download stream (crutch-01) — the symmetric mirror of
// defaultFrameReadTimeout. Generous for any live reader draining a 256-KiB data
// frame, fatal only to a stalled one. Without it, a wedged reader fills the
// kernel send buffer and writeFrame blocks forever, pinning the download
// goroutine and the engine fd (IdleTimeout never fires mid-request and the
// request context is not cancelled).
const defaultFrameWriteTimeout = 30 * time.Second

// requestIDHeader is the response header name for the per-request correlation
// id (T2-18). It is present on EVERY response — allow AND deny, unary AND
// streaming — and must never be used as a metric label (T2-2 cardinality rule).
const requestIDHeader = "x-request-id"

// OCSF File System Activity ids (class 1001). There is no rename/move id, so a
// move/copy is recorded as a Create on the produced (destination) handle
// (Q7). The set is the slice the namespace ops need; the auditgate branch owns
// the full enum, the wiring phase maps these onto it.
const (
	activityCreate = 1 // create / make / move-destination / copy-destination
	activityRead   = 2 // read / list
	activityDelete = 4 // delete / remove
)

// denyWith writes the REST deny response, emits a WARN log carrying the
// broker-resolved AuditReason truth (never the degraded wire reason), and
// records the deny in ops_total. The log carries deny_class (the truth) so
// operators see the real reason even when the WIRE degrades it for
// anti-enumeration. This is the single deny choke point; the LOCKED STAGE
// 0->4 order is unchanged — the log and metric recording are strictly additive
// observation. op is the southface Op string ("" if unknown at deny time,
// recorded as "internal" sentinel).
//
// denyWith uses the dispatcher's base logger (no request_id); call denyWithLog
// from request-scoped paths where a request_id-bearing logger is available.
//
// PENDING-PHASE-7(A3-deny): the refusal is written as a REST response — the
// authoritative HTTP status plus a BoundedReason {reason_code, message}
// diagnostic body (writeRESTDeny). Every op (the 16 unary-JSON ops and the two
// data-plane ops) now writes its pre-byte refusal this way.
func (d *dispatcher) denyWith(w http.ResponseWriter, v DenyVerdict, message string) {
	d.logger.Warn("broker deny",
		slog.String(observ.KeyDenyClass, v.AuditReason),
		slog.String(observ.KeyReason, message),
	)
	writeRESTDeny(w, v, message)
}

// denyWithLog is the request-scoped variant of denyWith: it uses the supplied
// logger (which carries the request_id via observ.KeyRequestID from a prior
// logger.With call) so deny WARN lines are correlated end-to-end.
func (d *dispatcher) denyWithLog(w http.ResponseWriter, l *slog.Logger, v DenyVerdict, message string) {
	l.Warn("broker deny",
		slog.String(observ.KeyDenyClass, v.AuditReason),
		slog.String(observ.KeyReason, message),
	)
	writeRESTDeny(w, v, message)
}

// recordAllow records ops_total{op, outcome=allow, deny_class=none} after a
// handler completes without a deny. RecordOp's deny_class enum is now derived
// from the shared denyclass vocabulary and "none" is always a valid label, so
// no recover() crutch guards this call: a panic here would be a genuine
// label-drift wiring bug (a new Op not added to knownOps) and MUST surface
// loudly in tests rather than be silently swallowed into an undercount.
func (d *dispatcher) recordAllow(op string) {
	if d.brokerMetrics == nil {
		return
	}
	d.brokerMetrics.RecordOp(op, "allow", denyclassNone)
}

// observeStage wraps a call to a stage function and records its latency in the
// stage_latency_seconds histogram. elapsed is in seconds. A nil brokerMetrics
// is a no-op — existing tests without a registry are unaffected.
func (d *dispatcher) observeStage(stage string, elapsed float64) {
	if d.brokerMetrics != nil {
		d.brokerMetrics.ObserveStage(stage, elapsed)
	}
}

// recordOp records one ops_total entry for the given op/outcome/deny_class
// triple, nil-guarding brokerMetrics. It is the streaming-path counterpart to
// the unary denyOp/recordAllow choke points: the two highest-volume data-plane
// ops (fileUpload/fileDownload) book their verdict through here so every
// upload/download deny-rate and throughput row is visible (southface-02). The
// deny_class single-source is the shared denyclass vocabulary (every value a
// streaming refusal carries as its audit reason is a valid RecordOp label), so
// no recover() crutch guards the call — a panic would be genuine label drift
// and MUST surface loudly in tests.
func (d *dispatcher) recordOp(op string, outcome, denyClass string) {
	if d.brokerMetrics != nil {
		d.brokerMetrics.RecordOp(op, outcome, denyClass)
	}
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
	// engine is the consumer-side storage seam the engine-plane handlers
	// call; the wiring phase binds the real local-volume engine.
	engine Engine
	// logger is the structured logger for deny WARNs and other diagnostic
	// events. Defaults to slog.DiscardHandler so tests that do not supply
	// one are unaffected. Every call site uses logger.With to carry a
	// *slog.Logger so T2-18 request-id threading drops in without rework.
	logger *slog.Logger
	// brokerMetrics is the telemetry metric set for ops_total and stage-latency
	// histograms. A nil value is a no-op — existing tests that do not supply one
	// compile and pass unchanged. The instrumentation is strictly additive:
	// timers wrap the EXISTING stage calls, ops_total records at the single deny
	// choke point (denyWith) and after a successful handler, and the LOCKED
	// STAGE 0->4 ordering is not modified.
	brokerMetrics *telemetry.BrokerMetrics
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
	// The real ceiling is the control-plane's BrokerMaxFileSizeBytes, bound by
	// Serve from cfg.BrokerMaxFileSize (validated positive there). A dispatcher
	// built without that wiring leaves this 0, so checkDeclaredSize refuses any
	// non-empty upload (declared > 0 > ceiling) — an unwired dispatcher fails
	// CLOSED and loudly rather than silently inheriting a placeholder ceiling.
	// Tests set a small value directly (the package is in-package).
	maxFileSize int64
	// frameReadTimeout bounds the wait for EACH inbound read off the streamed
	// upload body (NFR-SEC-46): a peer that opens an upload and stalls would
	// otherwise pin the goroutine, an fd-ceiling slot, and any acquired
	// in-flight bytes for the session's lifetime. serveUploadMultipart RE-ARMS
	// a frameReadTimeout-from-now read deadline (via http.NewResponseController)
	// before every filePart.Read, so a slow-but-progressing transfer keeps
	// pushing the deadline out while a STALL trips it: the deadline-exceeded
	// read surfaces as a non-EOF read error and aborts through the existing
	// hard-abort path (release fd/bytes, no torn object). LIVE: read by the
	// upload handler. Defaulted in newDispatcherWithEngine; tests shrink it.
	frameReadTimeout time.Duration
	// frameWriteTimeout bounds the wait for EACH outbound flush on the download
	// stream (NFR-SEC-46, crutch-01): the symmetric mirror of frameReadTimeout
	// for the egress leg. serveDownloadOctetStream RE-ARMS a
	// frameWriteTimeout-from-now write deadline (via http.NewResponseController)
	// before every flush; a stalled reader makes the next write error, which
	// propagates out of the flushing writer into engine.ReadRange, terminating
	// the stream and releasing the fd slot (the 200 header is already committed,
	// so the status cannot change). LIVE: read by the download handler.
	// Defaulted in newDispatcherWithEngine; tests shrink it.
	frameWriteTimeout time.Duration

	// grantedIntentsCeiling is the static -granted-intents ceiling (ADR-0029
	// Decision bullet 5): the intents the deployment serves. STAGE 0 intersects
	// the credential's claim with this ceiling to derive the EFFECTIVE grant set
	// the authz spine reads. The ceiling NEVER grants — an intent in the claim but
	// outside the ceiling is dropped (that op then denies at the resolver), and a
	// missing claim is never substituted by a ceiling value. A nil ceiling leaves
	// the claim unnarrowed (the pre-ADR-0029 behaviour), so every existing test
	// that builds the dispatcher without a ceiling is unaffected. Serve wires the
	// real ceiling from Config.GrantedIntents.
	grantedIntentsCeiling []Intent

	// subtrees is the intent->subtree map (ADR-0029 inv-10): the dispatch spine

	// and the two data-plane ops derive the join subtree from the ROUTE-OP-required
	// intent (never the wire hint) and pass it into canonicalizePath. A zero-value
	// (empty) map disables the join deployment-wide — the shipped static bind — so
	// canonicalizePath runs its pre-ADR-0029 static-path behaviour and every
	// existing caller is unaffected. Serve wires the real map from Config.Subtrees.
	subtrees SubtreeMap

	// credExtractor is the A5 credential-scope source for the UNARY REST path:

	// when non-nil, STAGE-0 derives the request's host-attested PeerScope from
	// the edge-injected Authorization: Bearer (deriveCredScope) rather than from
	// the unix peer-cred stashed in the connection context. When nil the unary
	// path falls back to peerScopeFromContext, the unix-transport source — so the
	// streaming branch (still on the Connect path this wave) and any caller that
	// injects PeerScope via contextWithPeerScope continue to work unchanged.
	//
	// PENDING-PHASE-7(A5-credscope): the production wiring binds a
	// CredentialScopeExtractor here; the streaming branch keeps the unix peer
	// scope until the data-plane ops pivot in a later wave.
	credExtractor CredentialScopeExtractor
}

// newDispatcher builds a dispatcher with the engine-plane handlers wired over
// the injected engine seam (the remaining ops stay unimplemented) and the
// injected authz/audit/ceilings seams. A nil engine leaves the registry
// fully unimplemented (the phase-8 spine tests construct the dispatcher
// without an engine).
func newDispatcher(resolver Resolver, guard Guard, ceilings CeilingsRegistry, sizeCeiling int64) *dispatcher {
	return newDispatcherWithEngine(resolver, guard, ceilings, sizeCeiling, nil)
}

// newDispatcherWithEngine builds a dispatcher binding the storage engine seam
// and a fresh session-scoped uuid store. When engine is non-nil it registers
// the engine-plane handlers (the seven phase-9 verbs plus readFile and the
// readMetadata resolve), replacing their unimplemented entries; the remaining
// ops stay unimplemented. The phase-8 spine ordering/registry tests use
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
		// (OPS-05) is REST-routed to serveUploadMultipart and never read from
		// this registry, so its entry stays unimplemented (see handler_stub.go).
		reg[OpReadFile] = handleReadFile
		// readMetadata is the path-axis metadata resolve the guest mount runs on
		// every Open/stat before a read (rclone ocufs resolve()); without it the
		// read plane returns 501 and no object round-trips back through the mount.
		reg[OpReadMetadata] = handleReadMetadata
	}
	return &dispatcher{
		resolver:    resolver,
		guard:       guard,
		ceilings:    ceilings,
		registry:    reg,
		engine:      engine,
		ids:         newObjectIDStore(),
		sizeCeiling: sizeCeiling,
		// maxFileSize is intentionally left 0 here: Serve sets it from the
		// validated cfg.BrokerMaxFileSize. An unwired dispatcher therefore
		// refuses any non-empty upload (fail-closed). See the field doc.
		maxFileSize: 0,
		// maxFileSize is intentionally left 0 here: Serve sets it from the
		// validated cfg.BrokerMaxFileSize. An unwired dispatcher therefore
		// refuses any non-empty upload (fail-closed). See the field doc.
		//
		// subtrees is the zero-value (static-path mode) here: the internal unit
		// constructors exercise dispatch logic that is orthogonal to the join, so
		// they run flat. The join is mandatory on the SHIPPED path — Serve refuses
		// an empty map at boot (ErrSubtreeDisabled) and the composition layer
		// defaults to DefaultSubtreeMap() — so static mode is unreachable in
		// production; only these in-package tests (and an explicit override) see it.
		frameReadTimeout:  defaultFrameReadTimeout,
		frameWriteTimeout: defaultFrameWriteTimeout,
		logger:            slog.New(slog.DiscardHandler),
	}
}

// ServeHTTP runs the LOCKED pipeline. The order is load-bearing and must not
// be reordered:
//
//	STAGE 0 header gate (NO body byte read): mint request id -> set
//	  x-request-id header -> derive request-scoped logger -> route ->
//	  Content-Type -> PeerScope (credential-scope on the unary REST path, or
//	  the unix peer scope from context for the streaming branch / injected
//	  callers) -> declared-size pre-buffer on Content-Length -> ops/s
//	  throttle keyed on the CHANNEL scope (never the body)
//	STAGE 1 strict envelope decode (through the MaxBytesReader backstop)
//	STAGE 1b channel-scope cross-check on the DECODED body (D2)
//	STAGE 2 authz (Resolver.Resolve with caller evidence from the channel)
//	STAGE 3 audit Mandate BEFORE any 2xx (NFR-SEC-79)
//	STAGE 4 registry[op] (all unimplemented in this build)
//
// Every refusal flows through the deny.go mapper — one source of truth.
func (d *dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// STAGE 0: mint the per-request correlation id and stamp it on the
	// response header immediately (before any WriteHeader path). The id is
	// a 32-char lowercase hex token from crypto/rand — high-cardinality but
	// NOT a metric label (T2-2 cardinality rule). It links the log lines,
	// the audit record, and the wire response for this single request.
	reqID := newCorrelationID()
	w.Header().Set(requestIDHeader, reqID)
	// Derive a request-scoped logger so every log line for this request
	// carries request_id without requiring each call site to pass it.
	reqLog := d.logger.With(slog.String(observ.KeyRequestID, reqID))
	// Panic containment (T2-4, RES-02): a recover() wrapper sitting OUTSIDE
	// the LOCKED STAGE 0->4 pipeline. On any panic it makes a best-effort
	// audit Mandate for an internal deny (NFR-SEC-79) then writes a structured
	// wire deny — never a naked connection drop. The STAGE 0->4 order is not
	// modified; this is a pure additive safety net.
	defer d.recoverDispatch(w, &reqLog)()

	// STAGE 0: route. A non-POST to a valid-shaped route is a 405; an
	// unknown route or version/content-type fault is invalid_argument. No
	// body byte is read in this stage (SEC-76/78).
	op, err := parseRoute(r.Method, r.URL.Path)
	if err != nil {
		if err == errBadMethod {
			w.Header().Set("Allow", http.MethodPost)
			d.denyWithLog(w, reqLog, mapDeny(denyMalformed).withStatus(http.StatusMethodNotAllowed), "method not allowed")
			return
		}
		d.denyWithLog(w, reqLog, mapDeny(denyClassForDecodeErr(err)), "unknown route")
		return
	}

	// Instrumentation: denyOp and allowOp record ops_total after the route is
	// known. They are STRICTLY ADDITIVE — they wrap d.denyWith / record allow,
	// never reorder STAGE 0->4. Calls BEFORE this point (unknown route, bad
	// method) do not have an op and use plain denyWith (no ops_total entry).
	opStr := string(op)
	denyOp := func(v DenyVerdict, message string) {
		d.denyWithLog(w, reqLog, v, message)
		if d.brokerMetrics != nil {
			// No recover() crutch: every AuditReason a refusal can carry is a
			// member of the shared denyclass vocabulary, which is exactly the
			// deny_class label enum RecordOp accepts. A panic here would be a
			// genuine label-drift wiring bug and MUST surface loudly in tests
			// rather than be swallowed into a silently-wrong deny counter.
			d.brokerMetrics.RecordOp(opStr, "deny", v.AuditReason)
		}
	}

	// DATA-PLANE OPS are NOT dispatched here. Both fileUpload (multipart) and
	// fileDownload (octet-stream) are REST-routed by the router to their dedicated
	// entrypoints (serveUploadMultipart / serveDownloadOctetStream) BEFORE the
	// request reaches this unary spine, so this ServeHTTP path now serves ONLY the
	// 16 unary-JSON ops. The retired Connect serveStreaming branch is gone — no op
	// rides it. A data-plane op reaching this spine directly (a caller that bypassed
	// the router) would fall through the unary Content-Type/Content-Length gate
	// below and be refused, which is the correct fail-closed behaviour for an
	// out-of-band call.

	// STAGE 0: Content-Type. The unary REST ops are application/json; the
	// Connect version header is gone (the REST transport pins no protocol-version
	// header).
	if err := checkContentType(r); err != nil {
		denyOp(mapDeny(denyClassForDecodeErr(err)), "Content-Type must be application/json")
		return
	}

	// STAGE 0: PeerScope — the host-attested channel identity. The SOURCE is
	// gated (A5): when a credential extractor is wired, the unary REST path
	// derives the scope from the edge-injected Authorization: Bearer
	// (peerScopeFromCredential); otherwise it reads the unix peer scope stashed
	// in the connection context (the streaming branch's source this wave, and the
	// source any test that injects PeerScope via contextWithPeerScope relies on).
	// A missing/rejected credential is unauthenticated (401); an absent context
	// scope on the fallback path is a wiring fault and fails closed.
	var ps PeerScope
	if d.credExtractor != nil {
		var v DenyVerdict
		var ok bool
		ps, v, ok = peerScopeFromCredential(r, d.credExtractor)
		if !ok {
			denyOp(v, "credential rejected")
			return
		}
		// -granted-intents ceiling (ADR-0029 Decision bullet 5): narrow the
		// credential's claim to the intents the deployment serves. The EFFECTIVE
		// grant set the authz spine reads (CallerEvidence.GrantedIntents below) is
		// claim ∩ ceiling — a claim intent outside the ceiling is dropped so that
		// op denies at the resolver, and a missing claim is never substituted by a
		// ceiling value (the intersection of an empty claim is empty, so every op
		// denies). A nil ceiling leaves the claim unnarrowed. The ceiling never
		// grants: it can only remove intents from the claim.
		if d.grantedIntentsCeiling != nil {
			ps.GrantedIntents = intersectIntents(ps.GrantedIntents, d.grantedIntentsCeiling)
		}
	} else {

		var ok bool
		ps, ok = peerScopeFromContext(r.Context())
		if !ok {
			denyOp(mapDeny(denyInternal), "no channel scope on connection")
			return
		}
	}

	// STAGE 0: declared-size pre-buffer on the Content-Length (SEC-78). A
	// unary request carries a known-size body; an absent Content-Length is
	// refused before any body byte is read. An over-ceiling length is a size
	// deny.
	cl := r.ContentLength
	if cl < 0 {
		denyOp(mapDeny(denyMalformed), "unary request requires Content-Length")
		return
	}
	if cl > d.sizeCeiling {
		denyOp(mapDeny(denySizeExceeded), "declared body size exceeds ceiling")
		return
	}

	// STAGE 0: ops/s throttle, keyed on the CHANNEL scope (PeerScope), never
	// on any body field — nothing trusts the body before STAGE 1b. A throttle
	// is resource_exhausted with NO x-deny-reason (n3).
	sess := d.ceilings.Session(ps.FilesystemID)
	if err := sess.TryConsumeOp(); err != nil {
		denyOp(mapDeny(denyClassForErr(err)), "operation rate ceiling exceeded")
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
			denyOp(mapDeny(denySizeExceeded), "declared body size exceeds ceiling")
			return
		}
		// Classify a client disconnect or deadline BEFORE the generic malformed
		// branch (mirrors denyClassForEngineErr step 0, T2-5/RES-03): a
		// cancelled or deadline-exceeded read is an aborted verdict, not a
		// durable record of the client sending malformed bytes. A genuinely
		// truncated or undecodable body that is NOT a disconnect falls through
		// to denyMalformed below.
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) ||
			r.Context().Err() != nil {
			denyOp(mapDeny(denyAborted), "client disconnected during request body read")
			return
		}
		denyOp(mapDeny(denyMalformed), "malformed request envelope")
		return
	}
	var env unaryEnvelope
	if err := decodeUnaryEnvelopeBytes(bodyBytes, &env); err != nil {
		denyOp(mapDeny(denyClassForDecodeErr(err)), "malformed request envelope")
		return
	}

	// STAGE 1b: channel-scope cross-check on the DECODED body. The body
	// filesystem_id is an untrusted hint; a value that disagrees with the
	// channel-bound scope is a scope_mismatch deny (permission_denied +
	// x-deny-reason), and the handler is never reached (D2/NFR-SEC-43).
	if env.FilesystemID != ps.FilesystemID {
		denyOp(mapDeny(denyScopeMismatch), "request scope does not match the session channel")
		return
	}

	// STAGE 1b: route-vs-envelope op cross-check is implicit — the body
	// carries no op field in this build; the route op is authoritative and
	// the body scope/intent are the only cross-checked fields.

	// STAGE 1b -> 2 BOUNDARY: derive the route-op required intent BEFORE the
	// canonicalize so the join subtree is known when the path is cleaned. This is
	// a pure closed-map lookup on the op (known since parseRoute); hoisting it
	// above the canonicalize does NOT reorder the LOCKED STAGE 0->4 pipeline — the
	// op/wire-intent cross-check below stays in its STAGE-2 position. An op absent
	// from the closed map is a wiring fault and fails closed.
	requiredIntent, ok := requiredIntentForOp(op)
	if !ok {
		denyOp(mapDeny(denyInternal), "no required intent bound to operation")
		return
	}
	subtree := d.subtrees.For(requiredIntent)
	// Close the per-request residual bypass (ADR-0029 "never bypass it"): when the
	// join is ENABLED (a populated map — the shipped posture, which Serve enforces
	// at boot), an intent with no mapped subtree must DENY rather than degrade this
	// one request to static-path mode. Without this, a future fourth intent or a
	// zero-value Intent would fall through to the flat layout and coincide the write
	// and downloadable axes for that request. When the map is disabled (empty),
	// static mode is intended — the in-package unit path only; Serve refuses an
	// empty map on the shipped path (ErrSubtreeDisabled), so this branch is never
	// reached in production.
	if d.subtrees.enabled() && subtree == "" {
		denyOp(mapDeny(denyInternal), "no subtree bound to the operation's intent")
		return
	}

	// STAGE 1b -> 2 BOUNDARY: canonicalize the decoded path ONCE (bypass-01/03),
	// joined under the intent's subtree (ADR-0029 inv-10). Nothing trusts the body
	// before STAGE 1b; now that the channel-scope cross-check has cleared, clean
	// the path a SINGLE time so authz, the downloadable tag, the engine, the uuid
	// store, and the audit record all see the SAME object. The subtree is derived
	// from the ROUTE-OP-required intent (never the wire), so a write op joins under
	// the RW subtree and a read op under the RO subtree — the ":ro" posture is
	// engine-enforced by the join, not a guest-mount artifact. This is an additive
	// step WITHIN the boundary — the LOCKED STAGE 0->4 order is unchanged — and it
	// runs BEFORE STAGE 2 so a `<downloadable-prefix>/../<private>` wire path can
	// never have its egress axis decided on the raw bytes while a different object
	// is read. A path the canonicalizer rejects (including one that escapes the
	// join) is invalid_argument at the boundary; the handler is never reached. From
	// here, env.Path is the canonical joined form and every downstream consumer
	// derives from it.
	canonPath, perr := canonicalizePath(env.Path, subtree)
	if perr != nil {
		denyOp(mapDeny(denyMalformed), "invalid or unsafe path")
		return
	}
	env.Path = canonPath

	// STAGE 1b -> 2 BOUNDARY (crutch-04): canonicalize the SECOND-LEG paths of the
	// two-path namespace ops (moveDirectory, copyFile, moveFile) through the SAME
	// canonicalizePath the primary path went through above, BEFORE STAGE 2 authz
	// and STAGE 3 audit. The two-path handlers used to feed req.Source/
	// req.Destination RAW into the engine (slash-strip only), so authz/audit
	// decided on the primary path while the engine validated a different,
	// un-canonicalized leg — the canonicalize-once-before-authz invariant
	// (bypass-01/03) held for the primary path but was broken for move/copy. The
	// engine-side ValidatePath/os.Root is still defense-in-depth (no escape), but
	// the authorized/audited leg must be the exact leg the engine touches. A
	// canonicalize error on either leg is denyMalformed HERE — symmetric with the
	// primary path — and the handler is never reached. canonSrc/canonDst are
	// empty for single-path ops, which never read them.
	canonSrc, canonDst, perr := canonicalizeMoveCopyLegs(op, bodyBytes, subtree)
	if perr != nil {
		denyOp(mapDeny(denyMalformed), "invalid or unsafe path")
		return
	}

	// STAGE 2: route-op -> required-intent binding (NFR-SEC-49, invariant 4).
	// The route op is AUTHORITATIVE for what the request does; the wire
	// authorization_metadata.intent is an untrusted hint. requiredIntent was
	// derived at the STAGE 1b->2 boundary above (hoisted so the join subtree is
	// known when the path is cleaned); the cross-check below refuses a wire intent
	// that disagrees with the op's required intent BEFORE the resolver is
	// consulted, so a read-only grant can never reach a mutation handler by
	// declaring intent=read on a mutation route.
	if env.AuthorizationMetadata.Intent != requiredIntent {

		denyOp(mapDeny(denyClassForDecodeErr(errRouteOpMismatch)), "authorization intent does not match the operation")
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
	authzStart := time.Now()
	// The resolver (and its StoredTagFunc) keys on the ENGINE-RELATIVE path with
	// NO leading slash — "outputs/uploads/x", never "/outputs/uploads/x"
	// (ADR-0029 inv-5). The north Files-API plane already passes engine-relative,
	// so normalising here gives both planes ONE convention at the tag boundary and
	// settles the cross-plane mismatch that let the leading-slash south path miss
	// the configured prefix. env.Path (leading-slash, the JOINED canonical form)
	// stays authoritative for the audit ObjectHandle, the uuid store, and the
	// engine handler; only the value the resolver sees is normalised, and it names
	// the SAME joined object the bytes land in (authz-path == engine-path).
	grant, err := d.resolver.Resolve(r.Context(), evidence, resolverRequest(req))
	d.observeStage("authz", time.Since(authzStart).Seconds())
	if err != nil {
		denyOp(mapDeny(denyClassForErr(err)), "authorization denied")
		return
	}

	// STAGE 3: audit Mandate BEFORE any 2xx (NFR-SEC-79). The event is the
	// per-op, broker-resolved-truth allow record (ActivityID / ObjectHandle /
	// Intent / Downloadable per op); an unavailable audit gate denies the
	// operation and the handler is never invoked. No x-deny-reason on an
	// audit-down verdict (n3). This pre-handler allow-Mandate stays HERE,
	// before STAGE 4 — the phase-8 ordering test still passes; a handler-stage
	// refusal emits a SECOND deny event through the mandateDeny hook below.
	allowEvent := d.auditEvent(op, ps, req, grant, canonDst)
	allowEvent.RequestID = reqID
	mandateStart := time.Now()
	mandateErr := d.guard.Mandate(r.Context(), mapAuditEvent(allowEvent))
	d.observeStage("audit_mandate", time.Since(mandateStart).Seconds())
	if mandateErr != nil {
		denyOp(mapDeny(denyClassForErr(mandateErr)), "audit gate unavailable")
		return
	}

	// STAGE 3 cleared: emit a DEBUG-level allow line so the request_id (T2-18)
	// appears in the log for successfully mandated requests. The deny path
	// already logs via denyWithLog; this ensures the id is visible on the
	// allow path too without adding an info-level line for every request.
	reqLog.Debug("broker allow",
		slog.String(observ.KeyOp, opStr),
	)

	// STAGE 4: the per-op handler. The engine-plane ops have real handlers; the
	// remaining ops stay unimplemented. A route op absent from the registry
	// is a wiring fault and fails closed.
	h, ok := d.registry[op]
	if !ok {
		denyOp(mapDeny(denyUnimplemented), "operation not registered")
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
		denyEvent := d.denyAuditEvent(op, ps, req, grant, canonDst, auditReason)
		denyEvent.RequestID = reqID
		if err := d.guard.Mandate(r.Context(), mapAuditEvent(denyEvent)); err != nil {
			denyOp(mapDeny(denyAuditDown), "audit gate unavailable")
			return
		}
		// Set CorrelationID to the request id (T2-18: one id, not two).
		v := mapDenyDegraded(auditReason, wireClass)
		v.CorrelationID = reqID
		denyOp(v, message)
	}

	// STAGE 4: time the engine handler call. The timer wraps h(...) as an
	// additive observation; the handler's own logic is unchanged.
	engineStart := time.Now()
	outcome := h(d.handlerDeps(), handlerCtx{
		ctx:         r.Context(),
		w:           w,
		op:          op,
		body:        bodyBytes,
		canonPath:   env.Path, // the spine-canonicalized primary path (bypass-01/03)
		subtree:     subtree,  // the ADR-0029 join subtree, for symmetric strip on emit
		canonSource: canonSrc, // the spine-canonicalized move/copy source leg (crutch-04)
		canonDest:   canonDst, // the spine-canonicalized move/copy destination leg (crutch-04)
		ps:          ps,
		grant:       grant,
		mandateDeny: mandateDeny,
	})
	d.observeStage("engine", time.Since(engineStart).Seconds())

	// Record ops_total EXACTLY once for the dispatched op, gated on the
	// handler's reported outcome (southface-01). recordAllow used to fire
	// UNCONDITIONALLY here, so a handler that refused INTERNALLY (intent_denied,
	// malformed body/cursor, denyEngine, directory_not_empty, not_downloadable,
	// unimplemented) still booked a spurious second ops_total{outcome=allow}
	// for a refused request. The outcome now gates it: a success books the
	// single allow; a refusal that recorded its own deny through mandateDeny
	// books nothing further; a refusal that wrote the wire error directly books
	// its single deny here.
	switch {
	case outcome.allowed:
		d.recordAllow(opStr)
	case outcome.denyClass != "" && d.brokerMetrics != nil:
		// The handler already wrote the wire error directly (decodeOp,
		// malformed cursor, unimplemented) and did NOT touch the counter, so
		// the spine books the single deny entry here — metric ONLY, never a
		// second wire write. No recover() crutch: outcome.denyClass is always a
		// member of the shared denyclass vocabulary, the exact deny_class label
		// enum RecordOp accepts; a panic here would be a genuine label-drift
		// wiring bug and MUST surface loudly in tests.
		d.brokerMetrics.RecordOp(opStr, "deny", outcome.denyClass)
	}
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

// canonicalizeMoveCopyLegs canonicalizes the SECOND-LEG paths (source and
// destination) of the two-path namespace ops (moveDirectory, copyFile,
// moveFile) through the SAME canonicalizePath the spine applies to the primary
// path at the STAGE 1b->2 boundary (crutch-04). It runs on the buffered body
// AFTER the channel-scope cross-check has cleared (nothing trusts the body
// before STAGE 1b) and BEFORE STAGE 2 authz / STAGE 3 audit, so the
// authorized/audited leg is the exact leg the engine touches.
//
// A body that cannot be decoded is treated as a missing leg ("" returned,
// no error): the op handler's strict decodeOp re-decodes the same bytes and
// owns the malformed-body refusal — this helper never pre-empts that with its
// own malformed verdict. A leg that decodes but is lexically invalid or escapes
// the scope (canonicalizePath error) returns the error so the spine denies
// denyMalformed before the engine — symmetric with the primary path.
//
// Both returned legs are in the guest leading-slash convention; the handler
// trims them through enginePath for the engine call. For a single-path op the
// returned legs are empty and the handler never reads them.
//
// subtree is the SAME op-derived join subtree the primary path took (ADR-0029
// inv-10): both legs of a move/copy carry the op's single intent, so both land
// under the same subtree and no cross-subtree move is expressible. An empty
// subtree disables the join (static-path mode) exactly as for the primary path.
func canonicalizeMoveCopyLegs(op Op, body []byte, subtree string) (src string, dst string, err error) {
	var rawSrc, rawDst string
	switch op {
	case OpMoveDirectory:
		var b moveDirectoryRequest
		if json.Unmarshal(body, &b) != nil {
			return "", "", nil
		}
		rawSrc, rawDst = b.Source, b.Destination
	case OpCopyFile:
		var b copyFileRequest
		if json.Unmarshal(body, &b) != nil {
			return "", "", nil
		}
		rawSrc, rawDst = b.Source, b.Destination
	case OpMoveFile:
		var b moveFileRequest
		if json.Unmarshal(body, &b) != nil {
			return "", "", nil
		}
		rawSrc, rawDst = b.Source, b.Destination
	default:
		return "", "", nil
	}
	src, err = canonicalizePath(rawSrc, subtree)
	if err != nil {
		return "", "", err
	}
	dst, err = canonicalizePath(rawDst, subtree)
	if err != nil {
		return "", "", err
	}
	return src, dst, nil
}

// objectHandleForOp derives the audited object handle for an op. For
// move/copy the handle is the DESTINATION (the produced object); for the
// others it is the envelope path. The destination passed in is the
// spine-canonicalized destination leg (canonDst) — cleaned through the SAME
// canonicalizer the dispatch boundary applies to the primary path at STAGE
// 1b/2 (bypass-01/03, crutch-04) — so the durable audit record names the
// broker-resolved truth and never a raw wire path that could encode traversal
// segments ("/pub/../priv/stolen") while the engine wrote a different object
// ("/priv/stolen"). The audited destination is now the EXACT leg the engine
// receives, because the spine canonicalizes it once and both the audit record
// and the engine call derive from that single cleaned form. A single-path op
// (or a two-path op whose body failed to decode, leaving canonDst empty) names
// the canonicalized primary path (req.Path), which the spine already cleaned at
// STAGE 1b (NFR-SEC-79).
func objectHandleForOp(op Op, scope string, req ResolveRequest, canonDst string) string {
	path := req.Path
	switch op {
	case OpMoveDirectory, OpCopyFile, OpMoveFile:
		if canonDst != "" {
			path = canonDst
		}
	}
	return scope + ":" + path
}

// auditEvent builds the per-op broker-resolved-truth ALLOW event. The concrete
// durable encoding is the audit gate's (frozen on its branch); the spine
// passes an opaque value through Guard.Mandate exactly as the real gate
// consumes it. The op-aware fields (ActivityID, ObjectHandle, Intent,
// Downloadable) are populated per Q7; the committed envelope fields keep their
// meaning. canonDst is the spine-canonicalized destination leg for a two-path
// op (crutch-04), empty for a single-path op.
func (d *dispatcher) auditEvent(op Op, ps PeerScope, req ResolveRequest, grant Grant, canonDst string) auditEvent {
	return auditEvent{
		Op:           op,
		Scope:        ps.FilesystemID,
		Path:         req.Path,
		Intent:       req.Intent,
		PeerUID:      ps.UID,
		PeerPID:      ps.PID,
		AccessTime:   nil,
		ActivityID:   activityForOp(op),
		ObjectHandle: objectHandleForOp(op, ps.FilesystemID, req, canonDst),
		ByteCount:    0,
		Downloadable: grant.Downloadable,
	}
}

// denyAuditEvent builds the per-op DENY event for a handler-stage operational
// refusal: the same op-aware shape as the allow event, carrying the
// broker-resolved truth as the DenyReason. It is emitted through the spine's
// guard (via the mandateDeny hook) BEFORE the wire deny so the durable record
// captures that the op did not take effect (T-09-04 / NFR-SEC-79). canonDst is
// the spine-canonicalized destination leg for a two-path op (crutch-04).
func (d *dispatcher) denyAuditEvent(op Op, ps PeerScope, req ResolveRequest, grant Grant, canonDst string, auditReason string) auditEvent {
	e := d.auditEvent(op, ps, req, grant, canonDst)
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
	// RequestID is the T2-18 correlation id minted at dispatch STAGE 0;
	// it links this audit record to the x-request-id response header and
	// the structured log line for the same request. Empty when the event
	// is synthesised outside a request context.
	RequestID string
}

// withStatus returns a copy of the verdict with an overridden HTTP status,
// used only for the 405 method-not-allowed path where the deny class stays
// malformed (invalid_argument) but the HTTP method semantics demand 405. The
// BoundedReason body still carries the malformed reason_code; only the
// authoritative status is overridden.
func (v DenyVerdict) withStatus(status int) DenyVerdict {
	v.WireStatus = status
	return v
}
