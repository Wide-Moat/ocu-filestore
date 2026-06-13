// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
)

// downloadChunkSize is the maximum number of raw bytes written into a single
// outbound data frame during a fileDownload stream. Large enough for
// throughput (256 KiB avoids frame-count overhead for multi-MiB objects),
// small enough to stay well under the per-frame transport ceiling and to
// keep outbound memory bounded regardless of object size.
const downloadChunkSize = 256 * 1024

// errSizeExceeded is the consumer-side mirror of ceilings.ErrSizeExceeded for
// the local whole-object pre-buffer check. checkDeclaredSize returns it; the
// handler maps it to the policy size deny (invalid_argument/size_exceeded),
// distinct from the transport frame-too-large reject (resource_exhausted).
var errSizeExceeded = errors.New("southface: declared size exceeds whole-object ceiling")

// checkDeclaredSize is the named local mirror of the engine-side free function
// ceilings.CheckDeclaredSize(declared, ceiling int64) error
// (feat/session-ceilings:internal/ceilings/ceilings.go). Its body is a single
// direct `>` comparison — NEVER a subtraction — so it is overflow-safe even
// when both operands approach math.MaxInt64 (a subtraction
// `declared-ceiling > 0` would overflow). The boundary is strict `>` (NOT
// `>=`): a declaration exactly at the ceiling is admitted. The consumer
// CeilingsSession seam does NOT expose this comparison (it is a free function
// on the real package, not a session method), so this is a local mirror, not a
// seam call — keeping the boundary semantics in ONE named place for the
// phase-11 seam swap.
func checkDeclaredSize(declared, ceiling int64) error {
	if declared > ceiling {
		return errSizeExceeded
	}
	return nil
}

// isStreamingOp reports whether an op is dispatched on the client/server
// streaming path rather than the unary pipeline. The flag is per-op (NOT a
// content-type sniff): fileUpload is the client-stream inbound; fileDownload
// is the server-stream outbound.
func isStreamingOp(op Op) bool {
	return op == OpFileUpload || op == OpFileDownload
}

// connContentTypeStream is the streaming Content-Type the south face admits on
// the streaming path; a charset or other parameter after it is tolerated.
const connContentTypeStream = "application/connect+json"

// checkStreamContentType admits application/connect+json (charset tolerated).
// The unary checkContentType hard-equals application/json and would reject the
// stream at the door (Pitfall 1), so the streaming path uses this instead.
func checkStreamContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct) == connContentTypeStream
}

// serveStreaming runs the STREAMING STAGE-0 gate and dispatches the streaming
// op. The gate mirrors the unary STAGE-0 but (a) admits
// application/connect+json (not application/json), (b) does NOT apply the
// unary Content-Length pre-buffer reject (a chunked body has no fixed length;
// size policy moves to declared_size_bytes after the params frame, Pitfall 2),
// and (c) keys the ops/s throttle on the CHANNEL scope. The stream is ALWAYS
// HTTP 200: any post-route refusal is emitted as a framed 0x02 error trailer,
// never a unary error body, so the guest's trailer-authoritative retry logic
// sees the verdict (WIRE-LESSONS #2). A pre-PeerScope wiring fault (no channel
// scope) is the one case with no session context to frame against — it fails
// closed with a unary internal error.
//
// reqID is the per-request correlation id minted by ServeHTTP at STAGE 0; it
// is already set on the response header by the caller. reqLog is a logger
// pre-decorated with request_id so streaming WARN lines carry the same id.
func (d *dispatcher) serveStreaming(w http.ResponseWriter, r *http.Request, op Op, reqID string, reqLog *slog.Logger) {
	// PeerScope first: without the channel binding there is no scope to key
	// audit/ceilings on — a wiring fault that fails closed. This is the only
	// pre-frame fault written as a unary error (no session to frame against).
	ps, ok := peerScopeFromContext(r.Context())
	if !ok {
		// x-request-id is already set on w.Header() by ServeHTTP before this
		// call, so it will appear on this unary error response too.
		d.recordOp(string(op), "deny", denyInternal)
		writeConnectError(w, mapDeny(denyInternal), "no channel scope on connection")
		return
	}

	// From here every refusal is a framed HTTP-200 trailer. Commit the 200
	// header (x-request-id is already queued on w.Header()) before the first
	// frame.
	w.Header().Set("Content-Type", connContentTypeStream)
	w.WriteHeader(http.StatusOK)

	// Streaming STAGE-0 denies record ops_total directly (southface-02): they
	// precede the op-specific handler's own deny/allow accounting, mirroring the
	// unary denyOp choke point for the throttle/header faults.
	opStr := string(op)
	if err := checkVersion(r); err != nil {
		d.recordOp(opStr, "deny", denyClassForDecodeErr(err))
		_ = writeEndStream(w, &connectError{Code: wireCodeInvalidArgument, Message: "missing or wrong Connect-Protocol-Version"})
		return
	}
	if !checkStreamContentType(r) {
		d.recordOp(opStr, "deny", denyMalformed)
		_ = writeEndStream(w, &connectError{Code: wireCodeInvalidArgument, Message: "Content-Type must be application/connect+json"})
		return
	}

	// ops/s throttle, keyed on the CHANNEL scope (never any body field).
	sess := d.ceilings.Session(ps.FilesystemID)
	if err := sess.TryConsumeOp(); err != nil {
		d.recordOp(opStr, "deny", denyClassForErr(err))
		_ = writeEndStream(w, &connectError{Code: wireCodeResourceExhausted, Message: "operation rate ceiling exceeded"})
		return
	}

	switch op {
	case OpFileUpload:
		d.handleFileUpload(streamCtx{
			w:      w,
			body:   r.Body,
			ctx:    r.Context(),
			ps:     ps,
			sess:   sess,
			reqID:  reqID,
			reqLog: reqLog,
		})
	case OpFileDownload:
		d.handleFileDownload(streamCtx{
			w:      w,
			body:   r.Body,
			ctx:    r.Context(),
			ps:     ps,
			sess:   sess,
			reqID:  reqID,
			reqLog: reqLog,
		})
	default:
		_ = writeEndStream(w, &connectError{Code: wireCodeUnimplemented, Message: "operation not implemented in this build"})
	}
}

// streamCtx carries what a streaming handler needs after the STREAMING STAGE-0
// gate has cleared the request: the response writer (a framed HTTP-200 body),
// the request body read frame-by-frame, the connection context, the
// channel-bound PeerScope, and the per-session ceilings handle. The audit
// hooks are built by the handler from the dispatcher's guard once the params
// (and the resolved grant) are known.
//
// reqID and reqLog carry the T2-18 correlation id (minted by ServeHTTP at
// STAGE 0) and the request-scoped logger so streaming audit events and log
// lines carry the same id as the x-request-id response header.
type streamCtx struct {
	w      http.ResponseWriter
	body   io.Reader
	ctx    context.Context
	ps     PeerScope
	sess   CeilingsSession
	reqID  string
	reqLog *slog.Logger
}

// streamAuditEvent builds a fileUpload audit event from the resolved params +
// grant. ActivityID is a Create (an upload produces a new object);
// Downloadable carries the resolved grant; ByteCount carries the declared
// size (the upload's intended byte count). The durable encoding is the audit
// gate's; the spine passes the value through Guard.Mandate. reqID is the
// T2-18 per-request correlation id threaded end-to-end.
func (d *dispatcher) streamAuditEvent(ps PeerScope, req ResolveRequest, grant Grant, declared int64, reqID string) auditEvent {
	return auditEvent{
		Op:           OpFileUpload,
		Scope:        ps.FilesystemID,
		Path:         req.Path,
		Intent:       req.Intent,
		PeerUID:      ps.UID,
		PeerPID:      ps.PID,
		ActivityID:   activityCreate,
		ObjectHandle: ps.FilesystemID + ":" + req.Path,
		ByteCount:    declared,
		Downloadable: grant.Downloadable,
		RequestID:    reqID,
	}
}

// handleFileUpload reassembles a client-streamed upload (OPS-05). The contract
// (every clause is load-bearing):
//
//   - Read exactly one params frame first; a read error or a leading
//     end-stream frame is a HARD ABORT (WIRE-LESSONS #1). Strict-decode it.
//   - declared_size_bytes is REQUIRED (<=0 denies invalid_argument, no escape
//     hatch — D5 footnote).
//   - Cross-check the decoded filesystem_id against the CHANNEL scope; key
//     everything on the channel scope, never the params value (Anti-pattern).
//   - Resolve(intent=write) from the channel scope; map a resolver error.
//   - PRE-BUFFER size reject (SEC-46): checkDeclaredSize(declared, maxFileSize)
//     BEFORE reading any chunk — zero chunk bytes read on reject (Pitfall 5).
//   - Mandate the ALLOW event BEFORE any chunk (audit-before-ack); an
//     audit-down error denies before any chunk.
//   - fd ceiling around the open handle; bytes ceiling around reassembly
//     (released on EVERY exit — Pitfall 6).
//   - Reassemble via a single io.Pipe -> engine.WriteStream(overwrite=
//     params.OverwriteExisting). Over-declaration (acc > declared) aborts at
//     the ceiling; under-declaration (acc != declared at half-close) also
//     aborts — both n2 invalid_argument/size_exceeded, staging nothing.
//   - EVERY reject writes the 0x02 trailer BEFORE pw.CloseWithError/return
//     (WIRE-LESSONS #2). The stream is always HTTP 200.
func (d *dispatcher) handleFileUpload(sc streamCtx) {
	// ABORTS write the trailer FIRST, then stop intake. denyTrailer emits the
	// deny audit (broker-resolved truth) then the framed verdict. It is called
	// with the resolved req/grant once known; before Resolve, req/grant are
	// zero values (the audit still records the scope/op/path truth available).
	var (
		req      ResolveRequest
		grant    Grant
		declared int64
		acquired int64 // total bytes AcquireBytes'd, released on every exit
	)

	// A deny-Mandate FAILURE degrades the trailer to unavailable (NFR-SEC-79,
	// invariant 8): if the deny record did not durably land, the chain's last
	// record may be the pre-chunk ALLOW — asserting allow for a refused
	// upload — so the verdict the guest sees must be audit-down, never the
	// original refusal. This mirrors the allow-Mandate failure path below.
	denyTrailer := func(auditReason, wireCode, message string) {
		sc.reqLog.Warn("broker deny",
			slog.String(observ.KeyDenyClass, auditReason),
			slog.String(observ.KeyReason, message),
		)
		ev := d.denyAuditEvent(OpFileUpload, sc.ps, req, grant, nil, auditReason)
		ev.RequestID = sc.reqID
		if err := d.guard.Mandate(sc.ctx, mapAuditEvent(ev)); err != nil {
			// Deny-Mandate failure degrades the verdict to audit_down; book the
			// metric as audit_down too so ops_total matches the wire verdict
			// (southface-02).
			d.recordOp(string(OpFileUpload), "deny", denyAuditDown)
			_ = writeEndStream(sc.w, &connectError{Code: wireCodeUnavailable, Message: "audit gate unavailable"})
			return
		}
		d.recordOp(string(OpFileUpload), "deny", auditReason)
		_ = writeEndStream(sc.w, &connectError{Code: wireCode, Message: message})
	}
	// ReleaseBytes balances AcquireBytes on EVERY exit (Pitfall 6). The
	// engine has consumed the bytes durably by the time WriteStream returns,
	// so the in-flight reservation frees once the handler exits regardless of
	// path.
	defer func() { sc.sess.ReleaseBytes(acquired) }()

	// Per-frame read deadline (NFR-SEC-46): extended before EVERY frame read
	// so a stalled peer's next readFrame errors and aborts through the
	// existing hard-abort path instead of pinning the goroutine, an fd slot,
	// and acquired bytes forever. Best-effort: a transport without deadline
	// support (the in-memory test recorder) is tolerated — the live
	// unix-socket server supports it, and its ReadHeaderTimeout re-arms the
	// connection deadline for any subsequent request.
	rc := http.NewResponseController(sc.w)
	extendReadDeadline := func() {
		_ = rc.SetReadDeadline(time.Now().Add(d.frameReadTimeout))
	}

	// --- params frame ---
	extendReadDeadline()
	params, err := readParamsFrame(sc.body)
	if err != nil {
		if errors.Is(err, errFrameTooLarge) {
			denyTrailer(denyThrottle, wireCodeResourceExhausted, "params frame exceeds transport ceiling")
			return
		}
		// truncated / undecodable / expected-params / leading end-stream:
		// HARD ABORT (WIRE-LESSONS #1).
		denyTrailer(denyMalformed, wireCodeInvalidArgument, "malformed params frame")
		return
	}
	declared = params.DeclaredSizeBytes
	if declared <= 0 {
		denyTrailer(denyMalformed, wireCodeInvalidArgument, "declared_size_bytes required")
		return
	}

	// --- channel-scope cross-check (key on the channel, never the body) ---
	if params.FilesystemID != sc.ps.FilesystemID {
		denyTrailer(denyScopeMismatch, wireCodePermissionDenied, "request scope does not match the session channel")
		return
	}

	// --- canonicalize the decoded path ONCE (bypass-01/03) ---
	// Mirror the unary spine boundary: clean params.Path a single time after the
	// scope cross-check and before authz/audit/engine so the resolver, the
	// audit ObjectHandle, and the engine WriteStream target all name the SAME
	// object. A path the canonicalizer rejects is a pre-allow invalid_argument
	// deny — nothing is staged.
	canonUpload, cerr := canonicalizePath(params.Path)
	if cerr != nil {
		denyTrailer(denyMalformed, wireCodeInvalidArgument, "invalid or unsafe path")
		return
	}
	params.Path = canonUpload

	// --- authz Resolve(intent=write) from the channel scope ---
	req = ResolveRequest{Filesystem: sc.ps.FilesystemID, Path: params.Path, Intent: IntentWrite}
	evidence := CallerEvidence{Scope: sc.ps.FilesystemID, GrantedIntents: sc.ps.GrantedIntents}
	grant, err = d.resolver.Resolve(sc.ctx, evidence, req)
	if err != nil {
		wireClass := denyClassForErr(err)
		v := mapDeny(wireClass)
		denyTrailer(wireClass, v.WireCode, "authorization denied")
		return
	}

	// --- PRE-BUFFER size reject (SEC-46): BEFORE any chunk is read ---
	if err := checkDeclaredSize(declared, d.maxFileSize); err != nil {
		denyTrailer(denySizeExceeded, wireCodeInvalidArgument, "declared size exceeds whole-object ceiling")
		return
	}

	// --- audit ALLOW before any chunk (audit-before-ack) ---
	allow := d.streamAuditEvent(sc.ps, req, grant, declared, sc.reqID)
	if err := d.guard.Mandate(sc.ctx, mapAuditEvent(allow)); err != nil {
		// The allow Mandate itself failed (audit down). Deny before any chunk;
		// do NOT re-Mandate a deny (the gate is unavailable) — just frame it.
		// Book the metric as audit_down (southface-02).
		d.recordOp(string(OpFileUpload), "deny", denyAuditDown)
		_ = writeEndStream(sc.w, &connectError{Code: wireCodeUnavailable, Message: "audit gate unavailable"})
		return
	}

	// --- fd ceiling around the open handle ---
	if err := sc.sess.TryAcquireFD(); err != nil {
		denyTrailer(denyThrottle, wireCodeResourceExhausted, "file-descriptor ceiling exceeded")
		return
	}
	defer sc.sess.ReleaseFD()

	// --- reassembly: single io.Pipe -> WriteStream(overwrite=params.OverwriteExisting) ---
	// overwrite_existing defaults to false when the field is absent (JSON zero
	// value), which preserves today's behaviour for any sender that omits it.
	//
	// engineStart times the engine write window (reassembly -> WriteStream
	// commit) for the stage_latency_seconds "engine" histogram, mirroring the
	// unary STAGE-4 timer (southface-02). It is observed once the WriteStream
	// outcome is known on the success commit below.
	engineStart := time.Now()
	pr, pw := io.Pipe()
	writeErrCh := make(chan error, 1)
	go func() {
		// Panic containment (T2-4, RES-02): on a panic in WriteStream,
		// recoverWriteStream closes pr with errInternalPanic (unblocking any
		// producer pw.Write immediately) and sends on writeErrCh so the
		// upload handler can drain and write the deny trailer. The engine's
		// temp+rename atomicity guarantees no torn object is visible.
		defer recoverWriteStream(pr, writeErrCh)
		err := d.engine.WriteStream(sc.ctx, sc.ps.FilesystemID, enginePath(params.Path), pr, params.OverwriteExisting)
		// Close the read end with the engine's error so a producer pw.Write
		// blocked on a reader that returned early (e.g. WriteStream refused
		// already_exists WITHOUT consuming r — A1) unblocks immediately with
		// that error instead of deadlocking on the unread pipe.
		pr.CloseWithError(err)
		writeErrCh <- err
	}()

	var acc int64
	for {
		extendReadDeadline()
		flag, payload, ferr := readFrame(sc.body)
		if ferr != nil {
			// Truncated / oversize frame: HARD ABORT (WIRE-LESSONS #1). The
			// deny Mandate runs first and the trailer (possibly degraded to
			// unavailable) is written BEFORE intake closes (WIRE-LESSONS #2).
			if errors.Is(ferr, errFrameTooLarge) {
				denyTrailer(denyThrottle, wireCodeResourceExhausted, "frame exceeds transport ceiling")
			} else {
				denyTrailer(denyAborted, wireCodeAborted, "malformed inbound frame")
			}
			// Close the engine pipe with a NON-EOF abort sentinel, never the raw
			// ferr: a truncated frame or a mid-stream connection drop surfaces as
			// io.EOF / io.ErrUnexpectedEOF, and io.Copy inside WriteStream treats
			// a pipe read returning io.EOF as a CLEAN end-of-stream — committing
			// the partial bytes (temp+rename) instead of discarding them. The
			// sentinel forces WriteStream to fail and reclaim the temp so an
			// aborted upload stages nothing visible (atomicity on the abort path).
			pw.CloseWithError(errStreamAborted)
			<-writeErrCh
			return
		}
		if flag == endStreamFlag {
			break // client half-close = authoritative end (no numChunks)
		}
		if flag != dataFlag {
			// Unknown frame flag (e.g. a compression flag this build does not
			// negotiate, or any reserved value): HARD ABORT, mirroring
			// readParamsFrame's flag check. Silently treating an unknown-flag
			// frame as a data frame would feed bytes framed under different
			// semantics into the reassembly (WIRE-LESSONS #1).
			denyTrailer(denyMalformed, wireCodeInvalidArgument, "unsupported frame flag")
			pw.CloseWithError(errMalformedFrame)
			<-writeErrCh
			return
		}

		cf, cerr := decodeChunkFrame(payload)
		if cerr != nil {
			// Undecodable / unknown-field / chunk-less data frame: HARD ABORT
			// (WIRE-LESSONS #1).
			denyTrailer(denyMalformed, wireCodeInvalidArgument, "malformed chunk frame")
			pw.CloseWithError(errMalformedFrame)
			<-writeErrCh
			return
		}

		n := int64(len(cf.Chunk))
		acc += n
		if acc > declared {
			// Over-declaration: abort at the ceiling (n2). Deny Mandate then
			// trailer, before intake closes.
			denyTrailer(denySizeExceeded, wireCodeInvalidArgument, "accumulated bytes exceed declared size")
			pw.CloseWithError(errSizeExceeded)
			<-writeErrCh
			return
		}

		if err := sc.sess.AcquireBytes(n); err != nil {
			denyTrailer(denyThrottle, wireCodeResourceExhausted, "in-flight byte ceiling exceeded")
			pw.CloseWithError(err)
			<-writeErrCh
			return
		}
		acquired += n

		if _, werr := pw.Write(cf.Chunk); werr != nil {
			// The pipe write failed: the engine rejected (e.g. already_exists,
			// A1). Drain the engine error and map it.
			engErr := <-writeErrCh
			v := mapDeny(denyClassForEngineErr(engErr))
			denyTrailer(auditTruthForEngineErr(engErr), v.WireCode, "upload refused")
			return
		}
	}

	// --- half-close: enforce the under-direction (n2) ---
	if acc != declared {
		denyTrailer(denySizeExceeded, wireCodeInvalidArgument, "accumulated bytes do not match declared size")
		pw.CloseWithError(errSizeExceeded)
		<-writeErrCh
		return
	}

	// Commit: closing the pipe writer signals EOF; WriteStream's temp+rename
	// makes the object visible only now.
	pw.Close()
	werr := <-writeErrCh
	d.observeStage("engine", time.Since(engineStart).Seconds())
	if werr != nil {
		v := mapDeny(denyClassForEngineErr(werr))
		denyTrailer(auditTruthForEngineErr(werr), v.WireCode, "upload refused")
		return
	}

	// SUCCESS: the ack IS the trailer. The allow Mandate already preceded it.
	d.recordOp(string(OpFileUpload), "allow", denyclassNone)
	_ = writeEndStream(sc.w, nil)
}

// streamDownloadAuditEvent builds a fileDownload audit event from the resolved
// params + grant. ActivityID is a Read; Downloadable carries the resolved
// grant; ByteCount is zero (byte count is unknown ahead of the range read;
// the audit records the intent, not the transferred size). ObjectHandle is
// the scope:path derived from the objectIDStore resolution. reqID is the
// T2-18 per-request correlation id threaded end-to-end.
func (d *dispatcher) streamDownloadAuditEvent(ps PeerScope, req ResolveRequest, grant Grant, reqID string) auditEvent {
	return auditEvent{
		Op:           OpFileDownload,
		Scope:        ps.FilesystemID,
		Path:         req.Path,
		Intent:       req.Intent,
		PeerUID:      ps.UID,
		PeerPID:      ps.PID,
		ActivityID:   activityRead,
		ObjectHandle: ps.FilesystemID + ":" + req.Path,
		ByteCount:    0,
		Downloadable: grant.Downloadable,
		RequestID:    reqID,
	}
}

// handleFileDownload streams the object bytes as a server-stream (OPS-06).
// The contract (every clause is load-bearing):
//
//   - Read exactly one params frame (ONE 0x00 data frame); strict-decode it.
//     A read error or a leading end-stream frame is a HARD ABORT (WIRE-LESSONS #1).
//   - Cross-check decoded filesystem_id against the CHANNEL scope; everything
//     keys on the channel scope (Anti-pattern).
//   - Resolve uuid→(scope,path) from the session-scoped objectIDStore; a uuid
//     unknown to this session is not_found. A cross-scope uuid (stored scope ≠
//     channel scope) audits as scope_mismatch but degrades to not_found on the
//     wire (anti-enumeration, D8).
//   - Resolve(intent=read) from the channel scope; map resolver errors.
//   - DOWNLOADABLE@READ from the broker-resolved grant (NFR-SEC-73): the wire
//     flag is NEVER trusted; a non-downloadable grant denies.
//   - Mandate the ALLOW event BEFORE the first data frame (audit-before-ack,
//     SEC-79); an audit-write failure denies before any byte is sent.
//   - Resolve the read window: a length of 0 is an EMPTY window (zero bytes),
//     never a read-to-EOF. A nil Range is the WHOLE object — its length is the
//     object's current size from a Stat run BEFORE the ALLOW Mandate, so a
//     vanished object records one deny, not an allow-then-deny pair.
//   - Stream bytes via engine.ReadRange(offset, length) in downloadChunkSize
//     chunks, each framed as a 0x00 data frame {"data":"<base64>"}.
//   - Finish with a 0x02 end-stream success trailer. A mid-stream engine error
//     terminates with a 0x02 error trailer; the stream is ALWAYS HTTP 200.
func (d *dispatcher) handleFileDownload(sc streamCtx) {
	var (
		req   ResolveRequest
		grant Grant
	)

	// denyDownloadTrailer emits the deny audit Mandate (broker-resolved truth)
	// then writes the deny trailer. If the Mandate itself fails, the verdict
	// degrades to unavailable — an unrecorded truth never surfaces on the wire
	// (NFR-SEC-79, invariant 8, mirrors denyTrailer in handleFileUpload).
	denyDownloadTrailer := func(auditReason, wireCode, message string) {
		sc.reqLog.Warn("broker deny",
			slog.String(observ.KeyDenyClass, auditReason),
			slog.String(observ.KeyReason, message),
		)
		ev := d.denyAuditEvent(OpFileDownload, sc.ps, req, grant, nil, auditReason)
		ev.RequestID = sc.reqID
		if err := d.guard.Mandate(sc.ctx, mapAuditEvent(ev)); err != nil {
			// Deny-Mandate failure degrades to audit_down; book the metric to
			// match the wire verdict (southface-02).
			d.recordOp(string(OpFileDownload), "deny", denyAuditDown)
			_ = writeEndStream(sc.w, &connectError{Code: wireCodeUnavailable, Message: "audit gate unavailable"})
			return
		}
		d.recordOp(string(OpFileDownload), "deny", auditReason)
		_ = writeEndStream(sc.w, &connectError{Code: wireCode, Message: message})
	}

	// Per-frame read deadline on the single inbound frame (the params frame).
	rc := http.NewResponseController(sc.w)
	_ = rc.SetReadDeadline(time.Now().Add(d.frameReadTimeout))

	// --- params frame (exactly one) ---
	flag, payload, err := readFrame(sc.body)
	if err != nil {
		if errors.Is(err, errFrameTooLarge) {
			denyDownloadTrailer(denyThrottle, wireCodeResourceExhausted, "params frame exceeds transport ceiling")
			return
		}
		denyDownloadTrailer(denyMalformed, wireCodeInvalidArgument, "malformed params frame")
		return
	}
	if flag != dataFlag {
		denyDownloadTrailer(denyMalformed, wireCodeInvalidArgument, "malformed params frame")
		return
	}

	var params fileDownloadRequest
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil {
		denyDownloadTrailer(denyMalformed, wireCodeInvalidArgument, "malformed params frame")
		return
	}
	var extra json.RawMessage
	if dec.Decode(&extra) == nil {
		denyDownloadTrailer(denyMalformed, wireCodeInvalidArgument, "malformed params frame")
		return
	}

	// --- channel-scope cross-check (key on the channel, never the body) ---
	if params.FilesystemID != sc.ps.FilesystemID {
		denyDownloadTrailer(denyScopeMismatch, wireCodePermissionDenied, "request scope does not match the session channel")
		return
	}

	// --- uuid → (scope, path) resolution via the session-scoped objectIDStore ---
	// The uuid was minted by this broker session's listing or readFile emitter.
	// An unknown uuid is not_found. A cross-scope uuid (the stored scope differs
	// from the channel scope) audits as scope_mismatch but degrades to not_found
	// on the wire so a valid uuid from another session cannot be used to enumerate
	// scope membership (D8, anti-enumeration).
	rec, ok := d.ids.lookup(params.UUID)
	if !ok {
		denyDownloadTrailer(denyNotFound, wireCodeNotFound, "object not found")
		return
	}
	if rec.scope != sc.ps.FilesystemID {
		// Cross-scope: audit scope_mismatch truth, wire not_found (D8). The
		// ops_total deny_class is the audited TRUTH (scope_mismatch), not the
		// degraded wire class — the metric carries the same truth the audit
		// record does (southface-02).
		//
		// Populate req from the resolved record (which holds the real path and
		// the probed scope) BEFORE building the deny event so the scope_mismatch
		// audit names the handle that was actually probed — an empty handle would
		// blind the anti-enumeration trail this deny exists to capture
		// (southface-06).
		probed := ResolveRequest{Filesystem: rec.scope, Path: rec.path, Intent: IntentRead}
		ev := d.denyAuditEvent(OpFileDownload, sc.ps, probed, grant, nil, denyScopeMismatch)
		ev.RequestID = sc.reqID
		if err := d.guard.Mandate(sc.ctx, mapAuditEvent(ev)); err != nil {
			d.recordOp(string(OpFileDownload), "deny", denyAuditDown)
			_ = writeEndStream(sc.w, &connectError{Code: wireCodeUnavailable, Message: "audit gate unavailable"})
			return
		}
		d.recordOp(string(OpFileDownload), "deny", denyScopeMismatch)
		_ = writeEndStream(sc.w, &connectError{Code: wireCodeNotFound, Message: "object not found"})
		return
	}
	// Canonicalize the resolved path ONCE before authz/audit/engine
	// (bypass-01/03). The uuid store is now keyed off canonical paths (the
	// listing and readFile emitters mint against the spine-canonicalized
	// req.Path), so this is normally a no-op identity; it is the belt-and-
	// suspenders that guarantees the downloadable tag, the engine ReadRange
	// target, and the audit ObjectHandle all name the SAME object even for any
	// record minted before this boundary existed. A non-canonical record is a
	// not_found-class refusal — never an egress grant on a dirty path.
	canonDownload, cerr := canonicalizePath(rec.path)
	if cerr != nil {
		denyDownloadTrailer(denyNotFound, wireCodeNotFound, "object not found")
		return
	}
	// Populate req from the resolved (scope, path) for the remainder of the
	// audit and resolver calls.
	req = ResolveRequest{Filesystem: sc.ps.FilesystemID, Path: canonDownload, Intent: IntentRead}

	// --- authz Resolve(intent=read) from the channel scope ---
	evidence := CallerEvidence{Scope: sc.ps.FilesystemID, GrantedIntents: sc.ps.GrantedIntents}
	grant, err = d.resolver.Resolve(sc.ctx, evidence, req)
	if err != nil {
		wireClass := denyClassForErr(err)
		v := mapDeny(wireClass)
		denyDownloadTrailer(wireClass, v.WireCode, "authorization denied")
		return
	}

	// --- DOWNLOADABLE@READ, broker-side (NFR-SEC-73, A2) ---
	// The grant is the broker-resolved truth; the wire flag is never consulted.
	if !grant.Downloadable {
		denyDownloadTrailer(denyNotDownloadable, wireCodePermissionDenied, "object not downloadable")
		return
	}

	// --- resolve the read window BEFORE the ALLOW audit ---
	// The engine ReadRange contract is the half-open window
	// [offset, offset+length): a length of 0 is an EMPTY window (zero bytes),
	// NOT a read-to-EOF — both engines treat it that way. A nil Range is
	// therefore a WHOLE-object read, for which the length is the object's
	// current size resolved by a Stat. The Stat runs BEFORE the ALLOW Mandate
	// so a vanished object (the listing that minted the uuid raced a delete)
	// records a single deny, never an allow-then-deny pair; it degrades to the
	// engine-classified verdict (not_found) and no bytes are sent.
	var offset, length int64
	if params.Range != nil {
		offset = params.Range.Offset
		length = params.Range.Length
	} else {
		// statSizeContained recovers a panicking engine.Stat into errInternalPanic
		// so a whole-object size probe cannot escape the streaming contract: every
		// download verdict is a framed HTTP-200 trailer, never a unary error from
		// the outer recoverDispatch net (which has already committed the 200
		// header here). A real Stat error or a recovered panic both classify
		// through denyClassForEngineErr (a panic → denyInternal).
		size, serr := statSizeContained(sc.ctx, d.engine, sc.ps.FilesystemID, enginePath(req.Path))
		if serr != nil {
			wireClass := denyClassForEngineErr(serr)
			denyDownloadTrailer(wireClass, mapDeny(wireClass).WireCode, "object not found")
			return
		}
		length = size
	}

	// --- audit ALLOW before any data frame (audit-before-ack, SEC-79) ---
	allow := d.streamDownloadAuditEvent(sc.ps, req, grant, sc.reqID)
	if err := d.guard.Mandate(sc.ctx, mapAuditEvent(allow)); err != nil {
		// The allow Mandate failed (audit down). Deny before any byte is sent;
		// do NOT re-Mandate a deny (the gate is unavailable). Book the metric as
		// audit_down (southface-02).
		d.recordOp(string(OpFileDownload), "deny", denyAuditDown)
		_ = writeEndStream(sc.w, &connectError{Code: wireCodeUnavailable, Message: "audit gate unavailable"})
		return
	}

	// --- fd ceiling around the engine read window (NFR-SEC-46, conc-02) ---
	// The download opens a real engine fd for the whole stream (ReadRange ->
	// OpenScopeRoot). Acquire the per-session fd slot BEFORE launching the
	// ReadRange goroutine and release it on every exit, exactly as the upload
	// path does — without this the session-fd ceiling governs uploads but is a
	// no-op for downloads, and (with crutch-01) a stalled reader's held fds
	// would accrue unbounded.
	if err := sc.sess.TryAcquireFD(); err != nil {
		denyDownloadTrailer(denyThrottle, wireCodeResourceExhausted, "file-descriptor ceiling exceeded")
		return
	}
	defer sc.sess.ReleaseFD()

	// --- stream bytes: ReadRange → framed data frames ---
	// engineStart times the engine read window (ReadRange -> last data frame)
	// for the stage_latency_seconds "engine" histogram, mirroring the unary
	// STAGE-4 timer (southface-02). It is observed at each terminal exit of the
	// streaming loop.
	engineStart := time.Now()
	rel := enginePath(req.Path)
	pr, pw := io.Pipe()
	readErrCh := make(chan error, 1)
	go func() {
		// Panic containment (T2-4, RES-02): on a panic in ReadRange,
		// recoverReadStream closes pw with errInternalPanic (unblocking the
		// consumer io.ReadFull loop immediately) and sends on readErrCh so
		// the download handler can terminate with an error trailer.
		defer recoverReadStream(pw, readErrCh)
		err := d.engine.ReadRange(sc.ctx, sc.ps.FilesystemID, rel, offset, length, pw)
		pw.CloseWithError(err)
		readErrCh <- err
	}()

	// Per-frame WRITE deadline (NFR-SEC-46, crutch-01): armed before EVERY
	// outbound data frame so a stalled reader's filled send buffer makes the
	// next writeFrame error instead of blocking forever. The errored writeFrame
	// runs the existing drain path below (CloseWithError on the read pipe ->
	// the ReadRange goroutine unblocks and returns -> the deferred ReleaseFD
	// fires). Best-effort: a transport without deadline support (the in-memory
	// test recorder) is tolerated exactly as the upload read deadline is — the
	// live unix-socket server supports it.
	extendWriteDeadline := func() {
		_ = rc.SetWriteDeadline(time.Now().Add(d.frameWriteTimeout))
	}

	buf := make([]byte, downloadChunkSize)
	for {
		n, rerr := io.ReadFull(pr, buf)
		if n > 0 {
			frame, merr := json.Marshal(downloadDataFrame{Data: buf[:n]})
			if merr != nil {
				// JSON marshal of a []byte is infallible in practice (base64).
				// Treat as internal; drain the reader and terminate with error.
				pr.CloseWithError(merr)
				<-readErrCh
				d.observeStage("engine", time.Since(engineStart).Seconds())
				d.recordOp(string(OpFileDownload), "deny", denyInternal)
				_ = writeEndStream(sc.w, &connectError{Code: wireCodeInternal, Message: "frame encode failed"})
				return
			}
			extendWriteDeadline()
			if werr := writeFrame(sc.w, dataFlag, frame); werr != nil {
				// Client disconnected; drain and return without a trailer
				// (connection is gone; writing a trailer would also fail). Book
				// the verdict as aborted so a dropped download is still visible
				// in ops_total (southface-02).
				pr.CloseWithError(werr)
				<-readErrCh
				d.observeStage("engine", time.Since(engineStart).Seconds())
				d.recordOp(string(OpFileDownload), "deny", denyAborted)
				return
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
				// EOF after a partial read (ReadFull returns ErrUnexpectedEOF
				// at the natural end of a non-multiple-of-chunk-size object).
				// Drain the engine goroutine, then write the success trailer.
				if engErr := <-readErrCh; engErr != nil {
					d.observeStage("engine", time.Since(engineStart).Seconds())
					d.recordOp(string(OpFileDownload), "deny", auditTruthForEngineErr(engErr))
					_ = writeEndStream(sc.w, &connectError{Code: wireCodeInternal, Message: "read error"})
					return
				}
				break
			}
			// A read error from the pipe means the engine goroutine faulted.
			// Drain the engine goroutine; prefer its error over the pipe's
			// consumer error (the engine error is the root cause).
			engErr := <-readErrCh
			if engErr == nil {
				engErr = rerr
			}
			sc.reqLog.Error("download engine fault", slog.String("err", engErr.Error()))
			d.observeStage("engine", time.Since(engineStart).Seconds())
			d.recordOp(string(OpFileDownload), "deny", auditTruthForEngineErr(engErr))
			_ = writeEndStream(sc.w, &connectError{Code: wireCodeInternal, Message: "read error"})
			return
		}
	}

	// SUCCESS: the ack IS the trailer. The allow Mandate already preceded it.
	d.observeStage("engine", time.Since(engineStart).Seconds())
	d.recordOp(string(OpFileDownload), "allow", denyclassNone)
	_ = writeEndStream(sc.w, nil)
}

// statSizeContained resolves the object's current size for a whole-object
// download via engine.Stat, recovering a panicking engine into errInternalPanic.
// The download handler runs Stat on the MAIN handler goroutine (not the
// ReadRange pipe goroutine, which has its own recoverReadStream), so without
// this guard a Stat panic would unwind to recoverDispatch and surface as a
// unary error AFTER the HTTP-200 stream header was already committed — breaking
// the always-framed-trailer streaming contract. A recovered panic returns a
// zero size and errInternalPanic, which the caller classifies through
// denyClassForEngineErr (→ denyInternal → wireCodeInternal), the same path as
// any other unrecognised engine fault.
func statSizeContained(ctx context.Context, e Engine, scope, path string) (size int64, err error) {
	defer func() {
		if v := recover(); v != nil {
			size = 0
			err = errInternalPanic
		}
	}()
	fi, serr := e.Stat(ctx, scope, path)
	if serr != nil {
		return 0, serr
	}
	return fi.Size, nil
}

// decodeChunkFrame strict-decodes one chunk data frame: unknown fields are
// rejected (DisallowUnknownFields), a trailing second JSON value is rejected
// (single-value enforcement, the same discipline as the params frame and
// every unary body), and an ABSENT or null chunk member is rejected — {} and
// {"chunk":null} are not 0-byte chunks, they are malformed frames. A present
// empty chunk ({"chunk":""}) decodes to a non-nil empty slice and is a legal
// 0-byte chunk. The contract-named numChunks member is accepted (see
// uploadChunkFrame) but never read.
func decodeChunkFrame(payload []byte) (uploadChunkFrame, error) {
	var cf uploadChunkFrame
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cf); err != nil {
		return uploadChunkFrame{}, errMalformedFrame
	}
	var extra json.RawMessage
	if dec.Decode(&extra) == nil {
		return uploadChunkFrame{}, errMalformedFrame
	}
	if cf.Chunk == nil {
		return uploadChunkFrame{}, errMalformedFrame
	}
	return cf, nil
}

// readParamsFrame reads the first frame and strict-decodes the params. A
// non-data flag (e.g. a leading end-stream frame) is errExpectedParams; a
// frame read error propagates (truncated/oversize). The params are strict
// (DisallowUnknownFields) so a rejected field (the absent overwrite knob, or
// metadata_retention_days) is refused.
func readParamsFrame(r io.Reader) (uploadParamsFrame, error) {
	flag, payload, err := readFrame(r)
	if err != nil {
		return uploadParamsFrame{}, err
	}
	if flag != dataFlag {
		return uploadParamsFrame{}, errExpectedParams
	}
	var p uploadParamsFrame
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return uploadParamsFrame{}, errMalformedFrame
	}
	var extra json.RawMessage
	if dec.Decode(&extra) == nil {
		return uploadParamsFrame{}, errMalformedFrame
	}
	return p, nil
}
