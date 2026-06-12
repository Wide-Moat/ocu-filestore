// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

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
// content-type sniff): fileUpload is the client-stream this phase implements;
// fileDownload is listed so the routing is correct, though it stays
// unimplemented (deferred).
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
func (d *dispatcher) serveStreaming(w http.ResponseWriter, r *http.Request, op Op) {
	// PeerScope first: without the channel binding there is no scope to key
	// audit/ceilings on — a wiring fault that fails closed. This is the only
	// pre-frame fault written as a unary error (no session to frame against).
	ps, ok := peerScopeFromContext(r.Context())
	if !ok {
		writeConnectError(w, mapDeny(denyInternal), "no channel scope on connection")
		return
	}

	// From here every refusal is a framed HTTP-200 trailer. Commit the 200
	// header before the first frame.
	w.Header().Set("Content-Type", connContentTypeStream)
	w.WriteHeader(http.StatusOK)

	if err := checkVersion(r); err != nil {
		_ = writeEndStream(w, &connectError{Code: wireCodeInvalidArgument, Message: "missing or wrong Connect-Protocol-Version"})
		return
	}
	if !checkStreamContentType(r) {
		_ = writeEndStream(w, &connectError{Code: wireCodeInvalidArgument, Message: "Content-Type must be application/connect+json"})
		return
	}

	// ops/s throttle, keyed on the CHANNEL scope (never any body field).
	sess := d.ceilings.Session(ps.FilesystemID)
	if err := sess.TryConsumeOp(); err != nil {
		_ = writeEndStream(w, &connectError{Code: wireCodeResourceExhausted, Message: "operation rate ceiling exceeded"})
		return
	}

	switch op {
	case OpFileUpload:
		d.handleFileUpload(streamCtx{
			w:    w,
			body: r.Body,
			ctx:  r.Context(),
			ps:   ps,
			sess: sess,
		})
	default: // OpFileDownload — deferred
		_ = writeEndStream(w, &connectError{Code: wireCodeUnimplemented, Message: "operation not implemented in this build"})
	}
}

// streamCtx carries what a streaming handler needs after the STREAMING STAGE-0
// gate has cleared the request: the response writer (a framed HTTP-200 body),
// the request body read frame-by-frame, the connection context, the
// channel-bound PeerScope, and the per-session ceilings handle. The audit
// hooks are built by the handler from the dispatcher's guard once the params
// (and the resolved grant) are known.
type streamCtx struct {
	w    http.ResponseWriter
	body io.Reader
	ctx  context.Context
	ps   PeerScope
	sess CeilingsSession
}

// streamAuditEvent builds a fileUpload audit event from the resolved params +
// grant. ActivityID is a Create (an upload produces a new object);
// Downloadable carries the resolved grant; ByteCount carries the declared
// size (the upload's intended byte count). The durable encoding is the audit
// gate's; the spine passes the value through Guard.Mandate.
func (d *dispatcher) streamAuditEvent(ps PeerScope, req ResolveRequest, grant Grant, declared int64) auditEvent {
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
		ev := d.denyAuditEvent(OpFileUpload, sc.ps, req, grant, nil, auditReason)
		if err := d.guard.Mandate(sc.ctx, mapAuditEvent(ev)); err != nil {
			_ = writeEndStream(sc.w, &connectError{Code: wireCodeUnavailable, Message: "audit gate unavailable"})
			return
		}
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
	allow := d.streamAuditEvent(sc.ps, req, grant, declared)
	if err := d.guard.Mandate(sc.ctx, mapAuditEvent(allow)); err != nil {
		// The allow Mandate itself failed (audit down). Deny before any chunk;
		// do NOT re-Mandate a deny (the gate is unavailable) — just frame it.
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
	pr, pw := io.Pipe()
	writeErrCh := make(chan error, 1)
	go func() {
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
			pw.CloseWithError(ferr)
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
	if werr := <-writeErrCh; werr != nil {
		v := mapDeny(denyClassForEngineErr(werr))
		denyTrailer(auditTruthForEngineErr(werr), v.WireCode, "upload refused")
		return
	}

	// SUCCESS: the ack IS the trailer. The allow Mandate already preceded it.
	_ = writeEndStream(sc.w, nil)
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
