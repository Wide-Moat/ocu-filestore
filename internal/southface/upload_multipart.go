// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
)

// PENDING-PHASE-7(A2-multipart): fileUpload over multipart/form-data. The wire
// is a POST carrying two ordered parts: (1) a form FIELD named "params" whose
// value is the upload params JSON (uploadParamsFrame: filesystem_id top-level,
// path, declared_size_bytes REQUIRED, overwrite_existing omitempty, write
// authorization_metadata); (2) a file PART named "file" (filename "upload")
// streaming the RAW source bytes with NO per-chunk envelope. The end of the
// "file" part is the closing multipart boundary. The body must yield EXACTLY
// declared_size_bytes — both over- and under-declaration are refused
// pre-assembly, staging nothing (the engine's temp+rename atomicity means a
// torn upload leaves no object). Sibling-proven, frozen pending #292.
//
// This handler PORTS the surviving upload algorithm from the Connect
// framed-trailer handleFileUpload: the declared-size pre-buffer reject, the
// channel-scope cross-check (request filesystem_id vs the credscope-bound
// scope), canonicalizePath, the Resolve(write-intent) authz, audit-before-ack
// via Guard.Mandate, the fd+in-flight-bytes ceilings (acquire/ReleaseBytes/
// ReleaseFD on EVERY exit path), the io.Pipe -> engine.WriteStream overwrite,
// and the over/under-declaration aborts. Only the TRANSPORT edges change: the
// Connect params-frame-then-chunk-frames loop becomes multipart NextPart()/part
// reads, and the writeEndStream trailer becomes plain HTTP — writeRESTDeny on a
// deny, HTTP 200 on success. The success body is the client-ignores-it tolerated
// form (an empty 200; the optional {"file":FilesystemFile} body is deferred).
//
// Unlike the streaming Connect path, NO HTTP status is committed until the
// terminal outcome is known: every pre-assembly check and every mid-stream abort
// writes a clean writeRESTDeny (status + BoundedReason), and success writes a
// single HTTP 200 at the very end. There is no framed-trailer-after-200 contract
// to honour, so a refusal is always a real HTTP status.

// uploadReadChunk is the buffer size for one read off the streamed "file" part.
// Each client write is below the per-message ceiling (defaultMessageCeiling); a
// single Read off the part may return less than a full client write, so the
// handler reads in a loop with this fixed buffer rather than assuming one read
// drains a write. It is the moral equivalent of one inbound data frame in the
// retired Connect path: every read is bytes-ceiling-acquired and size-checked
// against the running total before it reaches the engine pipe.
const uploadReadChunk = 256 * 1024

// errUploadOverDeclared — the streamed "file" part yielded MORE bytes than
// declared_size_bytes. Detected mid-stream (running total exceeds declared)
// before the excess reaches the engine, so the destination is never partially
// staged. Maps to invalid_argument/size_exceeded. Match with errors.Is.
var errUploadOverDeclared = errors.New("southface: upload body exceeds declared size")

// serveUploadMultipart is the STAGE-0 entry for the multipart fileUpload op on
// the REST transport. It mirrors the unary ServeHTTP STAGE-0 prologue (mint the
// per-request correlation id, stamp x-request-id, derive a request-scoped
// logger, install the panic-recovery net) and the channel-scope/throttle gate,
// then runs the multipart upload handler. It is the multipart counterpart to the
// retired serveStreaming entry.
//
// The PeerScope SOURCE is gated exactly as the unary path: when a credential
// extractor is wired, the scope is derived from the edge-injected Authorization:
// Bearer WITHOUT the request-fsid cross-check (the cross-check is the handler's
// params-scope cross-check, which already names the scope_mismatch truth);
// otherwise it reads the unix peer scope stashed in the connection context (the
// fallback source the router tests and any contextWithPeerScope caller rely on).
// A missing/rejected credential is unauthenticated (401); an absent context
// scope on the fallback path is a wiring fault and fails closed.
//
// Unlike the Connect streaming entry, NO HTTP 200 is committed here: a STAGE-0
// refusal is a real writeRESTDeny status, and the handler commits 200 only on a
// fully reassembled, size-matched success.
func (d *dispatcher) serveUploadMultipart(w http.ResponseWriter, r *http.Request) {
	reqID := newCorrelationID()
	w.Header().Set(requestIDHeader, reqID)
	reqLog := d.logger.With(slog.String(observ.KeyRequestID, reqID))
	defer d.recoverDispatch(w, &reqLog)()

	// STAGE 0: PeerScope — the host-attested channel identity. Source gated (A5)
	// exactly as the unary path.
	var ps PeerScope
	if d.credExtractor != nil {
		var v DenyVerdict
		var ok bool
		ps, v, ok = peerScopeFromCredential(r, d.credExtractor)
		if !ok {
			d.recordOp(string(OpFileUpload), "deny", v.AuditReason)
			d.denyWithLog(w, reqLog, v, "credential rejected")
			return
		}
	} else {
		var ok bool
		ps, ok = peerScopeFromContext(r.Context())
		if !ok {
			d.recordOp(string(OpFileUpload), "deny", denyInternal)
			d.denyWithLog(w, reqLog, mapDeny(denyInternal), "no channel scope on connection")
			return
		}
	}

	// STAGE 0: ops/s throttle, keyed on the CHANNEL scope (PeerScope), never on
	// any body field — nothing trusts the multipart params before the handler's
	// scope cross-check.
	sess := d.ceilings.Session(ps.FilesystemID)
	if err := sess.TryConsumeOp(); err != nil {
		d.recordOp(string(OpFileUpload), "deny", denyClassForErr(err))
		d.denyWithLog(w, reqLog, mapDeny(denyClassForErr(err)), "operation rate ceiling exceeded")
		return
	}

	d.handleFileUploadMultipart(w, r, ps, sess, reqID, reqLog)
}

// handleFileUploadMultipart reassembles a multipart/form-data upload (OPS-05)
// over the REST transport. Every clause of the surviving upload contract is
// load-bearing:
//
//   - Read the "params" part FIRST. A missing params part, a non-"params" first
//     part, or an undecodable params JSON is a HARD reject (invalid_argument).
//   - declared_size_bytes is REQUIRED (<=0 denies invalid_argument, no escape
//     hatch).
//   - Cross-check the decoded filesystem_id against the credscope-bound CHANNEL
//     scope; key everything on the channel scope, never the params value.
//   - canonicalizePath the decoded path ONCE before authz/audit/engine.
//   - Resolve(intent=write) from the channel scope; map a resolver error.
//   - PRE-ASSEMBLY size reject (SEC-46): checkDeclaredSize(declared, maxFileSize)
//     BEFORE reading any file byte.
//   - Mandate the ALLOW event BEFORE any file byte (audit-before-ack); an
//     audit-down error denies before any byte is read.
//   - fd ceiling around the open handle; bytes ceiling around reassembly
//     (released on EVERY exit).
//   - Reassemble via a single io.Pipe -> engine.WriteStream(overwrite=
//     params.OverwriteExisting). Over-declaration (acc > declared) aborts before
//     the excess reaches the engine; under-declaration (acc != declared at the
//     closing boundary) aborts — both invalid_argument/size_exceeded, staging
//     nothing (temp+rename atomicity).
//   - EVERY refusal writes writeRESTDeny (HTTP status + BoundedReason); success
//     writes a single HTTP 200 with no body the client reads.
func (d *dispatcher) handleFileUploadMultipart(w http.ResponseWriter, r *http.Request, ps PeerScope, sess CeilingsSession, reqID string, reqLog *slog.Logger) {
	var (
		req      ResolveRequest
		grant    Grant
		declared int64
		acquired int64 // total bytes AcquireBytes'd, released on every exit
	)

	// denyUpload emits the deny audit (broker-resolved truth) then the REST deny
	// response. A deny-Mandate FAILURE degrades the verdict to unavailable
	// (NFR-SEC-79, invariant 8): if the deny record did not durably land, the
	// chain's last record may be the pre-assembly ALLOW — asserting allow for a
	// refused upload — so the verdict the guest sees must be audit-down, never
	// the original refusal. This mirrors the allow-Mandate failure path below
	// and the retired Connect denyTrailer.
	denyUpload := func(auditReason, message string) {
		reqLog.Warn("broker deny",
			slog.String(observ.KeyDenyClass, auditReason),
			slog.String(observ.KeyReason, message),
		)
		ev := d.denyAuditEvent(OpFileUpload, ps, req, grant, "", auditReason)
		ev.RequestID = reqID
		if err := d.guard.Mandate(r.Context(), mapAuditEvent(ev)); err != nil {
			// Deny-Mandate failure degrades the verdict to audit_down; book the
			// metric as audit_down too so ops_total matches the wire verdict.
			d.recordOp(string(OpFileUpload), "deny", denyAuditDown)
			writeRESTDeny(w, mapDeny(denyAuditDown), "audit gate unavailable")
			return
		}
		d.recordOp(string(OpFileUpload), "deny", auditReason)
		writeRESTDeny(w, mapDeny(auditReason), message)
	}

	// ReleaseBytes balances AcquireBytes on EVERY exit. The engine has consumed
	// the bytes durably by the time WriteStream returns, so the in-flight
	// reservation frees once the handler exits regardless of path.
	defer func() { sess.ReleaseBytes(acquired) }()

	// --- multipart reader (streaming, NOT ParseMultipartForm which buffers) ---
	mr, err := r.MultipartReader()
	if err != nil {
		denyUpload(denyMalformed, "request is not multipart/form-data")
		return
	}

	// --- params part (FIRST part, form field "params") ---
	params, ok := d.readUploadParams(mr, denyUpload)
	if !ok {
		return
	}
	declared = params.DeclaredSizeBytes
	if declared <= 0 {
		denyUpload(denyMalformed, "declared_size_bytes required")
		return
	}

	// --- channel-scope cross-check (key on the channel, never the body) ---
	if params.FilesystemID != ps.FilesystemID {
		denyUpload(denyScopeMismatch, "request scope does not match the session channel")
		return
	}

	// --- canonicalize the decoded path ONCE (bypass-01/03) ---
	canonUpload, cerr := canonicalizePath(params.Path)
	if cerr != nil {
		denyUpload(denyMalformed, "invalid or unsafe path")
		return
	}
	params.Path = canonUpload

	// --- authz Resolve(intent=write) from the channel scope ---
	req = ResolveRequest{Filesystem: ps.FilesystemID, Path: params.Path, Intent: IntentWrite}
	evidence := CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: ps.GrantedIntents}
	grant, err = d.resolver.Resolve(r.Context(), evidence, req)
	if err != nil {
		denyUpload(denyClassForErr(err), "authorization denied")
		return
	}

	// --- PRE-ASSEMBLY size reject (SEC-46): BEFORE the file part is read ---
	if err := checkDeclaredSize(declared, d.maxFileSize); err != nil {
		denyUpload(denySizeExceeded, "declared size exceeds whole-object ceiling")
		return
	}

	// --- audit ALLOW before any file byte (audit-before-ack) ---
	allow := d.streamAuditEvent(ps, req, grant, declared, reqID)
	if err := d.guard.Mandate(r.Context(), mapAuditEvent(allow)); err != nil {
		// The allow Mandate itself failed (audit down). Deny before any byte; do
		// NOT re-Mandate a deny (the gate is unavailable) — just write it.
		d.recordOp(string(OpFileUpload), "deny", denyAuditDown)
		writeRESTDeny(w, mapDeny(denyAuditDown), "audit gate unavailable")
		return
	}

	// --- file part (SECOND part, form file "file") ---
	filePart, ok := d.openUploadFilePart(mr, denyUpload)
	if !ok {
		return
	}

	// --- fd ceiling around the open handle ---
	if err := sess.TryAcquireFD(); err != nil {
		denyUpload(denyThrottle, "file-descriptor ceiling exceeded")
		return
	}
	defer sess.ReleaseFD()

	// --- stall bound (NFR-SEC-46): re-armed per-read inbound deadline ---
	// rc is the per-connection ResponseController; armReadDeadline re-arms a
	// frameReadTimeout-from-now read deadline before EACH read off the file part
	// so a slow-but-progressing transfer is fine while a STALL (no byte for
	// frameReadTimeout) makes the next filePart.Read return a deadline error and
	// trips the existing hard-abort path. A ResponseController that does not
	// support read deadlines (e.g. an in-memory test recorder) returns
	// http.ErrNotSupported, in which case the per-read arming is a no-op and the
	// http.Server-level header/idle timeouts are the only backstop.
	rc := http.NewResponseController(w)
	armReadDeadline := func() {
		if err := rc.SetReadDeadline(time.Now().Add(d.frameReadTimeout)); err != nil &&
			!errors.Is(err, http.ErrNotSupported) {
			// A non-"unsupported" deadline-arming error is unexpected; surface it
			// in the diagnostic log but do NOT crash — the transfer continues under
			// the http.Server-level timeouts.
			reqLog.Warn("upload read-deadline arming failed",
				slog.String(observ.KeyReason, err.Error()),
			)
		}
	}

	// --- reassembly: single io.Pipe -> WriteStream(overwrite=OverwriteExisting) ---
	// overwrite_existing defaults to false when the field is absent (JSON zero
	// value), preserving create-new behaviour for any sender that omits it.
	engineStart := time.Now()
	pr, pw := io.Pipe()
	writeErrCh := make(chan error, 1)
	go func() {
		// Panic containment: on a panic in WriteStream, recoverWriteStream closes
		// pr with errInternalPanic (unblocking any producer pw.Write immediately)
		// and sends on writeErrCh. The engine's temp+rename atomicity guarantees
		// no torn object is visible.
		defer recoverWriteStream(pr, writeErrCh)
		werr := d.engine.WriteStream(r.Context(), ps.FilesystemID, enginePath(params.Path), pr, params.OverwriteExisting)
		// Close the read end with the engine's error so a producer pw.Write
		// blocked on a reader that returned early (e.g. WriteStream refused
		// already_exists WITHOUT consuming r) unblocks immediately with that error
		// instead of deadlocking on the unread pipe.
		pr.CloseWithError(werr)
		writeErrCh <- werr
	}()

	// Stream the raw file part into the engine pipe in ceiling-bounded reads,
	// enforcing the exact-byte declared-size contract as bytes arrive. Each read
	// is the moral equivalent of one inbound data frame: bytes-ceiling-acquired
	// and size-checked against the running total before it reaches the engine.
	var acc int64
	buf := make([]byte, uploadReadChunk)
	for {
		// Re-arm the inbound read deadline before EACH read: a transfer that keeps
		// making progress keeps pushing the deadline out, while a STALL trips it on
		// the next read (surfacing as a deadline-exceeded read error handled by the
		// hard-abort path below).
		armReadDeadline()
		n, rerr := filePart.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			acc += int64(n)
			if acc > declared {
				// Over-declaration: abort before the excess reaches the engine
				// (n2). Deny audit then REST deny, then close the engine pipe with
				// the size-exceeded sentinel so WriteStream reclaims the temp.
				denyUpload(denySizeExceeded, "uploaded bytes exceed declared size")
				pw.CloseWithError(errUploadOverDeclared)
				<-writeErrCh
				return
			}
			if err := sess.AcquireBytes(int64(n)); err != nil {
				denyUpload(denyThrottle, "in-flight byte ceiling exceeded")
				pw.CloseWithError(err)
				<-writeErrCh
				return
			}
			acquired += int64(n)

			if _, werr := pw.Write(chunk); werr != nil {
				// The pipe write failed: the engine rejected (e.g. already_exists)
				// WITHOUT consuming r. Drain the engine error and map it.
				engErr := <-writeErrCh
				denyUpload(auditTruthForEngineErr(engErr), "upload refused")
				return
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break // closing multipart boundary = authoritative end of the part
			}
			// A non-EOF read error from the part (truncated body / client
			// disconnect / a malformed trailing part boundary / a STALL that tripped
			// the re-armed read deadline, NFR-SEC-46): HARD ABORT. Close
			// the engine pipe with a NON-EOF abort sentinel, never the raw rerr: a
			// truncated body surfaces as io.ErrUnexpectedEOF, and io.Copy inside
			// WriteStream treats a pipe read returning io.EOF as a CLEAN end —
			// committing the partial bytes. The sentinel forces WriteStream to
			// fail and reclaim the temp so an aborted upload stages nothing.
			denyUpload(denyAborted, "malformed or truncated upload body")
			pw.CloseWithError(errStreamAborted)
			<-writeErrCh
			return
		}
	}

	// --- enforce the under-direction (n2): the body must yield EXACTLY declared ---
	if acc != declared {
		denyUpload(denySizeExceeded, "uploaded bytes do not match declared size")
		pw.CloseWithError(errUploadOverDeclared)
		<-writeErrCh
		return
	}

	// Commit: closing the pipe writer signals EOF; WriteStream's temp+rename
	// makes the object visible only now.
	pw.Close()
	werr := <-writeErrCh
	d.observeStage("engine", time.Since(engineStart).Seconds())
	if werr != nil {
		denyUpload(auditTruthForEngineErr(werr), "upload refused")
		return
	}

	// SUCCESS: HTTP 200. The client ignores the success body, so an empty 200 is
	// the tolerated form. The allow Mandate already preceded it.
	//
	// PENDING-PHASE-7(A2-multipart): the success-body shape is the
	// client-ignores-it tolerated form — an empty 200. The contract also tolerates
	// an optional {"file":FilesystemFile} body the client discards; emitting that
	// shape is deferred until the success-body pin lands.
	d.recordOp(string(OpFileUpload), "allow", denyclassNone)
	w.WriteHeader(http.StatusOK)
}

// readUploadParams reads the FIRST multipart part, which MUST be the "params"
// form field, and strict-decodes the upload params JSON from it. A missing part,
// a first part that is not the "params" field, an oversize params value, or an
// undecodable/unknown-field JSON is a hard reject written through denyReject
// (invalid_argument). It returns ok=false after writing the deny so the caller
// returns immediately.
//
// The params value is bounded by the per-message size ceiling (sizeCeiling)
// before decoding so a pathological params field cannot blow memory; the file
// PART, not the params FIELD, carries the bulk bytes.
func (d *dispatcher) readUploadParams(mr *multipart.Reader, denyReject func(auditReason, message string)) (uploadParamsFrame, bool) {
	part, err := mr.NextPart()
	if err != nil {
		denyReject(denyMalformed, "missing multipart params part")
		return uploadParamsFrame{}, false
	}
	if part.FormName() != multipartParamsField {
		denyReject(denyMalformed, "first multipart part must be the params field")
		return uploadParamsFrame{}, false
	}
	// Bound the params field read so a hostile sender cannot stream an unbounded
	// "params" value to exhaust memory; the bulk bytes belong to the file part.
	raw, err := io.ReadAll(io.LimitReader(part, d.sizeCeiling+1))
	if err != nil {
		denyReject(denyMalformed, "malformed multipart params part")
		return uploadParamsFrame{}, false
	}
	if int64(len(raw)) > d.sizeCeiling {
		denyReject(denyThrottle, "params field exceeds message ceiling")
		return uploadParamsFrame{}, false
	}

	var p uploadParamsFrame
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		denyReject(denyMalformed, "malformed params JSON")
		return uploadParamsFrame{}, false
	}
	var extra json.RawMessage
	if dec.Decode(&extra) == nil {
		// A trailing second JSON value: malformed (single-value enforcement, the
		// same discipline as the retired params frame and every unary body).
		denyReject(denyMalformed, "malformed params JSON")
		return uploadParamsFrame{}, false
	}
	return p, true
}

// openUploadFilePart reads the SECOND multipart part, which MUST be the "file"
// form file, and returns it as a streaming reader. A missing part or a second
// part that is not the "file" field is a hard reject written through denyReject
// (invalid_argument). It returns ok=false after writing the deny so the caller
// returns immediately. The part body is NOT buffered — the caller streams it
// into the engine pipe.
func (d *dispatcher) openUploadFilePart(mr *multipart.Reader, denyReject func(auditReason, message string)) (*multipart.Part, bool) {
	part, err := mr.NextPart()
	if err != nil {
		denyReject(denyMalformed, "missing multipart file part")
		return nil, false
	}
	if part.FormName() != multipartFileField {
		denyReject(denyMalformed, "second multipart part must be the file field")
		return nil, false
	}
	return part, true
}

// multipartParamsField / multipartFileField are the form-field names of the two
// fileUpload parts: the params JSON field and the streamed file part. They are
// the production constants the parity fixtures assert against
// (multipartParamsFieldName/multipartFileFieldName). A request whose
// Content-Type names multipart/form-data but carries no boundary cannot be
// parsed — r.MultipartReader() errors and the handler refuses it as malformed
// before any part is read, so the handler needs no separate boundary check.
const (
	multipartParamsField = "params"
	multipartFileField   = "file"
)
