// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
)

// PENDING-PHASE-7(A2-octet): fileDownload over chunked application/octet-stream.
// The wire is a POST carrying a JSON request body {filesystem_id top-level, uuid
// (the object is addressed by UUID, NOT a path), optional range{offset,length}
// as a *Range pointer with omitempty (a full download OMITS range; a ranged
// download sends it), read authorization_metadata}. On success the RESPONSE is
// HTTP 200 + Content-Type application/octet-stream whose body is the RAW object
// bytes streamed chunked — NO JSON, NO per-chunk envelope, NO base64. A deny
// reached BEFORE any byte is committed is a clean writeRESTDeny (HTTP status +
// BoundedReason). A mid-stream engine error AFTER the 200 header is committed
// just terminates the stream (the 200 header is already on the wire; the status
// cannot change). Sibling-proven, frozen pending #292.
//
// This handler PORTS the surviving download algorithm from the Connect
// framed-trailer handleFileDownload: the uuid->(scope,path) resolution via the
// session-scoped objectIDStore, the CROSS-SCOPE degrade (a uuid that resolves to
// a foreign scope -> 404 on the wire (anti-enumeration) but scope_mismatch as the
// AUDIT truth), canonicalizePath, the Resolve(read-intent) authz, the
// downloadable-at-read check from the broker-resolved grant (NFR-SEC-73), the
// nil-range -> engine.Stat whole-object size probe, the negative-offset/length
// reject, audit-before-ack via Guard.Mandate (audit-down denies before any byte),
// and the fd ceiling (acquire/release on every exit). Only the TRANSPORT edges
// change: the Connect end-stream trailer + base64 downloadDataFrame loop becomes
// either a PRE-byte writeRESTDeny (no 200 committed) or, on success, an HTTP 200
// + octet-stream header + a raw io.Copy of engine.ReadRange into the
// ResponseWriter (flushed as it goes; NO base64, NO framing). A mid-stream engine
// error after the 200 header just terminates the stream (logged; the status
// cannot be changed).
//
// Unlike the retired Connect path, NO HTTP 200 is committed until the read
// window is resolved, the grant cleared, and the ALLOW Mandate landed: every
// pre-byte refusal is a real HTTP status, and the 200 is written once, at the
// moment the first byte is about to flow.

// serveDownloadOctetStream is the STAGE-0 entry for the fileDownload op on the
// REST transport. It mirrors the unary ServeHTTP STAGE-0 prologue (mint the
// per-request correlation id, stamp x-request-id, derive a request-scoped logger,
// install the panic-recovery net) and the channel-scope/throttle gate, then runs
// the octet-stream download handler. It is the download counterpart to the
// retired serveStreaming entry and the sibling of serveUploadMultipart.
//
// The PeerScope SOURCE is gated exactly as the unary/upload paths: when a
// credential extractor is wired, the scope is derived from the edge-injected
// Authorization: Bearer WITHOUT the request-fsid cross-check (the cross-check is
// the handler's channel-scope cross-check on the decoded body, which already
// names the scope_mismatch truth); otherwise it reads the unix peer scope stashed
// in the connection context (the fallback source the router tests and any
// contextWithPeerScope caller rely on). A missing/rejected credential is
// unauthenticated (401); an absent context scope on the fallback path is a wiring
// fault and fails closed.
//
// Unlike the Connect streaming entry, NO HTTP 200 is committed in this prologue:
// a STAGE-0 refusal is a real writeRESTDeny status, and the handler commits 200
// only when the first object byte is about to flow.
func (d *dispatcher) serveDownloadOctetStream(w http.ResponseWriter, r *http.Request) {
	reqID := newCorrelationID()
	w.Header().Set(requestIDHeader, reqID)
	reqLog := d.logger.With(slog.String(observ.KeyRequestID, reqID))
	defer d.recoverDispatch(w, &reqLog)()

	// STAGE 0: PeerScope — the host-attested channel identity. Source gated (A5)
	// exactly as the unary/upload paths.
	var ps PeerScope
	if d.credExtractor != nil {
		var v DenyVerdict
		var ok bool
		ps, v, ok = peerScopeFromCredential(r, d.credExtractor)
		if !ok {
			d.recordOp(string(OpFileDownload), "deny", v.AuditReason)
			d.denyWithLog(w, reqLog, v, "credential rejected")
			return
		}
	} else {
		var ok bool
		ps, ok = peerScopeFromContext(r.Context())
		if !ok {
			d.recordOp(string(OpFileDownload), "deny", denyInternal)
			d.denyWithLog(w, reqLog, mapDeny(denyInternal), "no channel scope on connection")
			return
		}
	}

	// STAGE 0: ops/s throttle, keyed on the CHANNEL scope (PeerScope), never on
	// any body field — nothing trusts the request body before the handler's scope
	// cross-check.
	sess := d.ceilings.Session(ps.FilesystemID)
	if err := sess.TryConsumeOp(); err != nil {
		d.recordOp(string(OpFileDownload), "deny", denyClassForErr(err))
		d.denyWithLog(w, reqLog, mapDeny(denyClassForErr(err)), "operation rate ceiling exceeded")
		return
	}

	d.handleDownloadOctetStream(w, r, ps, sess, reqID, reqLog)
}

// handleDownloadOctetStream streams an object's bytes as a chunked
// application/octet-stream over the REST transport (OPS-06). Every clause of the
// surviving download contract is load-bearing:
//
//   - Strict-decode the JSON request {filesystem_id, uuid, optional
//     range{offset,length}, authorization_metadata}; an undecodable or
//     unknown-field body is invalid_argument.
//   - Cross-check the decoded filesystem_id against the channel scope; everything
//     keys on the channel scope, never the body value.
//   - Resolve uuid->(scope,path) via the session-scoped objectIDStore. A uuid
//     unknown to this session is not_found. A cross-scope uuid (the stored scope
//     differs from the channel scope) audits as scope_mismatch but degrades to
//     404 on the wire (anti-enumeration, D8).
//   - canonicalizePath the resolved path ONCE before authz/audit/engine.
//   - Resolve(intent=read) from the channel scope; map resolver errors.
//   - DOWNLOADABLE@READ from the broker-resolved grant (NFR-SEC-73): the wire
//     flag is NEVER trusted; a non-downloadable grant denies (403).
//   - Resolve the read window: a negative offset/length is invalid_argument
//     (400); a nil range is the WHOLE object, whose length is the object's
//     current size from a Stat run BEFORE the ALLOW Mandate (so a vanished object
//     records one deny, not an allow-then-deny pair).
//   - Mandate the ALLOW event BEFORE any byte (audit-before-ack, SEC-79); an
//     audit-write failure denies (503) before any byte is committed.
//   - fd ceiling around the engine read window (acquire BEFORE the 200 header;
//     released on every exit).
//   - On the first byte: write HTTP 200 + Content-Type application/octet-stream,
//     then io.Copy the raw engine.ReadRange bytes to the ResponseWriter, flushing
//     as they go (NO base64, NO framing). A mid-stream engine error after the 200
//     header just terminates the stream (logged; the status cannot change).
func (d *dispatcher) handleDownloadOctetStream(w http.ResponseWriter, r *http.Request, ps PeerScope, sess CeilingsSession, reqID string, reqLog *slog.Logger) {
	var (
		req   ResolveRequest
		grant Grant
	)

	// denyDownload emits the deny audit (broker-resolved truth) then the REST deny
	// response. It is the PRE-byte refusal path: it is only ever called before the
	// 200 header is committed, so it can always write a real HTTP status. A
	// deny-Mandate FAILURE degrades the verdict to unavailable (NFR-SEC-79,
	// invariant 8): if the deny record did not durably land, the chain's last
	// record may be a pre-byte ALLOW — asserting allow for a refused download — so
	// the verdict the guest sees must be audit-down, never the original refusal.
	// This mirrors the retired Connect denyDownloadTrailer.
	denyDownload := func(auditReason, message string) {
		reqLog.Warn("broker deny",
			slog.String(observ.KeyDenyClass, auditReason),
			slog.String(observ.KeyReason, message),
		)
		ev := d.denyAuditEvent(OpFileDownload, ps, req, grant, nil, auditReason)
		ev.RequestID = reqID
		if err := d.guard.Mandate(r.Context(), mapAuditEvent(ev)); err != nil {
			d.recordOp(string(OpFileDownload), "deny", denyAuditDown)
			writeRESTDeny(w, mapDeny(denyAuditDown), "audit gate unavailable")
			return
		}
		d.recordOp(string(OpFileDownload), "deny", auditReason)
		writeRESTDeny(w, mapDeny(auditReason), message)
	}

	// --- decode the JSON request body (bounded by the message ceiling) ---
	// The request body is a small JSON document (uuid + optional range), never the
	// bulk bytes — the bulk bytes are the RESPONSE. Bound the read so a hostile
	// sender cannot stream an unbounded request body to exhaust memory.
	raw, err := io.ReadAll(io.LimitReader(r.Body, d.sizeCeiling+1))
	if err != nil {
		denyDownload(denyMalformed, "malformed request body")
		return
	}
	if int64(len(raw)) > d.sizeCeiling {
		denyDownload(denyThrottle, "request body exceeds message ceiling")
		return
	}
	var params fileDownloadRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil {
		denyDownload(denyMalformed, "malformed request body")
		return
	}
	var extra json.RawMessage
	if dec.Decode(&extra) == nil {
		// A trailing second JSON value: malformed (single-value enforcement, the
		// same discipline as every unary body and the retired params frame).
		denyDownload(denyMalformed, "malformed request body")
		return
	}

	// --- channel-scope cross-check (key on the channel, never the body) ---
	if params.FilesystemID != ps.FilesystemID {
		denyDownload(denyScopeMismatch, "request scope does not match the session channel")
		return
	}

	// --- uuid -> (scope, path) resolution via the session-scoped objectIDStore ---
	// The uuid was minted by this broker session's listing or readFile emitter.
	// An unknown uuid is not_found. A cross-scope uuid (the stored scope differs
	// from the channel scope) audits as scope_mismatch but degrades to 404 on the
	// wire so a valid uuid from another session cannot be used to enumerate scope
	// membership (D8, anti-enumeration).
	rec, ok := d.ids.lookup(params.UUID)
	if !ok {
		denyDownload(denyNotFound, "object not found")
		return
	}
	if rec.scope != ps.FilesystemID {
		// Cross-scope: audit scope_mismatch truth, wire 404 (D8). The ops_total
		// deny_class is the audited TRUTH (scope_mismatch), not the degraded wire
		// class — the metric carries the same truth the audit record does.
		//
		// Populate req from the resolved record (which holds the real path and the
		// probed scope) BEFORE building the deny event so the scope_mismatch audit
		// names the handle that was actually probed — an empty handle would blind
		// the anti-enumeration trail this deny exists to capture.
		probed := ResolveRequest{Filesystem: rec.scope, Path: rec.path, Intent: IntentRead}
		ev := d.denyAuditEvent(OpFileDownload, ps, probed, grant, nil, denyScopeMismatch)
		ev.RequestID = reqID
		if err := d.guard.Mandate(r.Context(), mapAuditEvent(ev)); err != nil {
			d.recordOp(string(OpFileDownload), "deny", denyAuditDown)
			writeRESTDeny(w, mapDeny(denyAuditDown), "audit gate unavailable")
			return
		}
		d.recordOp(string(OpFileDownload), "deny", denyScopeMismatch)
		// The wire degrades to 404 (not_found) for anti-enumeration; the audited
		// truth named above stays scope_mismatch. mapDenyDegraded keeps the truth
		// out of the x-deny-reason header (the not_found wire class is header-less).
		v := mapDenyDegraded(denyScopeMismatch, denyNotFound)
		v.CorrelationID = reqID
		writeRESTDeny(w, v, "object not found")
		return
	}

	// Canonicalize the resolved path ONCE before authz/audit/engine
	// (bypass-01/03). The uuid store is keyed off canonical paths, so this is
	// normally an identity; it is the belt-and-suspenders that guarantees the
	// downloadable tag, the engine ReadRange target, and the audit ObjectHandle
	// all name the SAME object even for any record minted before this boundary
	// existed. A non-canonical record is a not_found-class refusal — never an
	// egress grant on a dirty path.
	canonDownload, cerr := canonicalizePath(rec.path)
	if cerr != nil {
		denyDownload(denyNotFound, "object not found")
		return
	}
	// Populate req from the resolved (scope, path) for the remainder of the audit
	// and resolver calls.
	req = ResolveRequest{Filesystem: ps.FilesystemID, Path: canonDownload, Intent: IntentRead}

	// --- authz Resolve(intent=read) from the channel scope ---
	evidence := CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: ps.GrantedIntents}
	grant, err = d.resolver.Resolve(r.Context(), evidence, req)
	if err != nil {
		denyDownload(denyClassForErr(err), "authorization denied")
		return
	}

	// --- DOWNLOADABLE@READ, broker-side (NFR-SEC-73, A2) ---
	// The grant is the broker-resolved truth; the wire flag is never consulted.
	if !grant.Downloadable {
		denyDownload(denyNotDownloadable, "object not downloadable")
		return
	}

	// --- resolve the read window BEFORE the ALLOW audit ---
	// The engine ReadRange contract is the half-open window
	// [offset, offset+length): a nil Range is a WHOLE-object read, for which the
	// length is the object's current size resolved by a Stat. The Stat runs BEFORE
	// the ALLOW Mandate so a vanished object (the listing that minted the uuid
	// raced a delete) records a single deny, never an allow-then-deny pair; it
	// degrades to the engine-classified verdict (not_found) and no bytes are sent.
	var offset, length int64
	if params.Range != nil {
		// Validate the client-supplied window BEFORE the ALLOW audit (SEC-79): a
		// negative offset or length is a malformed window — a client request fault.
		// Route it through the pre-byte deny as invalid_argument so the durable
		// chain records a single deny with no prior ALLOW.
		if params.Range.Offset < 0 || params.Range.Length < 0 {
			denyDownload(denyMalformed, "negative range offset or length")
			return
		}
		offset = params.Range.Offset
		length = params.Range.Length
	} else {
		// statSizeContained recovers a panicking engine.Stat into errInternalPanic
		// so a whole-object size probe cannot escape into a half-written response.
		// A real Stat error or a recovered panic both classify through
		// denyClassForEngineErr (a panic -> denyInternal).
		size, serr := statSizeContained(r.Context(), d.engine, ps.FilesystemID, enginePath(req.Path))
		if serr != nil {
			denyDownload(denyClassForEngineErr(serr), "object not found")
			return
		}
		length = size
	}

	// --- audit ALLOW before any byte (audit-before-ack, SEC-79) ---
	allow := d.streamDownloadAuditEvent(ps, req, grant, reqID)
	if err := d.guard.Mandate(r.Context(), mapAuditEvent(allow)); err != nil {
		// The allow Mandate failed (audit down). Deny before any byte is committed;
		// do NOT re-Mandate a deny (the gate is unavailable). Book the metric as
		// audit_down.
		d.recordOp(string(OpFileDownload), "deny", denyAuditDown)
		writeRESTDeny(w, mapDeny(denyAuditDown), "audit gate unavailable")
		return
	}

	// --- fd ceiling around the engine read window (NFR-SEC-46, conc-02) ---
	// The download opens a real engine fd for the whole stream (ReadRange ->
	// OpenScopeRoot). Acquire the per-session fd slot BEFORE committing the 200
	// header and release it on every exit, exactly as the upload path does.
	if err := sess.TryAcquireFD(); err != nil {
		denyDownload(denyThrottle, "file-descriptor ceiling exceeded")
		return
	}
	defer sess.ReleaseFD()

	// --- commit the 200 header and stream the raw bytes ---
	// From here NO refusal can change the status: the 200 + octet-stream header is
	// on the wire. A mid-stream engine error just terminates the stream (the
	// client reads to EOF or its own 16 GiB cap and detects the short read). The
	// raw engine bytes are copied directly into the ResponseWriter with no base64
	// and no per-chunk envelope.
	engineStart := time.Now()
	w.Header().Set("Content-Type", contentTypeOctetStream)
	w.WriteHeader(http.StatusOK)

	// flushWriter wraps the ResponseWriter so each engine write is flushed toward
	// the client as it arrives (chunked transfer), keeping outbound memory bounded
	// regardless of object size. A ResponseWriter that does not support flushing
	// (some test recorders) degrades to a plain copy — the bytes still arrive.
	fw := &flushingResponseWriter{w: w, flusher: asFlusher(w)}
	rerr := d.engine.ReadRange(r.Context(), ps.FilesystemID, enginePath(req.Path), offset, length, fw)
	d.observeStage("engine", time.Since(engineStart).Seconds())
	if rerr != nil {
		// A MID-STREAM engine error AFTER the 200 header. The status cannot be
		// changed; the stream simply terminates (the client reads to EOF / its own
		// cap and detects the short read). Log it and book the verdict as aborted
		// so a faulted download is still visible in ops_total.
		reqLog.Error("download engine fault after 200 committed",
			slog.String(observ.KeyDenyClass, auditTruthForEngineErr(rerr)),
			slog.String("err", rerr.Error()),
		)
		d.recordOp(string(OpFileDownload), "deny", auditTruthForEngineErr(rerr))
		return
	}

	// SUCCESS: the 200 + octet-stream body is complete. The allow Mandate already
	// preceded the first byte.
	d.recordOp(string(OpFileDownload), "allow", denyclassNone)
}

// contentTypeOctetStream is the fileDownload success RESPONSE Content-Type: the
// raw object bytes streamed chunked. It is never a REQUEST content type (the
// request is application/json). The parity oracle pins it as ctOctetStream.
const contentTypeOctetStream = "application/octet-stream"

// flushingResponseWriter adapts an http.ResponseWriter into an io.Writer that
// flushes toward the client after each write, so the download streams chunked
// rather than buffering the whole object. A nil flusher (a writer without
// http.Flusher support — e.g. an in-memory test recorder) degrades to a plain
// write; the bytes still arrive, just not incrementally flushed.
type flushingResponseWriter struct {
	w       io.Writer
	flusher http.Flusher
}

// Write copies the engine bytes to the underlying ResponseWriter and flushes the
// chunk toward the client. A write error (the client disconnected mid-stream)
// propagates back into engine.ReadRange, which stops producing.
func (f *flushingResponseWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if f.flusher != nil {
		f.flusher.Flush()
	}
	return n, err
}

// asFlusher returns w as an http.Flusher when it supports flushing, or nil when
// it does not (the bytes still arrive on a non-flushing writer; they are just
// not incrementally flushed).
func asFlusher(w http.ResponseWriter) http.Flusher {
	if fl, ok := w.(http.Flusher); ok {
		return fl
	}
	return nil
}
