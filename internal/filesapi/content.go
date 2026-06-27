// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// contentTypeOctetStream is the content success RESPONSE Content-Type: the raw
// object bytes streamed chunked.
const contentTypeOctetStream = "application/octet-stream"

// serveContent serves GET /v1/files/{file_id}/content: it resolves the file_id,
// re-derives the read authorization broker-side, resolves downloadable AT READ,
// audits BEFORE the first byte, and streams the raw object bytes.
//
// This PORTS the surviving download algorithm from the south octet-stream
// handler, with the keystone SIMPLIFICATION: the file_id resolves through the
// durable handle store (Store.Get), which already collapses absent and
// cross-scope into the SAME ErrNotFound — so there is NO cross-scope audit
// branch and NO 403/scope_mismatch path here. The engine target is the resolved
// Record's backend ObjectRef (the opaque engine-ready locator), normalised
// through enginePath as defense-in-depth.
//
// Order of operations (every clause load-bearing):
//
//   - Store.Get(file_id, attestedScope) -> Record | keystone 404.
//   - Resolve(intent=read) from the attested scope; map resolver errors.
//   - downloadable AT READ from the broker-resolved grant (NFR-SEC-73): a
//     non-downloadable grant denies 403 with engine.ReadRange NEVER called.
//   - resolve the read window: a negative offset/length is invalid_argument
//     (400); an ABSENT length reads from offset to EOF (the whole object when
//     offset is 0, an offset-only [offset, EOF) window otherwise), whose length
//     is a Stat (info.Size - offset, clamped >= 0) run BEFORE the ALLOW Mandate
//     (a vanished object records one deny, not allow-then-deny).
//   - Mandate the ALLOW BEFORE any byte (audit-before-ack, SEC-79); an audit
//     failure denies 503 with zero bytes.
//   - fd ceiling around the engine read window.
//   - on the first byte: 200 + octet-stream, then a flushed io.Copy of
//     engine.ReadRange. A mid-stream engine error after the 200 terminates the
//     stream (the status cannot change).
func (h *Handler) serveContent(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, fileID, reqID string, reqLog *slog.Logger) {
	sess := h.deps.Ceilings.Session(ps.FilesystemID)
	if err := sess.TryConsumeOp(); err != nil {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Throttle), "operation rate ceiling exceeded")
		return
	}

	// --- file_id resolution (keystone: absent == cross-scope == ErrNotFound) ---
	rec, err := h.deps.Store.Get(r.Context(), fileID, ps.FilesystemID)
	if err != nil {
		writeResolutionDeny(w, reqLog, err, reqID)
		return
	}

	// enginePath normalises the opaque backend ObjectRef into the engine's
	// relative convention as defense-in-depth; an ObjectRef that normalises to an
	// empty or escaping path is a not_found-class refusal (never an egress grant
	// on a dirty path), mirroring the south canonicalize step.
	engPath, ok := enginePath(rec.ObjectRef)
	if !ok {
		reqLog.Info("files-api content: object reference does not normalise",
			slog.String(observ.KeyDenyClass, denyclass.NotFound))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.NotFound), "not found")
		return
	}

	// --- authz Resolve(intent=read) from the attested scope ---
	req := southface.ResolveRequest{Filesystem: ps.FilesystemID, Path: engPath, Intent: southface.IntentRead}
	evidence := southface.CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: ps.GrantedIntents}
	grant, rerr := h.deps.Resolver.Resolve(r.Context(), evidence, req)
	if rerr != nil {
		h.denyContent(w, r, reqLog, ps, rec, grant, denyclass.IntentDenied, "authorization denied", reqID)
		return
	}

	// --- downloadable AT READ (NFR-SEC-73): the grant is the truth; the wire
	// flag is never consulted. A non-downloadable grant denies 403 and
	// engine.ReadRange is NEVER reached. ---
	if !grant.Downloadable {
		h.denyContent(w, r, reqLog, ps, rec, grant, denyclass.NotDownloadable, "object not downloadable", reqID)
		return
	}

	// --- resolve the read window BEFORE the ALLOW audit ---
	offset, length, rangeOK := parseContentRange(r)
	if !rangeOK {
		// A negative offset/length is a malformed window (client request fault).
		h.denyContent(w, r, reqLog, ps, rec, grant, denyclass.Malformed, "negative range offset or length", reqID)
		return
	}
	if !hasLength(r) {
		// The length param is ABSENT: the window runs from offset to EOF. This
		// covers BOTH the nil range (offset 0 -> whole object) and an offset-only
		// request (offset N -> [N, EOF)) — a missing length is never zero bytes.
		// Stat the size BEFORE the ALLOW Mandate so a vanished object records a
		// single deny, never allow-then-deny.
		info, serr := h.deps.Engine.Stat(r.Context(), ps.FilesystemID, engPath)
		if serr != nil {
			h.denyContent(w, r, reqLog, ps, rec, grant, denyclass.NotFound, "not found", reqID)
			return
		}
		// length = info.Size - offset, clamped to >= 0: an offset at or past EOF
		// reads zero bytes (a legitimate empty 200), never a negative window.
		length = info.Size - offset
		if length < 0 {
			length = 0
		}
	}

	// --- audit ALLOW before any byte (audit-before-ack, SEC-79) ---
	allow := readAllowEvent(ps, rec, grant, reqID)
	if merr := h.deps.Guard.Mandate(r.Context(), allow); merr != nil {
		// The allow Mandate failed (audit down). Deny before any byte; do NOT
		// re-Mandate a deny (the gate is unavailable).
		reqLog.Error("files-api content: allow audit failed before first byte",
			slog.String(observ.KeyDenyClass, denyclass.AuditDown))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
		return
	}

	// --- fd ceiling around the engine read window (NFR-SEC-46) ---
	if ferr := sess.TryAcquireFD(); ferr != nil {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Throttle), "file-descriptor ceiling exceeded")
		return
	}
	defer sess.ReleaseFD()

	// --- commit the 200 header and stream the raw bytes ---
	// From here NO refusal can change the status: the 200 + octet-stream header
	// is on the wire. A mid-stream engine error just terminates the stream.
	w.Header().Set("Content-Type", contentTypeOctetStream)
	w.WriteHeader(http.StatusOK)
	fw := &flushingResponseWriter{w: w, flusher: asFlusher(w)}
	if cerr := h.deps.Engine.ReadRange(r.Context(), ps.FilesystemID, engPath, offset, length, fw); cerr != nil {
		// A MID-STREAM engine error AFTER the 200 header. The status cannot change;
		// the stream simply terminates. Log it (the client detects the short read).
		reqLog.Error("files-api content: engine fault after 200 committed",
			slog.String(observ.KeyReason, cerr.Error()))
	}
}

// denyContent emits the deny audit (broker-resolved truth) then the REST deny
// response. It is the PRE-byte refusal path: only ever called before the 200
// header is committed, so it can always write a real HTTP status. A deny-Mandate
// FAILURE degrades the verdict to unavailable (NFR-SEC-79): if the deny record
// did not durably land, the verdict the caller sees must be audit-down.
//
// The wire verdict for a non-downloadable / intent-denied refusal is the
// authorization status (403); for a malformed range it is 400; for a vanished
// object it is the keystone 404. None of these is a file_id-resolution leak —
// the file_id ALREADY resolved (the record exists in scope); these are
// downstream authorization/argument/engine verdicts on a resolved object, not a
// cross-scope-vs-absent distinction.
func (h *Handler) denyContent(w http.ResponseWriter, r *http.Request, reqLog *slog.Logger, ps southface.PeerScope, rec handlestore.Record, grant southface.Grant, auditReason, message, reqID string) {
	reqLog.Warn("files-api content deny",
		slog.String(observ.KeyDenyClass, auditReason),
		slog.String(observ.KeyReason, message))
	ev := readDenyEvent(ps, rec, grant, auditReason, reqID)
	if merr := h.deps.Guard.Mandate(r.Context(), ev); merr != nil {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
		return
	}
	denywire.WriteRESTDeny(w, denywire.MapDeny(auditReason), message)
}

// contentOffsetParam / contentLengthParam are the optional read-window query
// parameters: a half-open [offset, offset+length) window. Both absent is a
// whole-object read.
const (
	contentOffsetParam = "offset"
	contentLengthParam = "length"
)

// hasLength reports whether the request carries an explicit length query
// parameter. When false the window runs from offset to EOF (length resolved by a
// Stat as info.Size - offset): a missing length is read-to-end, NOT zero bytes.
// The offset alone never determines the window length, so an offset-only request
// (offset present, length absent) takes the Stat path just like a nil range.
func hasLength(r *http.Request) bool {
	return r.URL.Query().Has(contentLengthParam)
}

// parseContentRange parses the optional offset/length query parameters into the
// half-open engine window. A missing parameter defaults to zero. A non-integer
// or NEGATIVE value is a malformed window (ok=false -> 400). When neither is
// present the caller treats it as a whole-object read (length resolved by Stat).
func parseContentRange(r *http.Request) (offset, length int64, ok bool) {
	q := r.URL.Query()
	off, ok1 := parseNonNegInt64(q.Get(contentOffsetParam))
	if !ok1 {
		return 0, 0, false
	}
	ln, ok2 := parseNonNegInt64(q.Get(contentLengthParam))
	if !ok2 {
		return 0, 0, false
	}
	return off, ln, true
}

// parseNonNegInt64 parses a non-negative int64 from raw. An empty string is zero
// (ok=true). A non-integer or negative value is ok=false.
func parseNonNegInt64(raw string) (int64, bool) {
	if strings.TrimSpace(raw) == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// enginePath normalises an opaque backend object reference into the engine's
// relative convention (no leading slash, "." for the root) and rejects a
// reference that is empty after trimming or that escapes via a "..": such a
// reference is a not_found-class refusal (ok=false), never an egress target.
//
// The handle store documents ObjectRef as the engine-ready backend locator; this
// normalisation is the belt-and-suspenders that guarantees a stored reference can
// never name an out-of-tree object even if a future producer writes a dirty ref.
// It mirrors the south enginePath/canonicalizePath obligation without importing
// the south-private helpers.
func enginePath(objectRef string) (string, bool) {
	p := strings.TrimPrefix(strings.TrimSpace(objectRef), "/")
	if p == "" {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", false
		}
	}
	return p, true
}

// flushingResponseWriter adapts an http.ResponseWriter into an io.Writer that
// flushes toward the client after each write, so the content streams chunked
// rather than buffering the whole object. A nil flusher (a writer without
// http.Flusher support — e.g. an in-memory test recorder) degrades to a plain
// write; the bytes still arrive, just not incrementally flushed.
type flushingResponseWriter struct {
	w       io.Writer
	flusher http.Flusher
}

// Write copies the engine bytes to the underlying writer and flushes the chunk
// toward the client. A write error (client disconnected mid-stream) propagates
// back into engine.ReadRange, which stops producing.
func (f *flushingResponseWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if f.flusher != nil {
		f.flusher.Flush()
	}
	return n, err
}

// asFlusher returns w as an http.Flusher when it supports flushing, or nil when
// it does not.
func asFlusher(w http.ResponseWriter) http.Flusher {
	if fl, ok := w.(http.Flusher); ok {
		return fl
	}
	return nil
}
