// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net/http"
	"path"
	"strings"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// serveCreate serves POST /v1/files: it streams a multipart/form-data upload
// into the engine and, once the bytes are durable, Puts a durable handle and
// returns 201 + the minted FileObject. It MIRRORS the south upload pipeline
// (internal/southface/upload_multipart.go): the declared-size pre-buffer reject,
// the scope cross-check, canonicalizePath, Resolve(intent=write),
// audit-before-ack via Guard.Mandate, the fd+in-flight-bytes ceilings (released
// on EVERY exit), the io.Pipe -> engine.WriteStream(overwrite) reassembly, and
// the over/under-declaration aborts. Only the transport and the SUCCESS shape
// differ from a read handler: a create writes bytes then a durable handle, and
// success is 201 + FileObject (not the read plane's 200-or-stream).
//
// The request carries two ordered multipart parts: (1) a form FIELD named
// "params" whose value is the upload params JSON (path, declared_size_bytes
// REQUIRED, overwrite_existing, media_type, filename); (2) a file PART named
// "file" streaming the raw source bytes. The body must yield EXACTLY
// declared_size_bytes — over- and under-declaration are refused, staging nothing
// (the engine's temp+rename atomicity means a torn upload leaves no object).
//
// Order of operations (every clause load-bearing):
//
//   - ops/s throttle keyed on the attested CHANNEL scope, never a body field.
//   - MultipartReader; a non-multipart body is a 400 malformed.
//   - Read the "params" part FIRST; strict-decode it. declared_size_bytes is
//     REQUIRED (<=0 -> 400).
//   - Cross-check params.filesystem_id (when present) against the attested scope
//     — a mismatch is a 403 scope_mismatch (MIRRORING SOUTH), NOT a 404: create
//     mints a NEW id, it never resolves one, so the anti-enumeration keystone
//     (which governs file_id resolution) does not apply.
//   - canonicalizePath ONCE; a traversal/unsafe path is a 400 malformed.
//   - Resolve(intent=write) from the attested scope; map resolver errors.
//   - PRE-ASSEMBLY size reject (SEC-46): declared > MaxFileSize -> 400 size
//     BEFORE any file byte, overflow-safe strict > (at-ceiling admitted).
//   - Mandate the ALLOW BEFORE the file part is opened (audit-before-ack,
//     SEC-79); an audit-down error denies before any byte, without re-Mandating.
//   - Read the "file" part; fd ceiling around the open handle.
//   - Reassemble via a single io.Pipe -> WriteStream, enforcing the exact-byte
//     declared-size contract as bytes arrive; over/under-declaration and a
//     truncated body abort with a NON-EOF sentinel so WriteStream reclaims the
//     temp (an aborted upload stages nothing).
//   - COMMIT: pw.Close() signals EOF; map the engine error (already_exists ->
//     409). Only now are the bytes durable.
//   - Store.Put the durable handle; a store latch is a 503.
//   - SUCCESS: 201 + newFileObject(mintedRecord).
func (h *Handler) serveCreate(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, reqID string, reqLog *slog.Logger) {
	var (
		req       southface.ResolveRequest
		grant     southface.Grant
		engineRef string // the canonical engine path the write targets / the ObjectRef stored
		declared  int64
		acquired  int64 // total bytes AcquireBytes'd, released on every exit
	)

	sess := h.deps.Ceilings.Session(ps.FilesystemID)

	// denyCreate emits the deny audit (broker-resolved truth) then the REST deny.
	// A deny-Mandate FAILURE degrades the verdict to audit_down (NFR-SEC-79): if
	// the deny record did not durably land, the chain's last record may be the
	// pre-assembly ALLOW — asserting allow for a refused create — so the verdict
	// the caller sees must be audit_down, never the original refusal. This mirrors
	// the south denyUpload and the allow-Mandate failure path below.
	denyCreate := func(auditReason, message string) {
		reqLog.Warn("files-api create deny",
			slog.String(observ.KeyDenyClass, auditReason),
			slog.String(observ.KeyReason, message))
		ev := createDenyEvent(ps, engineRef, grant, auditReason, reqID)
		if merr := h.deps.Guard.Mandate(r.Context(), ev); merr != nil {
			denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
			return
		}
		denywire.WriteRESTDeny(w, denywire.MapDeny(auditReason), message)
	}

	// ReleaseBytes balances AcquireBytes on EVERY exit. The engine has consumed
	// the bytes durably by the time WriteStream returns, so the in-flight
	// reservation frees once the handler exits regardless of path.
	defer func() { sess.ReleaseBytes(acquired) }()

	// --- ops/s throttle, keyed on the CHANNEL scope (mirrors the north read
	// path and the south upload STAGE-0 gate). ---
	if err := sess.TryConsumeOp(); err != nil {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Throttle), "operation rate ceiling exceeded")
		return
	}

	// --- multipart reader (streaming, NOT ParseMultipartForm which buffers) ---
	mr, err := r.MultipartReader()
	if err != nil {
		denyCreate(denyclass.Malformed, "request is not multipart/form-data")
		return
	}

	// --- params part (FIRST part, form field "params") ---
	params, ok := h.readCreateParams(mr, denyCreate)
	if !ok {
		return
	}
	declared = params.DeclaredSizeBytes
	if declared <= 0 {
		denyCreate(denyclass.Malformed, "declared_size_bytes required (>0)")
		return
	}

	// --- scope cross-check (params.filesystem_id is an untrusted hint; the
	// attested header scope is authority). An EMPTY body filesystem_id is allowed
	// (the header decides); a PRESENT one that disagrees is a scope_mismatch (403,
	// MIRRORING SOUTH — create mints a new id, so this is NOT the file_id
	// resolution keystone's 404). ---
	if params.FilesystemID != "" && params.FilesystemID != ps.FilesystemID {
		denyCreate(denyclass.ScopeMismatch, "request scope does not match the attested scope")
		return
	}

	// --- canonicalize the decoded path ONCE (bypass-01/03) then map to the
	// engine's relative convention. The canonical engine path is what authz, the
	// audit record, the engine write, and the stored ObjectRef ALL see. ---
	canonPath, cok := canonicalizeCreatePath(params.Path)
	if !cok {
		denyCreate(denyclass.Malformed, "invalid or unsafe path")
		return
	}
	engineRef = canonPath

	// --- NORTH LANDING JOIN (ADR-0029:46, the human->sandbox direction). Join the
	// canonical wire path under the deployment map's read subtree (h.deps.
	// CreateSubtree, injected at construction) so a browser File-Pane upload lands
	// where the agent's south read-mount looks — the default split joins reads
	// under "uploads", so a root-landed upload would be INVISIBLE to the agent.
	// This ONE assignment threads the joined path into authz Resolve, the audit
	// createAllowEvent, Engine.WriteStream, AND the stored ObjectRef — engineRef is
	// the single path var every downstream consumer reads. The join is applied
	// AFTER canonicalizeCreatePath's NUL/URL/traversal/root-reject checks, so a
	// hostile wire path can never escape via the join: canonPath is already clean
	// and rootless, and path.Join(cleanSubtree, cleanRel) stays within the subtree.
	// An empty CreateSubtree is static-path mode: the create writes at the scope
	// root verbatim (path.Join skipped). ---
	if h.deps.CreateSubtree != "" {
		engineRef = path.Join(h.deps.CreateSubtree, canonPath)
	}

	// --- authz Resolve(intent=write) from the attested scope. The evidence
	// grants BOTH read and write intents: the F9 host-attested scope is trusted
	// for write on its OWN filesystem (component-08 has already done the upstream
	// three-axis authorization before the F9 call), exactly as the south upload
	// grants write from the channel scope. The placeholder ScopeSource stamps only
	// read intent on ps.GrantedIntents (the read/delete plane's need), so the write
	// verb ADDS write intent here rather than widening the scope-source grant for
	// every plane — see createEvidenceIntents. The broker-side Resolver is still
	// the deny-by-default decision; this evidence is only an input to it. ---
	req = southface.ResolveRequest{Filesystem: ps.FilesystemID, Path: engineRef, Intent: southface.IntentWrite}
	evidence := southface.CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: createEvidenceIntents(ps)}
	grant, err = h.deps.Resolver.Resolve(r.Context(), evidence, req)
	if err != nil {
		denyCreate(denyClassForResolveErr(err), "authorization denied")
		return
	}

	// --- PRE-ASSEMBLY size reject (SEC-46): BEFORE the file part is read. A
	// strict `>` compare (at-ceiling admitted), overflow-safe (never a
	// subtraction). ---
	if declared > h.deps.MaxFileSize {
		denyCreate(denyclass.SizeExceeded, "declared size exceeds whole-object ceiling")
		return
	}

	// --- audit ALLOW before any file byte (audit-before-ack, SEC-79). The ALLOW
	// lands BEFORE the file part is opened / the first byte is read. ---
	allow := createAllowEvent(ps, engineRef, grant, declared, reqID)
	if merr := h.deps.Guard.Mandate(r.Context(), allow); merr != nil {
		// The allow Mandate itself failed (audit down). Deny before any byte; do
		// NOT re-Mandate a deny (the gate is unavailable) — just write it.
		reqLog.Error("files-api create: allow audit failed before first byte",
			slog.String(observ.KeyDenyClass, denyclass.AuditDown))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
		return
	}

	// --- file part (SECOND part, form file "file") ---
	filePart, ok := h.openCreateFilePart(mr, denyCreate)
	if !ok {
		return
	}

	// --- fd ceiling around the open handle ---
	if err := sess.TryAcquireFD(); err != nil {
		denyCreate(denyclass.Throttle, "file-descriptor ceiling exceeded")
		return
	}
	defer sess.ReleaseFD()

	// --- ENSURE THE JOIN-SUBTREE PARENT CHAIN (ADR-0029). The S3 engine's WriteStream
	// refuses a write whose immediate parent directory marker is absent (parentExists ->
	// *fs.PathError wrapping fs.ErrNotExist): before the north landing join, the object
	// landed at the scope root whose parent is the always-present root, so no marker was
	// needed; the join lands it under CreateSubtree ("uploads"), and a nested wire path
	// lands it deeper still ("uploads/nested/..."), whose markers nothing else creates.
	// Ensure the object's parent chain here, idempotently and engine-agnostically, via
	// the shared southface.EnsureDir walker — the SAME dir-marker convention the south
	// make_parents spine composes over.
	//
	// NFR-SEC-73: the ensure must materialise nothing OUTSIDE the join subtree. The
	// argument is path.Dir(engineRef), and engineRef is the POST-canonicalize, POST-join
	// path — CreateSubtree + a clean, traversal-free remainder — so path.Dir(engineRef)
	// is closed under the subtree: it is CreateSubtree itself or a strict descendant,
	// never a climb above the prefix. The containment guard asserts exactly that; in join
	// mode a guard miss is impossible by construction, so it is an internal invariant
	// violation (fail closed + audit), NEVER a silent unguarded ensure. Static-path mode
	// (empty CreateSubtree) ensures NOTHING: the object lands at the scope root whose
	// parent always exists, and any nested static path relies on the operator-provisioned
	// tree plus the engine's own parentExists 404 (correct fail-closed). A marker failure
	// is an internal fault, not client-attributable, so it denies denyclass.Internal
	// WITHOUT reaching WriteStream. ---
	if h.deps.CreateSubtree != "" {
		ensureDir := path.Dir(engineRef)
		if ensureDir != h.deps.CreateSubtree && !strings.HasPrefix(ensureDir, h.deps.CreateSubtree+"/") {
			// Impossible under the join above (engineRef is subtree-prefixed and clean):
			// a miss means the join invariant was broken upstream. Fail closed, never
			// ensure outside the subtree.
			reqLog.Error("files-api create: join-subtree containment invariant violated",
				slog.String(observ.KeyReason, "ensure dir escaped the create subtree"))
			denyCreate(denyclass.Internal, "internal error")
			return
		}
		if eerr := southface.EnsureDir(r.Context(), h.deps.Engine, ps.FilesystemID, ensureDir); eerr != nil {
			// A backend refusal on the marker write is the BACKEND's condition,
			// not this service's fault: transient (e.g. a full backend refusing
			// the PUT with a 5xx) is backend_unavailable, load-shed is throttle.
			// Anything else stays the fail-closed internal.
			class := denyclass.Internal
			reason := "internal error"
			switch {
			case errors.Is(eerr, southface.ErrBackendTransient):
				class, reason = denyclass.BackendUnavailable, "storage backend unavailable"
			case errors.Is(eerr, southface.ErrBackendThrottled):
				class, reason = denyclass.Throttle, "storage backend throttled"
			}
			reqLog.Error("files-api create: ensure join-subtree parent failed",
				slog.String(observ.KeyReason, eerr.Error()),
				slog.String(observ.KeyDenyClass, class))
			denyCreate(class, reason)
			return
		}
	}

	// --- reassembly: single io.Pipe -> WriteStream(overwrite=OverwriteExisting).
	// overwrite_existing defaults to false when absent (JSON zero value),
	// preserving create-new behaviour for any sender that omits it. ---
	pr, pw := io.Pipe()
	// writeErrCh carries the engine's WriteStream outcome: the error AND, on
	// success, the content SHA-256 the engine computed in its single write pass
	// (D6, PARITY-LEDGER-147). The digest is read ONLY on the success path (after
	// the half-close), so the abort receives discard it; the record Put threads it
	// northward.
	writeErrCh := make(chan writeResult, 1)
	go func() {
		// Panic containment: on a panic in WriteStream, recoverCreateWriteStream
		// closes pr with the internal sentinel (unblocking any producer pw.Write)
		// and sends on writeErrCh. The engine's temp+rename atomicity guarantees no
		// torn object is visible.
		defer recoverCreateWriteStream(pr, writeErrCh)
		digest, werr := h.deps.Engine.WriteStream(r.Context(), ps.FilesystemID, engineRef, pr, params.OverwriteExisting)
		// Close the read end with the engine's error so a producer pw.Write blocked
		// on a reader that returned early (e.g. WriteStream refused already_exists
		// WITHOUT consuming r) unblocks immediately with that error instead of
		// deadlocking on the unread pipe.
		pr.CloseWithError(werr)
		writeErrCh <- writeResult{digest: digest, err: werr}
	}()

	// Stream the raw file part into the engine pipe in ceiling-bounded reads,
	// enforcing the exact-byte declared-size contract as bytes arrive. Each read
	// is bytes-ceiling-acquired and size-checked against the running total before
	// it reaches the engine.
	var acc int64
	buf := make([]byte, createReadChunk)
	for {
		n, rerr := filePart.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			acc += int64(n)
			if acc > declared {
				// Over-declaration: abort before the excess reaches the engine. Deny
				// audit then REST deny, then close the engine pipe with a NON-EOF
				// sentinel so WriteStream reclaims the temp.
				denyCreate(denyclass.SizeExceeded, "uploaded bytes exceed declared size")
				pw.CloseWithError(errCreateAborted)
				<-writeErrCh
				return
			}
			if err := sess.AcquireBytes(int64(n)); err != nil {
				denyCreate(denyclass.Throttle, "in-flight byte ceiling exceeded")
				pw.CloseWithError(err)
				<-writeErrCh
				return
			}
			acquired += int64(n)

			if _, werr := pw.Write(chunk); werr != nil {
				// The pipe write failed: the engine rejected (e.g. already_exists)
				// WITHOUT consuming r. Drain the engine error and map it.
				engRes := <-writeErrCh
				denyCreate(denyClassForEngineErr(engRes.err), "upload refused")
				return
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break // closing multipart boundary = authoritative end of the part
			}
			// A non-EOF read error (truncated body / client disconnect / malformed
			// trailing boundary): HARD ABORT. Close the engine pipe with a NON-EOF
			// abort sentinel, never the raw rerr: io.Copy inside WriteStream treats a
			// pipe read returning io.EOF as a CLEAN end and would commit the partial
			// bytes. The sentinel forces WriteStream to fail and reclaim the temp.
			denyCreate(denyclass.Malformed, "malformed or truncated upload body")
			pw.CloseWithError(errCreateAborted)
			<-writeErrCh
			return
		}
	}

	// --- under-declaration: the body must yield EXACTLY declared ---
	if acc != declared {
		denyCreate(denyclass.SizeExceeded, "uploaded bytes do not match declared size")
		pw.CloseWithError(errCreateAborted)
		<-writeErrCh
		return
	}

	// Commit: closing the pipe writer signals EOF; WriteStream's temp+rename makes
	// the object visible only now.
	pw.Close()
	writeRes := <-writeErrCh
	if writeRes.err != nil {
		denyCreate(denyClassForEngineErr(writeRes.err), "upload refused")
		return
	}

	// --- bytes are now durable: Put the durable handle referencing the engine
	// object. DownloadablePolicyRef is deliberately left empty (Q2 deferred —
	// downloadable resolves at read, never stamped at write).
	//
	// DESIGN-ACCEPTED ORPHAN WINDOW: the bytes are committed to the engine
	// namespace BEFORE the handle is Put, so a Put failure below leaves a
	// fully-written object with NO file_id — orphan bytes reachable by no
	// Files-API verb (List/Get/content/delete all resolve through the handle
	// store). This is accepted, not a leak: the ALLOW was already audited, the
	// caller gets a 503 and no id, and the orphan is reclaimed by the engine's
	// workspace Provision/Teardown sweep (the ephemeral-workspace model — the
	// broker takes on no durable retention). The alternative (handle-before-bytes)
	// would mint a file_id that resolves to absent bytes — a worse contract. ---
	rec, perr := h.deps.Store.Put(r.Context(), handlestore.PutInput{
		Scope:     ps.FilesystemID,
		ObjectRef: engineRef,
		Filename:  createFilename(params, engineRef),
		Mime:      params.MediaType,
		Size:      declared,
		// Sha256 is the engine's single-pass content digest (D6): the record
		// carries it so the north list surfaces it for upload-client content
		// dedup. Empty when the engine returned no digest - the compat window.
		Sha256: writeRes.digest,
	})
	if perr != nil {
		// The bytes are durable but the handle did not land. A latched store is a
		// transient broker-internal state (recovery is a restart): 503 (unavailable,
		// retryable); any other store error fails closed to 500. This is NOT a
		// client-attributable deny, so it is written directly (no deny audit — the
		// ALLOW already recorded the durable create; the missing handle is a
		// broker-internal fault, not a refusal of the caller's request).
		if errors.Is(perr, handlestore.ErrStoreUnavailable) {
			reqLog.Error("files-api create: handle store unavailable after durable write",
				slog.String(observ.KeyDenyClass, denyclass.BackendUnavailable))
			denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.BackendUnavailable), "handle store unavailable")
			return
		}
		reqLog.Error("files-api create: handle store Put failed after durable write",
			slog.String(observ.KeyReason, perr.Error()))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Internal), "internal error")
		return
	}

	// SUCCESS: 201 Created + the minted FileObject.
	writeJSON(w, http.StatusCreated, newFileObject(rec))
}

// createReadChunk is the buffer size for one read off the streamed "file" part.
// A single Read off the part may return less than a full client write, so the
// handler reads in a loop with this fixed buffer; each read is
// bytes-ceiling-acquired and size-checked against the running total before it
// reaches the engine. It mirrors the south uploadReadChunk.
const createReadChunk = 256 * 1024

// createParamsField / createFileField are the form-field names of the two upload
// parts: the params JSON field and the streamed file part. They match the south
// multipart field names.
const (
	createParamsField = "params"
	createFileField   = "file"
)

// errCreateAborted is the hard-abort sentinel the reassembler closes the engine
// pipe with on an over/under-declaration or a truncated body. It MUST be distinct
// from io.EOF: io.Copy inside WriteStream treats a pipe read returning io.EOF as
// a CLEAN end-of-stream and would commit the partial bytes (temp+rename), so a
// non-EOF sentinel is what forces WriteStream to fail and discard the temp,
// preserving the abort-stages-nothing invariant. It mirrors the south
// errStreamAborted.
var errCreateAborted = errors.New("filesapi: inbound upload aborted before half-close")

// errCreateInternalPanic is the sentinel the pipe goroutine's panic-recovery
// sends when WriteStream panics: it unblocks a producer pw.Write and lets the
// handler drain writeErrCh and abort. It classifies (via denyClassForEngineErr)
// to the internal deny class, the same as any unrecognised engine fault. It
// mirrors the south errInternalPanic.
var errCreateInternalPanic = errors.New("filesapi: engine WriteStream panicked")

// createUploadParams is the strict-decoded "params" field of a create upload. It
// carries the same top-level fields the south upload params frame declares that
// the create write plane consumes: filesystem_id (an untrusted hint cross-checked
// against the attested scope), path, declared_size_bytes (REQUIRED),
// overwrite_existing (defaults false when absent), media_type (the response
// mime_type), and filename (the display name). Unknown fields are refused
// (DisallowUnknownFields) so a caller cannot smuggle an unrecognised parameter.
// createAuthorizationMetadata mirrors the contract AuthorizationMetadata
// (files-api.openapi.yaml, additionalProperties:false): the create-time intent
// and downloadable request. Scope still rides the attested header, never this
// body; this is design-level create-meta.
type createAuthorizationMetadata struct {
	Intent       string `json:"intent"`
	Downloadable bool   `json:"downloadable"`
}

type createUploadParams struct {
	FilesystemID      string `json:"filesystem_id"`
	Path              string `json:"path"`
	DeclaredSizeBytes int64  `json:"declared_size_bytes"`
	OverwriteExisting bool   `json:"overwrite_existing"`
	MediaType         string `json:"media_type"`
	Filename          string `json:"filename"`
	// The struct MUST implement EVERY CreateFileParams property the frozen
	// contract declares — DisallowUnknownFields rejects any contract-legal field
	// this struct omits, 400ing a conforming client. authorization_metadata,
	// metadata, tags, ttl_seconds are create-meta the write plane may ignore, but
	// it MUST accept them or the upload fails at strict-decode.
	AuthorizationMetadata *createAuthorizationMetadata `json:"authorization_metadata"`
	Metadata              map[string]any               `json:"metadata"`
	Tags                  []string                     `json:"tags"`
	TTLSeconds            *int64                       `json:"ttl_seconds"`
}

// readCreateParams reads the FIRST multipart part, which MUST be the "params"
// form field, and strict-decodes the upload params JSON from it. A missing part,
// a non-"params" first part, an oversize params value, or an
// undecodable/unknown-field/trailing-value JSON is a hard reject written through
// denyReject (400 malformed). It returns ok=false after writing the deny so the
// caller returns immediately. The params value is bounded by SizeCeiling before
// decoding so a pathological params field cannot exhaust memory; the file PART,
// not the params FIELD, carries the bulk bytes.
func (h *Handler) readCreateParams(mr *multipart.Reader, denyReject func(auditReason, message string)) (createUploadParams, bool) {
	part, err := mr.NextPart()
	if err != nil {
		denyReject(denyclass.Malformed, "missing multipart params part")
		return createUploadParams{}, false
	}
	if part.FormName() != createParamsField {
		denyReject(denyclass.Malformed, "first multipart part must be the params field")
		return createUploadParams{}, false
	}
	raw, err := io.ReadAll(io.LimitReader(part, h.deps.SizeCeiling+1))
	if err != nil {
		denyReject(denyclass.Malformed, "malformed multipart params part")
		return createUploadParams{}, false
	}
	if int64(len(raw)) > h.deps.SizeCeiling {
		denyReject(denyclass.Throttle, "params field exceeds message ceiling")
		return createUploadParams{}, false
	}

	var p createUploadParams
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		denyReject(denyclass.Malformed, "malformed params JSON")
		return createUploadParams{}, false
	}
	var extra json.RawMessage
	if dec.Decode(&extra) == nil {
		// A trailing second JSON value: malformed (single-value enforcement).
		denyReject(denyclass.Malformed, "malformed params JSON")
		return createUploadParams{}, false
	}
	return p, true
}

// openCreateFilePart reads the SECOND multipart part, which MUST be the "file"
// form file, and returns it as a streaming reader. A missing part or a second
// part that is not the "file" field is a hard reject written through denyReject
// (400 malformed). It returns ok=false after writing the deny so the caller
// returns immediately. The part body is NOT buffered — the caller streams it into
// the engine pipe.
func (h *Handler) openCreateFilePart(mr *multipart.Reader, denyReject func(auditReason, message string)) (*multipart.Part, bool) {
	part, err := mr.NextPart()
	if err != nil {
		denyReject(denyclass.Malformed, "missing multipart file part")
		return nil, false
	}
	if part.FormName() != createFileField {
		denyReject(denyclass.Malformed, "second multipart part must be the file field")
		return nil, false
	}
	return part, true
}

// createEvidenceIntents returns the intent grant the create verb presents to the
// Resolver: the scope's own granted intents PLUS write. The placeholder
// ScopeSource stamps only read intent on ps.GrantedIntents (the read/delete
// plane's need); the write verb adds IntentWrite so the Resolver's intentGranted
// gate passes, MIRRORING how the south upload resolves write from the attested
// channel scope. It de-duplicates so a scope source that already grants write is
// not double-listed. The broker-side Resolver remains the deny-by-default
// decision; this is only an input to that re-derivation.
func createEvidenceIntents(ps southface.PeerScope) []southface.Intent {
	out := make([]southface.Intent, 0, len(ps.GrantedIntents)+1)
	hasWrite := false
	for _, in := range ps.GrantedIntents {
		out = append(out, in)
		if in == southface.IntentWrite {
			hasWrite = true
		}
	}
	if !hasWrite {
		out = append(out, southface.IntentWrite)
	}
	return out
}

// createFilename resolves the stored display name: the caller-supplied filename
// when present, else the leaf of the canonical engine path (the last path
// segment). A path that is the scope root or has no usable leaf falls back to the
// engine reference itself so the record always carries a non-empty display name.
func createFilename(params createUploadParams, engineRef string) string {
	if params.Filename != "" {
		return params.Filename
	}
	leaf := path.Base(engineRef)
	if leaf == "" || leaf == "." || leaf == "/" {
		return engineRef
	}
	return leaf
}

// canonicalizeCreatePath maps a caller-supplied wire path to the single
// canonical engine-relative form the create write targets, or an error for an
// unsafe path. It reproduces the wire-boundary obligation the south
// canonicalizePath+enginePath pair discharges: reject a NUL byte, a URL-shaped
// handle, and an absolute/".." path that escapes the scope root, apply
// path.Clean, then strip to the engine's relative convention (no leading slash;
// the scope root is rejected as an unsafe target — a create must name an object,
// not the root). The cleaned form is what authz, the audit record, the engine
// write, and the stored ObjectRef ALL see, so no layer can disagree about which
// object the path names.
//
// It is a north-local mirror rather than a call into the south-private helper:
// the filesapi plane keeps the same consumer-seam isolation the south face keeps
// (it does not import the south-private canonicalizer), exactly as content.go's
// enginePath mirrors the read-side normalisation. The north landing subtree the
// serveCreate join prepends to this canonical form is the deployment map's read
// entry, injected at construction (Deps.CreateSubtree) — still no south
// canonicalizer import.
func canonicalizeCreatePath(wire string) (string, bool) {
	if strings.ContainsRune(wire, '\x00') {
		return "", false
	}
	if hasURLScheme(wire) {
		return "", false
	}
	// Anchor at the scope root so a leading-slash path and a relative path clean
	// identically. path.Clean collapses any leading ".." against this "/" anchor
	// down to the root itself (path.Clean("/..") == "/", path.Clean("/../x") ==
	// "/x"), so an over-climb never survives here as a residual "/..". The check
	// below is therefore UNREACHABLE under this anchoring — it is retained only as
	// defense-in-depth against a future change to the anchoring above, not as a
	// live second traversal barrier. The reachable over-climb-to-root reduces to
	// the scope root and is refused by the eng == "" check further down (a create
	// must name a concrete object, not the root), which is the load-bearing barrier.
	rel := strings.TrimPrefix(wire, "/")
	clean := path.Clean("/" + rel)
	if clean == "/.." || strings.HasPrefix(clean, "/../") {
		return "", false
	}
	// Strip to the engine's relative convention. The scope root ("/" -> "") is an
	// unsafe create target: a create must name a concrete object, not the root.
	eng := strings.TrimPrefix(clean, "/")
	if eng == "" {
		return "", false
	}
	return eng, true
}

// hasURLScheme reports whether s begins with an RFC-3986 scheme followed by
// "://". It runs on the raw input BEFORE path.Clean, which deduplicates "//" and
// would hide the scheme shape — blocking a backend address (e.g. "s3://bucket/
// key") smuggled through the path field. It mirrors the south hasURLScheme.
func hasURLScheme(s string) bool {
	i := 0
	isAlpha := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	if i >= len(s) || !isAlpha(s[i]) {
		return false
	}
	i++
	for i < len(s) && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '+' || s[i] == '-' || s[i] == '.') {
		i++
	}
	return i+2 < len(s) && s[i] == ':' && s[i+1] == '/' && s[i+2] == '/'
}

// writeResult is the outcome the WriteStream pipe goroutine sends on writeErrCh:
// the engine error and, on success, the content SHA-256 the engine computed in
// its single write pass (D6, PARITY-LEDGER-147). On any error path (engine
// refusal, abort, panic) the digest is empty and only err is consumed; the
// success path threads the digest into the durable handle record.
type writeResult struct {
	digest string
	err    error
}

// recoverCreateWriteStream is the panic-containment wrapper for the WriteStream
// pipe goroutine. On a panic it closes the pipe reader with the internal
// sentinel (unblocking a producer pw.Write blocked on the reader) and sends the
// sentinel on writeErrCh so the handler drains and aborts. The engine's
// temp+rename atomicity guarantees an aborted WriteStream writes nothing to the
// namespace. It is a north-local mirror of the south recoverWriteStream. The
// digest is empty on a panic (no successful write occurred).
func recoverCreateWriteStream(pr *io.PipeReader, writeErrCh chan<- writeResult) {
	if v := recover(); v == nil {
		return
	}
	pr.CloseWithError(errCreateInternalPanic)
	writeErrCh <- writeResult{err: errCreateInternalPanic}
}

// denyClassForResolveErr names the deny class for a Resolver seam sentinel,
// MIRRORING the south denyClassForErr for the authz axes the create path can
// surface: a scope mismatch, an intent-denied, a size-exceeded, a throttle, an
// audit-down, or a cancellation. An error outside the known set is a wiring fault
// and fails closed to internal.
func denyClassForResolveErr(err error) string {
	switch {
	case errors.Is(err, southface.ErrScopeMismatch):
		return denyclass.ScopeMismatch
	case errors.Is(err, southface.ErrIntentDenied):
		return denyclass.IntentDenied
	case errors.Is(err, southface.ErrNotDownloadable):
		return denyclass.NotDownloadable
	case errors.Is(err, southface.ErrSizeExceeded):
		return denyclass.SizeExceeded
	case errors.Is(err, southface.ErrThrottleExceeded),
		errors.Is(err, southface.ErrBytesExceeded),
		errors.Is(err, southface.ErrFDExceeded):
		return denyclass.Throttle
	case errors.Is(err, southface.ErrAuditUnavailable):
		return denyclass.AuditDown
	default:
		return denyclass.Internal
	}
}

// denyClassForEngineErr names the deny class for an engine WriteStream error on
// the create path: an already-exists refusal (overwrite_existing=false against an
// existing object) is the 409 already_exists class; a missing-parent write (the
// client named a path whose parent directory does not exist) is a
// client-attributable 404 not_found, NOT an internal fault; a throttled or
// transient backend refusal is the backend's condition (429 throttle / 503
// backend_unavailable), matching the south spine's rows for the same mirrors;
// anything else fails closed to internal. It mirrors the south spine
// engine-error classifier (internal/southface: fs.ErrNotExist -> not_found,
// fs.ErrExist -> already_exists, throttled/transient -> throttle/unavailable)
// for the subset a create WriteStream can surface. The engine surfaces a
// missing-parent as a raw *fs.PathError wrapping fs.ErrNotExist, so the match is
// on the standard-library sentinel, exactly as the south classifier does.
func denyClassForEngineErr(err error) string {
	switch {
	case errors.Is(err, southface.ErrAlreadyExists), errors.Is(err, fs.ErrExist):
		return denyclass.AlreadyExists
	case errors.Is(err, fs.ErrNotExist):
		return denyclass.NotFound
	case errors.Is(err, southface.ErrBackendThrottled):
		return denyclass.Throttle
	case errors.Is(err, southface.ErrBackendTransient):
		return denyclass.BackendUnavailable
	default:
		return denyclass.Internal
	}
}
