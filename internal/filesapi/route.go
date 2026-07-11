// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// The five Files-API endpoints (ADR-0023):
//
//	POST   /v1/files              create  (multipart upload -> 201 + FileObject)
//	GET    /v1/files              list
//	GET    /v1/files/{file_id}    metadata
//	GET    /v1/files/{file_id}/content   bytes
//	DELETE /v1/files/{file_id}    delete
//
// The route layer dispatches by method+path, derives the host-attested scope
// ONCE per request, and refuses with a header-less anti-enumeration 404 on any
// unknown path. There is NO 403 on any file_id-resolution path: a route the
// handler does not recognise is a 404 (path enumeration is refused exactly like
// handle enumeration), and an unsupported method on a KNOWN route is a 405 +
// Allow (an HTTP-method fault, not an authorization verdict).

// filesRoot is the collection path; filesPrefix is the per-resource prefix.
const (
	filesRoot   = "/v1/files"
	filesPrefix = "/v1/files/"
)

// requestIDHeader is the per-request correlation header stamped on every
// response (allow and deny alike), so the audit record, the response header, and
// the log line share one id. It matches the south face's header name.
const requestIDHeader = "x-request-id"

// ServeHTTP is the Files-API entry. It stamps a per-request correlation id,
// derives the host-attested scope (fail-closed), then dispatches to the matching
// endpoint. An unknown path is a header-less 404 (anti-enumeration); an
// unsupported method on a known path is a 405 + Allow.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := newRequestID()
	w.Header().Set(requestIDHeader, reqID)
	reqLog := h.deps.Logger.With(slog.String(observ.KeyRequestID, reqID))

	// Derive the host-attested scope ONCE (fail-closed). A request without a
	// resolvable attested scope is a wiring fault on the F9 channel — refuse it
	// before touching the store. The refusal is an internal/503 class: it is a
	// channel-attestation defect, never a client authorization verdict (so it
	// can never be a 403 that would leak a scope distinction).
	ps, ok := h.deps.Scope.Scope(r)
	if !ok {
		// A request without a resolvable host-attested scope is a channel
		// attestation/wiring fault on the F9 leg — transient and retryable, so the
		// wire signals 503 (unavailable). It is NEVER a 403: a 403 would be an
		// authorization verdict that could leak a scope distinction; the missing
		// scope is a channel defect, not a per-request authorization outcome.
		reqLog.Warn("files-api request without host-attested scope",
			slog.String(observ.KeyReason, "no_attested_scope"))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.BackendUnavailable), "missing host-attested scope")
		return
	}

	// North shape guard (ADR-0030 north face, open question #348): the resolved
	// filesystem_id must be a single, clean path element. A traversal-shaped scope
	// (a separator, NUL, "." / "..", or a non-clean form) is refused at THIS choke
	// point - the one place FilesystemID is derived per request - so a malformed
	// scope never reaches the store or the engine. It reuses the SAME 503
	// fail-closed deny as the missing-scope path (no distinct deny class, so it can
	// never leak a scope distinction and is never a 403). This is a COOPERATIVE
	// shape guard, not a per-chat authorization point: the caller supplies the whole
	// filesystem_id, so this cannot enforce which chat a caller may reach - per-chat
	// isolation lives on the credential/south path. It enforces only that the value
	// is a legal directory element.
	if err := validateScopeShape(ps.FilesystemID); err != nil {
		reqLog.Warn("files-api request with malformed scope shape",
			slog.String(observ.KeyReason, "malformed_scope_shape"))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.BackendUnavailable), "malformed scope shape")
		return
	}

	path := r.URL.Path
	switch {
	case path == filesRoot:
		h.routeCollection(w, r, ps, reqID, reqLog)
	case path == archivePath:
		// The additive archive verb is a SIBLING off /v1/files, matched BEFORE the
		// per-resource prefix below so "archive" is never parsed as a {file_id}.
		h.routeArchive(w, r, ps, reqID, reqLog)
	case strings.HasPrefix(path, filesPrefix):
		h.routeResource(w, r, ps, reqID, reqLog, strings.TrimPrefix(path, filesPrefix))
	default:
		// Unknown path: header-less 404 (anti-enumeration). A path the handler
		// does not serve is indistinguishable from an absent resource.
		writeNotFound(w)
	}
}

// routeCollection dispatches the /v1/files collection: GET lists, POST creates
// (multipart upload). Any other method is 405 + Allow.
func (h *Handler) routeCollection(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, reqID string, reqLog *slog.Logger) {
	switch r.Method {
	case http.MethodGet:
		h.serveList(w, r, ps, reqLog)
	case http.MethodPost:
		h.serveCreate(w, r, ps, reqID, reqLog)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// routeArchive dispatches the additive /v1/files/archive verb: GET streams a zip
// of the named accessible files. Any other method is 405 + Allow: GET.
func (h *Handler) routeArchive(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, reqID string, reqLog *slog.Logger) {
	switch r.Method {
	case http.MethodGet:
		h.serveArchive(w, r, ps, reqID, reqLog)
	default:
		writeMethodNotAllowed(w, http.MethodGet)
	}
}

// routeResource dispatches the per-resource paths under /v1/files/: the bare
// {file_id} (GET metadata, DELETE delete) and {file_id}/content (GET bytes). A
// malformed tail (empty file_id, an unknown sub-path) is a header-less 404.
func (h *Handler) routeResource(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, reqID string, reqLog *slog.Logger, tail string) {
	// tail is the path after "/v1/files/". It is either "{file_id}" or
	// "{file_id}/content"; anything else is an unknown resource (404).
	if tail == "" {
		writeNotFound(w)
		return
	}
	fileID, sub, hasSub := strings.Cut(tail, "/")
	if fileID == "" {
		writeNotFound(w)
		return
	}

	if hasSub {
		// Only {file_id}/content is a known sub-resource; anything else is 404.
		if sub != "content" {
			writeNotFound(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.serveContent(w, r, ps, fileID, reqID, reqLog)
		default:
			writeMethodNotAllowed(w, http.MethodGet)
		}
		return
	}

	// Bare {file_id}: GET metadata, DELETE delete.
	switch r.Method {
	case http.MethodGet:
		h.serveMetadata(w, r, ps, fileID, reqID, reqLog)
	case http.MethodDelete:
		h.serveDelete(w, r, ps, fileID, reqID, reqLog)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodDelete)
	}
}

// writeNotFound writes the header-less anti-enumeration 404 for an UNKNOWN-PATH
// resolution failure: an unknown route path, an empty/malformed resource tail, or
// the archive verb's empty accessible set. It carries no x-deny-reason header and
// is byte-identical to writeResolutionDeny's file_id-resolution 404, so a probe
// cannot tell an unknown path from an absent or a cross-scope file_id — the two
// writers together present the single keystone deny SHAPE on the wire. The
// file_id-resolution 404s themselves (absent OR cross-scope handle) are written by
// writeResolutionDeny, not here; this writer never consults the store.
func writeNotFound(w http.ResponseWriter) {
	denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.NotFound), "not found")
}

// writeMethodNotAllowed writes a 405 with the Allow header listing the methods a
// known route accepts. A method fault on a known route is an HTTP-semantics
// refusal, NOT an authorization verdict — it carries no x-deny-reason and is a
// distinct class from the not_found resolution path (it never leaks whether a
// file_id exists, because it is decided on the ROUTE before any store lookup).
func writeMethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	// 405 is an HTTP-method semantics status; the deny vocabulary has no
	// dedicated class, so it is written directly with a malformed reason_code
	// body for diagnostics (invalid_argument family) but the AUTHORITATIVE status
	// is overridden to 405.
	v := denywire.MapDeny(denyclass.Malformed)
	v.WireStatus = http.StatusMethodNotAllowed
	denywire.WriteRESTDeny(w, v, "method not allowed")
}

// newRequestID returns a 32-char lowercase hex correlation id from 16 bytes of
// crypto/rand. A failing kernel CSPRNG is unrecoverable — fail loud.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("filesapi: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
