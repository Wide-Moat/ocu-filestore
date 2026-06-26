// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// serveMetadata serves GET /v1/files/{file_id}: it resolves the file_id against
// the host-attested scope and returns the FileObject, or the keystone 404.
//
// KEYSTONE: Store.Get returns the SAME handlestore.ErrNotFound for an absent
// file_id AND a cross-scope one. This handler maps that single sentinel to a
// header-less 404 with NO branch that distinguishes the two — it is structurally
// incapable of returning 403/scope_mismatch on the file_id path. A store-latch
// fault (ErrStoreUnavailable) is a broker-internal 503, never a client deny.
//
// downloadable is omitted from the FileObject (resolved at read only, NFR-SEC-73).
func (h *Handler) serveMetadata(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, fileID, reqID string, reqLog *slog.Logger) {
	rec, err := h.deps.Store.Get(r.Context(), fileID, ps.FilesystemID)
	if err != nil {
		writeResolutionDeny(w, reqLog, err, reqID)
		return
	}
	writeJSON(w, http.StatusOK, newFileObject(rec))
}

// writeResolutionDeny is the SINGLE deny path for a file_id resolution failure,
// shared by metadata, content, and delete. It maps the store sentinel to the
// wire:
//
//   - handlestore.ErrNotFound (absent OR cross-scope — the same sentinel) ->
//     header-less 404 (the keystone; the two are indistinguishable).
//   - handlestore.ErrStoreUnavailable (the store latched) -> 503 internal.
//   - any other error -> 503 internal (fail closed; a wiring fault is never a
//     client-attributable deny that could leak a scope distinction).
//
// There is NO 403 branch here BY CONSTRUCTION: this function is the only place a
// file_id-resolution error reaches the wire, and it has no permission_denied
// path. CorrelationID is carried for the not_found case so the log/audit/wire
// share one id even though the not_found wire class is header-less.
func writeResolutionDeny(w http.ResponseWriter, reqLog *slog.Logger, err error, reqID string) {
	switch {
	case errors.Is(err, handlestore.ErrNotFound):
		// Keystone: header-less 404. No x-deny-reason — a probe cannot tell an
		// absent file_id from a cross-scope one.
		reqLog.Info("files-api resolution not found",
			slog.String(observ.KeyDenyClass, denyclass.NotFound))
		v := denywire.MapDeny(denyclass.NotFound)
		v.CorrelationID = reqID
		denywire.WriteRESTDeny(w, v, "not found")
	case errors.Is(err, handlestore.ErrStoreUnavailable):
		// A latched durable handle store is a transient broker-internal state
		// (recovery is a restart): the wire signals 503 (unavailable, retryable),
		// distinct from a 500 permanent fault. The audited truth is the store
		// latch; the wire class is the backend_unavailable family (503).
		reqLog.Error("files-api handle store unavailable",
			slog.String(observ.KeyDenyClass, denyclass.BackendUnavailable))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.BackendUnavailable), "handle store unavailable")
	default:
		reqLog.Error("files-api resolution error",
			slog.String(observ.KeyReason, err.Error()))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Internal), "internal error")
	}
}

// writeJSON writes a success JSON body with the given status. It is the shared
// success-path writer for metadata and list. A marshal failure is a programmer
// error (the value types are closed structs), so it degrades to a 500 with no
// body rather than a partial write.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
