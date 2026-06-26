// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// serveDelete serves DELETE /v1/files/{file_id}: Get-then-audit-then-Delete.
//
// Order (Default 2, load-bearing):
//
//   - Store.Get(file_id, attestedScope) resolves the record IFF the scope
//     byte-matches; absent OR cross-scope is the SAME keystone 404 (no
//     distinguishing branch).
//   - Mandate the ALLOW audit (ObjectHandle = Record.ObjectRef) AFTER the
//     successful Get and BEFORE the tombstone (audit-before-ack, SEC-79): the
//     durable record names the object the delete is about to remove. An audit
//     failure denies 503 and the tombstone is NEVER written.
//   - Store.Delete tombstones the record. A latched store (mutation-path fault)
//     returns ErrStoreUnavailable -> emit a DENY audit (best-effort) and 503.
//
// A successful delete returns 204 No Content (no body).
func (h *Handler) serveDelete(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, fileID, reqID string, reqLog *slog.Logger) {
	// --- Get first (keystone: absent == cross-scope == ErrNotFound) ---
	rec, err := h.deps.Store.Get(r.Context(), fileID, ps.FilesystemID)
	if err != nil {
		writeResolutionDeny(w, reqLog, err, reqID)
		return
	}

	// --- audit ALLOW after the Get, BEFORE the tombstone (audit-before-ack) ---
	allow := deleteAllowEvent(ps, rec, reqID)
	if merr := h.deps.Guard.Mandate(r.Context(), allow); merr != nil {
		reqLog.Error("files-api delete: allow audit failed before tombstone",
			slog.String(observ.KeyDenyClass, denyclass.AuditDown))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
		return
	}

	// --- tombstone ---
	derr := h.deps.Store.Delete(r.Context(), fileID, ps.FilesystemID)
	if derr != nil {
		h.denyDeleteAfterAudit(w, r, reqLog, ps, rec, derr, reqID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// denyDeleteAfterAudit handles a Delete failure that occurs AFTER the ALLOW
// audit landed. A latched store (ErrStoreUnavailable) is the expected case: the
// mutation could not durably record, so the operation is denied 503 (Default 2)
// and a best-effort DENY audit names the object whose delete was refused. A
// concurrent ErrNotFound (the record was deleted between Get and Delete by
// another caller in the same scope) is the keystone 404 — still no cross-scope
// leak. Any other error is a broker-internal 503.
func (h *Handler) denyDeleteAfterAudit(w http.ResponseWriter, r *http.Request, reqLog *slog.Logger, ps southface.PeerScope, rec handlestore.Record, derr error, reqID string) {
	if errors.Is(derr, handlestore.ErrNotFound) {
		// Raced to empty between Get and Delete: keystone 404 (no leak).
		writeResolutionDeny(w, reqLog, derr, reqID)
		return
	}

	// Latched store (or any other mutation fault): deny 503. Emit a best-effort
	// DENY audit naming the object; if the audit gate is ALSO down the deny still
	// stands (the verdict is already unavailable — re-failing the audit cannot
	// make it worse, and the operation never acked a mutation).
	reqLog.Error("files-api delete: store unavailable after allow audit",
		slog.String(observ.KeyDenyClass, denyclass.BackendUnavailable),
		slog.String(observ.KeyReason, derr.Error()))
	deny := deleteDenyEvent(ps, rec, denyclass.BackendUnavailable, reqID)
	_ = h.deps.Guard.Mandate(r.Context(), deny)
	denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.BackendUnavailable), "handle store unavailable")
}
