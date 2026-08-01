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

// serveDelete serves DELETE /v1/files/{file_id}:
// charge-then-Get-then-authorize-then-audit-then-Delete.
//
// Order (Default 2, load-bearing):
//
//   - ops/s charge FIRST (NFR-SEC-46), before the store is read: an exhausted
//     bucket costs neither a handle resolution nor a mutation attempt.
//   - Store.Get(file_id, attestedScope) resolves the record IFF the scope
//     byte-matches; absent OR cross-scope is the SAME keystone 404 (no
//     distinguishing branch), and records no activity — an unresolved file_id
//     named no object in this scope.
//   - Resolve(intent=write) from the attested scope: the three axes are
//     re-derived broker-side per request, deny-by-default. A delete is a
//     NAMESPACE MUTATION, so the axis is write — the same class the repo's
//     closed route-op map gives removeFile and the same intent the delete audit
//     event stamps. A deny here is a 403 on an ALREADY-resolved record, never
//     the keystone's absent-vs-foreign distinction — and under the shipped F9
//     grant it is a shape the seam permits rather than one a deployment
//     produces, since the evidence below satisfies the intent axis by
//     construction (see fencedGrantedIntents).
//   - Mandate the ALLOW audit (ObjectHandle = Record.ObjectRef) AFTER the
//     authorization and BEFORE the tombstone (audit-before-ack, SEC-79): the
//     durable record names the object the delete is about to remove. An audit
//     failure denies 503 and the tombstone is NEVER written.
//   - Store.Delete tombstones the record. A latched store (mutation-path fault)
//     returns ErrStoreUnavailable -> emit a DENY audit (best-effort) and 503.
//
// A successful delete returns 204 No Content (no body).
func (h *Handler) serveDelete(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, fileID, reqID string, reqLog *slog.Logger) {
	// --- ops/s throttle, keyed on the CHANNEL scope (mirrors every other north
	// verb). Charged BEFORE the store so a refused request costs neither a
	// resolution nor a mutation attempt. ---
	sess := h.deps.Ceilings.Session(ps.FilesystemID)
	if oerr := sess.TryConsumeOp(); oerr != nil {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Throttle), "operation rate ceiling exceeded")
		return
	}

	// --- Get first (keystone: absent == cross-scope == ErrNotFound) ---
	rec, err := h.deps.Store.Get(r.Context(), fileID, ps.FilesystemID)
	if err != nil {
		writeResolutionDeny(w, reqLog, err, reqID)
		return
	}

	// --- authz Resolve(intent=write) from the attested scope ---
	//
	// The question is asked at the record's stored backend reference VERBATIM,
	// with no enginePath normalisation. The two byte-reading verbs normalise
	// because the normalised path is what they then hand to the engine; a delete
	// dials no engine at all (Store.Delete tombstones the north handle — byte
	// lifecycle belongs to the engine), so there is no engine path to normalise
	// FOR. Refusing a non-normalising reference here would also strand the
	// handle: unreadable AND undeletable, still listed. For a destructive verb,
	// "fail closed" that keeps a suspect record alive points the wrong way.
	//
	// The evidence ADDS write intent (writeEvidenceIntents), exactly as the
	// create verb does: the shipped F9 ScopeSource stamps only read intent, so
	// presenting ps.GrantedIntents verbatim would deny every live delete on the
	// intent axis. The Resolver stays the deny-by-default decision — but with
	// this evidence and this scope source it has no axis left to fail on, so the
	// arm below is a guarded seam, not a live gate (see fencedGrantedIntents).
	req := southface.ResolveRequest{Filesystem: ps.FilesystemID, Path: rec.ObjectRef, Intent: southface.IntentWrite}
	evidence := southface.CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: writeEvidenceIntents(ps)}
	if _, rerr := h.deps.Resolver.Resolve(r.Context(), evidence, req); rerr != nil {
		h.denyDelete(w, r, reqLog, ps, rec, denyClassForResolveErr(rerr), "authorization denied", reqID)
		return
	}

	// --- audit ALLOW after the authorization, BEFORE the tombstone
	// (audit-before-ack) ---
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

// denyDelete emits the delete DENY audit (the broker-resolved truth) then the
// REST deny response. It is the PRE-MUTATION refusal path: it is only ever
// reached before the ALLOW audit and therefore before the tombstone, so the
// durable store is untouched and it can always write a real HTTP status.
//
// A deny-Mandate FAILURE degrades the verdict to audit_down (NFR-SEC-79):
// a refusal the chain does not carry is not a refusal the wire may assert. This
// is the OPPOSITE rule from denyDeleteAfterAudit, and deliberately so — there
// the ALLOW already landed and the operation acked nothing, so a failed deny
// record cannot make the verdict worse; here the deny record is the ONLY record
// the request would produce.
func (h *Handler) denyDelete(w http.ResponseWriter, r *http.Request, reqLog *slog.Logger, ps southface.PeerScope, rec handlestore.Record, auditReason, message, reqID string) {
	reqLog.Warn("files-api delete deny",
		slog.String(observ.KeyDenyClass, auditReason),
		slog.String(observ.KeyReason, message))
	ev := deleteDenyEvent(ps, rec, auditReason, reqID)
	if merr := h.deps.Guard.Mandate(r.Context(), ev); merr != nil {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
		return
	}
	denywire.WriteRESTDeny(w, denywire.MapDeny(auditReason), message)
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
