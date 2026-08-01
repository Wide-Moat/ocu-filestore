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
// Order of operations (every clause load-bearing, mirroring the content verb):
//
//   - ops/s charge FIRST (NFR-SEC-46), before the store is read: an exhausted
//     bucket costs no handle resolution.
//   - Store.Get(file_id, attestedScope) -> Record | keystone 404. An unresolved
//     file_id records NO activity: it named no object in this scope, so there is
//     nothing honest to record — and a record of it would rebuild, in the durable
//     chain, the absent-vs-foreign distinction the keystone erases on the wire.
//   - enginePath normalises the stored ObjectRef as defense-in-depth; a reference
//     that does not normalise names no in-tree object, so the metadata verb
//     refuses it not_found rather than describing it.
//   - Resolve(intent=read) from the attested scope: the three axes are re-derived
//     broker-side per request, deny-by-default. The record ALREADY resolved in
//     scope at this point, so a 403 here is a downstream authorization verdict on
//     a resolved object, never the keystone's absent-vs-foreign distinction.
//   - Mandate the ALLOW BEFORE the FileObject reaches the caller
//     (audit-before-ack, SEC-79): an audit-down denies 503 and the record the
//     caller asked about never leaves the broker.
//
// downloadable is NOT gated here: metadata emits no object bytes, so the
// NFR-SEC-73 egress gate stays on the two byte-emitting north verbs (content and
// archive). The resolved value is RECORDED on the event and stays omitted from
// the FileObject (resolved at read, never stamped at write).
func (h *Handler) serveMetadata(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, fileID, reqID string, reqLog *slog.Logger) {
	// --- ops/s throttle, keyed on the CHANNEL scope (mirrors the content read
	// path). It is charged BEFORE the store so a refused request costs no handle
	// resolution. ---
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
	// empty or escaping path is a not_found-class refusal, exactly as on the
	// content path. It is also the path the authorization question below is asked
	// about, so the resolver is never handed a dirty reference.
	engPath, ok := enginePath(rec.ObjectRef)
	if !ok {
		reqLog.Info("files-api metadata: object reference does not normalise",
			slog.String(observ.KeyDenyClass, denyclass.NotFound))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.NotFound), "not found")
		return
	}

	// --- authz Resolve(intent=read) from the attested scope ---
	req := southface.ResolveRequest{Filesystem: ps.FilesystemID, Path: engPath, Intent: southface.IntentRead}
	evidence := southface.CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: ps.GrantedIntents}
	grant, rerr := h.deps.Resolver.Resolve(r.Context(), evidence, req)
	if rerr != nil {
		h.denyRead(w, r, reqLog, opMetadata, ps, rec, grant, denyClassForResolveErr(rerr), "authorization denied", reqID)
		return
	}

	// --- audit ALLOW before the FileObject is acknowledged (SEC-79) ---
	allow := readAllowEvent(ps, rec, grant, reqID)
	if merr := h.deps.Guard.Mandate(r.Context(), allow); merr != nil {
		// The allow Mandate itself failed (audit down). Deny before the record
		// reaches the caller; do NOT re-Mandate a deny (the gate is unavailable).
		reqLog.Error("files-api metadata: allow audit failed before the file object",
			slog.String(observ.KeyDenyClass, denyclass.AuditDown))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
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
