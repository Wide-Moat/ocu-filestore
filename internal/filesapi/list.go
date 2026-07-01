// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// listLimitParam / listAfterParam are the query parameters the list endpoint
// reads: an optional page-size limit and the forward cursor. The forward cursor
// is ?after=<next_cursor> (ADR-0028) — a caller passes the previous page's opaque
// next_cursor token to fetch the next page. It carries the store's created-at/
// file-id boundary tuple and is opaque to the caller; a bare last_id is NOT a
// valid cursor (the created-at-primary keyset walk cannot resume from it — a
// deleted boundary record would repeat or strand a record).
const (
	listLimitParam = "limit"
	listAfterParam = "after"
)

// serveList serves GET /v1/files: a scope-bound page of FileObjects paged by
// ?after=<next_cursor>. The page is bound to the host-attested scope — List
// returns ONLY records in that scope, so a caller never sees another scope's
// handles (the same scope binding the keystone enforces on Get). A malformed
// limit is a client request fault (400); a store error is a broker-internal 503.
//
// downloadable is omitted from every FileObject in the page (Default 1).
func (h *Handler) serveList(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, reqLog *slog.Logger) {
	limit, ok := parseLimit(r.URL.Query().Get(listLimitParam))
	if !ok {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Malformed), "invalid limit parameter")
		return
	}
	// The forward cursor is the previous page's opaque next_cursor token, passed
	// verbatim as the store's continuation. The store decodes it (a malformed
	// token surfaces as a store error -> 503); the wire never carries the bare
	// boundary id as a cursor.
	after := r.URL.Query().Get(listAfterParam)

	page, err := h.deps.Store.List(r.Context(), handlestore.ListInput{
		Scope:  ps.FilesystemID,
		Cursor: after,
		Limit:  limit,
	})
	if err != nil {
		// A list failure is a transient broker-internal state (the store carries
		// no client-attributable deny for a read listing); fail closed to 503
		// (unavailable, retryable).
		reqLog.Error("files-api list error",
			slog.String(observ.KeyReason, err.Error()))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.BackendUnavailable), "list failed")
		return
	}

	writeJSON(w, http.StatusOK, newListResponse(page))
}

// parseLimit parses the optional limit query parameter. An empty value is the
// store default (0). A non-integer or negative value is a malformed request
// (ok=false). A zero or positive integer passes through.
func parseLimit(raw string) (int, bool) {
	if raw == "" {
		return 0, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
