// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"strconv"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// reconcileMaxWalkDepth caps the engine-namespace reconcile walk so a pathological
// or hostile tree can neither exhaust the stack nor drive an unbounded per-level
// engine-call loop (NFR-SEC-46). It mirrors the southface maxWalkDepth (256): the
// south spine caps its recursive listing at the same depth, and the reconcile
// walks the SAME namespace, so one convention bounds both. The south constant is
// package-private (consumer-seam isolation — this plane does not import the
// south-private walker), so the value is mirrored here with the shared rationale,
// exactly as content.go mirrors the south enginePath rather than importing it.
const reconcileMaxWalkDepth = 256

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

	// WHOLE-TREE BRIDGE (ADR-0029:46, "the scope's owner sees the whole tree"). On
	// the CURSORLESS FIRST PAGE, reconcile the engine namespace into the north
	// handle store BEFORE the paged List so a deliverable the agent wrote through
	// the SOUTH FUSE mount — which mints no north file_id and would otherwise be
	// invisible to the File Pane — surfaces with a stable handle. The reconcile is
	// gated to after=="" (a subsequent page walks the store the first page already
	// reconciled, never re-walking the engine) and skipped on a latched store
	// (EnsureObject is a mutation; a write-fault store must not attempt one). A
	// reconcile error is an HONEST DEGRADE: the pane still sees north-created
	// handles, so a transient engine hiccup must not 503 the list.
	if after == "" && !h.deps.Store.Latched() {
		h.reconcileEngineNamespace(r.Context(), ps.FilesystemID, reqLog)
	}

	page, err := h.deps.Store.List(r.Context(), handlestore.ListInput{
		Scope:  ps.FilesystemID,
		Cursor: after,
		Limit:  limit,
	})
	if err != nil {
		// A malformed ?after cursor — an undecodable/wrong-version token, or a
		// bare last_id that was never a valid cursor — is a CLIENT fault, not a
		// backend state. Map it to 400 invalid_argument (ADR-0028: a malformed
		// cursor is a client rejection), matching the invalid-limit branch above
		// and the south leg's malformed-cursor mapping. A retryable 503 here would
		// invite an infinite retry loop on a permanently bad token.
		if errors.Is(err, handlestore.ErrMalformedCursor) {
			denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Malformed), "malformed cursor")
			return
		}
		// Any other list failure is a transient broker-internal state (the store
		// carries no client-attributable deny for a read listing); fail closed to
		// 503 (unavailable, retryable).
		reqLog.Error("files-api list error",
			slog.String(observ.KeyReason, err.Error()))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.BackendUnavailable), "list failed")
		return
	}

	writeJSON(w, http.StatusOK, newListResponse(page))
}

// reconcileEngineNamespace walks the engine namespace of scope and mints a
// north handle (EnsureObject) for every NON-directory object that carries none,
// so the whole tree — including agent deliverables written through the south FUSE
// mount — surfaces in the north list (ADR-0029:46). The walk is ITERATIVE over an
// explicit frame stack (no recursion: a hostile tree depth must never become
// goroutine stack depth) and hard-capped at reconcileMaxWalkDepth (NFR-SEC-46),
// mirroring the south spine's bounded listing walk.
//
// It is an HONEST DEGRADE, never a hard fail: any engine error (the namespace
// unavailable) stops the reconcile and returns — serveList falls through to the
// plain Store.List, so the pane still sees every north-CREATED handle. An
// EnsureObject that returns a tombstone-mask ErrNotFound or a store error is
// tolerated per object (the object is skipped) so one deleted or one un-mintable
// object never strands the rest of the walk.
//
// CreatedAt is store-clock-stamped inside EnsureObject (never the engine
// ModTime), and the ObjectRef is engine-relative with no leading slash — the SAME
// convention the create path stores (ADR-0029 inv-5), so a north-created object
// and its engine-visible twin key to ONE handle (the anti-dup invariant).
func (h *Handler) reconcileEngineNamespace(ctx context.Context, scope string, reqLog *slog.Logger) {
	// A walk frame is one listed directory level and the cursor into its entries.
	type walkFrame struct {
		rel     string // engine-relative directory path ("." at the root)
		entries []southface.FileInfo
		next    int
	}

	rootEntries, err := h.deps.Engine.List(ctx, scope, ".")
	if err != nil {
		// Honest degrade: the engine namespace is unavailable. Do NOT fail the
		// list — fall through to the plain Store.List so the pane still sees
		// north-created handles. Log at info (a transient hiccup, not an error the
		// operator must act on).
		reqLog.Info("files-api list: engine namespace reconcile skipped",
			slog.String(observ.KeyReason, err.Error()))
		return
	}
	stack := []walkFrame{{rel: ".", entries: rootEntries}}

	for len(stack) > 0 {
		if ctx.Err() != nil {
			return // client disconnect / deadline: stop the reconcile quietly.
		}
		top := &stack[len(stack)-1]
		if top.next >= len(top.entries) {
			stack = stack[:len(stack)-1]
			continue
		}
		e := top.entries[top.next]
		top.next++

		// childRel is the engine-relative path of this entry: the parent path joined
		// with the entry name, no leading slash (the root parent "." contributes
		// nothing). This is the SAME convention the create path stores as ObjectRef.
		childRel := e.Name
		if top.rel != "." && top.rel != "" {
			childRel = top.rel + "/" + e.Name
		}

		if e.IsDir {
			// Descend, bounded. A tree deeper than the cap refuses cleanly (stops
			// the reconcile) rather than exhausting the stack — the pane still lists
			// every handle already minted above the cap.
			if len(stack) >= reconcileMaxWalkDepth {
				reqLog.Info("files-api list: engine namespace reconcile depth cap reached",
					slog.String(observ.KeyReason, "walk depth exceeded"))
				return
			}
			children, cerr := h.deps.Engine.List(ctx, scope, childRel)
			if cerr != nil {
				// Honest degrade mid-walk: stop, do not fail the list.
				reqLog.Info("files-api list: engine namespace reconcile stopped mid-walk",
					slog.String(observ.KeyReason, cerr.Error()))
				return
			}
			stack = append(stack, walkFrame{rel: childRel, entries: children})
			continue
		}

		// A non-directory object: mint-on-first-sight. A tombstone-mask ErrNotFound
		// (the operator deleted this ref) or any per-object store error is tolerated
		// — skip this object, keep walking, so one deleted/un-mintable object never
		// strands the rest of the tree.
		_, eerr := h.deps.Store.EnsureObject(ctx, handlestore.EnsureInput{
			Scope:     scope,
			ObjectRef: childRel,
			Filename:  path.Base(childRel),
			Mime:      "",
			Size:      e.Size,
		})
		if eerr != nil {
			reqLog.Info("files-api list: engine object not reconciled",
				slog.String(observ.KeyReason, eerr.Error()))
		}
	}
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
