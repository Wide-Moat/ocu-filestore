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
// package-private (consumer-seam isolation -- this plane does not import the
// south-private walker), so the value is mirrored here with the shared rationale,
// exactly as content.go mirrors the south enginePath rather than importing it.
const reconcileMaxWalkDepth = 256

// listLimitParam / listAfterParam are the query parameters the list endpoint
// reads: an optional page-size limit and the forward cursor. The forward cursor
// is ?after=<next_cursor> (ADR-0028) -- a caller passes the previous page's opaque
// next_cursor token to fetch the next page. It carries the store's created-at/
// file-id boundary tuple and is opaque to the caller; a bare last_id is NOT a
// valid cursor (the created-at-primary keyset walk cannot resume from it -- a
// deleted boundary record would repeat or strand a record).
const (
	listLimitParam = "limit"
	listAfterParam = "after"
	// listOrderParam selects the page direction: "desc" walks newest-first
	// (CreatedAt, FileID descending); anything else (including omitted) is the
	// historical ascending default. The File Pane sends order=desc so a
	// just-written deliverable -- the newest record -- lands on the first page it
	// fetches instead of being stranded off page 1 once the scope holds a full
	// page of objects (#182). The direction is carried in the cursor bytes, so a
	// paged request must send the same order it started with.
	listOrderParam = "order"
	listOrderDesc  = "desc"
)

// listScopeRootPath is the engine-relative path the list verb authorizes and
// records. A listing is a read of the WHOLE scope subtree, not of one object, so
// the scope root is the honest handle for it: it is the exact token
// reconcileEngineNamespace hands Engine.List to start the walk, and it is a
// legal non-empty RelativePath under the frozen wire contract (RelativePath
// carries minLength 1, so an empty object_handle would be off-contract).
//
// A page may span many subtrees, so the resolver is asked ONE scope-root
// question rather than one question per record: the scope axis is the
// load-bearing one for a listing, and it is exercised here. Per-record filtering
// of a page is a different design with its own contract question (whether a
// filtered record leaks by absence) and is deliberately not smuggled in.
const listScopeRootPath = "."

// serveList serves GET /v1/files: a scope-bound page of FileObjects paged by
// ?after=<next_cursor>. The page is bound to the host-attested scope -- List
// returns ONLY records in that scope, so a caller never sees another scope's
// handles (the same scope binding the keystone enforces on Get). A malformed
// limit is a client request fault (400); a store error is a broker-internal 503.
//
// Order of operations (every clause load-bearing, mirroring the content verb):
//
//   - ops/s charge FIRST (NFR-SEC-46), before any store or engine touch: an
//     exhausted bucket costs a listing walk of nothing.
//   - parse the limit / cursor / order (a malformed limit is a client fault; no
//     object has been named and no authorization resolved yet, so it records no
//     activity). The direction is request shape, not an authorization axis.
//   - Resolve(intent=read) at the scope root from the attested scope: the three
//     axes are re-derived broker-side per request, deny-by-default. Under the
//     shipped F9 grant that re-derivation has no axis left to fail on, so
//     denyList's resolver-error arm is defence in depth against a future scope
//     source, not a refusal a deployment produces today -- see
//     fencedGrantedIntents.
//   - Mandate the ALLOW BEFORE the reconcile (audit-before-ack, SEC-79). The
//     reconcile MUTATES the durable handle store (EnsureObject mints handles),
//     so no durable state may change ahead of its record; an audit failure
//     denies 503 with zero mints.
//   - only then the reconcile + the paged Store.List.
//
// downloadable is NOT gated here: a listing emits no object bytes, so the
// NFR-SEC-73 egress gate stays on the two byte-emitting north verbs (content and
// archive). The resolved value is RECORDED on the event, never enforced.
//
// downloadable is omitted from every FileObject in the page (Default 1).
func (h *Handler) serveList(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, reqID string, reqLog *slog.Logger) {
	// --- ops/s throttle, keyed on the CHANNEL scope (mirrors the content read
	// path and the create verb). It is charged BEFORE the store and the engine so
	// a refused request costs neither a walk nor a page. ---
	sess := h.deps.Ceilings.Session(ps.FilesystemID)
	if err := sess.TryConsumeOp(); err != nil {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Throttle), "operation rate ceiling exceeded")
		return
	}

	limit, ok := parseLimit(r.URL.Query().Get(listLimitParam))
	if !ok {
		// A malformed limit is refused BEFORE authorization is resolved: no object
		// has been named and no grant exists, so there is no honest file activity
		// to record (a DENY here would have to invent a downloadable value that was
		// never resolved). It is a request-shape fault, not a storage access.
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Malformed), "invalid limit parameter")
		return
	}
	// The forward cursor is the previous page's opaque next_cursor token, passed
	// verbatim as the store's continuation. The store decodes it (a malformed
	// token surfaces as a store error -> 503); the wire never carries the bare
	// boundary id as a cursor.
	after := r.URL.Query().Get(listAfterParam)

	// The page direction. "desc" is newest-first; anything else (including
	// omitted) is the ascending default, so an old caller that never sends the
	// param keeps its historical order. On a paged request the direction is also
	// carried in the cursor bytes, so the caller sends the same order it started
	// with -- a mismatch is not a client fault the wire names, it just resolves
	// the boundary in the sent direction.
	//
	// Parsed with the limit and the cursor, BEFORE authorization is resolved: the
	// direction is request shape, not an authorization axis, and an unknown value
	// is not a client fault (it falls back to ascending), so this branch can never
	// refuse ahead of the Resolve below.
	order := handlestore.ListOrderAsc
	if r.URL.Query().Get(listOrderParam) == listOrderDesc {
		order = handlestore.ListOrderDesc
	}

	// --- authz Resolve(intent=read) at the scope root from the attested scope ---
	req := southface.ResolveRequest{Filesystem: ps.FilesystemID, Path: listScopeRootPath, Intent: southface.IntentRead}
	evidence := southface.CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: ps.GrantedIntents}
	grant, rerr := h.deps.Resolver.Resolve(r.Context(), evidence, req)
	if rerr != nil {
		h.denyList(w, r, reqLog, ps, grant, denyClassForResolveErr(rerr), "authorization denied", reqID)
		return
	}

	// --- audit ALLOW BEFORE the reconcile mutates the durable store (SEC-79) ---
	// The reconcile below mints durable handles (Store.EnsureObject). The ALLOW
	// must land first so no durable state change ever precedes its record; an
	// audit-down denies 503 with zero mints and zero page.
	allow := listAllowEvent(ps, grant, reqID)
	if merr := h.deps.Guard.Mandate(r.Context(), allow); merr != nil {
		// The allow Mandate itself failed (audit down). Deny before any store
		// mutation; do NOT re-Mandate a deny (the gate is unavailable).
		reqLog.Error("files-api list: allow audit failed before the namespace reconcile",
			slog.String(observ.KeyDenyClass, denyclass.AuditDown))
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
		return
	}

	// WHOLE-TREE BRIDGE (ADR-0029:46, "the scope's owner sees the whole tree"). On
	// the CURSORLESS FIRST PAGE, reconcile the engine namespace into the north
	// handle store BEFORE the paged List so a deliverable the agent wrote through
	// the SOUTH FUSE mount -- which mints no north file_id and would otherwise be
	// invisible to the File Pane -- surfaces with a stable handle. The reconcile is
	// gated to after=="" (a subsequent page walks the store the first page already
	// reconciled, never re-walking the engine) and skipped on a latched store
	// (EnsureObject is a mutation; a write-fault store must not attempt one). A
	// reconcile error is an HONEST DEGRADE: the pane still sees north-created
	// handles, so a transient engine hiccup must not 503 the list.
	//
	// The mint carries NO event of its own: it materialises the north handle index
	// over objects the engine ALREADY holds -- it creates no backend object and
	// moves no byte, so a per-object Create(1) would be a dishonest durable
	// record. The engine-namespace walk it performs IS the read the ALLOW above
	// names at the scope root; the obligation the invariant places on it is
	// ORDERING, discharged by Mandating that ALLOW first.
	if after == "" && !h.deps.Store.Latched() {
		h.reconcileEngineNamespace(r.Context(), ps.FilesystemID, reqLog)
	}

	page, err := h.deps.Store.List(r.Context(), handlestore.ListInput{
		Scope:  ps.FilesystemID,
		Cursor: after,
		Limit:  limit,
		Order:  order,
	})
	if err != nil {
		// A malformed ?after cursor -- an undecodable/wrong-version token, or a
		// bare last_id that was never a valid cursor -- is a CLIENT fault, not a
		// backend state. Map it to 400 invalid_argument (ADR-0028: a malformed
		// cursor is a client rejection), matching the invalid-limit branch above
		// and the south leg's malformed-cursor mapping. A retryable 503 here would
		// invite an infinite retry loop on a permanently bad token.
		//
		// Both branches land AFTER the ALLOW audit, so each emits a BEST-EFFORT
		// DENY naming the refused listing (mirroring denyDeleteAfterAudit): the
		// chain's last record must not assert an allow for a listing the caller
		// never received. A failed deny-Mandate cannot make the verdict worse (the
		// operation acked nothing), so the original verdict stands.
		class, message := denyclass.BackendUnavailable, "list failed"
		if errors.Is(err, handlestore.ErrMalformedCursor) {
			class, message = denyclass.Malformed, "malformed cursor"
		} else {
			reqLog.Error("files-api list error",
				slog.String(observ.KeyReason, err.Error()))
		}
		_ = h.deps.Guard.Mandate(r.Context(), listDenyEvent(ps, grant, class, reqID))
		denywire.WriteRESTDeny(w, denywire.MapDeny(class), message)
		return
	}

	writeJSON(w, http.StatusOK, newListResponse(page))
}

// denyList emits the list DENY audit (the broker-resolved truth) then the REST
// deny response. It is the PRE-mutation refusal path: it is only ever reached
// before the reconcile, so it can always write a real HTTP status and the
// durable store is untouched. A deny-Mandate FAILURE degrades the verdict to
// audit_down (NFR-SEC-79): if the deny record did not durably land, the verdict
// the caller sees must be audit-down, mirroring denyRead.
func (h *Handler) denyList(w http.ResponseWriter, r *http.Request, reqLog *slog.Logger, ps southface.PeerScope, grant southface.Grant, auditReason, message, reqID string) {
	reqLog.Warn("files-api list deny",
		slog.String(observ.KeyDenyClass, auditReason),
		slog.String(observ.KeyReason, message))
	ev := listDenyEvent(ps, grant, auditReason, reqID)
	if merr := h.deps.Guard.Mandate(r.Context(), ev); merr != nil {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
		return
	}
	denywire.WriteRESTDeny(w, denywire.MapDeny(auditReason), message)
}

// reconcileEngineNamespace walks the engine namespace of scope and mints a
// north handle (EnsureObject) for every NON-directory object that carries none,
// so the whole tree -- including agent deliverables written through the south FUSE
// mount -- surfaces in the north list (ADR-0029:46). The walk is ITERATIVE over an
// explicit frame stack (no recursion: a hostile tree depth must never become
// goroutine stack depth) and hard-capped at reconcileMaxWalkDepth (NFR-SEC-46),
// mirroring the south spine's bounded listing walk.
//
// It is an HONEST DEGRADE, never a hard fail: any engine error (the namespace
// unavailable) stops the reconcile and returns -- serveList falls through to the
// plain Store.List, so the pane still sees every north-CREATED handle. An
// EnsureObject that returns a tombstone-mask ErrNotFound or a store error is
// tolerated per object (the object is skipped) so one deleted or one un-mintable
// object never strands the rest of the walk.
//
// CreatedAt is store-clock-stamped inside EnsureObject (never the engine
// ModTime), and the ObjectRef is engine-relative with no leading slash -- the SAME
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
		// list -- fall through to the plain Store.List so the pane still sees
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
			// the reconcile) rather than exhausting the stack -- the pane still lists
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
		// -- skip this object, keep walking, so one deleted/un-mintable object never
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
