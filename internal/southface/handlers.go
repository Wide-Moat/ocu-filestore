// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"time"
)

// handlerDeps carries the per-op handler dependencies: the consumer-side
// storage engine seam and the session-scoped uuid record store. The seven
// phase-9 handlers are methods-by-injection — free functions taking *handlerDeps
// and a handlerCtx — so the dispatcher owns the seam wiring and the handlers
// stay pure over it.
type handlerDeps struct {
	engine Engine
	ids    *objectIDStore
}

// defaultPageSize is the server-side listing page size when the request omits
// limit (or sends a non-positive value). The guest does not always send a
// limit; a bounded default keeps a single page under the response ceiling
// while still spanning multiple pages for a large tree.
const defaultPageSize = 1000

// mtimeString formats an engine ModTime for the guest-read mtime field. RFC
// 3339 (UTC) is the stable, guest-parseable form.
func mtimeString(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// writeAck writes the bare ack body {} with a 200 status — the response for
// all six mutation ops (D9).
func writeAck(w http.ResponseWriter) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ackResponse{})
}

// writeJSON writes a 200 response with the given body.
func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

// decodeOp strict-decodes the op body from the buffered request into out; a
// malformed body or unknown field denies invalid_argument (no header) — the
// same strict discipline as the spine envelope. On failure it writes the
// deny and returns false; no audit deny event is emitted for a malformed body
// (the spine already mandated the allow event on the well-formed envelope, and
// a body that fails the op-level strict decode is a request fault, mapped to
// the malformed-envelope wire class).
func decodeOp(hc handlerCtx, out any) bool {
	if err := decodeStrictBytes(hc.body, out); err != nil {
		writeConnectError(hc.w, mapDeny(denyMalformed), "malformed request body")
		return false
	}
	return true
}

// assertWriteGrant is the defense-in-depth write-class gate every mutation
// handler runs BEFORE any engine touch (NFR-SEC-49, invariant 4): even if the
// spine's route-op->required-intent binding were ever regressed, a session
// whose channel-bound grant set lacks IntentWrite can never reach a mutating
// engine verb. It mirrors handleReadFile's hc.grant downloadable check —
// deny-by-default, asserted at the handler in addition to the spine. On a
// missing write grant it emits the intent_denied deny audit event and writes
// the wire deny, returning false; the handler returns immediately.
func assertWriteGrant(hc handlerCtx) bool {
	for _, g := range hc.ps.GrantedIntents {
		if g == IntentWrite {
			return true
		}
	}
	hc.mandateDeny(denyIntentDenied, denyIntentDenied, "intent denied for operation")
	return false
}

// denyEngine maps an engine error to its deny class, emits the handler-stage
// deny audit event with the broker-resolved truth, and writes the wire deny
// (which MAY degrade away from the truth, D8). The audited truth for an
// escape/lexical-reject is recorded distinct from the degraded not_found wire
// class.
func denyEngine(hc handlerCtx, err error) {
	wireClass := denyClassForEngineErr(err)
	auditReason := auditTruthForEngineErr(err)
	hc.mandateDeny(auditReason, wireClass, "operation refused")
}

// auditTruthForEngineErr names the broker-resolved AUDIT truth for an engine
// error — distinct from the wire class when the wire degrades (D8).
// context.Canceled and context.DeadlineExceeded are classified FIRST as
// denyAborted (T2-5, RES-03): a client disconnect or deadline is a clean
// "aborted" verdict, audited as such, not as an internal error. An escape
// or lexical reject audits as the escape truth even though the wire shows
// not_found (anti-enumeration); EEXIST audits already_exists; ENOENT audits
// not_found.
func auditTruthForEngineErr(err error) string {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return denyAborted
	case errors.Is(err, errAlreadyExists), errors.Is(err, fs.ErrExist):
		return denyAlreadyExists
	case errors.Is(err, fs.ErrNotExist):
		return denyNotFound
	case errors.Is(err, errInvalidPath), isPathEscape(err):
		return denyScopeMismatch // escape truth: a path leaving the bound scope
	default:
		return denyInternal
	}
}

// makeDirs composes per-component MakeDir over the engine's single-level verb
// (Pattern 3). With parents false it calls MakeDir once on the full relative
// path (a missing parent then surfaces ENOENT). With parents true it creates
// each prefix in turn, tolerating an intermediate EEXIST as success and
// surfacing only the FINAL component's EEXIST as the caller-visible
// already_exists. The component count is capped at maxWalkDepth BEFORE any
// engine call (NFR-SEC-46): a body-ceiling-sized path of millions of
// components must not drive a per-component engine-call loop or build a tree
// no later walk can traverse; the real engine's ValidatePath enforces its own
// component cap, this guard keeps the spine safe independent of the bound
// engine.
func (d *handlerDeps) makeDirs(ctx context.Context, scope, rel string, parents bool) error {
	if !parents {
		return d.engine.MakeDir(ctx, scope, rel)
	}
	parts := strings.Split(rel, "/")
	if len(parts) > maxWalkDepth {
		return errInvalidPath
	}
	for i := range parts {
		prefix := strings.Join(parts[:i+1], "/")
		err := d.engine.MakeDir(ctx, scope, prefix)
		if err == nil {
			continue
		}
		if errors.Is(err, fs.ErrExist) {
			if i < len(parts)-1 {
				continue // intermediate already exists: ok
			}
			return err // final component already exists: caller-visible
		}
		return err
	}
	return nil
}

// listOneLevel returns the engine entries under rel, sorted by Name ascending
// for deterministic emit order (cursor stability, Pattern 6).
func (d *handlerDeps) listOneLevel(ctx context.Context, scope, rel string) ([]FileInfo, error) {
	entries, err := d.engine.List(ctx, scope, rel)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// walkResult is one emitted entry in the deterministic walk: its full
// engine-relative path and its engine FileInfo.
type walkResult struct {
	rel  string
	info FileInfo
}

// maxWalkDepth is the HARD depth cap on the recursive listing traversal and
// the make_parents component count (NFR-SEC-46). The real engine's lexical
// path validation caps a single path's component count below this, so a
// legitimately-built tree can never reach the cap; a deeper tree (a hostile
// or pre-existing layout) refuses cleanly instead of exhausting the stack —
// the pre-fix recursive descent could hit Go's non-recoverable max-stack
// fatal and kill the single-session daemon.
const maxWalkDepth = 256

// errWalkDepthExceeded names a traversal that crossed maxWalkDepth. It maps
// to the internal deny class (a tree this deep is not reachable through the
// validated mutation surface).
var errWalkDepthExceeded = errors.New("southface: directory tree exceeds the maximum walk depth")

// walk streams the deterministic name-sorted entry order for a listing — one
// level (recursive=false) or depth-first pre-order (recursive=true) over the
// engine List — to the emit callback. A directory is emitted before its
// children so the keyset cursor over the full relative path strictly
// advances; the root itself is not emitted, only its contents.
//
// The traversal is ITERATIVE over an explicit frame stack (no recursion: a
// hostile tree depth must never translate into goroutine stack depth), hard-
// capped at maxWalkDepth, and checks ctx between entries so a client
// disconnect aborts the walk. emit returns false to stop the walk early —
// the pagination path stops as soon as its page (plus the one look-ahead
// entry that mints the cursor) is satisfied, visiting O(page) not O(tree).
func (d *handlerDeps) walk(ctx context.Context, scope, rootRel string, recursive bool, emit func(walkResult) bool) error {
	type walkFrame struct {
		rel     string
		entries []FileInfo
		next    int
	}

	rootEntries, err := d.listOneLevel(ctx, scope, rootRel)
	if err != nil {
		return err
	}
	stack := []walkFrame{{rel: rootRel, entries: rootEntries}}

	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return err // disconnect/cancel aborts the walk
		}
		top := &stack[len(stack)-1]
		if top.next >= len(top.entries) {
			stack = stack[:len(stack)-1]
			continue
		}
		e := top.entries[top.next]
		top.next++

		childRel := e.Name
		if top.rel != "." && top.rel != "" {
			childRel = top.rel + "/" + e.Name
		}
		if !emit(walkResult{rel: childRel, info: e}) {
			return nil
		}
		if recursive && e.IsDir {
			if len(stack) >= maxWalkDepth {
				return errWalkDepthExceeded
			}
			children, err := d.listOneLevel(ctx, scope, childRel)
			if err != nil {
				return err
			}
			stack = append(stack, walkFrame{rel: childRel, entries: children})
		}
	}
	return nil
}

// handleListDirectory implements OPS-01: the Entry-union listing with the
// opaque keyset cursor. It strict-decodes the request, translates the guest
// path, walks the engine deterministically under the REQUEST context, resumes
// after the decoded cursor, emits a bounded page in guest-read field names
// with guest-convention paths, and mints the next cursor from the last
// emitted entry (empty on the last page). The walk stops as soon as the page
// is satisfied — limit+1 emitted entries visited, never the whole subtree.
func handleListDirectory(d *handlerDeps, hc handlerCtx) {
	var req listDirectoryRequest
	if !decodeOp(hc, &req) {
		return
	}
	ctx := hc.ctxOrBackground()
	scope := hc.ps.FilesystemID
	rootRel := enginePath(req.Path)

	after, err := decodeCursor(req.Cursor)
	if err != nil {
		// A malformed cursor is a request fault, not an engine error: deny
		// invalid_argument (no header), no engine touch.
		writeConnectError(hc.w, mapDeny(denyMalformed), "malformed cursor")
		return
	}

	limit := req.Limit
	if limit <= 0 {
		limit = defaultPageSize
	}
	// Clamp the PREALLOCATION only (the page size itself stays limit): a
	// guest-supplied limit must not size a make() directly.
	prealloc := limit
	if prealloc > defaultPageSize {
		prealloc = defaultPageSize
	}

	resp := listDirectoryResponse{Entries: make([]entry, 0, prealloc)}
	var lastEmitted string
	emitted := 0
	walkErr := d.walk(ctx, scope, rootRel, req.Recursive, func(wr walkResult) bool {
		if after != "" && wr.rel <= after {
			return true // resume strictly after the cursor's keyset position
		}
		if emitted >= limit {
			// More entries remain: mint the next cursor from the last emitted
			// full relative path (strictly greater than any prior page's
			// cursor, so the guest progress guard advances) and STOP the walk
			// — the page is done, the rest of the tree is never visited.
			resp.Cursor = encodeCursor(lastEmitted)
			return false
		}
		gp := guestPath(wr.rel)
		if wr.info.IsDir {
			resp.Entries = append(resp.Entries, entry{Directory: &directory{
				Path:  gp,
				MTime: mtimeString(wr.info.ModTime),
			}})
		} else {
			resp.Entries = append(resp.Entries, entry{File: &filesystemFile{
				Path:  gp,
				Size:  wr.info.Size,
				MTime: mtimeString(wr.info.ModTime),
				MIME:  mimeForPath(wr.rel),
				UUID:  d.ids.idFor(scope, gp),
			}})
		}
		lastEmitted = wr.rel
		emitted++
		return true
	})
	if walkErr != nil {
		denyEngine(hc, walkErr)
		return
	}
	writeJSON(hc.w, resp)
}

// mimeForPath returns a guest-read mime hint derived from the path extension.
// The south face does not sniff content; a coarse extension map is sufficient
// for the mount surface (the read-time disposition and the authoritative type
// are resolved elsewhere).
func mimeForPath(rel string) string {
	i := strings.LastIndexByte(rel, '.')
	if i < 0 || i == len(rel)-1 {
		return "application/octet-stream"
	}
	switch strings.ToLower(rel[i+1:]) {
	case "txt":
		return "text/plain"
	case "json":
		return "application/json"
	case "html", "htm":
		return "text/html"
	case "png":
		return "image/png"
	case "jpg", "jpeg":
		return "image/jpeg"
	default:
		return "application/octet-stream"
	}
}

// handleMakeDirectory implements OPS-02 makeDirectory: compose make_parents
// over the single-level engine MakeDir; bare ack on success.
func handleMakeDirectory(d *handlerDeps, hc handlerCtx) {
	var req makeDirectoryRequest
	if !decodeOp(hc, &req) {
		return
	}
	if !assertWriteGrant(hc) {
		return
	}
	rel := enginePath(req.Path)
	if err := d.makeDirs(hc.ctxOrBackground(), hc.ps.FilesystemID, rel, req.MakeParents); err != nil {
		denyEngine(hc, err)
		return
	}
	writeAck(hc.w)
}

// handleMoveDirectory implements OPS-02 moveDirectory: engine MoveDir with
// overwrite=false (no overwrite field on this op); bare ack on success.
func handleMoveDirectory(d *handlerDeps, hc handlerCtx) {
	var req moveDirectoryRequest
	if !decodeOp(hc, &req) {
		return
	}
	if !assertWriteGrant(hc) {
		return
	}
	src := enginePath(req.Source)
	dst := enginePath(req.Destination)
	if err := d.engine.MoveDir(hc.ctxOrBackground(), hc.ps.FilesystemID, src, dst, false); err != nil {
		denyEngine(hc, err)
		return
	}
	// The moved-away subtree's uuid records are now stale: evict them so the
	// session-scoped store stays bounded (N8). The destination subtree mints
	// fresh ids on its next observation.
	d.ids.evictTree(hc.ps.FilesystemID, guestPath(src))
	writeAck(hc.w)
}

// handleRemoveDirectory implements OPS-02 removeDirectory with the non-empty
// guard (Pattern 4): recursive=false on a non-empty directory refuses
// invalid_argument WITHOUT deleting (the audited truth is denyDirNotEmpty, a
// distinct token from malformed_envelope); recursive=true deletes the subtree.
func handleRemoveDirectory(d *handlerDeps, hc handlerCtx) {
	var req removeDirectoryRequest
	if !decodeOp(hc, &req) {
		return
	}
	if !assertWriteGrant(hc) {
		return
	}
	ctx := hc.ctxOrBackground()
	scope := hc.ps.FilesystemID
	rel := enginePath(req.Path)

	if !req.Recursive {
		entries, err := d.engine.List(ctx, scope, rel)
		if err != nil {
			denyEngine(hc, err)
			return
		}
		if len(entries) > 0 {
			// Refuse WITHOUT deleting: the audited truth is directory_not_empty,
			// the wire class invalid_argument (no header). The engine RemoveDir
			// is never called on the non-empty path.
			hc.mandateDeny(denyDirNotEmpty, denyDirNotEmpty, "directory not empty")
			return
		}
	}
	if err := d.engine.RemoveDir(ctx, scope, rel); err != nil {
		denyEngine(hc, err)
		return
	}
	// Evict the removed subtree's uuid records (N8): the store stays bounded
	// by the live namespace; the read path re-validates existence anyway.
	d.ids.evictTree(scope, guestPath(rel))
	writeAck(hc.w)
}

// handleCopyFile implements OPS-03 copyFile: engine CopyFile with
// overwrite=OverwriteExisting; bare ack on success.
func handleCopyFile(d *handlerDeps, hc handlerCtx) {
	var req copyFileRequest
	if !decodeOp(hc, &req) {
		return
	}
	if !assertWriteGrant(hc) {
		return
	}
	src := enginePath(req.Source)
	dst := enginePath(req.Destination)
	if err := d.engine.CopyFile(hc.ctxOrBackground(), hc.ps.FilesystemID, src, dst, req.OverwriteExisting); err != nil {
		denyEngine(hc, err)
		return
	}
	writeAck(hc.w)
}

// handleMoveFile implements OPS-03 moveFile: engine MoveFile with
// overwrite=OverwriteExisting; bare ack on success.
func handleMoveFile(d *handlerDeps, hc handlerCtx) {
	var req moveFileRequest
	if !decodeOp(hc, &req) {
		return
	}
	if !assertWriteGrant(hc) {
		return
	}
	src := enginePath(req.Source)
	dst := enginePath(req.Destination)
	if err := d.engine.MoveFile(hc.ctxOrBackground(), hc.ps.FilesystemID, src, dst, req.OverwriteExisting); err != nil {
		denyEngine(hc, err)
		return
	}
	// The source path no longer names an object: evict its uuid record (N8).
	// The destination keeps any existing record — its (scope, path) pair
	// still names a live object and identity is re-validated at read.
	d.ids.evict(hc.ps.FilesystemID, guestPath(src))
	writeAck(hc.w)
}

// handleRemoveFile implements OPS-03 removeFile: engine RemoveFile; bare ack
// on success.
func handleRemoveFile(d *handlerDeps, hc handlerCtx) {
	var req removeFileRequest
	if !decodeOp(hc, &req) {
		return
	}
	if !assertWriteGrant(hc) {
		return
	}
	rel := enginePath(req.Path)
	if err := d.engine.RemoveFile(hc.ctxOrBackground(), hc.ps.FilesystemID, rel); err != nil {
		denyEngine(hc, err)
		return
	}
	// Evict the removed object's uuid record (N8).
	d.ids.evict(hc.ps.FilesystemID, guestPath(rel))
	writeAck(hc.w)
}

// handleReadFile implements OPS-04 readFile: a UNARY op on the existing
// dispatch pipeline. It strict-decodes {filesystem_id, path, range}, enforces
// downloadable AT READ from the broker-resolved grant FIRST (A2/SEC-73),
// validates the target through engine.Stat WITHOUT reading any content
// (readFile emits NO content; D6 TBD content body stays TBD), and emits the
// metadata-only {file: File} body.
//
// NO CONTENT IS READ (NFR-SEC-46/78): an earlier build validated the window
// by copying it into an in-memory buffer with the guest-supplied length —
// K concurrent reads of a multi-GiB object could heap K x size. Stat answers
// everything this op emits (existence, size, mtime), and the engine's
// half-open window contract makes a range read past EOF a no-error
// short-read anyway, so a range can never fail validation that Stat passes.
// The guest range is accepted and intentionally unused here; bulk bytes are
// the deferred fileDownload server-stream's job.
func handleReadFile(d *handlerDeps, hc handlerCtx) {
	var req readFileRequest
	if !decodeOp(hc, &req) {
		return
	}

	// DOWNLOADABLE@READ, FIRST (SEC-73 wire half, A2). The spine's STAGE-2
	// Resolve(intent=read) already produced the authoritative grant; a
	// non-downloadable read denies BEFORE any engine touch, regardless of the
	// wire authorization_metadata.downloadable flag or any write-time stored
	// tag. The handler reads ONLY hc.grant.Downloadable — never the wire flag.
	if !hc.grant.Downloadable {
		hc.mandateDeny(denyNotDownloadable, denyNotDownloadable, "object not downloadable")
		return
	}

	ctx := hc.ctxOrBackground()
	scope := hc.ps.FilesystemID
	rel := enginePath(req.Path)

	// Stat-only validation: existence and metadata, zero content bytes read,
	// O(1) memory regardless of object size or the guest-declared range.
	info, err := d.engine.Stat(ctx, scope, rel)
	if err != nil {
		denyEngine(hc, err)
		return
	}
	if info.IsDir {
		// readFile names a file; a directory target is not_found (the same
		// class the read path surfaced for a directory before).
		hc.mandateDeny(denyNotFound, denyNotFound, "object is not a file")
		return
	}
	gp := guestPath(rel)
	writeJSON(hc.w, readFileResponse{File: file{
		Path:  gp,
		Size:  info.Size,
		MTime: mtimeString(info.ModTime),
		MIME:  mimeForPath(rel),
		UUID:  d.ids.idFor(scope, gp),
	}})
}
