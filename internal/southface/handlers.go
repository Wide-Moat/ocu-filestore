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
// error — distinct from the wire class when the wire degrades (D8). An escape
// or lexical reject audits as the escape truth even though the wire shows
// not_found (anti-enumeration); EEXIST audits already_exists; ENOENT audits
// not_found.
func auditTruthForEngineErr(err error) string {
	switch {
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
// already_exists.
func (d *handlerDeps) makeDirs(ctx context.Context, scope, rel string, parents bool) error {
	if !parents {
		return d.engine.MakeDir(ctx, scope, rel)
	}
	parts := strings.Split(rel, "/")
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

// walk produces the deterministic name-sorted entry order for a listing,
// one level (recursive=false) or depth-first (recursive=true) over the engine
// List. A directory is emitted before its children (pre-order) so the keyset
// cursor over the full relative path strictly advances. The root itself is not
// emitted; only its contents.
func (d *handlerDeps) walk(ctx context.Context, scope, rootRel string, recursive bool) ([]walkResult, error) {
	var out []walkResult
	var descend func(rel string) error
	descend = func(rel string) error {
		entries, err := d.listOneLevel(ctx, scope, rel)
		if err != nil {
			return err
		}
		for _, e := range entries {
			childRel := e.Name
			if rel != "." && rel != "" {
				childRel = rel + "/" + e.Name
			}
			out = append(out, walkResult{rel: childRel, info: e})
			if recursive && e.IsDir {
				if err := descend(childRel); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := descend(rootRel); err != nil {
		return nil, err
	}
	return out, nil
}

// handleListDirectory implements OPS-01: the Entry-union listing with the
// opaque keyset cursor. It strict-decodes the request, translates the guest
// path, walks the engine deterministically, resumes after the decoded cursor,
// emits a bounded page in guest-read field names with guest-convention paths,
// and mints the next cursor from the last emitted entry (empty on the last
// page).
func handleListDirectory(d *handlerDeps, hc handlerCtx) {
	var req listDirectoryRequest
	if !decodeOp(hc, &req) {
		return
	}
	ctx := context.Background()
	scope := hc.ps.FilesystemID
	rootRel := enginePath(req.Path)

	after, err := decodeCursor(req.Cursor)
	if err != nil {
		// A malformed cursor is a request fault, not an engine error: deny
		// invalid_argument (no header), no engine touch.
		writeConnectError(hc.w, mapDeny(denyMalformed), "malformed cursor")
		return
	}

	all, err := d.walk(ctx, scope, rootRel, req.Recursive)
	if err != nil {
		denyEngine(hc, err)
		return
	}

	limit := req.Limit
	if limit <= 0 {
		limit = defaultPageSize
	}

	resp := listDirectoryResponse{Entries: make([]entry, 0, limit)}
	var lastEmitted string
	emitted := 0
	for _, wr := range all {
		if after != "" && wr.rel <= after {
			continue // resume strictly after the cursor's keyset position
		}
		if emitted >= limit {
			// More entries remain: mint the next cursor from the last emitted
			// full relative path (strictly greater than any prior page's
			// cursor, so the guest progress guard advances).
			resp.Cursor = encodeCursor(lastEmitted)
			break
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
	rel := enginePath(req.Path)
	if err := d.makeDirs(context.Background(), hc.ps.FilesystemID, rel, req.MakeParents); err != nil {
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
	src := enginePath(req.Source)
	dst := enginePath(req.Destination)
	if err := d.engine.MoveDir(context.Background(), hc.ps.FilesystemID, src, dst, false); err != nil {
		denyEngine(hc, err)
		return
	}
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
	ctx := context.Background()
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
	writeAck(hc.w)
}

// handleCopyFile implements OPS-03 copyFile: engine CopyFile with
// overwrite=OverwriteExisting; bare ack on success.
func handleCopyFile(d *handlerDeps, hc handlerCtx) {
	var req copyFileRequest
	if !decodeOp(hc, &req) {
		return
	}
	src := enginePath(req.Source)
	dst := enginePath(req.Destination)
	if err := d.engine.CopyFile(context.Background(), hc.ps.FilesystemID, src, dst, req.OverwriteExisting); err != nil {
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
	src := enginePath(req.Source)
	dst := enginePath(req.Destination)
	if err := d.engine.MoveFile(context.Background(), hc.ps.FilesystemID, src, dst, req.OverwriteExisting); err != nil {
		denyEngine(hc, err)
		return
	}
	writeAck(hc.w)
}

// handleRemoveFile implements OPS-03 removeFile: engine RemoveFile; bare ack
// on success.
func handleRemoveFile(d *handlerDeps, hc handlerCtx) {
	var req removeFileRequest
	if !decodeOp(hc, &req) {
		return
	}
	rel := enginePath(req.Path)
	if err := d.engine.RemoveFile(context.Background(), hc.ps.FilesystemID, rel); err != nil {
		denyEngine(hc, err)
		return
	}
	writeAck(hc.w)
}
