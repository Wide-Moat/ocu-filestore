// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"archive/zip"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// archivePath is the additive OCU-extension collection verb: GET
// /v1/files/archive bundles the named accessible files into a single zip. It is
// a SIBLING off /v1/files, not a per-resource path, so the router MUST intercept
// it BEFORE the /v1/files/ prefix case — otherwise "archive" is parsed as a
// {file_id}.
const archivePath = "/v1/files/archive"

// archiveFileIDParam is the repeated query parameter naming the file_id set to
// bundle. It is read as r.URL.Query()["file_id"] — a []string, one value per id.
const archiveFileIDParam = "file_id"

// contentTypeZip is the archive success RESPONSE Content-Type.
const contentTypeZip = "application/zip"

// archiveFilename is the download filename stamped in Content-Disposition. It is
// a fixed zip name so the body downloads (not renders inline); the archive is a
// bundle of many files, so no single member name is authoritative.
const archiveFilename = "archive.zip"

// archiveMember is one resolved+authorized+downloadable file that will become a
// zip entry: the durable record, its normalised engine path, the broker-resolved
// grant, and the Stat'd byte length. The set is assembled — every id resolved,
// authorized, downloadable-checked, and Stat'd — BEFORE any status is committed,
// so the 200 can never be walked back once the zip stream starts.
type archiveMember struct {
	rec     handlestore.Record
	engPath string
	grant   southface.Grant
	size    int64
}

// serveArchive serves GET /v1/files/archive?file_id=<id>&file_id=<id>...: it
// resolves each named id under the keystone, re-derives read authorization
// broker-side, resolves downloadable AT READ, audits EVERY included file BEFORE
// any byte, then streams a single zip of the accessible members.
//
// This is the collection-verb sibling of serveContent, applied N times with the
// anti-enumeration keystone lifted to the WHOLE set:
//
//   - Per id, Store.Get collapses absent and cross-scope into the SAME
//     ErrNotFound — such an id is SILENTLY excluded (never a per-id error, never
//     a probe oracle). A non-downloadable grant is likewise excluded, not a 403
//     for the whole archive: "accessible" means resolvable AND downloadable.
//   - When NO named id resolves in scope (or none is downloadable) the response
//     is the header-less keystone 404 — never 403, never a 200 empty zip: a
//     distinguishable response would leak whether ANY named id exists elsewhere.
//   - A backend FAULT is not a per-id skip: an ErrStoreUnavailable from the store
//     (or any non-ErrNotFound resolution error) fails the WHOLE request 503.
//
// Order of operations (every clause load-bearing):
//
//   - Resolve + authorize + downloadable-check + Stat EVERY id, collecting the
//     accessible members. A skip is silent; a backend fault is a whole-request
//     503; the set is complete before any status is chosen.
//   - Empty set -> keystone 404 (the anti-enumeration keystone for this verb).
//   - Mandate the ALLOW for EVERY member BEFORE the 200 is committed
//     (audit-before-ack, SEC-79): all-up-front, so an audit-down can never leave
//     a half-written zip with an unaudited member. A single failed Mandate fails
//     the whole request 503 with zero bytes.
//   - Commit 200 + application/zip + attachment, then stream each member: an fd
//     slot is acquired per file around its engine read window and released
//     between files. A mid-stream engine error after the 200 cannot change the
//     status; the stream terminates.
func (h *Handler) serveArchive(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, reqID string, reqLog *slog.Logger) {
	sess := h.deps.Ceilings.Session(ps.FilesystemID)
	if err := sess.TryConsumeOp(); err != nil {
		denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Throttle), "operation rate ceiling exceeded")
		return
	}

	ids := r.URL.Query()[archiveFileIDParam]

	// --- resolve + authorize + downloadable-check + Stat every id ---
	// A skip is silent (keystone: absent == cross-scope == not-downloadable is
	// never distinguishable). A backend fault fails the whole request 503.
	members := make([]archiveMember, 0, len(ids))
	for _, fileID := range ids {
		rec, err := h.deps.Store.Get(r.Context(), fileID, ps.FilesystemID)
		if err != nil {
			if errors.Is(err, handlestore.ErrNotFound) {
				// Keystone: absent OR cross-scope. Silently excluded — no per-id
				// error, no probe oracle.
				continue
			}
			// A store-latch (ErrStoreUnavailable) or any other resolution error is a
			// backend fault, NOT a per-id skip: the whole request fails 503. A skip
			// here would silently drop a member on a transient fault and hand back a
			// partial archive that the caller cannot tell from a complete one.
			reqLog.Error("files-api archive: handle store unavailable",
				slog.String(observ.KeyDenyClass, denyclass.BackendUnavailable),
				slog.String(observ.KeyReason, err.Error()))
			denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.BackendUnavailable), "handle store unavailable")
			return
		}

		// enginePath normalises the opaque backend ObjectRef; a reference that does
		// not normalise names no in-tree object and is silently excluded (never an
		// egress target on a dirty path), mirroring the content path's refusal but
		// degraded to a keystone skip for the collection verb.
		engPath, ok := enginePath(rec.ObjectRef)
		if !ok {
			continue
		}

		// Re-derive read authorization broker-side. A resolver deny excludes the
		// member (it is not accessible); it is never a 403 for the whole archive.
		req := southface.ResolveRequest{Filesystem: ps.FilesystemID, Path: engPath, Intent: southface.IntentRead}
		evidence := southface.CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: ps.GrantedIntents}
		grant, rerr := h.deps.Resolver.Resolve(r.Context(), evidence, req)
		if rerr != nil {
			continue
		}

		// downloadable AT READ (NFR-SEC-73): a non-downloadable object is not an
		// accessible member — silently excluded, never a whole-archive 403.
		if !grant.Downloadable {
			continue
		}

		// Stat the size for the zip entry BEFORE any ALLOW is Mandated. A vanished
		// object (Stat fault) is excluded like any other inaccessible member — no
		// allow-then-deny, no partial-set leak.
		info, serr := h.deps.Engine.Stat(r.Context(), ps.FilesystemID, engPath)
		if serr != nil {
			continue
		}
		size := info.Size
		if size < 0 {
			size = 0
		}

		members = append(members, archiveMember{rec: rec, engPath: engPath, grant: grant, size: size})
	}

	// --- empty set -> keystone 404 (anti-enumeration) ---
	// No named id resolved in scope (or none was downloadable). The response is
	// the header-less keystone 404 — never 403, never a 200 empty zip: a
	// distinguishable response would leak whether ANY named id exists elsewhere.
	// The empty file_id list lands here too (nothing to resolve resolves nothing).
	if len(members) == 0 {
		reqLog.Info("files-api archive: no named id resolved in scope",
			slog.String(observ.KeyDenyClass, denyclass.NotFound))
		writeNotFound(w)
		return
	}

	// --- audit ALL members' ALLOW BEFORE the 200 (audit-before-ack, SEC-79) ---
	// All-up-front: every member's ALLOW is Mandated before a single zip byte, so
	// an audit-down can never leave a half-written zip with an unaudited member. A
	// single failed Mandate fails the WHOLE request 503 with zero bytes.
	for i := range members {
		allow := readAllowEvent(ps, members[i].rec, members[i].grant, reqID)
		if merr := h.deps.Guard.Mandate(r.Context(), allow); merr != nil {
			reqLog.Error("files-api archive: allow audit failed before first byte",
				slog.String(observ.KeyDenyClass, denyclass.AuditDown))
			denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.AuditDown), "audit gate unavailable")
			return
		}
	}

	// --- commit the 200 header and stream the zip ---
	// From here NO refusal can change the status: the 200 + application/zip
	// headers are on the wire. Content-Disposition: attachment names a zip file so
	// the body downloads rather than renders inline. A mid-stream engine error just
	// terminates the stream.
	w.Header().Set("Content-Type", contentTypeZip)
	w.Header().Set("Content-Disposition", `attachment; filename="`+archiveFilename+`"`)
	w.WriteHeader(http.StatusOK)

	h.streamArchive(w, r, ps, sess, members, reqLog)
}

// streamArchive writes the zip of the (already resolved, authorized, and
// audited) members to w. It is only reached AFTER the 200 header is committed, so
// no error it encounters can change the status: a fault is logged and the stream
// terminates. Each member's bytes are read under a freshly acquired fd slot,
// released before the next member, so the fd ceiling is enforced per read. Entry
// names collide-dedupe so two members with the same filename both survive.
func (h *Handler) streamArchive(w http.ResponseWriter, r *http.Request, ps southface.PeerScope, sess southface.CeilingsSession, members []archiveMember, reqLog *slog.Logger) {
	zw := zip.NewWriter(w)
	defer func() {
		if cerr := zw.Close(); cerr != nil {
			reqLog.Error("files-api archive: zip finalize failed after 200 committed",
				slog.String(observ.KeyReason, cerr.Error()))
		}
	}()

	used := make(map[string]int, len(members))
	for i := range members {
		m := members[i]
		entryName := dedupeEntryName(used, sanitizeEntryName(m.rec.Filename))

		// Per-file fd slot around the engine read window (NFR-SEC-46), released
		// before the next member. An exhausted fd ceiling MID-ARCHIVE cannot change
		// the committed 200; the member is skipped from the stream and logged.
		if ferr := sess.TryAcquireFD(); ferr != nil {
			reqLog.Error("files-api archive: fd ceiling exceeded mid-stream",
				slog.String(observ.KeyReason, ferr.Error()))
			return
		}

		entry, cerr := zw.Create(entryName)
		if cerr != nil {
			sess.ReleaseFD()
			reqLog.Error("files-api archive: zip entry create failed after 200 committed",
				slog.String(observ.KeyReason, cerr.Error()))
			return
		}

		rerr := h.deps.Engine.ReadRange(r.Context(), ps.FilesystemID, m.engPath, 0, m.size, entry)
		sess.ReleaseFD()
		if rerr != nil {
			// A MID-STREAM engine error AFTER the 200 header. The status cannot
			// change; the stream simply terminates (the client detects the short
			// read via the incomplete zip).
			reqLog.Error("files-api archive: engine fault after 200 committed",
				slog.String(observ.KeyReason, rerr.Error()))
			return
		}
	}
}

// sanitizeEntryName reduces a caller-controlled stored Filename to a flat zip
// entry name that cannot escape the archive root. The stored filename is
// attacker-influenced (it is echoed from the create request, create.go
// createFilename, and never sanitized at write), so a value like
// "../../../etc/passwd" would otherwise flow verbatim into the zip entry name
// and a naive extractor would write outside its extraction directory (zip-slip).
// It first normalises backslashes to '/' (so a Windows-style path cannot smuggle
// a component past path.Base, which splits only on '/'), takes path.Base to drop
// every directory component, and refuses the traversal/degenerate leftovers
// ("", ".", "..") by falling back to the synthetic "file". The result contains
// no path separator and no traversal element, so it always names a member at the
// archive root.
func sanitizeEntryName(filename string) string {
	name := strings.ReplaceAll(filename, "\\", "/")
	name = path.Base(name)
	if name == "" || name == "." || name == ".." || name == "/" {
		return "file"
	}
	return name
}

// dedupeEntryName returns a zip entry name unique within the archive: an empty or
// first-seen name passes through (empty becomes a synthetic "file"), and a
// collision gets a "-N" suffix before any extension so two members with the same
// display name both survive in the bundle. It assumes its input is already a
// flat, separator-free name (sanitizeEntryName guarantees this upstream); it only
// deduplicates and never fabricates a path separator. Archive-root containment is
// sanitizeEntryName's responsibility, not this function's.
func dedupeEntryName(used map[string]int, filename string) string {
	name := filename
	if name == "" {
		name = "file"
	}
	if _, seen := used[name]; !seen {
		used[name] = 1
		return name
	}
	// A collision: append the next ordinal for this base name.
	n := used[name]
	used[name] = n + 1
	deduped := name + "-" + strconv.Itoa(n)
	// The deduped name could itself collide with a literal member of that shape;
	// walk forward until it is free.
	for {
		if _, seen := used[deduped]; !seen {
			used[deduped] = 1
			return deduped
		}
		n++
		used[name] = n + 1
		deduped = name + "-" + strconv.Itoa(n)
	}
}
