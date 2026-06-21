// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"net/http"
	"regexp"
	"testing"
)

// REST parity fixtures — the frozen-pending-#292 wire oracle.
//
// This file transcribes the south-face REST/HTTP wire surface as a set of Go
// fixtures stated in THIS repo's own words: the route table, the per-operation
// request bodies, the response bodies, the deny status map, and the credential
// surface. These fixtures are the OWN-OUTPUT oracle: this wave they assert
// against themselves (TestRESTParityFixtures), pinning a fixed target; later
// waves drive a live server against the SAME fixtures so the server's emitted
// wire is checked against this pinned target rather than against itself.
//
// The route, the multipart upload framing, the octet-stream download framing,
// the deny status map, and filesystem_id being a top-level sibling of
// authorization_metadata are sibling-proven and FROZEN pending the #292 canon
// merge — see docs/pending-phase7.md and the per-group PENDING-PHASE-7 markers
// below. Until #292 merges, every fixture group carries a grep-able
// "// PENDING-PHASE-7(<id>): ..." marker; those flip to "frozen @ canon-rev
// <sha>" after the merge.
//
// Discipline: these are facts about the wire this broker speaks. They are not
// quoted from, attributed to, or derived-as-provenance from any other system;
// they are the contract this package implements.

// ---------------------------------------------------------------------------
// Group A1-route — the route table.
// PHASE-7(A1-route): frozen @ canon-rev a030b7be914b: POST <service_url>/v1/filestore/fs/<operation>;
// contract FORM ratified by #292 @ a030b7be914b; governing ADR remains status:proposed — freezes the wire FORM, not ADR acceptance
// the operation is the trailing path segment; method is always POST; the
// transport is REST-JSON over HTTP/2 (unary), multipart for fileUpload, and
// chunked octet-stream for fileDownload. Sibling-proven, frozen pending #292.
// ---------------------------------------------------------------------------

// restBasePath is the fixed route base every south-face operation hangs off.
// The full route for an operation is restBasePath + string(op).
const restBaseFixture = "/v1/filestore/fs/"

// restMethodFixture is the only legal method for every route. A non-POST
// method to any /v1/filestore/fs/<op> route is refused (405).
const restMethodFixture = http.MethodPost

// routeContentType names the request Content-Type for each operation's
// transport class.
type routeContentType string

const (
	// ctJSON — REST-JSON request body (the 16 unary ops + the fileDownload
	// request).
	ctJSON routeContentType = "application/json"
	// ctMultipart — multipart/form-data with a generated boundary (fileUpload
	// only). The boundary parameter is appended by the multipart writer, so the
	// header value begins with this media type but is not byte-equal to it.
	ctMultipart routeContentType = "multipart/form-data"
	// ctOctetStream — the fileDownload RESPONSE Content-Type (chunked raw
	// bytes). It is never a REQUEST content type.
	ctOctetStream routeContentType = "application/octet-stream"
)

// routeFixture is one row of the route table: the operation, its trailing path
// segment, its request transport class, and its response transport class.
type routeFixture struct {
	op          Op
	pathSegment string
	reqClass    routeContentType
	respClass   routeContentType
	authzIntent Intent // the op-derived intent stamped on authorization_metadata
}

// routeFixtures is the closed route table for all 18 operations: 16 unary-JSON
// ops, fileUpload (multipart request, JSON-or-empty response), and fileDownload
// (JSON request, octet-stream response). The pathSegment equals string(op) for
// every row — the operation name IS the trailing route segment.
var routeFixtures = []routeFixture{
	// Read-class unary-JSON ops.
	{OpListDirectory, "listDirectory", ctJSON, ctJSON, IntentRead},
	{OpReadFile, "readFile", ctJSON, ctJSON, IntentRead},
	{OpReadMetadata, "readMetadata", ctJSON, ctJSON, IntentRead},
	{OpGetFileMetadata, "getFileMetadata", ctJSON, ctJSON, IntentRead},
	{OpListFiles, "listFiles", ctJSON, ctJSON, IntentRead},
	// Write-class unary-JSON ops.
	{OpMakeDirectory, "makeDirectory", ctJSON, ctJSON, IntentWrite},
	{OpMoveDirectory, "moveDirectory", ctJSON, ctJSON, IntentWrite},
	{OpRemoveDirectory, "removeDirectory", ctJSON, ctJSON, IntentWrite},
	{OpCreateFile, "createFile", ctJSON, ctJSON, IntentWrite},
	{OpCopyFile, "copyFile", ctJSON, ctJSON, IntentWrite},
	{OpMoveFile, "moveFile", ctJSON, ctJSON, IntentWrite},
	{OpRemoveFile, "removeFile", ctJSON, ctJSON, IntentWrite},
	{OpImportFiles, "importFiles", ctJSON, ctJSON, IntentWrite},
	{OpImportZip, "importZip", ctJSON, ctJSON, IntentWrite},
	{OpMigrateFilesystem, "migrateFilesystem", ctJSON, ctJSON, IntentWrite},
	{OpRemoveFilesystem, "removeFilesystem", ctJSON, ctJSON, IntentWrite},
	// Data-plane ops with distinct transport classes.
	{OpFileUpload, "fileUpload", ctMultipart, ctJSON, IntentWrite},
	{OpFileDownload, "fileDownload", ctJSON, ctOctetStream, IntentRead},
}

// routeFor builds the full request route for an operation.
func routeFor(op Op) string { return restBaseFixture + string(op) }

// ---------------------------------------------------------------------------
// Group A4-fsid-toplevel — the common request envelope shape.
// PHASE-7(A4-fsid-toplevel): frozen @ canon-rev a030b7be914b: filesystem_id is a TOP-LEVEL field, a
// contract FORM ratified by #292 @ a030b7be914b; governing ADR remains status:proposed — freezes the wire FORM, not ADR acceptance
// sibling of authorization_metadata, NOT nested inside it. authorization_metadata
// carries exactly {intent, downloadable}. downloadable is a hint the broker
// never trusts at read. Sibling-proven, frozen pending #292.
// ---------------------------------------------------------------------------

// authzMetaFixture is the authorization_metadata sub-object carried on every
// request body: the op-derived intent and the never-trusted downloadable hint.
// downloadable is always false on the wire as sent — it is a read-time hint the
// broker re-derives from its own resolved grant and never honours from the
// request.
type authzMetaFixture struct {
	Intent       Intent `json:"intent"`
	Downloadable bool   `json:"downloadable"`
}

func readMeta() authzMetaFixture  { return authzMetaFixture{Intent: IntentRead, Downloadable: false} }
func writeMeta() authzMetaFixture { return authzMetaFixture{Intent: IntentWrite, Downloadable: false} }

// ---------------------------------------------------------------------------
// Group A1/A4 request bodies — per-op JSON field sets.
// The per-op request shapes below pin the exact JSON field set each operation
// sends: filesystem_id top-level, bare source/destination names on move/copy,
// the uuid axis on getFileMetadata/listFiles/fileDownload, the readFile range
// as a NON-pointer always-serialized struct, and the fileDownload range as a
// *pointer with omitempty. PENDING-PHASE-7(A4-fsid-toplevel).
// ---------------------------------------------------------------------------

// rangeFixture is the half-open [offset, offset+length) window. length 0 means
// "to EOF" / full object. The two range carriers below differ ONLY in their
// serialization discipline, not their shape.
type rangeFixture struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// pathReadReq is the request shape for path-axis read ops: listDirectory,
// readMetadata. filesystem_id top-level + path + read authorization_metadata.
type pathReadReq struct {
	FilesystemID          string           `json:"filesystem_id"`
	Path                  string           `json:"path"`
	Cursor                string           `json:"cursor,omitempty"`
	AuthorizationMetadata authzMetaFixture `json:"authorization_metadata"`
}

// pathWriteReq is the request shape for path-axis write ops: makeDirectory,
// removeDirectory, createFile, removeFile, importFiles, importZip.
type pathWriteReq struct {
	FilesystemID          string           `json:"filesystem_id"`
	Path                  string           `json:"path"`
	AuthorizationMetadata authzMetaFixture `json:"authorization_metadata"`
}

// srcDstReq is the request shape for moveDirectory (no overwrite). The bare
// field names are "source"/"destination" — NOT source_path/destination_path.
type srcDstReq struct {
	FilesystemID          string           `json:"filesystem_id"`
	Source                string           `json:"source"`
	Destination           string           `json:"destination"`
	AuthorizationMetadata authzMetaFixture `json:"authorization_metadata"`
}

// srcDstOverwriteReq is the request shape for copyFile/moveFile: bare
// source/destination plus an always-present overwrite_existing key (the field
// has no omitempty, so the key is ALWAYS serialized).
type srcDstOverwriteReq struct {
	FilesystemID          string           `json:"filesystem_id"`
	Source                string           `json:"source"`
	Destination           string           `json:"destination"`
	OverwriteExisting     bool             `json:"overwrite_existing"`
	AuthorizationMetadata authzMetaFixture `json:"authorization_metadata"`
}

// readFileReq is the readFile request: path-axis read with a NON-pointer range
// that is ALWAYS serialized. A zero-value range serializes as
// {"offset":0,"length":0} and the broker reads length 0 as "full file".
type readFileReq struct {
	FilesystemID          string           `json:"filesystem_id"`
	Path                  string           `json:"path"`
	Range                 rangeFixture     `json:"range"`
	AuthorizationMetadata authzMetaFixture `json:"authorization_metadata"`
}

// uuidReadReq is the request shape for uuid-axis read ops: getFileMetadata,
// listFiles. There is NO path; the object is addressed by uuid. listFiles adds
// an after_uuid cursor on page 2+ (omitempty, so page 1 omits it).
type uuidReadReq struct {
	FilesystemID          string           `json:"filesystem_id"`
	UUID                  string           `json:"uuid"`
	AfterUUID             string           `json:"after_uuid,omitempty"`
	AuthorizationMetadata authzMetaFixture `json:"authorization_metadata"`
}

// fsidOnlyWriteReq is the request shape for the filesystem-scoped write ops
// that carry no path and no uuid: migrateFilesystem, removeFilesystem.
type fsidOnlyWriteReq struct {
	FilesystemID          string           `json:"filesystem_id"`
	AuthorizationMetadata authzMetaFixture `json:"authorization_metadata"`
}

// fileDownloadReq is the fileDownload JSON request: uuid-axis (NOT path) with a
// *pointer* range carrying omitempty. A full download OMITS the range entirely;
// a ranged download serializes the window.
//
// PENDING-PHASE-7(A2-octet): the response to this request is the raw object
// bytes as a chunked application/octet-stream — no JSON envelope, no per-chunk
// framing. Sibling-proven, frozen pending #292.
type fileDownloadReq struct {
	FilesystemID          string           `json:"filesystem_id"`
	UUID                  string           `json:"uuid"`
	Range                 *rangeFixture    `json:"range,omitempty"`
	AuthorizationMetadata authzMetaFixture `json:"authorization_metadata"`
}

// ---------------------------------------------------------------------------
// Group A2-multipart — the fileUpload multipart params field set.
// PENDING-PHASE-7(A2-multipart): fileUpload is multipart/form-data with two
// parts: a "params" form field carrying the upload params JSON, then a "file"
// form file carrying the raw object bytes streamed to the closing boundary. The
// params JSON declares declared_size_bytes (REQUIRED) and overwrite_existing
// (omitempty: a create-new write OMITS the key; an overwrite-in-place write
// sends it true). Sibling-proven, frozen pending #292.
// ---------------------------------------------------------------------------

// multipartParamsFieldName is the form-field name of the params part.
const multipartParamsFieldName = "params"

// multipartFileFieldName is the form-field name of the streamed file part.
const multipartFileFieldName = "file"

// multipartFileFilename is the filename the file part declares. It is a fixed
// placeholder; the authoritative destination is params.path, not this filename.
const multipartFileFilename = "upload"

// uploadParamsFixture is the JSON carried by the "params" form field of a
// fileUpload. declared_size_bytes is REQUIRED and equals the total source size
// (a body that does not yield exactly declared_size_bytes is refused
// broker-side). overwrite_existing carries omitempty: a create-new write OMITS
// the key (JSON zero false → key absent); an overwrite-in-place write sends it
// true.
type uploadParamsFixture struct {
	FilesystemID          string           `json:"filesystem_id"`
	Path                  string           `json:"path"`
	DeclaredSizeBytes     int64            `json:"declared_size_bytes"`
	OverwriteExisting     bool             `json:"overwrite_existing,omitempty"`
	AuthorizationMetadata authzMetaFixture `json:"authorization_metadata"`
}

// ---------------------------------------------------------------------------
// Group response bodies — the per-op success body shapes.
// Ten bare-ack ops alias an empty ack object. The File/FilesystemFile carry
// {path,size,mtime,mode,sha,mime,uuid}; Directory carries {path,mode,mtime};
// a list entry is a file XOR directory union; ListFilesResponse carries
// {files, after_uuid}; ReadFileResponse is metadata-only (no content field).
// All response decoding is tolerant — an unknown future field is ignored;
// success is signalled by the HTTP 2xx status, not by a body discriminant.
// ---------------------------------------------------------------------------

// ackFixture is the empty bare-ack response body `{}`. The ten ops that ack
// (makeDirectory, moveDirectory, removeDirectory, copyFile, moveFile,
// removeFile, importFiles, importZip, migrateFilesystem, removeFilesystem) all
// return this; the success signal is the 2xx status, and any body fields are
// ignored by the tolerant decoder.
type ackFixture struct{}

// bareAckOps is the closed set of ten operations whose success body is the bare
// ack. PENDING-PHASE-7(A1-route) — these flip to "frozen @ canon-rev <sha>"
// after #292.
var bareAckOps = []Op{
	OpMakeDirectory, OpMoveDirectory, OpRemoveDirectory,
	OpCopyFile, OpMoveFile, OpRemoveFile,
	OpImportFiles, OpImportZip,
	OpMigrateFilesystem, OpRemoveFilesystem,
}

// fileMetaFixture is the full file metadata shape carried by File and
// FilesystemFile (intentionally identical field sets):
// {path,size,mtime,mode,sha,mime,uuid}. Every field carries omitempty.
type fileMetaFixture struct {
	Path  string `json:"path,omitempty"`
	Size  int64  `json:"size,omitempty"`
	MTime string `json:"mtime,omitempty"`
	Mode  string `json:"mode,omitempty"`
	SHA   string `json:"sha,omitempty"`
	MIME  string `json:"mime,omitempty"`
	UUID  string `json:"uuid,omitempty"`
}

// dirMetaFixture is the Directory shape: {path,mode,mtime}. A directory carries
// no size/sha/mime/uuid on the listing surface. Every field carries omitempty.
type dirMetaFixture struct {
	Path  string `json:"path,omitempty"`
	Mode  string `json:"mode,omitempty"`
	MTime string `json:"mtime,omitempty"`
}

// listEntryFixture is the listDirectory entry union: EXACTLY ONE of file or
// directory is present (file XOR directory). omitempty drops the unset branch,
// so the wire carries {"file":...} or {"directory":...} but never both and
// never neither.
type listEntryFixture struct {
	File      *fileMetaFixture `json:"file,omitempty"`
	Directory *dirMetaFixture  `json:"directory,omitempty"`
}

// listDirectoryRespFixture is the listDirectory success body: an entry union
// list plus an opaque cursor (empty on the last page; a non-empty cursor is
// echoed back as the request "cursor" to fetch the next page; a repeated cursor
// aborts paging on the non-progress guard).
type listDirectoryRespFixture struct {
	Entries []listEntryFixture `json:"entries,omitempty"`
	Cursor  string             `json:"cursor,omitempty"`
}

// listFilesRespFixture is the listFiles success body: a FilesystemFile list
// plus the uuid-axis cursor after_uuid (empty terminates; non-empty is echoed
// back as the request after_uuid; a repeated value aborts on the non-progress
// guard).
type listFilesRespFixture struct {
	Files     []fileMetaFixture `json:"files,omitempty"`
	AfterUUID string            `json:"after_uuid,omitempty"`
}

// createFileRespFixture is the createFile success body: a non-omitempty nested
// {"file": FilesystemFile}.
type createFileRespFixture struct {
	File fileMetaFixture `json:"file"`
}

// getFileMetadataRespFixture is the getFileMetadata success body (uuid-axis):
// {"file": FilesystemFile}.
type getFileMetadataRespFixture struct {
	File fileMetaFixture `json:"file"`
}

// readFileRespFixture is the readFile success body: METADATA-ONLY {"file": File}
// with NO content/data field. The content field is unpinned (TBD); a broker
// that includes one has it silently dropped by the tolerant decoder. Bulk bytes
// come via fileDownload, never here.
type readFileRespFixture struct {
	File fileMetaFixture `json:"file"`
}

// readMetadataRespFixture is the readMetadata success body: {"file": File,
// "directory": Directory}. Both keys are present (non-omitempty); one is
// empty/zero depending on whether the path resolves to a file or a directory.
type readMetadataRespFixture struct {
	File      fileMetaFixture `json:"file"`
	Directory dirMetaFixture  `json:"directory"`
}

// ---------------------------------------------------------------------------
// Group A3-deny — the deny status map.
// PENDING-PHASE-7(A3-deny): the deny verdict is the HTTP status (authoritative)
// plus a BoundedReason {reason_code, message} diagnostic body. The status map:
// 401|403 → permission, 404 → not_found (incl. the anti-enumeration degrade),
// 409 → already_exists, 400|422 → invalid, 429|503 → retryable (429 may carry
// Retry-After), everything else → permanent. The reason_code is a
// pattern-validated open string (^[A-Z][A-Z0-9_]{1,63}$), not an enum; the
// default vocabulary below is preferred for log consistency. Sibling-proven,
// frozen pending #292.
// ---------------------------------------------------------------------------

// denyClassFixture is the client-visible verdict class an HTTP status maps to.
type denyClassFixture string

const (
	denyClassPermission    denyClassFixture = "permission"
	denyClassNotFound      denyClassFixture = "not_found"
	denyClassAlreadyExists denyClassFixture = "already_exists"
	denyClassInvalid       denyClassFixture = "invalid"
	denyClassRetryable     denyClassFixture = "retryable"
	denyClassPermanent     denyClassFixture = "permanent"
)

// statusDenyClass maps an HTTP status to its client-visible verdict class. The
// status is AUTHORITATIVE — the diagnostic body never drives this mapping. Any
// non-2xx status not named here is "permanent" (the explicit no-retry default,
// so a stray status never loops a write forever).
func statusDenyClass(status int) denyClassFixture {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden: // 401, 403
		return denyClassPermission
	case http.StatusNotFound: // 404
		return denyClassNotFound
	case http.StatusConflict: // 409
		return denyClassAlreadyExists
	case http.StatusBadRequest, http.StatusUnprocessableEntity: // 400, 422
		return denyClassInvalid
	case http.StatusTooManyRequests, http.StatusServiceUnavailable: // 429, 503
		return denyClassRetryable
	default:
		return denyClassPermanent
	}
}

// denyStatusFixture is one row of the deny status table: a wire status and the
// class it maps to.
type denyStatusFixture struct {
	status int
	class  denyClassFixture
}

// denyStatusFixtures is the deny status table: the statuses with a named class
// plus a representative "else" status proving the permanent default.
var denyStatusFixtures = []denyStatusFixture{
	{http.StatusUnauthorized, denyClassPermission},       // 401
	{http.StatusForbidden, denyClassPermission},          // 403
	{http.StatusNotFound, denyClassNotFound},             // 404
	{http.StatusConflict, denyClassAlreadyExists},        // 409
	{http.StatusBadRequest, denyClassInvalid},            // 400
	{http.StatusUnprocessableEntity, denyClassInvalid},   // 422
	{http.StatusTooManyRequests, denyClassRetryable},     // 429
	{http.StatusServiceUnavailable, denyClassRetryable},  // 503
	{http.StatusInternalServerError, denyClassPermanent}, // 500 → else
	{http.StatusNotImplemented, denyClassPermanent},      // 501 → else
	{http.StatusGatewayTimeout, denyClassPermanent},      // 504 → else
}

// The BoundedReason deny body type (boundedReason) and its message-length
// ceiling (boundedReasonMessageMax) are owned by the production restdeny.go now
// that a live unary deny writer emits them; this fixture group asserts against
// those shared definitions rather than a test-only copy.

// reasonCodePattern is the validation pattern for a BoundedReason.reason_code:
// an uppercase-led token of 2..64 chars over [A-Z0-9_]. It has no production
// constant (the reason_code is an open string the writer never closes), so the
// fixture owns it and the writer's emitted codes are checked against it.
const reasonCodePattern = `^[A-Z][A-Z0-9_]{1,63}$`

// defaultReasonVocabulary is the preferred (not enforced) reason_code vocabulary
// for log consistency. The reason_code field accepts any pattern-valid string;
// these are the values this broker emits for the common verdicts.
var defaultReasonVocabulary = []string{
	"SCOPE_MISMATCH",
	"INTENT_DENIED",
	"NOT_DOWNLOADABLE",
	"LEASE_EXPIRED",
	"SIZE_EXCEEDED",
	"NOT_FOUND",
}

// ---------------------------------------------------------------------------
// Group A5-credscope — the credential surface.
// PENDING-PHASE-7(A5-credscope): the service receives ONLY the edge-injected
// real credential on Authorization: Bearer (never the guest weak JWT). It
// forwards that bearer to the engine unmodified; the engine enforces the
// filesystem_id scope on it (403 foreign / 401 missing-expired) per the
// authority's contract — it does NOT JWKS-verify the bearer (the edge owns
// weak-JWT validation). The scope check sits at the service/route layer feeding
// a thin engine (OQ-2 option c). Component-04 mints/signs nothing.
// Sibling-proven, frozen pending #292.
// ---------------------------------------------------------------------------

// The credential surface constants (authHeaderName, bearerScheme) are owned by
// the production credscope.go now that a live route layer reads them; this
// fixture group asserts against those shared definitions rather than a test-only
// copy.

// ---------------------------------------------------------------------------
// The oracle test: every fixture group asserts against itself this wave.
// ---------------------------------------------------------------------------

// TestRESTParityFixtures pins the REST wire fixtures as a self-consistent
// oracle. Later waves drive a live server against these same fixtures; this
// wave proves the fixtures are internally coherent (route table complete and
// well-formed, request/response bodies serialize to the pinned field sets, the
// deny status map total, the credential surface fixed).
func TestRESTParityFixtures(t *testing.T) {
	t.Run("A1-route/table-covers-all-ops-once", testRouteTableComplete)
	t.Run("A1-route/path-segment-equals-op", testRoutePathSegment)
	t.Run("A1-route/method-is-post", testRouteMethod)
	t.Run("A1-route/transport-classes-and-intent", testRouteTransportClasses)
	t.Run("A4-fsid-toplevel/filesystem-id-is-sibling-of-authz-meta", testFsidTopLevel)
	t.Run("A4-fsid-toplevel/request-field-sets", testRequestFieldSets)
	t.Run("readFile/range-always-serialized", testReadFileRangeAlwaysSerialized)
	t.Run("fileDownload/range-omitempty-uuid-axis", testFileDownloadRangeOmitempty)
	t.Run("A2-multipart/upload-params-field-set", testUploadParamsFieldSet)
	t.Run("response/ten-bare-ack-ops", testBareAckOps)
	t.Run("response/metadata-and-union-shapes", testResponseShapes)
	t.Run("readFile/response-is-metadata-only", testReadFileMetadataOnly)
	t.Run("A3-deny/status-map-total", testDenyStatusMap)
	t.Run("A3-deny/bounded-reason-shape", testBoundedReasonShape)
	t.Run("A5-credscope/bearer-surface", testCredScopeSurface)
}

// testRouteTableComplete asserts the route table covers every known op exactly
// once and names no op outside the frozen enum.
func testRouteTableComplete(t *testing.T) {
	seen := make(map[Op]bool, len(routeFixtures))
	for _, r := range routeFixtures {
		if seen[r.op] {
			t.Errorf("op %q appears twice in the route table", r.op)
		}
		seen[r.op] = true
		if _, ok := knownOps[r.op]; !ok {
			t.Errorf("route table names op %q which is not in knownOps", r.op)
		}
	}
	for op := range knownOps {
		if !seen[op] {
			t.Errorf("known op %q is missing from the route table", op)
		}
	}
	if len(routeFixtures) != len(knownOps) {
		t.Errorf("route table has %d rows, knownOps has %d", len(routeFixtures), len(knownOps))
	}
}

// testRoutePathSegment asserts the trailing path segment equals the op name and
// the full route is restBase + op, for every row.
func testRoutePathSegment(t *testing.T) {
	for _, r := range routeFixtures {
		if r.pathSegment != string(r.op) {
			t.Errorf("op %q: path segment %q != op name", r.op, r.pathSegment)
		}
		want := restBaseFixture + string(r.op)
		if got := routeFor(r.op); got != want {
			t.Errorf("op %q: routeFor = %q, want %q", r.op, got, want)
		}
	}
}

// testRouteTransportClasses asserts the per-op request/response transport
// classes and the op-derived intent. Exactly one op (fileUpload) carries a
// multipart request; exactly one op (fileDownload) responds with an
// octet-stream; every other op is JSON in and JSON out. Each row's intent is
// cross-checked against the surviving opRequiredIntent map, so a fixture intent
// drifting from the authoritative route-op intent is a test failure.
func testRouteTransportClasses(t *testing.T) {
	var multipartReq, octetResp int
	for _, r := range routeFixtures {
		// Request class: only fileUpload is multipart; everything else is JSON.
		if r.op == OpFileUpload {
			if r.reqClass != ctMultipart {
				t.Errorf("op %q: request class %q, want multipart", r.op, r.reqClass)
			}
			multipartReq++
		} else if r.reqClass != ctJSON {
			t.Errorf("op %q: request class %q, want JSON", r.op, r.reqClass)
		}

		// Response class: only fileDownload is an octet-stream; everything
		// else is JSON.
		if r.op == OpFileDownload {
			if r.respClass != ctOctetStream {
				t.Errorf("op %q: response class %q, want octet-stream", r.op, r.respClass)
			}
			octetResp++
		} else if r.respClass != ctJSON {
			t.Errorf("op %q: response class %q, want JSON", r.op, r.respClass)
		}

		// Intent: the fixture must agree with the authoritative route-op
		// intent the spine derives.
		want, ok := requiredIntentForOp(r.op)
		if !ok {
			t.Errorf("op %q: no required-intent row in opRequiredIntent", r.op)
			continue
		}
		if r.authzIntent != want {
			t.Errorf("op %q: fixture intent %q != route-op intent %q", r.op, r.authzIntent, want)
		}
	}
	if multipartReq != 1 {
		t.Errorf("multipart request ops = %d, want exactly 1 (fileUpload)", multipartReq)
	}
	if octetResp != 1 {
		t.Errorf("octet-stream response ops = %d, want exactly 1 (fileDownload)", octetResp)
	}
}

// testRouteMethod asserts every route uses POST.
func testRouteMethod(t *testing.T) {
	if restMethodFixture != http.MethodPost {
		t.Fatalf("route method is %q, want POST", restMethodFixture)
	}
}

// testFsidTopLevel asserts filesystem_id is a top-level sibling of
// authorization_metadata on every request body and never nested inside it.
func testFsidTopLevel(t *testing.T) {
	bodies := []any{
		pathReadReq{FilesystemID: "fs-1", Path: "/a", AuthorizationMetadata: readMeta()},
		pathWriteReq{FilesystemID: "fs-1", Path: "/a", AuthorizationMetadata: writeMeta()},
		srcDstReq{FilesystemID: "fs-1", Source: "/a", Destination: "/b", AuthorizationMetadata: writeMeta()},
		srcDstOverwriteReq{FilesystemID: "fs-1", Source: "/a", Destination: "/b", AuthorizationMetadata: writeMeta()},
		readFileReq{FilesystemID: "fs-1", Path: "/a", AuthorizationMetadata: readMeta()},
		uuidReadReq{FilesystemID: "fs-1", UUID: "u-1", AuthorizationMetadata: readMeta()},
		fsidOnlyWriteReq{FilesystemID: "fs-1", AuthorizationMetadata: writeMeta()},
		fileDownloadReq{FilesystemID: "fs-1", UUID: "u-1", AuthorizationMetadata: readMeta()},
		uploadParamsFixture{FilesystemID: "fs-1", Path: "/a", DeclaredSizeBytes: 1, AuthorizationMetadata: writeMeta()},
	}
	for _, b := range bodies {
		top := decodeToMap(t, b)
		if _, ok := top["filesystem_id"]; !ok {
			t.Errorf("%T: filesystem_id is not a top-level field", b)
		}
		meta, ok := top["authorization_metadata"].(map[string]any)
		if !ok {
			t.Errorf("%T: authorization_metadata is missing or not an object", b)
			continue
		}
		if _, nested := meta["filesystem_id"]; nested {
			t.Errorf("%T: filesystem_id is nested inside authorization_metadata", b)
		}
		// authorization_metadata carries exactly {intent, downloadable}.
		if len(meta) != 2 {
			t.Errorf("%T: authorization_metadata has %d keys, want 2 {intent,downloadable}", b, len(meta))
		}
		if _, ok := meta["intent"]; !ok {
			t.Errorf("%T: authorization_metadata missing intent", b)
		}
		if _, ok := meta["downloadable"]; !ok {
			t.Errorf("%T: authorization_metadata missing downloadable", b)
		}
	}
}

// testRequestFieldSets asserts each request shape serializes to exactly its
// pinned top-level field set (the bare source/destination names on move/copy,
// the uuid axis on uuid-keyed ops, the fsid-only shape on the filesystem ops).
func testRequestFieldSets(t *testing.T) {
	cases := []struct {
		name string
		body any
		want []string
	}{
		{
			"listDirectory-page1",
			pathReadReq{FilesystemID: "fs", Path: "/d", AuthorizationMetadata: readMeta()},
			[]string{"filesystem_id", "path", "authorization_metadata"},
		},
		{
			"listDirectory-page2-adds-cursor",
			pathReadReq{FilesystemID: "fs", Path: "/d", Cursor: "c1", AuthorizationMetadata: readMeta()},
			[]string{"filesystem_id", "path", "cursor", "authorization_metadata"},
		},
		{
			"makeDirectory",
			pathWriteReq{FilesystemID: "fs", Path: "/d", AuthorizationMetadata: writeMeta()},
			[]string{"filesystem_id", "path", "authorization_metadata"},
		},
		{
			"moveDirectory-bare-source-destination",
			srcDstReq{FilesystemID: "fs", Source: "/a", Destination: "/b", AuthorizationMetadata: writeMeta()},
			[]string{"filesystem_id", "source", "destination", "authorization_metadata"},
		},
		{
			"copyFile-overwrite-always-present",
			srcDstOverwriteReq{FilesystemID: "fs", Source: "/a", Destination: "/b", AuthorizationMetadata: writeMeta()},
			[]string{"filesystem_id", "source", "destination", "overwrite_existing", "authorization_metadata"},
		},
		{
			"moveFile-overwrite-always-present",
			srcDstOverwriteReq{FilesystemID: "fs", Source: "/a", Destination: "/b", AuthorizationMetadata: writeMeta()},
			[]string{"filesystem_id", "source", "destination", "overwrite_existing", "authorization_metadata"},
		},
		{
			"getFileMetadata-uuid-axis",
			uuidReadReq{FilesystemID: "fs", UUID: "u", AuthorizationMetadata: readMeta()},
			[]string{"filesystem_id", "uuid", "authorization_metadata"},
		},
		{
			"listFiles-page1-uuid-axis",
			uuidReadReq{FilesystemID: "fs", UUID: "u", AuthorizationMetadata: readMeta()},
			[]string{"filesystem_id", "uuid", "authorization_metadata"},
		},
		{
			"listFiles-page2-adds-after_uuid",
			uuidReadReq{FilesystemID: "fs", UUID: "u", AfterUUID: "u9", AuthorizationMetadata: readMeta()},
			[]string{"filesystem_id", "uuid", "after_uuid", "authorization_metadata"},
		},
		{
			"migrateFilesystem-fsid-only",
			fsidOnlyWriteReq{FilesystemID: "fs", AuthorizationMetadata: writeMeta()},
			[]string{"filesystem_id", "authorization_metadata"},
		},
		{
			"removeFilesystem-fsid-only",
			fsidOnlyWriteReq{FilesystemID: "fs", AuthorizationMetadata: writeMeta()},
			[]string{"filesystem_id", "authorization_metadata"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertKeySet(t, decodeToMap(t, c.body), c.want)
		})
	}
}

// testReadFileRangeAlwaysSerialized asserts the readFile range is a NON-pointer
// struct that is ALWAYS present, even at its zero value (serializing as
// {"offset":0,"length":0}); length 0 means full-file.
func testReadFileRangeAlwaysSerialized(t *testing.T) {
	// Zero-value range still serializes the key.
	zero := readFileReq{FilesystemID: "fs", Path: "/a", AuthorizationMetadata: readMeta()}
	top := decodeToMap(t, zero)
	rng, ok := top["range"].(map[string]any)
	if !ok {
		t.Fatalf("readFile zero range: range key absent or not an object: %v", top["range"])
	}
	if rng["offset"] != float64(0) || rng["length"] != float64(0) {
		t.Errorf("readFile zero range: got %v, want {offset:0,length:0}", rng)
	}
	assertKeySet(t, top, []string{"filesystem_id", "path", "range", "authorization_metadata"})

	// A non-zero range serializes its window.
	win := readFileReq{FilesystemID: "fs", Path: "/a", Range: rangeFixture{Offset: 10, Length: 20}, AuthorizationMetadata: readMeta()}
	rng2 := decodeToMap(t, win)["range"].(map[string]any)
	if rng2["offset"] != float64(10) || rng2["length"] != float64(20) {
		t.Errorf("readFile window range: got %v, want {offset:10,length:20}", rng2)
	}
}

// testFileDownloadRangeOmitempty asserts the fileDownload request is uuid-axis
// (no path) with a *pointer* range carrying omitempty: a full download OMITS the
// range key entirely; a ranged download serializes the window.
func testFileDownloadRangeOmitempty(t *testing.T) {
	// Full download: no range key, uuid axis, no path.
	full := fileDownloadReq{FilesystemID: "fs", UUID: "u", AuthorizationMetadata: readMeta()}
	top := decodeToMap(t, full)
	if _, ok := top["range"]; ok {
		t.Errorf("fileDownload full: range key must be OMITTED, got %v", top["range"])
	}
	if _, ok := top["path"]; ok {
		t.Errorf("fileDownload is uuid-axis: must carry no path, got %v", top["path"])
	}
	assertKeySet(t, top, []string{"filesystem_id", "uuid", "authorization_metadata"})

	// Ranged download: range present.
	win := fileDownloadReq{FilesystemID: "fs", UUID: "u", Range: &rangeFixture{Offset: 5, Length: 7}, AuthorizationMetadata: readMeta()}
	top2 := decodeToMap(t, win)
	rng, ok := top2["range"].(map[string]any)
	if !ok {
		t.Fatalf("fileDownload ranged: range key absent: %v", top2)
	}
	if rng["offset"] != float64(5) || rng["length"] != float64(7) {
		t.Errorf("fileDownload ranged: got %v, want {offset:5,length:7}", rng)
	}
	assertKeySet(t, top2, []string{"filesystem_id", "uuid", "range", "authorization_metadata"})
}

// testUploadParamsFieldSet asserts the fileUpload params JSON field set:
// declared_size_bytes REQUIRED (always present), overwrite_existing omitempty (a
// create-new write omits it; an overwrite write sends true), filesystem_id
// top-level, write authorization_metadata. It also pins the multipart field
// names.
func testUploadParamsFieldSet(t *testing.T) {
	if multipartParamsFieldName != "params" || multipartFileFieldName != "file" || multipartFileFilename != "upload" {
		t.Fatalf("multipart names drifted: params=%q file=%q filename=%q",
			multipartParamsFieldName, multipartFileFieldName, multipartFileFilename)
	}

	// Create-new write: overwrite_existing OMITTED.
	create := uploadParamsFixture{FilesystemID: "fs", Path: "/a", DeclaredSizeBytes: 42, AuthorizationMetadata: writeMeta()}
	top := decodeToMap(t, create)
	if _, ok := top["overwrite_existing"]; ok {
		t.Errorf("create-new upload: overwrite_existing must be OMITTED, got %v", top["overwrite_existing"])
	}
	if top["declared_size_bytes"] != float64(42) {
		t.Errorf("upload declared_size_bytes: got %v, want 42 (REQUIRED, always present)", top["declared_size_bytes"])
	}
	assertKeySet(t, top, []string{"filesystem_id", "path", "declared_size_bytes", "authorization_metadata"})

	// Overwrite-in-place write: overwrite_existing present and true.
	over := uploadParamsFixture{FilesystemID: "fs", Path: "/a", DeclaredSizeBytes: 42, OverwriteExisting: true, AuthorizationMetadata: writeMeta()}
	top2 := decodeToMap(t, over)
	if top2["overwrite_existing"] != true {
		t.Errorf("overwrite upload: overwrite_existing must be true, got %v", top2["overwrite_existing"])
	}
	assertKeySet(t, top2, []string{"filesystem_id", "path", "declared_size_bytes", "overwrite_existing", "authorization_metadata"})
}

// testBareAckOps asserts exactly ten ops return the bare ack, the ack body is
// the empty object `{}`, and the bare-ack set is disjoint from the metadata-
// returning ops.
func testBareAckOps(t *testing.T) {
	if len(bareAckOps) != 10 {
		t.Fatalf("bare-ack op set has %d entries, want 10", len(bareAckOps))
	}
	seen := make(map[Op]bool, len(bareAckOps))
	for _, op := range bareAckOps {
		if seen[op] {
			t.Errorf("bare-ack op %q listed twice", op)
		}
		seen[op] = true
		if _, ok := knownOps[op]; !ok {
			t.Errorf("bare-ack op %q is not a known op", op)
		}
	}
	// The bare ack serializes to the empty object.
	raw, err := json.Marshal(ackFixture{})
	if err != nil {
		t.Fatalf("marshal ack: %v", err)
	}
	if string(raw) != "{}" {
		t.Errorf("ack body = %q, want {}", raw)
	}
	// Metadata-returning ops must NOT be in the bare-ack set.
	for _, op := range []Op{OpCreateFile, OpReadFile, OpReadMetadata, OpGetFileMetadata, OpListFiles, OpListDirectory} {
		if seen[op] {
			t.Errorf("op %q returns metadata but is in the bare-ack set", op)
		}
	}
}

// testResponseShapes asserts the metadata, directory, and union response shapes
// serialize to their pinned field sets and the list-entry union carries exactly
// one branch.
func testResponseShapes(t *testing.T) {
	// File/FilesystemFile field set.
	fm := fileMetaFixture{Path: "/a", Size: 3, MTime: "t", Mode: "0644", SHA: "abc", MIME: "text/plain", UUID: "u"}
	assertKeySet(t, decodeToMap(t, fm), []string{"path", "size", "mtime", "mode", "sha", "mime", "uuid"})

	// Directory field set.
	dm := dirMetaFixture{Path: "/d", Mode: "0755", MTime: "t"}
	assertKeySet(t, decodeToMap(t, dm), []string{"path", "mode", "mtime"})

	// Entry union: exactly the file branch.
	fileEntry := listEntryFixture{File: &fileMetaFixture{Path: "/a", UUID: "u"}}
	fe := decodeToMap(t, fileEntry)
	if _, ok := fe["file"]; !ok {
		t.Errorf("file entry: missing file branch")
	}
	if _, ok := fe["directory"]; ok {
		t.Errorf("file entry: directory branch must be omitted, got %v", fe["directory"])
	}

	// Entry union: exactly the directory branch.
	dirEntry := listEntryFixture{Directory: &dirMetaFixture{Path: "/d"}}
	de := decodeToMap(t, dirEntry)
	if _, ok := de["directory"]; !ok {
		t.Errorf("directory entry: missing directory branch")
	}
	if _, ok := de["file"]; ok {
		t.Errorf("directory entry: file branch must be omitted, got %v", de["file"])
	}

	// listFiles response field set.
	lf := listFilesRespFixture{Files: []fileMetaFixture{{Path: "/a", UUID: "u"}}, AfterUUID: "u9"}
	assertKeySet(t, decodeToMap(t, lf), []string{"files", "after_uuid"})

	// readMetadata response carries both keys.
	rm := readMetadataRespFixture{File: fileMetaFixture{Path: "/a"}, Directory: dirMetaFixture{Path: "/a"}}
	assertKeySet(t, decodeToMap(t, rm), []string{"file", "directory"})

	// createFile response carries the single non-omitempty nested file.
	cf := createFileRespFixture{File: fileMetaFixture{Path: "/a", UUID: "u"}}
	assertKeySet(t, decodeToMap(t, cf), []string{"file"})

	// getFileMetadata response (uuid-axis) carries the single nested file.
	gm := getFileMetadataRespFixture{File: fileMetaFixture{Path: "/a", UUID: "u"}}
	assertKeySet(t, decodeToMap(t, gm), []string{"file"})
}

// testReadFileMetadataOnly asserts the readFile response carries the file
// metadata and NO content/data/bytes field.
func testReadFileMetadataOnly(t *testing.T) {
	resp := readFileRespFixture{File: fileMetaFixture{Path: "/a", Size: 9, UUID: "u"}}
	top := decodeToMap(t, resp)
	assertKeySet(t, top, []string{"file"})
	for _, banned := range []string{"content", "data", "bytes"} {
		if _, ok := top[banned]; ok {
			t.Errorf("readFile response carries forbidden %q field (metadata-only)", banned)
		}
	}
	file, ok := top["file"].(map[string]any)
	if !ok {
		t.Fatalf("readFile response: file is not an object: %v", top["file"])
	}
	for _, banned := range []string{"content", "data", "bytes"} {
		if _, ok := file[banned]; ok {
			t.Errorf("readFile response file carries forbidden %q field (metadata-only)", banned)
		}
	}
}

// testDenyStatusMap asserts the deny status table maps every named status to
// its class and the permanent default catches unnamed non-2xx statuses.
func testDenyStatusMap(t *testing.T) {
	for _, c := range denyStatusFixtures {
		if got := statusDenyClass(c.status); got != c.class {
			t.Errorf("status %d: got class %q, want %q", c.status, got, c.class)
		}
	}
	// Spot-check the permanent default on a status not in the table at all.
	if got := statusDenyClass(418); got != denyClassPermanent {
		t.Errorf("status 418 (unnamed): got class %q, want permanent", got)
	}
	// 429 is the retryable status that may carry Retry-After; 503 is retryable
	// but does not honour Retry-After. Both map to retryable here (the
	// Retry-After nuance is a header behaviour, not a class).
	if statusDenyClass(http.StatusTooManyRequests) != denyClassRetryable {
		t.Errorf("429 must be retryable")
	}
	if statusDenyClass(http.StatusServiceUnavailable) != denyClassRetryable {
		t.Errorf("503 must be retryable")
	}
}

// testBoundedReasonShape asserts the BoundedReason diagnostic body shape: a
// reason_code matching the open pattern, a bounded message, and the preferred
// default vocabulary all matching the pattern.
func testBoundedReasonShape(t *testing.T) {
	// The production deny body serializes to exactly {reason_code, message}.
	br := boundedReason{ReasonCode: "SCOPE_MISMATCH", Message: "scope mismatch"}
	assertKeySet(t, decodeToMap(t, br), []string{"reason_code", "message"})

	if boundedReasonMessageMax != 256 {
		t.Errorf("BoundedReason message max = %d, want 256", boundedReasonMessageMax)
	}
	if reasonCodePattern != `^[A-Z][A-Z0-9_]{1,63}$` {
		t.Errorf("reason_code pattern drifted: %q", reasonCodePattern)
	}
	// Every default-vocabulary value must satisfy the open pattern.
	re := mustCompile(t, reasonCodePattern)
	for _, code := range defaultReasonVocabulary {
		if !re.MatchString(code) {
			t.Errorf("default reason vocabulary %q does not match the open pattern", code)
		}
	}
	// The pattern is OPEN: a non-vocabulary but pattern-valid code is legal.
	if !re.MatchString("CUSTOM_REASON_42") {
		t.Errorf("pattern must accept a non-vocabulary but well-formed reason_code")
	}
	// A lowercase or too-short code is rejected.
	for _, bad := range []string{"scope_mismatch", "A", "9X", "X-Y"} {
		if re.MatchString(bad) {
			t.Errorf("reason_code pattern wrongly accepts %q", bad)
		}
	}

	// The production reason_code derivation (reasonCodeForVerdict) emits the
	// preferred default vocabulary for the common verdicts and is always
	// pattern-valid: the uppercased wire code matches the open pattern, and an
	// empty wire code falls back to a valid token.
	for _, class := range defaultReasonVocabulary {
		_ = class // the vocabulary is asserted above; the verdict mapping below
		// proves the writer derives a pattern-valid code from a real verdict.
	}
	for _, v := range []DenyVerdict{
		mapDeny(denyScopeMismatch),
		mapDeny(denyNotFound),
		mapDeny(denyThrottle),
		mapDeny(denyLeaseExpired),
		{}, // empty wire code -> INTERNAL fallback
	} {
		if got := reasonCodeForVerdict(v); !re.MatchString(got) {
			t.Errorf("reasonCodeForVerdict(%+v) = %q, not pattern-valid", v, got)
		}
	}
}

// testCredScopeSurface asserts the credential surface: the only credential
// header is Authorization and the scheme prefix is the literal "Bearer ".
func testCredScopeSurface(t *testing.T) {
	if authHeaderName != "Authorization" {
		t.Errorf("credential header = %q, want Authorization", authHeaderName)
	}
	if bearerScheme != "Bearer " {
		t.Errorf("bearer scheme prefix = %q, want \"Bearer \" (capital B, single trailing space)", bearerScheme)
	}
}

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------

// decodeToMap marshals v to JSON then decodes it into a generic map, so a test
// can assert the exact top-level key set and nested shapes the wire carries.
func decodeToMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal %T to map: %v", v, err)
	}
	return m
}

// assertKeySet fails unless the map's key set is EXACTLY want (no missing, no
// extra). It is the field-set oracle: a request/response that grows or loses a
// top-level field is a wire change and must update the fixture deliberately.
func assertKeySet(t *testing.T, m map[string]any, want []string) {
	t.Helper()
	wantSet := make(map[string]bool, len(want))
	for _, k := range want {
		wantSet[k] = true
	}
	for k := range m {
		if !wantSet[k] {
			t.Errorf("unexpected field %q (key set: %v, want: %v)", k, keysOf(m), want)
		}
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("missing field %q (key set: %v, want: %v)", k, keysOf(m), want)
		}
	}
}

// keysOf returns the key list of a map for diagnostics.
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// mustCompile compiles a regexp or fails the test — used to exercise the
// BoundedReason reason_code open pattern.
func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("compile pattern %q: %v", pattern, err)
	}
	return re
}
