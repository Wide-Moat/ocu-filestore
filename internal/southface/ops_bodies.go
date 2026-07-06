// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

// This file declares the per-operation request and response bodies for the
// seven phase-9 ops. The spine validated scope/intent on the unaryEnvelope;
// each handler strict-decodes its WHOLE op body (DisallowUnknownFields) so an
// unexpected field still rejects. All field shapes are pinned by rev-2 (D6)
// and the D9 bare-ack correction; the guest-read field names on the listing
// response are load-bearing (the guest mount reads path/size/mtime/mime/uuid
// for files and path/mtime for directories).

// listDirectoryRequest is the only phase-9 request with pagination fields.
// limit/cursor/recursive are accept-when-present with safe defaults
// (server-default page size / first page / one level) per Pitfall 7.
type listDirectoryRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	Limit                 int                   `json:"limit"`
	Cursor                string                `json:"cursor"`
	Recursive             bool                  `json:"recursive"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// makeDirectoryRequest carries make_parents (accept-when-present, default
// false — the guest does not yet send it but rev-2 pins it).
type makeDirectoryRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	MakeParents           bool                  `json:"make_parents"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// moveDirectoryRequest carries NO overwrite field — the engine MoveDir is
// called with overwrite=false, so an existing destination refuses.
type moveDirectoryRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Source                string                `json:"source"`
	Destination           string                `json:"destination"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// removeDirectoryRequest carries recursive (accept-when-present, default
// false -> refuse-if-non-empty without deleting).
type removeDirectoryRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	Recursive             bool                  `json:"recursive"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// copyFileRequest and moveFileRequest share the source/destination/overwrite
// shape.
type copyFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Source                string                `json:"source"`
	Destination           string                `json:"destination"`
	OverwriteExisting     bool                  `json:"overwrite_existing"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

type moveFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Source                string                `json:"source"`
	Destination           string                `json:"destination"`
	OverwriteExisting     bool                  `json:"overwrite_existing"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// removeFileRequest names a single file path.
type removeFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// ackResponse is the bare ack body `{}` returned by all six mutation ops
// (make/move/removeDirectory, copy/move/removeFile) — D9: the shipped guest
// decoder reads each into an empty struct and dereferences no `file` body.
type ackResponse struct{}

// listDirectoryResponse is the only non-trivial phase-9 body: the Entry-union
// listing plus the opaque keyset cursor (empty on the last page).
type listDirectoryResponse struct {
	Entries []entry `json:"entries"`
	Cursor  string  `json:"cursor"`
}

// entry is the listDirectory union: exactly one of File or Directory is set.
// omitempty drops the unset branch so the wire carries {"file":...} or
// {"directory":...} but never both.
type entry struct {
	File      *filesystemFile `json:"file,omitempty"`
	Directory *directory      `json:"directory,omitempty"`
}

// filesystemFile carries the guest-read field names the mount consumes
// (path/size/mtime/mime/uuid). The uuid is the broker-minted object handle
// stamped lazily at emit time. Paths are guest-convention (leading slash).
type filesystemFile struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	MTime string `json:"mtime"`
	MIME  string `json:"mime"`
	UUID  string `json:"uuid"`
}

// directory carries the guest-read directory field names (path/mtime); a
// directory has no size/uuid in the listing surface.
type directory struct {
	Path  string `json:"path"`
	MTime string `json:"mtime"`
}

// fileRange is the half-open [offset, offset+length) read window on a readFile
// request. An absent range (a nil *fileRange on the request) is a full read;
// a range past EOF short-reads to EOF without error (engine ReadRange
// contract).
type fileRange struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// readFileRequest is the pinned readFile (OPS-04) body: {filesystem_id, path,
// range{offset,length}} plus the D3 authorization_metadata. Range is a pointer
// so an absent range decodes as nil (full read). The authorization_metadata
// downloadable flag is NEVER trusted at read — the broker re-derives
// downloadable from its own resolved grant (A2/SEC-73).
type readFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	Range                 *fileRange            `json:"range"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// file is the readFile metadata-only response shape: the guest-read field
// names (path/size/mtime/mime/uuid). It carries NO content/data/bytes field —
// readFile emits metadata only; bulk bytes are the deferred fileDownload
// server-stream's job (D6 TBD content body stays TBD). Its shape matches
// filesystemFile so both faces read the same field names.
type file struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	MTime string `json:"mtime"`
	MIME  string `json:"mime"`
	UUID  string `json:"uuid"`
}

// readFileResponse wraps the metadata-only file body: {file: File}. No content
// field exists on this op (D6).
type readFileResponse struct {
	File file `json:"file"`
}

// readMetadataRequest is the pinned readMetadata body: {filesystem_id, path}
// plus the D3 authorization_metadata. It is the path-axis metadata resolve the
// guest mount runs on every Open/stat (the rclone ocufs resolve() fallback) to
// fetch the object's uuid handle and size BEFORE a read. The
// authorization_metadata.downloadable flag is never trusted here; this is a
// metadata resolve, not a content read, so it carries no downloadable gate.
type readMetadataRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// readMetadataResponse is the arm-discriminated resolve body the guest reads:
// exactly one of file or directory is set (omitempty drops the unset arm, so
// the wire carries {"file":...} or {"directory":...}). The guest classifies by
// arm — a file arm always carries an mtime and a uuid handle; a directory arm
// carries path/mtime only. Both arms absent means not-found. The field names
// match the listDirectory union (filesystemFile / directory) so both faces read
// the same shapes.
type readMetadataResponse struct {
	File      *filesystemFile `json:"file,omitempty"`
	Directory *directory      `json:"directory,omitempty"`
}

// uploadParamsFrame is the FIRST (and exactly one) frame of a fileUpload
// stream (OPS-05, D5). It is strict-decoded (DisallowUnknownFields): every
// field the guest may legitimately send is declared so a guest that carries
// metadata/media_type/tags/ttl_seconds/overwrite_existing is not rejected,
// while an unknown field (e.g. the rejected metadata_retention_days) is
// refused. filesystem_id/path are top-level (D3); filesystem_id is an
// untrusted hint cross-checked against the channel scope. declared_size_bytes
// is REQUIRED — absent/<=0 denies invalid_argument with no escape hatch (D5
// footnote). ttl_seconds clamps to session teardown and is never a retention
// guarantee; metadata_retention_days does not exist (rejected).
// overwrite_existing defaults to false when absent (JSON zero value), which
// preserves today's overwrite=false behaviour for any sender that omits it.
type uploadParamsFrame struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	DeclaredSizeBytes     int64                 `json:"declared_size_bytes"`
	OverwriteExisting     bool                  `json:"overwrite_existing"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
	Metadata              map[string]string     `json:"metadata"`
	MediaType             string                `json:"media_type"`
	Tags                  []string              `json:"tags"`
	TTLSeconds            int64                 `json:"ttl_seconds"`
}

// fileDownloadRequest is the FIRST (and exactly one) frame of a fileDownload
// stream (OPS-06). It is strict-decoded (DisallowUnknownFields). The uuid
// is the broker-held object handle minted by the listing/readFile emitter
// (objectIDStore); the broker resolves uuid→(scope,path) internally — a
// cross-scope uuid presentation degrades to not_found on the wire (D8,
// anti-enumeration). filesystem_id is an untrusted hint cross-checked
// against the channel scope. The authorization_metadata.downloadable flag
// is NEVER trusted at read — the broker re-derives downloadable from its
// own resolved grant at read time (NFR-SEC-73). Range is a pointer so an
// absent range decodes as nil (full read from offset 0 to EOF).
type fileDownloadRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	UUID                  string                `json:"uuid"`
	Range                 *fileRange            `json:"range"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}
