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
