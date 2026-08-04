// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"mime"
	"path/filepath"
	"strings"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
)

// FileObject is the Files-API JSON representation of a stored file handle
// (ADR-0023, the Anthropic Files dialect). It is built from a handlestore.Record
// for the metadata and list endpoints.
//
// downloadable is DELIBERATELY OMITTED here (Default 1): downloadable resolves
// AT READ, never stamped at write (NFR-SEC-73), so the list and metadata views —
// which do not perform a read — must not carry a downloadable flag that would be
// a forbidden write-time stamp. Only the content endpoint resolves downloadable,
// and it does so against the broker-resolved grant, never a field on this object.
//
// The public file_id is the handle; the backend ObjectRef is NEVER surfaced —
// it is the engine's internal locator and leaks the storage layout. CreatedAt is
// the store-stamped durable timestamp.
type FileObject struct {
	// ID is the public broker-minted file_id (the handle the wire presents).
	ID string `json:"id"`
	// Type is the constant object tag for the Files dialect.
	Type string `json:"type"`
	// Filename is the caller-supplied display name.
	Filename string `json:"filename"`
	// MimeType is the caller-supplied content type.
	MimeType string `json:"mime_type"`
	// SizeBytes is the stored object's byte length.
	SizeBytes int64 `json:"size_bytes"`
	// CreatedAt is the store-stamped durable RFC-3339 UTC creation time.
	CreatedAt string `json:"created_at"`
	// Sha256 is the lowercase-hex SHA-256 of the stored content (D6,
	// PARITY-LEDGER-147). It is an ADDITIVE OPTIONAL response field: the engine
	// already computes this digest in its single write pass, so the north list
	// standardises on it (NOT md5) for content dedup - an edited same-size file
	// carries a new digest and is re-uploaded. omitempty keeps the field ABSENT
	// for a record with no recorded digest (a pre-D6 handle, or a reconcile-minted
	// whole-tree object), so a client falls back to name+size - the designed
	// back-compat window. ADR-0028 froze the six-field body and DEFERRED a
	// checksum field; this addition is the deferred field, standardised on sha256
	// (canon ADR in flight: content-hash manifest, D6, PARITY-LEDGER-147).
	Sha256 string `json:"sha256,omitempty"`
}

// fileObjectType is the constant Files-API object tag.
const fileObjectType = "file"

// newFileObject maps a durable handle Record to its public FileObject. It copies
// only the caller-facing metadata; the backend ObjectRef and the scope binding
// stay internal (the ObjectRef is the engine locator, the scope is the
// attestation axis — neither belongs on the wire). downloadable is omitted by
// construction (the struct has no such field).
func newFileObject(r handlestore.Record) FileObject {
	return FileObject{
		ID:        r.FileID,
		Type:      fileObjectType,
		Filename:  r.Filename,
		MimeType:  resolveMime(r.Mime, r.Filename),
		SizeBytes: r.Size,
		CreatedAt: r.CreatedAt,
		Sha256:    r.Sha256,
	}
}

// resolveMime returns the stored content type, or derives one from the filename
// extension when the record carries none. A guest FUSE write PUTs an S3 object
// with no Content-Type, so the durable record's Mime is "" for every agent-
// written file; without this, a client (the File Pane preview, any F9 reader)
// cannot classify an image the model produced. Read-time derivation at this one
// projection choke-point covers already-stored objects and any writer, and it is
// consistent with the content endpoint serving the same type. A stored Mime
// always wins; the fallback runs only when it is absent.
func resolveMime(stored, filename string) string {
	if stored != "" {
		return stored
	}
	ext := filepath.Ext(filename)
	if ext == "" {
		return ""
	}
	if t := mime.TypeByExtension(ext); t != "" {
		// TypeByExtension may append "; charset=utf-8"; keep only the media type
		// so the wire carries a bare "image/png" like a stored content type.
		if i := strings.IndexByte(t, ';'); i >= 0 {
			return strings.TrimSpace(t[:i])
		}
		return t
	}
	return ""
}

// ListResponse is the Files-API list envelope (ADR-0028): the page of
// FileObjects, whether more pages follow, informational boundary ids, and the
// opaque forward cursor. Only data and has_more are always present; first_id,
// last_id, and next_cursor are omitted when they do not apply (an empty page has
// no boundary ids; the final page has no next_cursor).
//
// first_id/last_id are INFORMATIONAL boundary markers, NOT resume keys. The
// forward cursor is next_cursor, passed back as ?after=<next_cursor>: it is the
// store's opaque keyset token (created-at/file-id boundary tuple), which survives
// a deleted boundary record where a bare last_id would repeat or strand a record.
type ListResponse struct {
	// Data is the page of file objects in the store's stable total order.
	Data []FileObject `json:"data"`
	// HasMore is true when at least one more record sorts after this page.
	HasMore bool `json:"has_more"`
	// FirstID is the id of the first record on this page (informational, omitted
	// on an empty page).
	FirstID string `json:"first_id,omitempty"`
	// LastID is the id of the last record on this page (informational boundary
	// marker, NOT the resume key; omitted on an empty page).
	LastID string `json:"last_id,omitempty"`
	// NextCursor is the opaque forward resume token passed back as ?after=; present
	// while HasMore is true, omitted on the final page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// newListResponse builds the list envelope from a handlestore.ListPage. The Data
// slice is always non-nil (an empty page marshals as [] not null) so a caller
// never has to special-case a JSON null for the page array.
func newListResponse(page handlestore.ListPage) ListResponse {
	data := make([]FileObject, 0, len(page.Records))
	for _, rec := range page.Records {
		data = append(data, newFileObject(rec))
	}
	return ListResponse{
		Data:       data,
		HasMore:    page.HasMore,
		FirstID:    page.FirstID,
		LastID:     page.LastID,
		NextCursor: page.NextCursor,
	}
}
