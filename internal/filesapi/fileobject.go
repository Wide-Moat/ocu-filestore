// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import "github.com/Wide-Moat/ocu-filestore/internal/handlestore"

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
		MimeType:  r.Mime,
		SizeBytes: r.Size,
		CreatedAt: r.CreatedAt,
	}
}

// ListResponse is the Files-API list envelope (ADR-0023): the page of
// FileObjects plus the pagination cursor and page bounds. The field names match
// the Files dialect (data / has_more / first_id / last_id). next_cursor is the
// opaque continuation token a caller passes back to fetch the next page.
type ListResponse struct {
	// Data is the page of file objects in the store's stable total order.
	Data []FileObject `json:"data"`
	// HasMore is true when at least one more record sorts after this page.
	HasMore bool `json:"has_more"`
	// FirstID is the file_id of the first record on this page (empty page -> "").
	FirstID string `json:"first_id"`
	// LastID is the file_id of the last record on this page (empty page -> "").
	LastID string `json:"last_id"`
	// NextCursor is the opaque token to pass as the next page's cursor, or empty
	// when this is the final page.
	NextCursor string `json:"next_cursor"`
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
