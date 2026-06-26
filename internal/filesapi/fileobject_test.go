// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
)

// TestFileObjectMapsRecord pins the Record -> FileObject mapping in the Files
// dialect: the public file_id, the constant type tag, filename, mime, size, and
// the store-stamped created_at.
func TestFileObjectMapsRecord(t *testing.T) {
	rec := handlestore.Record{
		FileID:    "fid-123",
		Scope:     "fs-alpha",
		ObjectRef: "backend/obj/secret",
		Filename:  "report.pdf",
		Mime:      "application/pdf",
		Size:      4096,
		CreatedAt: "2026-06-23T00:00:00Z",
	}
	fo := newFileObject(rec)
	if fo.ID != "fid-123" || fo.Type != "file" || fo.Filename != "report.pdf" ||
		fo.MimeType != "application/pdf" || fo.SizeBytes != 4096 || fo.CreatedAt != "2026-06-23T00:00:00Z" {
		t.Fatalf("FileObject = %+v, mismatch", fo)
	}
}

// TestFileObjectOmitsDownloadableAndObjectRef pins that the marshalled
// FileObject carries NO downloadable field (resolved at read only, NFR-SEC-73)
// and NEVER leaks the backend object_ref or the scope.
func TestFileObjectOmitsDownloadableAndObjectRef(t *testing.T) {
	rec := handlestore.Record{
		FileID:                "fid-123",
		Scope:                 "fs-alpha",
		ObjectRef:             "backend/obj/secret-9999",
		Filename:              "doc",
		DownloadablePolicyRef: "policy-ref-xyz",
	}
	raw, err := json.Marshal(newFileObject(rec))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	for _, forbidden := range []string{"downloadable", "object_ref", "secret-9999", "fs-alpha", "policy", "scope"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("FileObject JSON %q leaks %q", s, forbidden)
		}
	}
}

// TestListResponseEnvelope pins the list envelope: the data array, the
// pagination flags/bounds, and the omission of downloadable on every entry.
func TestListResponseEnvelope(t *testing.T) {
	page := handlestore.ListPage{
		Records: []handlestore.Record{
			{FileID: "f1", Filename: "a", ObjectRef: "o1"},
			{FileID: "f2", Filename: "b", ObjectRef: "o2"},
		},
		HasMore:    true,
		FirstID:    "f1",
		LastID:     "f2",
		NextCursor: "cursor-f2",
	}
	env := newListResponse(page)
	if len(env.Data) != 2 || env.Data[0].ID != "f1" || env.Data[1].ID != "f2" {
		t.Fatalf("Data = %+v, want two file objects", env.Data)
	}
	if !env.HasMore || env.FirstID != "f1" || env.LastID != "f2" || env.NextCursor != "cursor-f2" {
		t.Fatalf("envelope pagination fields mismatch: %+v", env)
	}
	raw, _ := json.Marshal(env)
	if strings.Contains(string(raw), "downloadable") || strings.Contains(string(raw), "object_ref") {
		t.Fatalf("list envelope leaks downloadable/object_ref: %s", raw)
	}
}

// TestListResponseEmptyPageMarshalsArray pins that an empty page marshals data
// as [] (not null) so a caller never special-cases a JSON null.
func TestListResponseEmptyPageMarshalsArray(t *testing.T) {
	env := newListResponse(handlestore.ListPage{})
	raw, _ := json.Marshal(env)
	if !strings.Contains(string(raw), `"data":[]`) {
		t.Fatalf("empty page data is not []: %s", raw)
	}
}
