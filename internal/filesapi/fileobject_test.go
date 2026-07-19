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

// TestFileObjectDerivesMimeWhenAbsent is the read-plane content-type guard: a
// guest FUSE write stores an S3 object with no Content-Type, so the durable
// Record's Mime is "" for every agent-written file. The projection must derive
// a media type from the filename extension so a File Pane preview (or any F9
// reader) can classify the model's output. A stored Mime always wins. This is
// the non-vacuous guard that keeps the fix honest: it stays RED until the
// read-time derivation lands (revert resolveMime -> mime_type "" for a .png).
func TestFileObjectDerivesMimeWhenAbsent(t *testing.T) {
	cases := []struct {
		filename string
		stored   string
		want     string
	}{
		// The load-bearing case: a guest-written PNG with no stored mime must
		// project image/png so the preview classifies it as an image.
		{"chart.png", "", "image/png"},
		{"notes.txt", "", "text/plain"},
		// A stored content type always wins over the extension.
		{"report.pdf", "application/pdf", "application/pdf"},
		// A stored type wins even when it disagrees with the extension.
		{"data.bin", "application/json", "application/json"},
		// No extension and no stored type -> empty, not a guess.
		{"README", "", ""},
	}
	for _, c := range cases {
		fo := newFileObject(handlestore.Record{
			FileID:   "fid-mime",
			Filename: c.filename,
			Mime:     c.stored,
		})
		// Derived types may carry a charset suffix from the platform mime table;
		// compare on the bare media type.
		got := fo.MimeType
		if i := strings.IndexByte(got, ';'); i >= 0 {
			got = strings.TrimSpace(got[:i])
		}
		if got != c.want {
			t.Fatalf("newFileObject(%q, stored=%q).MimeType = %q, want %q",
				c.filename, c.stored, fo.MimeType, c.want)
		}
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
// as [] (not null) so a caller never special-cases a JSON null, and that the
// optional boundary/cursor fields are ABSENT (omitempty), not empty strings: the
// contract marks first_id, last_id, and next_cursor absent on an empty/final page
// (min length 1 when present), so emitting "" would violate the wire schema.
func TestListResponseEmptyPageMarshalsArray(t *testing.T) {
	env := newListResponse(handlestore.ListPage{})
	raw, _ := json.Marshal(env)
	s := string(raw)
	if !strings.Contains(s, `"data":[]`) {
		t.Fatalf("empty page data is not []: %s", raw)
	}
	for _, field := range []string{"first_id", "last_id", "next_cursor"} {
		if strings.Contains(s, `"`+field+`"`) {
			t.Fatalf("empty page emitted %q (want it absent via omitempty): %s", field, raw)
		}
	}
	// has_more is always present (a bool, not omitempty).
	if !strings.Contains(s, `"has_more"`) {
		t.Fatalf("has_more missing from the envelope: %s", raw)
	}
}
