// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"reflect"
	"testing"
)

// goldenScope is the GOLDEN-FIXTURES triplet scope.
const goldenScope = "fs-golden-01"

// parseJSON parses a response body into a generic value for parsed-equal
// comparison (key order is encoder-dependent; compare structurally).
func parseJSON(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, string(b))
	}
	return v
}

// TestGoldenMutationAcks pins that all six mutation ops emit a parsed-equal
// bare ack {} (D9). The golden body is the load-bearing parity case shared
// with the guest decoder, which reads each into an empty struct.
func TestGoldenMutationAcks(t *testing.T) {
	wantAck := parseJSON(t, []byte(`{}`))

	cases := []struct {
		op   Op
		body string
		seed func(*fakeEngine)
	}{
		{
			op:   OpMakeDirectory,
			body: `{"filesystem_id":"fs-golden-01","path":"/golden-dir","make_parents":false,"authorization_metadata":{"intent":"write","downloadable":false}}`,
		},
		{
			op:   OpMoveDirectory,
			body: `{"filesystem_id":"fs-golden-01","source":"/golden-dir","destination":"/golden-moved","authorization_metadata":{"intent":"write","downloadable":false}}`,
			seed: func(e *fakeEngine) { e.mkdirSeed(goldenScope, "golden-dir") },
		},
		{
			op:   OpRemoveDirectory,
			body: `{"filesystem_id":"fs-golden-01","path":"/golden-dir","recursive":true,"authorization_metadata":{"intent":"write","downloadable":false}}`,
			seed: func(e *fakeEngine) { e.mkdirSeed(goldenScope, "golden-dir") },
		},
		{
			op:   OpCopyFile,
			body: `{"filesystem_id":"fs-golden-01","source":"/golden.bin","destination":"/golden-copy.bin","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`,
			seed: func(e *fakeEngine) { e.putFile(goldenScope, "golden.bin", 42) },
		},
		{
			op:   OpMoveFile,
			body: `{"filesystem_id":"fs-golden-01","source":"/golden.bin","destination":"/golden-moved.bin","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`,
			seed: func(e *fakeEngine) { e.putFile(goldenScope, "golden.bin", 42) },
		},
		{
			op:   OpRemoveFile,
			body: `{"filesystem_id":"fs-golden-01","path":"/golden.bin","authorization_metadata":{"intent":"write","downloadable":false}}`,
			seed: func(e *fakeEngine) { e.putFile(goldenScope, "golden.bin", 42) },
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.op), func(t *testing.T) {
			eng := newFakeEngine()
			if tc.seed != nil {
				tc.seed(eng)
			}
			d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
			w := serveOp(d, tc.op, tc.body, goldenScope, okIntents())
			if w.Code != 200 {
				t.Fatalf("%s status = %d, want 200; body %s", tc.op, w.Code, w.Body.String())
			}
			got := parseJSON(t, w.Body.Bytes())
			if !reflect.DeepEqual(got, wantAck) {
				t.Fatalf("%s response = %s, want bare {}", tc.op, w.Body.String())
			}
		})
	}
}

// TestGoldenListDirectory pins the load-bearing listDirectory union golden:
// the response is parsed-equal to the expected Entry-union body with
// guest-read field names and guest-convention paths. The uuid is minted (not
// fixed), so the golden compares the structural shape with the uuid masked.
func TestGoldenListDirectory(t *testing.T) {
	eng := newFakeEngine()
	eng.mkdirSeed(goldenScope, "golden-dir")
	eng.putFile(goldenScope, "golden.bin", 42)
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	body := `{"filesystem_id":"fs-golden-01","path":"/","limit":0,"cursor":"","recursive":false,"authorization_metadata":{"intent":"read","downloadable":false}}`
	w := serveOp(d, OpListDirectory, body, goldenScope, okIntents())
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}

	var resp listDirectoryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not a listDirectoryResponse: %v", err)
	}
	if resp.Cursor != "" {
		t.Fatalf("single-page golden cursor = %q, want empty", resp.Cursor)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("golden listing has %d entries, want 2 (the dir + the file)", len(resp.Entries))
	}

	var gotFile *filesystemFile
	var gotDir *directory
	for _, e := range resp.Entries {
		if e.File != nil {
			gotFile = e.File
		}
		if e.Directory != nil {
			gotDir = e.Directory
		}
	}
	if gotDir == nil || gotDir.Path != "/golden-dir" {
		t.Fatalf("golden dir entry = %+v, want path /golden-dir", gotDir)
	}
	if gotFile == nil {
		t.Fatal("golden file entry missing")
	}
	if gotFile.Path != "/golden.bin" {
		t.Fatalf("golden file path = %q, want /golden.bin", gotFile.Path)
	}
	if gotFile.Size != 42 {
		t.Fatalf("golden file size = %d, want 42", gotFile.Size)
	}
	if len(gotFile.UUID) != 32 {
		t.Fatalf("golden file uuid = %q, want a 32-char minted handle", gotFile.UUID)
	}
	if gotFile.MTime == "" || gotFile.MIME == "" {
		t.Fatalf("golden file missing guest-read mtime/mime: %+v", gotFile)
	}
}

// TestGoldenReadFileMetadata pins the readFile (OPS-04) metadata-only response
// against the GOLDEN-FIXTURES triplet (fs-golden-01 / golden.bin, 42 bytes):
// the body is parsed-equal to {"file":{...}} carrying the guest-read field
// names with NO content body (D6). The grant is downloadable.
func TestGoldenReadFileMetadata(t *testing.T) {
	eng := newFakeEngine()
	eng.putBytes(goldenScope, "golden.bin", make([]byte, 42))
	d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)

	body := `{"filesystem_id":"fs-golden-01","path":"/golden.bin","range":{"offset":0,"length":42},"authorization_metadata":{"intent":"read","downloadable":false}}`
	w := serveOp(d, OpReadFile, body, goldenScope, okIntents())
	resp := decodeReadFile(t, w)

	// The metadata-only contract: full object size, guest-convention path, a
	// minted 32-char uuid handle, and the guest-read mtime/mime present.
	if resp.File.Path != "/golden.bin" {
		t.Fatalf("golden readFile path = %q, want /golden.bin", resp.File.Path)
	}
	if resp.File.Size != 42 {
		t.Fatalf("golden readFile size = %d, want 42", resp.File.Size)
	}
	if len(resp.File.UUID) != 32 {
		t.Fatalf("golden readFile uuid = %q, want a 32-char minted handle", resp.File.UUID)
	}
	if resp.File.MTime == "" || resp.File.MIME == "" {
		t.Fatalf("golden readFile missing guest-read mtime/mime: %+v", resp.File)
	}

	// Parsed-equal structure: the top object has exactly the "file" key, and
	// the file object has exactly the five metadata keys (no content body).
	top := parseJSON(t, w.Body.Bytes()).(map[string]any)
	if len(top) != 1 {
		t.Fatalf("readFile body has %d top-level keys, want 1 (file): %s", len(top), w.Body.String())
	}
	fileObj, ok := top["file"].(map[string]any)
	if !ok {
		t.Fatalf("readFile body file is not an object: %s", w.Body.String())
	}
	wantKeys := map[string]bool{"path": true, "size": true, "mtime": true, "mime": true, "uuid": true}
	if len(fileObj) != len(wantKeys) {
		t.Fatalf("file object has %d keys, want %d (metadata-only): %s", len(fileObj), len(wantKeys), w.Body.String())
	}
	for k := range fileObj {
		if !wantKeys[k] {
			t.Fatalf("file object carries unexpected key %q (D6 metadata-only): %s", k, w.Body.String())
		}
	}
}
