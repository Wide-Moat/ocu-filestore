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
