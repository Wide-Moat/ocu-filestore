// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestStore opens a fresh DiskStore on a temp-dir log and returns its path.
func newTestStore(t *testing.T) (string, *DiskStore) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "handles.jsonl")
	s, err := NewDiskStore(path)
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return path, s
}

// samplePut is a representative PutInput under the given scope.
func samplePut(scope, name string) PutInput {
	return PutInput{
		Scope:                 scope,
		ObjectRef:             "obj/" + name,
		Filename:              name,
		Mime:                  "application/octet-stream",
		Size:                  42,
		DownloadablePolicyRef: "policy/default",
	}
}

// TestPutStampsAndMints pins Put: it mints a 32-hex file_id (never caller-set),
// stamps CreatedAt from the store clock (RFC-3339), and returns the record.
func TestPutStampsAndMints(t *testing.T) {
	_, s := newTestStore(t)
	rec, err := s.Put(context.Background(), samplePut("fs-A", "a.txt"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if len(rec.FileID) != 32 {
		t.Fatalf("file_id %q len = %d, want 32", rec.FileID, len(rec.FileID))
	}
	if rec.CreatedAt == "" {
		t.Fatal("CreatedAt empty, want a store-stamped RFC-3339 timestamp")
	}
	if !strings.HasSuffix(rec.CreatedAt, "Z") {
		t.Fatalf("CreatedAt = %q, want UTC (trailing Z)", rec.CreatedAt)
	}
	if rec.Scope != "fs-A" || rec.Filename != "a.txt" || rec.DownloadablePolicyRef != "policy/default" {
		t.Fatalf("record fields not carried through: %+v", rec)
	}
}

// TestPutDistinctFileIDs pins that two Puts mint distinct file_ids.
func TestPutDistinctFileIDs(t *testing.T) {
	_, s := newTestStore(t)
	r1, _ := s.Put(context.Background(), samplePut("fs-A", "a"))
	r2, _ := s.Put(context.Background(), samplePut("fs-A", "b"))
	if r1.FileID == r2.FileID {
		t.Fatalf("two Puts shared file_id %q", r1.FileID)
	}
}

// TestPutReplayAcrossRestart pins durability: records Put before a Close
// reappear identically after a fresh NewDiskStore on the same path.
func TestPutReplayAcrossRestart(t *testing.T) {
	path, s := newTestStore(t)
	want := map[string]Record{}
	for _, n := range []string{"a", "b", "c"} {
		rec, err := s.Put(context.Background(), samplePut("fs-A", n))
		if err != nil {
			t.Fatalf("Put %s: %v", n, err)
		}
		want[rec.FileID] = rec
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewDiskStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	for id, rec := range want {
		got, err := s2.Get(context.Background(), id, "fs-A")
		if err != nil {
			t.Fatalf("Get(%s) after restart: %v", id, err)
		}
		if got != rec {
			t.Fatalf("replayed record mismatch:\n got %+v\nwant %+v", got, rec)
		}
	}
}

// TestNewDiskStoreCreatesFile pins the two-fsync creation branch: a brand-new
// path yields a usable store and an existing 0o600 file.
func TestNewDiskStoreCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handles.jsonl")
	s, err := NewDiskStore(path)
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}
	defer s.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat created log: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("log perms = %o, want 600", info.Mode().Perm())
	}
}

// TestReplayRefusesUnparseableCompleteLine pins fail-closed start: a complete
// (newline-terminated) line that does not parse is corruption — the constructor
// refuses to start rather than serve on a truncated map.
func TestReplayRefusesUnparseableCompleteLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handles.jsonl")
	if err := os.WriteFile(path, []byte("{not valid json}\n"), 0o600); err != nil {
		t.Fatalf("seed corrupt log: %v", err)
	}
	_, err := NewDiskStore(path)
	if err == nil {
		t.Fatal("NewDiskStore on corrupt log = nil, want a fail-closed refusal")
	}
	if !strings.Contains(err.Error(), "existing log invalid") {
		t.Fatalf("error = %v, want existing-log-invalid refusal", err)
	}
}

// TestReplayRefusesUnknownOp pins that an unknown op discriminator on a complete
// line is corruption.
func TestReplayRefusesUnknownOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handles.jsonl")
	if err := os.WriteFile(path, []byte(`{"op":"rename","file_id":"x"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := NewDiskStore(path); err == nil {
		t.Fatal("NewDiskStore on unknown op = nil, want refusal")
	}
}

// TestReplayDropsTornTail pins that a trailing partial line with no newline is
// an un-acked torn write: it is dropped (Truncate+Sync) and the acked prefix
// survives, so the store starts clean and the next Put cannot merge into the
// fragment.
func TestReplayDropsTornTail(t *testing.T) {
	path, s := newTestStore(t)
	rec, err := s.Put(context.Background(), samplePut("fs-A", "a"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Append a torn (no-newline) partial line directly to the file.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for torn append: %v", err)
	}
	if _, err := f.WriteString(`{"op":"put","record":{"file_id":"torn`); err != nil {
		t.Fatalf("write torn: %v", err)
	}
	_ = f.Close()

	before, _ := os.Stat(path)
	s2, err := NewDiskStore(path)
	if err != nil {
		t.Fatalf("reopen with torn tail: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	after, _ := os.Stat(path)
	if after.Size() >= before.Size() {
		t.Fatalf("torn tail not dropped: size before=%d after=%d", before.Size(), after.Size())
	}
	// The acked record still resolves; the torn one never existed.
	if _, err := s2.Get(context.Background(), rec.FileID, "fs-A"); err != nil {
		t.Fatalf("acked record lost after torn-tail drop: %v", err)
	}
	if _, err := s2.Get(context.Background(), "torn", "fs-A"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("torn record resolved: %v, want ErrNotFound", err)
	}
	// A fresh Put after recovery lands as its own clean line.
	if _, err := s2.Put(context.Background(), samplePut("fs-A", "b")); err != nil {
		t.Fatalf("Put after torn recovery: %v", err)
	}
}

// TestListScopeBound pins that List returns only the requested scope's records.
func TestListScopeBound(t *testing.T) {
	_, s := newTestStore(t)
	a1, _ := s.Put(context.Background(), samplePut("fs-A", "a1"))
	a2, _ := s.Put(context.Background(), samplePut("fs-A", "a2"))
	_, _ = s.Put(context.Background(), samplePut("fs-B", "b1"))

	page, err := s.List(context.Background(), ListInput{Scope: "fs-A"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("List(fs-A) returned %d records, want 2", len(page.Records))
	}
	got := map[string]bool{}
	for _, r := range page.Records {
		if r.Scope != "fs-A" {
			t.Fatalf("List(fs-A) leaked a %q record", r.Scope)
		}
		got[r.FileID] = true
	}
	if !got[a1.FileID] || !got[a2.FileID] {
		t.Fatalf("List(fs-A) missing an expected record: %+v", got)
	}
}

// TestCloseIdempotent pins that a second Close is a no-op returning nil.
func TestCloseIdempotent(t *testing.T) {
	_, s := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v, want nil (idempotent)", err)
	}
}

// TestPutOnClosedStoreFailsClosed pins that a mutation after Close is denied
// (ErrStoreUnavailable) rather than writing to a released descriptor.
func TestPutOnClosedStoreFailsClosed(t *testing.T) {
	_, s := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := s.Put(context.Background(), samplePut("fs-A", "a")); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("Put after Close = %v, want ErrStoreUnavailable", err)
	}
}
