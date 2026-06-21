// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"pgregory.net/rapid"
)

// arbitraryPut draws a structurally valid PutInput with a small sampled scope
// and arbitrary short metadata.
func arbitraryPut(rt *rapid.T) PutInput {
	return PutInput{
		Scope:                 rapid.SampledFrom([]string{"fs-A", "fs-B", "fs-C"}).Draw(rt, "scope"),
		ObjectRef:             rapid.String().Draw(rt, "object_ref"),
		Filename:              rapid.String().Draw(rt, "filename"),
		Mime:                  rapid.SampledFrom([]string{"text/plain", "application/json", "image/png"}).Draw(rt, "mime"),
		Size:                  rapid.Int64Range(0, 1<<40).Draw(rt, "size"),
		DownloadablePolicyRef: rapid.String().Draw(rt, "policy"),
	}
}

// snapshot returns the store's resolvable records as a file_id -> Record map by
// asking Get under each record's own scope. It is the observable projection a
// restart must reproduce.
func snapshot(t *testing.T, s *DiskStore, ids map[string]Record) map[string]Record {
	t.Helper()
	out := map[string]Record{}
	for id, rec := range ids {
		got, err := s.Get(context.Background(), id, rec.Scope)
		if err != nil {
			t.Fatalf("Get(%s) = %v, want the record", id, err)
		}
		out[id] = got
	}
	return out
}

// TestPropReplayReproducesMap asserts that a sequence of rapid Puts, written
// through a store and replayed by a fresh store on the same path, reproduces an
// IDENTICAL resolvable map (durability + last-write-wins replay).
func TestPropReplayReproducesMap(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		path := filepath.Join(t.TempDir(), "handles.jsonl")
		s, err := NewDiskStore(path)
		if err != nil {
			rt.Fatalf("NewDiskStore: %v", err)
		}

		puts := rapid.SliceOfN(rapid.Custom(arbitraryPut), 1, 12).Draw(rt, "puts")
		ids := map[string]Record{}
		for i, in := range puts {
			rec, err := s.Put(context.Background(), in)
			if err != nil {
				rt.Fatalf("Put #%d: %v", i, err)
			}
			ids[rec.FileID] = rec
		}
		want := snapshot(t, s, ids)
		if err := s.Close(); err != nil {
			rt.Fatalf("close: %v", err)
		}

		s2, err := NewDiskStore(path)
		if err != nil {
			rt.Fatalf("reopen: %v", err)
		}
		got := snapshot(t, s2, ids)
		_ = s2.Close()

		if len(got) != len(want) {
			rt.Fatalf("replayed map size = %d, want %d", len(got), len(want))
		}
		for id, w := range want {
			if got[id] != w {
				rt.Fatalf("replayed record %s mismatch:\n got %+v\nwant %+v", id, got[id], w)
			}
		}
	})
}

// TestPropTornTailDropsExactSuffix asserts that appending an arbitrary
// non-newline-terminated suffix to a healthy log is treated as a torn un-acked
// write: the recovered store drops EXACTLY that suffix (file shrinks to the
// acked prefix) and every acked record still resolves.
func TestPropTornTailDropsExactSuffix(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		path := filepath.Join(t.TempDir(), "handles.jsonl")
		s, err := NewDiskStore(path)
		if err != nil {
			rt.Fatalf("NewDiskStore: %v", err)
		}
		puts := rapid.SliceOfN(rapid.Custom(arbitraryPut), 1, 8).Draw(rt, "puts")
		ids := map[string]Record{}
		for _, in := range puts {
			rec, err := s.Put(context.Background(), in)
			if err != nil {
				rt.Fatalf("Put: %v", err)
			}
			ids[rec.FileID] = rec
		}
		if err := s.Close(); err != nil {
			rt.Fatalf("close: %v", err)
		}

		ackedSize := func() int64 {
			info, err := os.Stat(path)
			if err != nil {
				rt.Fatalf("stat: %v", err)
			}
			return info.Size()
		}()

		// Append a non-empty torn suffix WITHOUT a trailing newline.
		suffix := rapid.StringMatching(`[^\n]+`).Draw(rt, "suffix")
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			rt.Fatalf("open for torn append: %v", err)
		}
		if _, err := f.WriteString(suffix); err != nil {
			rt.Fatalf("write torn suffix: %v", err)
		}
		_ = f.Close()

		s2, err := NewDiskStore(path)
		if err != nil {
			rt.Fatalf("reopen with torn tail: %v", err)
		}
		defer s2.Close()

		// The file shrank back to EXACTLY the acked prefix.
		if got := func() int64 {
			info, _ := os.Stat(path)
			return info.Size()
		}(); got != ackedSize {
			rt.Fatalf("after torn-tail drop size = %d, want exactly the acked prefix %d", got, ackedSize)
		}
		// Every acked record still resolves.
		for id, rec := range ids {
			if _, err := s2.Get(context.Background(), id, rec.Scope); err != nil {
				rt.Fatalf("acked record %s lost after torn-tail drop: %v", id, err)
			}
		}
	})
}
