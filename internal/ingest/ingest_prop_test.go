// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// adversarialNames seeds the namespace generator with the corpus shapes
// that must keep rejecting; rapid mixes them with arbitrary strings.
var adversarialNames = []string{
	"../escape", "/abs/path", "C:/evil", `..\..\smuggle`, `etc\passwd`,
	"s3://bucket/key", ".", "", "ok.txt", "dir/file.bin", "dir/", "a/../b",
	"evil\x00.txt", "..", "a/../../b",
}

// TestPropNamespaceContainment asserts that no accepted archive ever
// yields an out-of-namespace staged name, and that every rejection aborts
// the sink (ARC-02, NFR-SEC-80). Non-vacuity: the reject counter must
// fire at least once across the run; a hand-built guaranteed-traversal
// sub-case keeps it from ever being vacuous.
func TestPropNamespaceContainment(t *testing.T) {
	rejects := 0
	check := func(tb failer, data []byte) {
		sink := &recordingSink{}
		err := ValidateZip(context.Background(), data, testConfig(), sink)
		if err == nil {
			if !sink.committed {
				tb.Fatalf("nil error but sink not committed")
			}
			names := append(append([]string{}, sink.staged...), sink.dirs...)
			for _, name := range names {
				if !filepath.IsLocal(name) || name == "." {
					tb.Fatalf("accepted entry escapes namespace: %q", name)
				}
			}
			if len(sink.symlinks) != 0 {
				tb.Fatalf("symlink staged on this shelf: %v", sink.symlinks)
			}
			return
		}
		rejects++
		if !sink.aborted {
			tb.Fatalf("error %v but sink not aborted", err)
		}
		if sink.committed {
			tb.Fatalf("error %v but sink committed", err)
		}
	}

	nameGen := rapid.OneOf(rapid.SampledFrom(adversarialNames), rapid.String())
	rapid.Check(t, func(rt *rapid.T) {
		names := rapid.SliceOfN(nameGen, 1, 8).Draw(rt, "names")
		buf := &bytes.Buffer{}
		w := zip.NewWriter(buf)
		for _, name := range names {
			fw, err := w.CreateHeader(&zip.FileHeader{Name: name})
			if err != nil {
				continue
			}
			if !strings.HasSuffix(name, "/") {
				_, _ = fw.Write([]byte("payload"))
			}
		}
		if err := w.Close(); err != nil {
			return // unbuildable draw; nothing to assert
		}
		check(rt, buf.Bytes())
	})

	// Guaranteed-traversal sub-case through the same assertion path.
	check(t, buildZip(t, zipEntry{name: "../guaranteed-escape", body: []byte("x")}))

	if rejects == 0 {
		t.Fatal("vacuous run: the namespace reject branch never fired")
	}
}

// TestPropCeilingAlwaysRejects asserts that every archive whose
// decompressed total exceeds the ceiling is rejected with ErrTotalExceeded
// and an aborted sink, for any bomb size in (ceiling, 3*ceiling]
// (ARC-01, NFR-SEC-80). Non-vacuity: the reject counter increments on
// every draw and must be > 0 at the end of the run.
func TestPropCeilingAlwaysRejects(t *testing.T) {
	const ceiling int64 = 64 << 10
	rejects := 0
	rapid.Check(t, func(rt *rapid.T) {
		size := rapid.Int64Range(ceiling+1, ceiling*3).Draw(rt, "entry_size")
		data := buildBombZip(rt, size)
		cfg := testConfig()
		cfg.TotalUncompressedCeiling = ceiling
		sink := &recordingSink{}
		err := ValidateZip(context.Background(), data, cfg, sink)
		if err == nil {
			rt.Fatalf("bomb of %d bytes accepted over the %d-byte ceiling", size, ceiling)
		}
		if !errors.Is(err, ErrTotalExceeded) {
			rt.Fatalf("wrong rejection: %v, want ErrTotalExceeded", err)
		}
		if !sink.aborted || sink.committed {
			rt.Fatalf("sink state after rejection: aborted=%v committed=%v", sink.aborted, sink.committed)
		}
		rejects++
	})
	if rejects == 0 {
		t.Fatal("vacuous run: the ceiling reject branch never fired")
	}
}

// buildBombZip builds a one-entry archive whose deflated body decompresses
// to size zero bytes — tiny on the wire, oversize when extracted.
func buildBombZip(t failer, size int64) []byte {
	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	fw, err := w.CreateHeader(&zip.FileHeader{Name: "bomb.bin", Method: zip.Deflate})
	if err != nil {
		t.Fatalf("create bomb header: %v", err)
	}
	if _, err := fw.Write(make([]byte, size)); err != nil {
		t.Fatalf("write bomb body: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close bomb writer: %v", err)
	}
	return buf.Bytes()
}
