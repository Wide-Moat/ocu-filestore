// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"context"
	"io"
	"io/fs"
	"testing"
)

// recordingSink is the shared in-memory ExtractSink for the unit corpus
// and the properties: it records staged names, directory names, symlink
// calls, and the commit/abort outcome, and consumes every staged reader
// fully so the streaming count is exercised end to end.
type recordingSink struct {
	staged    []string
	dirs      []string
	symlinks  []string
	contents  map[string][]byte
	committed bool
	aborted   bool
}

func (s *recordingSink) StageEntry(_ context.Context, name string, r io.Reader, _ fs.FileMode) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if s.contents == nil {
		s.contents = make(map[string][]byte)
	}
	s.staged = append(s.staged, name)
	s.contents[name] = b
	return nil
}

func (s *recordingSink) MakeDir(_ context.Context, name string) error {
	s.dirs = append(s.dirs, name)
	return nil
}

func (s *recordingSink) MakeSymlink(_ context.Context, name, _ string) error {
	s.symlinks = append(s.symlinks, name)
	return nil
}

func (s *recordingSink) Commit(_ context.Context) error {
	s.committed = true
	return nil
}

func (s *recordingSink) Abort(_ context.Context) {
	s.aborted = true
}

// --- Wave-0 RED scaffolds: one function per ARC corpus row. Bodies are
// filled by the later tasks; until then each fails loud (never skipped).

// TestTraversalEntry pins ARC-02: a traversal entry name is rejected with
// ErrInvalidEntry before the sink sees it; nothing staged, sink aborted.
func TestTraversalEntry(t *testing.T) {
	t.Fatal("unimplemented: traversal entry rejected before sink (ARC-02)")
}

// TestSymlinkEscape pins ARC-02: a symlink entry whose target resolves
// outside the destination rejects with ErrSymlinkEscape — a typed reason
// distinct from the traversal reject.
func TestSymlinkEscape(t *testing.T) {
	t.Fatal("unimplemented: symlink escape rejected with distinct sentinel (ARC-02)")
}

// TestSymlinkInsideUnsupported pins the shelf boundary: an inside-resolving
// symlink target rejects with ErrSymlinkUnsupported; no symlink entry is
// ever staged on this shelf.
func TestSymlinkInsideUnsupported(t *testing.T) {
	t.Fatal("unimplemented: inside-resolving symlink rejected, nothing staged (ARC-02)")
}

// TestEntryCountCeiling pins ARC-01: more entries than the ceiling rejects
// immediately after the central directory parse, before any entry byte.
func TestEntryCountCeiling(t *testing.T) {
	t.Fatal("unimplemented: entry-count ceiling rejects pre-read (ARC-01)")
}

// TestTotalCeilingStreaming pins ARC-01: the cross-entry decompressed
// total halts extraction mid-stream at the ceiling.
func TestTotalCeilingStreaming(t *testing.T) {
	t.Fatal("unimplemented: streaming total ceiling halts mid-extract (ARC-01)")
}

// TestHeaderLies pins ARC-01: the streaming count, never the header-claimed
// size, governs the ceiling.
func TestHeaderLies(t *testing.T) {
	t.Fatal("unimplemented: header-claimed size never governs (ARC-01)")
}

// TestPolyglotMismatch pins ARC-03: declared-vs-resolved disagreement is
// recorded; under the empty policy nothing is rejected.
func TestPolyglotMismatch(t *testing.T) {
	t.Fatal("unimplemented: polyglot mismatch recorded (ARC-03)")
}

// TestDeniedTypeReject pins ARC-03: a policy-denied resolved type rejects
// pre-stage with ErrTypeDenied and the sink aborts.
func TestDeniedTypeReject(t *testing.T) {
	t.Fatal("unimplemented: denied type rejects pre-stage (ARC-03)")
}

// TestEmptyPolicyRecord pins ARC-03: the zero policy denies nothing —
// classification is recorded, the entry stages, the archive commits.
func TestEmptyPolicyRecord(t *testing.T) {
	t.Fatal("unimplemented: empty policy classifies and records only (ARC-03)")
}

// TestSupplementalMagic pins ARC-03: the supplemental table resolves the
// executable formats DetectContentType reports as octet-stream.
func TestSupplementalMagic(t *testing.T) {
	t.Fatal("unimplemented: supplemental magic table (ARC-03)")
}

// TestBackslashEntry pins ARC-02: backslash separators normalize before
// every other check, so a smuggled "..\" traversal still rejects.
func TestBackslashEntry(t *testing.T) {
	t.Fatal("unimplemented: backslash normalization (ARC-02)")
}

// TestDriveLetterEntry pins ARC-02: drive-letter names reject explicitly —
// filepath.IsLocal is OS-dependent and passes them on linux/darwin.
func TestDriveLetterEntry(t *testing.T) {
	t.Fatal("unimplemented: drive-letter entry rejected (ARC-02)")
}

// TestAbsolutePathEntry pins ARC-02: absolute entry names reject.
func TestAbsolutePathEntry(t *testing.T) {
	t.Fatal("unimplemented: absolute entry name rejected (ARC-02)")
}
