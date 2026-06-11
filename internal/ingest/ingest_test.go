// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"
)

// elfBytes is a realistic ELF header prefix: magic plus the NUL-bearing
// ident padding that forces http.DetectContentType to octet-stream, so the
// supplemental table is what resolves it.
func elfBytes() []byte {
	return []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

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
	// Lexical layer: every traversal shape rejects, safe names clean.
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"dotdot traversal", "../../../etc/passwd"},
		{"interior dotdot escape", "a/../../b"},
		{"bare dotdot", ".."},
		{"nul byte", "evil\x00.txt"},
		{"url scheme", "s3://bucket/key"},
		{"empty", ""},
		{"dot", "."},
		{"cleans to dot", "a/.."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateEntryName(tc.raw); !errors.Is(err, ErrInvalidEntry) {
				t.Fatalf("validateEntryName(%q): got %v, want ErrInvalidEntry", tc.raw, err)
			}
		})
	}
	for _, ok := range []string{"ok.txt", "dir/file.bin", "a/b/c"} {
		clean, err := validateEntryName(ok)
		if err != nil || clean != ok {
			t.Fatalf("validateEntryName(%q): got (%q, %v), want (%q, nil)", ok, clean, err, ok)
		}
	}

	t.Fatal("unimplemented: traversal entry rejected before sink via ValidateZip (ARC-02)")
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
// executable formats DetectContentType reports as octet-stream, the
// stdlib's positive identifications are never overridden, and the
// mismatch flag follows the declared type.
func TestSupplementalMagic(t *testing.T) {
	// All eight supplemental rows, straight through the table.
	for _, tc := range []struct {
		name  string
		magic []byte
		want  string
	}{
		{"elf", []byte{0x7f, 'E', 'L', 'F'}, "application/x-elf"},
		{"pe-mz", []byte{'M', 'Z'}, "application/x-msdownload"},
		{"mach-o 64 le", []byte{0xcf, 0xfa, 0xed, 0xfe}, "application/x-mach-binary"},
		{"mach-o 32 le", []byte{0xce, 0xfa, 0xed, 0xfe}, "application/x-mach-binary"},
		{"mach-o 64 be", []byte{0xfe, 0xed, 0xfa, 0xcf}, "application/x-mach-binary"},
		{"mach-o 32 be", []byte{0xfe, 0xed, 0xfa, 0xce}, "application/x-mach-binary"},
		{"mach-o universal", []byte{0xca, 0xfe, 0xba, 0xbe}, "application/x-mach-binary"},
		{"shebang", []byte{'#', '!'}, "text/x-script"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := supplementalSniff(tc.magic)
			if !ok || got != tc.want {
				t.Fatalf("supplementalSniff(% x): got (%q, %v), want (%q, true)", tc.magic, got, ok, tc.want)
			}
		})
	}

	// No supplemental match: ok=false, and detect keeps octet-stream.
	junk := []byte{0x01, 0x02, 0x03, 0x00}
	if got, ok := supplementalSniff(junk); ok {
		t.Fatalf("supplementalSniff(junk): got (%q, true), want no match", got)
	}
	if res := detect(junk, ""); res.Resolved != "application/octet-stream" {
		t.Fatalf("detect(junk): resolved %q, want application/octet-stream", res.Resolved)
	}

	// detect() routes octet-stream through the supplemental table; a
	// realistic header (magic + NUL padding) is what reaches it.
	machO := append([]byte{0xcf, 0xfa, 0xed, 0xfe}, make([]byte, 12)...)
	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{"elf via detect", elfBytes(), "application/x-elf"},
		{"pe via detect", append([]byte{'M', 'Z'}, make([]byte, 14)...), "application/x-msdownload"},
		{"mach-o via detect", machO, "application/x-mach-binary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := detect(tc.body, "")
			if res.Resolved != tc.want {
				t.Fatalf("detect: resolved %q, want %q", res.Resolved, tc.want)
			}
			if res.Mismatch {
				t.Fatal("detect: mismatch true with empty declared type")
			}
		})
	}

	// The stdlib's positive identification wins: a PNG never consults the
	// supplemental table, and a declared type that disagrees flags.
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0}
	res := detect(png, "text/plain")
	if res.Resolved != "image/png" || !res.Mismatch {
		t.Fatalf("detect(png, text/plain): got %+v, want resolved image/png with mismatch", res)
	}
	// Matching declared type: no mismatch.
	if res := detect(png, "image/png"); res.Mismatch {
		t.Fatalf("detect(png, image/png): mismatch true, want false")
	}
}

// TestBackslashEntry pins ARC-02: backslash separators normalize before
// every other check, so a plain Windows-zipped name cleans to its nested
// form and a smuggled "..\" traversal still rejects.
func TestBackslashEntry(t *testing.T) {
	clean, err := validateEntryName(`foo\bar`)
	if err != nil || clean != "foo/bar" {
		t.Fatalf(`validateEntryName(foo\bar): got (%q, %v), want ("foo/bar", nil)`, clean, err)
	}
	clean, err = validateEntryName(`dir\sub\f.txt`)
	if err != nil || clean != "dir/sub/f.txt" {
		t.Fatalf(`validateEntryName(dir\sub\f.txt): got (%q, %v), want ("dir/sub/f.txt", nil)`, clean, err)
	}
	for _, raw := range []string{`..\..\evil`, `a\..\..\b`, `\\server\share\f`} {
		if _, err := validateEntryName(raw); !errors.Is(err, ErrInvalidEntry) {
			t.Fatalf("validateEntryName(%q): got %v, want ErrInvalidEntry", raw, err)
		}
	}
}

// TestDriveLetterEntry pins ARC-02: drive-letter names reject explicitly —
// filepath.IsLocal is OS-dependent and passes them on linux/darwin.
func TestDriveLetterEntry(t *testing.T) {
	for _, raw := range []string{"C:/evil", `c:\evil`, "Z:stuff", `C:\Windows\System32`} {
		if _, err := validateEntryName(raw); !errors.Is(err, ErrInvalidEntry) {
			t.Fatalf("validateEntryName(%q): got %v, want ErrInvalidEntry", raw, err)
		}
	}
}

// TestAbsolutePathEntry pins ARC-02: absolute entry names reject.
func TestAbsolutePathEntry(t *testing.T) {
	for _, raw := range []string{"/etc/passwd", "/", "//host/share"} {
		if _, err := validateEntryName(raw); !errors.Is(err, ErrInvalidEntry) {
			t.Fatalf("validateEntryName(%q): got %v, want ErrInvalidEntry", raw, err)
		}
	}
}
