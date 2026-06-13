// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
)

// failer is the assertion surface shared by *testing.T and *rapid.T, so
// the in-memory archive builders work from both the unit corpus and the
// properties.
type failer interface {
	Fatalf(format string, args ...any)
}

// zipEntry describes one in-memory archive entry. The zero mode leaves the
// writer's default (regular file); a body on a "/"-suffixed name is a
// builder error.
type zipEntry struct {
	name    string
	body    []byte
	comment string
	mode    fs.FileMode
	deflate bool
}

// buildZip assembles an archive fully in memory — no testdata binaries are
// ever committed; every adversarial shape is constructed per run.
func buildZip(t failer, entries ...zipEntry) []byte {
	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	for _, e := range entries {
		fh := &zip.FileHeader{Name: e.name, Comment: e.comment}
		if e.deflate {
			fh.Method = zip.Deflate
		}
		if e.mode != 0 {
			fh.SetMode(e.mode)
		}
		fw, err := w.CreateHeader(fh)
		if err != nil {
			t.Fatalf("create header %q: %v", e.name, err)
		}
		if len(e.body) > 0 {
			if _, err := fw.Write(e.body); err != nil {
				t.Fatalf("write entry %q: %v", e.name, err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

// testConfig returns the canonical-default config with the lexical
// destination anchor the symlink checks need; the path is never opened.
func testConfig() Config {
	return Config{
		TotalUncompressedCeiling: DefaultTotalUncompressedCeiling,
		EntryCeiling:             DefaultEntryCeiling,
		DestDir:                  "/var/broker/scope",
	}
}

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

	// Full path: the traversal entry never reaches the sink.
	data := buildZip(t, zipEntry{name: "../../../etc/passwd", body: []byte("pwned")})
	sink := &recordingSink{}
	err := ValidateZip(context.Background(), data, testConfig(), sink)
	if !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("ValidateZip: got %v, want ErrInvalidEntry", err)
	}
	if len(sink.staged) != 0 || len(sink.dirs) != 0 || len(sink.symlinks) != 0 {
		t.Fatalf("sink saw entries from a rejected archive: staged=%v dirs=%v symlinks=%v",
			sink.staged, sink.dirs, sink.symlinks)
	}
	if !sink.aborted || sink.committed {
		t.Fatalf("sink state: aborted=%v committed=%v, want aborted only", sink.aborted, sink.committed)
	}
}

// TestSymlinkEscape pins ARC-02: a symlink entry whose target resolves
// outside the destination rejects with ErrSymlinkEscape — a typed reason
// distinct from the traversal reject.
func TestSymlinkEscape(t *testing.T) {
	// Lexical layer: absolute targets reject first and unconditionally;
	// NUL rejects; an inside-resolving relative target passes this check.
	dest := "/var/broker/scope"
	for _, tc := range []struct{ name, entry, target string }{
		{"absolute target", "link", "/etc/passwd"},
		{"relative escape", "link", "../outside"},
		{"nul target", "link", "bad\x00target"},
		{"deep relative escape", "dir/link", "../../../outside"},
	} {
		t.Run("lexical "+tc.name, func(t *testing.T) {
			if err := validateSymlinkTarget(tc.entry, tc.target, dest); !errors.Is(err, ErrSymlinkEscape) {
				t.Fatalf("validateSymlinkTarget(%q, %q): got %v, want ErrSymlinkEscape", tc.entry, tc.target, err)
			}
		})
	}
	if err := validateSymlinkTarget("dir/link", "../sibling.txt", dest); err != nil {
		t.Fatalf("inside-resolving target: got %v, want nil from the lexical check", err)
	}

	// Full path: the escaping symlink entry rejects, the sink stays empty.
	for _, tc := range []struct{ name, target string }{
		{"relative escape", "../outside"},
		{"absolute target", "/etc/passwd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := buildZip(t, zipEntry{name: "link", body: []byte(tc.target), mode: fs.ModeSymlink | 0o777})
			sink := &recordingSink{}
			err := ValidateZip(context.Background(), data, testConfig(), sink)
			if !errors.Is(err, ErrSymlinkEscape) {
				t.Fatalf("ValidateZip: got %v, want ErrSymlinkEscape", err)
			}
			if errors.Is(err, ErrInvalidEntry) {
				t.Fatal("symlink reject must stay distinct from the traversal sentinel")
			}
			if len(sink.staged) != 0 || len(sink.symlinks) != 0 {
				t.Fatalf("sink saw the symlink entry: staged=%v symlinks=%v", sink.staged, sink.symlinks)
			}
			if !sink.aborted || sink.committed {
				t.Fatalf("sink state: aborted=%v committed=%v, want aborted only", sink.aborted, sink.committed)
			}
		})
	}
}

// TestSymlinkInsideUnsupported pins the shelf boundary: an inside-resolving
// symlink target rejects with ErrSymlinkUnsupported; no symlink entry is
// ever staged on this shelf — staging the target text as file content
// would silently change semantics.
func TestSymlinkInsideUnsupported(t *testing.T) {
	data := buildZip(t, zipEntry{name: "link", body: []byte("inside.txt"), mode: fs.ModeSymlink | 0o777})
	sink := &recordingSink{}
	err := ValidateZip(context.Background(), data, testConfig(), sink)
	if !errors.Is(err, ErrSymlinkUnsupported) {
		t.Fatalf("ValidateZip: got %v, want ErrSymlinkUnsupported", err)
	}
	if errors.Is(err, ErrSymlinkEscape) {
		t.Fatal("inside-resolving target must not report an escape")
	}
	if len(sink.staged) != 0 || len(sink.symlinks) != 0 || len(sink.dirs) != 0 {
		t.Fatalf("sink saw the symlink entry: staged=%v symlinks=%v dirs=%v", sink.staged, sink.symlinks, sink.dirs)
	}
	if !sink.aborted || sink.committed {
		t.Fatalf("sink state: aborted=%v committed=%v, want aborted only", sink.aborted, sink.committed)
	}
}

// TestEntryCountCeiling pins ARC-01: more entries than the ceiling rejects
// immediately after the central directory parse, before any entry byte.
func TestEntryCountCeiling(t *testing.T) {
	entries := make([]zipEntry, 6)
	for i := range entries {
		entries[i] = zipEntry{name: fmt.Sprintf("f%d.txt", i), body: []byte("x")}
	}
	cfg := testConfig()
	cfg.EntryCeiling = 5
	sink := &recordingSink{}
	err := ValidateZip(context.Background(), buildZip(t, entries...), cfg, sink)
	if !errors.Is(err, ErrEntryCountExceeded) {
		t.Fatalf("ValidateZip: got %v, want ErrEntryCountExceeded", err)
	}
	var ae *ArchiveError
	if !errors.As(err, &ae) {
		t.Fatalf("ValidateZip: %v is not an *ArchiveError", err)
	}
	if ae.Count != 6 || ae.Ceiling != 5 {
		t.Fatalf("ArchiveError arithmetic: count=%d ceiling=%d, want 6 > 5", ae.Count, ae.Ceiling)
	}
	if len(sink.staged) != 0 || len(sink.dirs) != 0 {
		t.Fatal("entry bytes reached the sink before the count check")
	}
	if !sink.aborted || sink.committed {
		t.Fatalf("sink state: aborted=%v committed=%v, want aborted only", sink.aborted, sink.committed)
	}
}

// TestTotalCeilingStreaming pins ARC-01: the cross-entry decompressed
// total halts extraction mid-stream at the ceiling; the count is shared
// across entries, not per entry.
func TestTotalCeilingStreaming(t *testing.T) {
	t.Run("single oversize entry", func(t *testing.T) {
		cfg := testConfig()
		cfg.TotalUncompressedCeiling = 512 << 10
		data := buildZip(t, zipEntry{name: "bomb.bin", body: make([]byte, 2<<20), deflate: true})
		sink := &recordingSink{}
		err := ValidateZip(context.Background(), data, cfg, sink)
		if !errors.Is(err, ErrTotalExceeded) {
			t.Fatalf("ValidateZip: got %v, want ErrTotalExceeded", err)
		}
		if len(sink.staged) != 0 {
			t.Fatal("over-ceiling entry recorded as staged")
		}
		if !sink.aborted || sink.committed {
			t.Fatalf("sink state: aborted=%v committed=%v, want aborted only", sink.aborted, sink.committed)
		}
	})
	t.Run("cross-entry running total", func(t *testing.T) {
		// Each entry is under the ceiling alone; together they cross it.
		cfg := testConfig()
		cfg.TotalUncompressedCeiling = 512 << 10
		data := buildZip(t,
			zipEntry{name: "a.bin", body: make([]byte, 384<<10), deflate: true},
			zipEntry{name: "b.bin", body: make([]byte, 384<<10), deflate: true},
		)
		sink := &recordingSink{}
		err := ValidateZip(context.Background(), data, cfg, sink)
		if !errors.Is(err, ErrTotalExceeded) {
			t.Fatalf("ValidateZip: got %v, want ErrTotalExceeded from the shared total", err)
		}
		if !sink.aborted || sink.committed {
			t.Fatalf("sink state: aborted=%v committed=%v, want aborted only", sink.aborted, sink.committed)
		}
	})
}

// TestHeaderLies pins ARC-01: the streaming count, never the header-claimed
// size, governs the ceiling. The corpus patches the central-directory
// UncompressedSize and clears the data-descriptor flag, in both lying
// directions.
func TestHeaderLies(t *testing.T) {
	centralDirSig := []byte{0x50, 0x4b, 0x01, 0x02}
	patch := func(t *testing.T, data []byte, claim uint32) {
		cidx := bytes.Index(data, centralDirSig)
		if cidx < 0 {
			t.Fatal("central directory signature not found")
		}
		binary.LittleEndian.PutUint32(data[cidx+24:], claim)
		flags := binary.LittleEndian.Uint16(data[cidx+8:])
		binary.LittleEndian.PutUint16(data[cidx+8:], flags&^uint16(0x8))
	}

	t.Run("huge claim small body never trips the ceiling", func(t *testing.T) {
		data := buildZip(t, zipEntry{name: "liar.txt", body: []byte("actual tiny content"), deflate: true})
		patch(t, data, 2<<30) // claim 2 GiB; actual bytes: 19
		cfg := testConfig()
		cfg.TotalUncompressedCeiling = 1 << 20 // far below the claim
		sink := &recordingSink{}
		err := ValidateZip(context.Background(), data, cfg, sink)
		if errors.Is(err, ErrTotalExceeded) {
			t.Fatalf("the header claim governed the ceiling: %v", err)
		}
		if err == nil {
			t.Fatal("patched archive read cleanly; want the reader's size-mismatch error")
		}
		if !sink.aborted || sink.committed {
			t.Fatalf("sink state: aborted=%v committed=%v, want aborted only", sink.aborted, sink.committed)
		}
	})

	t.Run("tiny claim real bomb still rejected", func(t *testing.T) {
		// A small claim cannot raise the budget either: the stdlib
		// reader bounds reads by the claimed size and rejects the
		// overrun as a format error before the streaming count would
		// cross the ceiling. Whichever control fires first, the bomb
		// never reaches a commit — the claim only ever shrinks what
		// streams, it never bypasses the ceiling.
		data := buildZip(t, zipEntry{name: "bomb.bin", body: make([]byte, 2<<20), deflate: true})
		patch(t, data, 10) // claim 10 bytes; actual: 2 MiB
		cfg := testConfig()
		cfg.TotalUncompressedCeiling = 512 << 10
		sink := &recordingSink{}
		err := ValidateZip(context.Background(), data, cfg, sink)
		if err == nil {
			t.Fatal("lying bomb accepted")
		}
		if len(sink.staged) != 0 {
			t.Fatalf("lying bomb staged: %v", sink.staged)
		}
		if !sink.aborted || sink.committed {
			t.Fatalf("sink state: aborted=%v committed=%v, want aborted only", sink.aborted, sink.committed)
		}
	})
}

// TestPolyglotMismatch pins ARC-03: declared-vs-resolved disagreement is
// recorded; under the empty policy nothing is rejected.
func TestPolyglotMismatch(t *testing.T) {
	// GIF magic over zip-shaped bytes: the sniff window resolves the
	// first-bytes identity; the declared type disagrees.
	body := append([]byte("GIF89a"), 0x50, 0x4b, 0x03, 0x04)
	body = append(body, make([]byte, 64)...)

	var recorded []ClassificationResult
	cfg := testConfig()
	cfg.Record = func(_ string, res ClassificationResult) { recorded = append(recorded, res) }

	data := buildZip(t, zipEntry{name: "image.gif", body: body, comment: "application/zip"})
	sink := &recordingSink{}
	if err := ValidateZip(context.Background(), data, cfg, sink); err != nil {
		t.Fatalf("empty policy must record, never reject: %v", err)
	}
	if !sink.committed || sink.aborted {
		t.Fatalf("sink state: aborted=%v committed=%v, want committed only", sink.aborted, sink.committed)
	}
	if len(recorded) != 1 {
		t.Fatalf("recorded %d classifications, want 1", len(recorded))
	}
	got := recorded[0]
	if got.Declared != "application/zip" || got.Resolved != "image/gif" || !got.Mismatch {
		t.Fatalf("classification: %+v, want declared application/zip, resolved image/gif, mismatch", got)
	}
}

// TestDeniedTypeReject pins ARC-03: a policy-denied resolved type rejects
// pre-stage with ErrTypeDenied and the sink aborts; classification is
// still recorded for the denied entry.
func TestDeniedTypeReject(t *testing.T) {
	var recorded []ClassificationResult
	cfg := testConfig()
	cfg.TypePolicy = DenyTypes("application/x-elf")
	cfg.Record = func(_ string, res ClassificationResult) { recorded = append(recorded, res) }

	data := buildZip(t, zipEntry{name: "innocent.txt", body: elfBytes()})
	sink := &recordingSink{}
	err := ValidateZip(context.Background(), data, cfg, sink)
	if !errors.Is(err, ErrTypeDenied) {
		t.Fatalf("ValidateZip: got %v, want ErrTypeDenied", err)
	}
	var ae *ArchiveError
	if !errors.As(err, &ae) || ae.Type != "application/x-elf" {
		t.Fatalf("ArchiveError type field: %+v, want application/x-elf", ae)
	}
	if len(sink.staged) != 0 {
		t.Fatal("denied entry bytes reached the sink")
	}
	if !sink.aborted || sink.committed {
		t.Fatalf("sink state: aborted=%v committed=%v, want aborted only", sink.aborted, sink.committed)
	}
	if len(recorded) != 1 || recorded[0].Resolved != "application/x-elf" {
		t.Fatalf("denied entry classification not recorded: %+v", recorded)
	}
}

// TestEmptyPolicyRecord pins ARC-03: the zero policy denies nothing —
// classification is recorded, the entry stages byte-complete (the
// classification window is replayed to the sink), the archive commits.
func TestEmptyPolicyRecord(t *testing.T) {
	var recorded []ClassificationResult
	cfg := testConfig()
	cfg.Record = func(_ string, res ClassificationResult) { recorded = append(recorded, res) }

	// Body longer than the 512-byte sniff window, so a lost window would
	// surface as truncated staged content.
	body := append(elfBytes(), make([]byte, 600)...)
	data := buildZip(t,
		zipEntry{name: "sub/"},
		zipEntry{name: "bin/tool", body: body, deflate: true},
	)
	sink := &recordingSink{}
	if err := ValidateZip(context.Background(), data, cfg, sink); err != nil {
		t.Fatalf("empty policy must classify and record only: %v", err)
	}
	if !sink.committed || sink.aborted {
		t.Fatalf("sink state: aborted=%v committed=%v, want committed only", sink.aborted, sink.committed)
	}
	if len(sink.dirs) != 1 || sink.dirs[0] != "sub" {
		t.Fatalf("dirs: %v, want [sub]", sink.dirs)
	}
	if len(sink.staged) != 1 || sink.staged[0] != "bin/tool" {
		t.Fatalf("staged: %v, want [bin/tool]", sink.staged)
	}
	if !bytes.Equal(sink.contents["bin/tool"], body) {
		t.Fatalf("staged content truncated: got %d bytes, want %d", len(sink.contents["bin/tool"]), len(body))
	}
	if len(recorded) != 1 || recorded[0].Resolved != "application/x-elf" || recorded[0].Mismatch {
		t.Fatalf("classification: %+v, want resolved application/x-elf, no mismatch", recorded)
	}
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

// TestArchiveError_Error pins the structured rendering of ArchiveError.Error:
// each combination of filled fields appends its clause in the documented order
// (entry → type → count/ceiling), and errors.Is still matches the sentinel
// Code through the error chain. Every branch of Error() is exercised so the
// method is no longer 0% covered.
func TestArchiveError_Error(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  *ArchiveError
		// substrings that MUST appear in the rendered message
		wantContains []string
		// sentinel the error must match via errors.Is
		wantCode error
	}{
		{
			name:         "code only",
			err:          &ArchiveError{Code: ErrInvalidEntry},
			wantContains: []string{ErrInvalidEntry.Error()},
			wantCode:     ErrInvalidEntry,
		},
		{
			name:         "code + entry name",
			err:          &ArchiveError{Code: ErrInvalidEntry, EntryName: "../../evil.txt"},
			wantContains: []string{ErrInvalidEntry.Error(), "../../evil.txt"},
			wantCode:     ErrInvalidEntry,
		},
		{
			name:         "code + type",
			err:          &ArchiveError{Code: ErrTypeDenied, Type: "application/x-executable"},
			wantContains: []string{ErrTypeDenied.Error(), "application/x-executable"},
			wantCode:     ErrTypeDenied,
		},
		{
			name:         "code + entry + type",
			err:          &ArchiveError{Code: ErrTypeDenied, EntryName: "run.exe", Type: "application/x-elf"},
			wantContains: []string{ErrTypeDenied.Error(), "run.exe", "application/x-elf"},
			wantCode:     ErrTypeDenied,
		},
		{
			name:         "code + count + ceiling",
			err:          &ArchiveError{Code: ErrEntryCountExceeded, Count: 50001, Ceiling: 50000},
			wantContains: []string{ErrEntryCountExceeded.Error(), "50001", "50000"},
			wantCode:     ErrEntryCountExceeded,
		},
		{
			name:         "code + entry + count + ceiling",
			err:          &ArchiveError{Code: ErrTotalExceeded, EntryName: "big.bin", Count: 0, Ceiling: 1},
			wantContains: []string{ErrTotalExceeded.Error(), "big.bin", "0", "1"},
			wantCode:     ErrTotalExceeded,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			for _, want := range tc.wantContains {
				if !strings.Contains(msg, want) {
					t.Fatalf("ArchiveError.Error() = %q, must contain %q", msg, want)
				}
			}
			if !errors.Is(tc.err, tc.wantCode) {
				t.Fatalf("errors.Is(%v, %v) = false, Unwrap must return the Code sentinel", tc.err, tc.wantCode)
			}
		})
	}
}

// TestInvalidArchiveBytes pins the parse-failure leg of ValidateZip: bytes that
// are not a zip archive (a too-short buffer, random noise) are rejected with
// ErrInvalidArchive before any entry is read, and the sink is aborted — nothing
// staged becomes visible (the defer safety net fires on the early return).
func TestInvalidArchiveBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes []byte
	}{
		{"empty", nil},
		{"too short", []byte{0x50, 0x4b}},
		{"random noise", []byte("this is plainly not a zip archive at all")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &recordingSink{}
			err := ValidateZip(context.Background(), tc.bytes, testConfig(), sink)
			if !errors.Is(err, ErrInvalidArchive) {
				t.Fatalf("ValidateZip(%s): got %v, want ErrInvalidArchive", tc.name, err)
			}
			if len(sink.staged) != 0 || sink.committed {
				t.Fatalf("sink leaked state on a parse failure: staged=%v committed=%v", sink.staged, sink.committed)
			}
			if !sink.aborted {
				t.Fatalf("sink not aborted on a parse failure")
			}
		})
	}
}

// failingSink wraps recordingSink and fails a chosen seam, so the sink-error
// wrap legs of processEntry (StageEntry, MakeDir) and the commit-error leg of
// ValidateZip are exercised. It is a fault-injection fake, not a mock of a real
// service — the engine's real sink lands at wiring time.
type failingSink struct {
	recordingSink
	stageErr  error
	dirErr    error
	commitErr error
}

func (s *failingSink) StageEntry(ctx context.Context, name string, r io.Reader, mode fs.FileMode) error {
	if s.stageErr != nil {
		// Drain the reader so the tee/counting path still runs before the fault.
		_, _ = io.Copy(io.Discard, r)
		return s.stageErr
	}
	return s.recordingSink.StageEntry(ctx, name, r, mode)
}

func (s *failingSink) MakeDir(ctx context.Context, name string) error {
	if s.dirErr != nil {
		return s.dirErr
	}
	return s.recordingSink.MakeDir(ctx, name)
}

func (s *failingSink) Commit(ctx context.Context) error {
	if s.commitErr != nil {
		return s.commitErr
	}
	return s.recordingSink.Commit(ctx)
}

// TestSinkFailuresAbort pins the sink-error legs: a StageEntry, MakeDir, or
// Commit failure propagates a wrapped error (errors.Is still finds the sink's
// own sentinel through the wrap) and leaves the sink aborted, never committed.
// A Commit failure is the boundary case — every entry passed every check, yet a
// commit fault must still abort and surface, never silently half-commit.
func TestSinkFailuresAbort(t *testing.T) {
	boom := errors.New("sink seam failure")

	t.Run("stage entry failure", func(t *testing.T) {
		data := buildZip(t, zipEntry{name: "f.txt", body: []byte("content bytes")})
		sink := &failingSink{stageErr: boom}
		err := ValidateZip(context.Background(), data, testConfig(), sink)
		if !errors.Is(err, boom) {
			t.Fatalf("ValidateZip: got %v, want the StageEntry fault wrapped", err)
		}
		if sink.committed || !sink.aborted {
			t.Fatalf("sink state: committed=%v aborted=%v, want aborted only", sink.committed, sink.aborted)
		}
	})

	t.Run("make dir failure", func(t *testing.T) {
		data := buildZip(t, zipEntry{name: "adir/", mode: fs.ModeDir | 0o755})
		sink := &failingSink{dirErr: boom}
		err := ValidateZip(context.Background(), data, testConfig(), sink)
		if !errors.Is(err, boom) {
			t.Fatalf("ValidateZip: got %v, want the MakeDir fault wrapped", err)
		}
		if sink.committed || !sink.aborted {
			t.Fatalf("sink state: committed=%v aborted=%v, want aborted only", sink.committed, sink.aborted)
		}
	})

	t.Run("commit failure", func(t *testing.T) {
		// Every entry passes every check, so the success path reaches Commit;
		// the commit fault must still abort and surface wrapped.
		data := buildZip(t, zipEntry{name: "ok.txt", body: []byte("all entries pass")})
		sink := &failingSink{commitErr: boom}
		err := ValidateZip(context.Background(), data, testConfig(), sink)
		if !errors.Is(err, boom) {
			t.Fatalf("ValidateZip: got %v, want the Commit fault wrapped", err)
		}
		if sink.committed {
			t.Fatalf("sink marked committed despite a commit fault")
		}
		if !sink.aborted {
			t.Fatalf("sink not aborted on a commit fault")
		}
	})
}
