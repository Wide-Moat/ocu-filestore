// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
)

// ValidateZip validates, classifies, and stages the zip archive held in
// staged, writing accepted entries into sink. The staged bytes are already
// body-ceiling-bounded upstream; ValidateZip does not re-check body size.
// Nested archives are opaque bytes — exactly one level is ever processed,
// so nesting is not an amplification vector. The day-one declared-type
// source is the entry comment field; the wire carries no per-entry
// content type yet.
//
// On any rejection it returns a typed error (match with errors.Is) and
// the sink is aborted; sink.Commit fires only when every entry passed
// every check (ARC-01, ARC-02, ARC-03).
func ValidateZip(ctx context.Context, staged []byte, cfg Config, sink ExtractSink) error {
	// Failure-path safety net: every return before the success path flips
	// committed leaves the sink aborted, so nothing staged becomes
	// visible after any rejection.
	committed := false
	defer func() {
		if !committed {
			sink.Abort(ctx)
		}
	}()

	r, err := zip.NewReader(bytes.NewReader(staged), int64(len(staged)))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}

	// Entry-count ceiling: a single check on the parsed central
	// directory, before any entry byte is read (ARC-01, NFR-SEC-80).
	if len(r.File) > cfg.EntryCeiling {
		return &ArchiveError{Code: ErrEntryCountExceeded, Count: len(r.File), Ceiling: cfg.EntryCeiling}
	}

	// The running decompressed total is shared across ALL entries: the
	// ceiling bounds the archive, not each entry (ARC-01). seen tracks the
	// cleaned name of every entry already accepted this archive, so a second
	// entry that cleans to the same in-namespace path is rejected fail-closed
	// before it reaches the sink rather than silently overwriting the first
	// with undefined ordering (a file/file, file/dir, or
	// separator-normalization collision); deny-by-default, consistent with the
	// engine's destination-collision posture.
	var total int64
	seen := make(map[string]bool, len(r.File))
	for _, f := range r.File {
		if err := processEntry(ctx, f, cfg, &total, seen, sink); err != nil {
			return err
		}
	}

	if err := sink.Commit(ctx); err != nil {
		return fmt.Errorf("ingest: sink commit: %w", err)
	}
	committed = true
	return nil
}

// processEntry owns one entry's full check order: lexical name -> dir ->
// symlink -> classify -> policy -> stage. It is a helper so each entry's
// reader Close is deferred per entry — a defer inside the caller's range
// loop would accumulate open readers across the whole archive.
func processEntry(ctx context.Context, f *zip.File, cfg Config, total *int64, seen map[string]bool, sink ExtractSink) error {
	cleanName, err := validateEntryName(f.Name)
	if err != nil {
		return &ArchiveError{Code: ErrInvalidEntry, EntryName: f.Name}
	}

	// Collision check before any sink call: a second entry cleaning to a name
	// already accepted this archive is rejected fail-closed, so it can never
	// overwrite the first (or stage a file where a directory was made, or
	// vice versa) with undefined ordering. Recorded only after the name is
	// known safe, so an invalid name never poisons the seen set.
	if seen[cleanName] {
		return &ArchiveError{Code: ErrDuplicateEntry, EntryName: f.Name}
	}
	seen[cleanName] = true

	fi := f.FileInfo()

	if fi.IsDir() {
		if err := sink.MakeDir(ctx, cleanName); err != nil {
			return fmt.Errorf("ingest: make dir %q: %w", cleanName, err)
		}
		return nil
	}

	if fi.Mode()&fs.ModeSymlink != 0 {
		rc, err := f.Open()
		if err != nil {
			// The staged bytes are an in-memory buffer, so a per-entry open
			// failure is never an I/O fault — it is the archive's local
			// header or compression metadata being malformed. Surface it as
			// the typed parse-failure sentinel so callers classify every
			// corrupt-archive condition uniformly (errors.Is ErrInvalidArchive)
			// rather than receiving an untyped wrap.
			return fmt.Errorf("%w: open symlink entry %q: %v", ErrInvalidArchive, cleanName, err)
		}
		target, rerr := io.ReadAll(io.LimitReader(rc, 4096))
		rc.Close()
		if rerr != nil {
			return fmt.Errorf("%w: read symlink target %q: %v", ErrInvalidArchive, cleanName, rerr)
		}
		if err := validateSymlinkTarget(cleanName, string(target), cfg.DestDir); err != nil {
			return &ArchiveError{Code: ErrSymlinkEscape, EntryName: f.Name}
		}
		// No symlink entry is ever staged on this shelf. The target's
		// containment was just validated so the reject reason is
		// truthful, but staging the target string through StageEntry
		// would silently change semantics — a reader would receive the
		// link target text as file content. Inside-resolving targets
		// reject fail-closed until the sink's MakeSymlink is implemented
		// at wiring time; the sink sees nothing in either branch.
		return &ArchiveError{Code: ErrSymlinkUnsupported, EntryName: f.Name}
	}

	// Defence in depth against a symlink (or other special file) smuggled in
	// a non-Unix creator archive: the decoded FileInfo mode only carries the
	// symlink bit when the creator host is Unix, so the branch above can miss
	// a crafted entry whose Unix mode bits are present in the central
	// directory but not surfaced by the standard-library decode. Read the raw
	// Unix file-type out of the external attributes directly; if it names any
	// non-regular, non-directory type, refuse to classify it as a regular
	// file rather than stage its target/payload as inert content.
	if t := unixFileType(f.ExternalAttrs); t != 0 && t != unixModeRegular && t != unixModeDir {
		return &ArchiveError{Code: ErrUnclassifiableEntry, EntryName: f.Name}
	}

	rc, err := f.Open()
	if err != nil {
		// In-memory staged bytes: a per-entry open failure is malformed-archive
		// metadata, not an I/O fault. Typed so callers classify it uniformly.
		return fmt.Errorf("%w: open entry %q: %v", ErrInvalidArchive, cleanName, err)
	}
	defer rc.Close()

	// The first <=512 bytes drive classification and are replayed to the
	// sink via MultiReader so the staged stream is complete — the zip
	// reader is sequential and consumed bytes do not come back.
	firstBuf := make([]byte, 512)
	n, rerr := io.ReadFull(rc, firstBuf)
	if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
		return fmt.Errorf("%w: read entry %q: %v", ErrInvalidArchive, cleanName, rerr)
	}
	firstBuf = firstBuf[:n]

	result := detect(firstBuf, f.Comment)
	if cfg.Record != nil {
		cfg.Record(cleanName, result)
	}
	if cfg.TypePolicy.Denies(result.Resolved) {
		return &ArchiveError{Code: ErrTypeDenied, EntryName: f.Name, Type: result.Resolved}
	}

	// The tee routes every byte the sink consumes through the counting
	// writer, so the cross-entry total is enforced on actual decompressed
	// bytes as they stream — never on a header claim. The zip reader is
	// wrapped so a corruption error it raises mid-decompression (a malformed
	// local header or truncated compressed data the central directory did not
	// reveal) is captured at its source and distinguished from a genuine sink
	// fault: the former is a typed malformed-archive condition, the latter is
	// the sink's own error preserved verbatim for errors.Is matching.
	src := &errCapturingReader{r: rc}
	cw := &countingWriter{w: io.Discard, total: total, ceiling: cfg.TotalUncompressedCeiling}
	entry := io.TeeReader(io.MultiReader(bytes.NewReader(firstBuf), src), cw)
	if err := sink.StageEntry(ctx, cleanName, entry, fi.Mode()); err != nil {
		if src.err != nil {
			// The fault originated in the zip reader, not the sink: the
			// archive bytes are malformed. Type it so callers classify every
			// corrupt-archive condition uniformly (errors.Is ErrInvalidArchive).
			return fmt.Errorf("%w: read entry %q: %v", ErrInvalidArchive, cleanName, src.err)
		}
		return fmt.Errorf("ingest: stage entry %q: %w", cleanName, err)
	}
	return nil
}

// errCapturingReader records the first non-EOF read error raised by the
// underlying zip-entry reader, so a corruption surfaced mid-decompression can
// be distinguished from a sink fault after StageEntry returns. io.EOF is not
// captured: it is the clean end of the entry, not a fault.
type errCapturingReader struct {
	r   io.Reader
	err error
}

func (e *errCapturingReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && err != io.EOF {
		e.err = err
	}
	return n, err
}

// Unix S_IFMT file-type bits as carried in the high 16 bits of a zip entry's
// central-directory external attributes. They are present whenever a creator
// stamped a Unix mode, independent of the CreatorVersion host byte, so they
// expose a non-regular type even when the standard-library FileInfo decode
// (which only reads the symlink bit for a Unix creator host) does not.
const (
	unixModeIFMT    = 0o170000 // S_IFMT: the file-type field mask
	unixModeRegular = 0o100000 // S_IFREG
	unixModeDir     = 0o040000 // S_IFDIR
)

// unixFileType returns the S_IFMT file-type field from a zip entry's external
// attributes, or 0 when no Unix mode is recorded (a pure MS-DOS attribute
// word leaves the high bits clear). The caller treats a recorded type that is
// neither regular nor directory as unclassifiable.
func unixFileType(externalAttrs uint32) uint32 {
	return (externalAttrs >> 16) & unixModeIFMT
}

// countingWriter enforces the cross-entry decompressed-total ceiling. It
// sits on the tee between the zip reader and the sink, so the count grows
// with the actual decompressed bytes the sink consumes; the header-claimed
// UncompressedSize64 is a claim, not a measurement, and is never consulted
// (ARC-01, NFR-SEC-80).
type countingWriter struct {
	w       io.Writer // forwarded writes; io.Discard in the tee wiring
	total   *int64    // running total shared across all entries
	ceiling int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	*cw.total += int64(len(p))
	if *cw.total > cw.ceiling {
		return 0, ErrTotalExceeded
	}
	return cw.w.Write(p)
}
