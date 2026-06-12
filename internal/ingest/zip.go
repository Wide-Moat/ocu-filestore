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
	// ceiling bounds the archive, not each entry (ARC-01).
	var total int64
	for _, f := range r.File {
		if err := processEntry(ctx, f, cfg, &total, sink); err != nil {
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
func processEntry(ctx context.Context, f *zip.File, cfg Config, total *int64, sink ExtractSink) error {
	cleanName, err := validateEntryName(f.Name)
	if err != nil {
		return &ArchiveError{Code: ErrInvalidEntry, EntryName: f.Name}
	}

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
			return fmt.Errorf("ingest: open symlink entry %q: %w", cleanName, err)
		}
		target, rerr := io.ReadAll(io.LimitReader(rc, 4096))
		rc.Close()
		if rerr != nil {
			return fmt.Errorf("ingest: read symlink target %q: %w", cleanName, rerr)
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

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("ingest: open entry %q: %w", cleanName, err)
	}
	defer rc.Close()

	// The first <=512 bytes drive classification and are replayed to the
	// sink via MultiReader so the staged stream is complete — the zip
	// reader is sequential and consumed bytes do not come back.
	firstBuf := make([]byte, 512)
	n, rerr := io.ReadFull(rc, firstBuf)
	if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
		return fmt.Errorf("ingest: read entry %q: %w", cleanName, rerr)
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
	// bytes as they stream — never on a header claim.
	cw := &countingWriter{w: io.Discard, total: total, ceiling: cfg.TotalUncompressedCeiling}
	entry := io.TeeReader(io.MultiReader(bytes.NewReader(firstBuf), rc), cw)
	if err := sink.StageEntry(ctx, cleanName, entry, fi.Mode()); err != nil {
		return fmt.Errorf("ingest: stage entry %q: %w", cleanName, err)
	}
	return nil
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
