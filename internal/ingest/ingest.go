// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ingest is the archive validation and classification seam every
// staged archive crosses before any entry becomes mount-visible: streaming
// ceilings on the uncompressed total and the entry count (NFR-SEC-80),
// lexical rejection of traversal and symlink-escape entry names, and
// magic-byte classification of every regular-file entry, recorded before
// its bytes are committed (NFR-SEC-81). Enforcement reads actual
// decompressed bytes — a header-claimed size is never the control. Accepted
// entries flow through the ExtractSink seam the engine implements at wiring
// time; any rejection aborts the sink, so nothing staged becomes visible.
//
// The package never opens the filesystem: every check is lexical or streams
// over in-memory bytes, and Config.DestDir is a containment anchor for path
// math, never an opened path. Runtime containment (os.Root, O_NOFOLLOW
// component resolution) is the engine's job; this layer rejects what would
// be unsafe before the engine ever sees it — defense in depth, not
// redundancy.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// Canonical ceiling defaults (NFR-SEC-80). Config does not self-default:
// the caller passes explicit values, and a zero ceiling rejects every
// non-empty archive — fail-closed, never fail-open.
const (
	// DefaultTotalUncompressedCeiling is the canonical uncompressed-total
	// ceiling: 1 GiB across all entries of one archive.
	DefaultTotalUncompressedCeiling int64 = 1 << 30
	// DefaultEntryCeiling is the canonical entry-count ceiling.
	DefaultEntryCeiling = 100_000
)

// Config holds the ceilings, the containment anchor, and the per-scope
// policy for one validation pass.
type Config struct {
	// TotalUncompressedCeiling is the maximum total decompressed bytes
	// across ALL entries, enforced by the streaming count on every write —
	// never by any header-claimed size. Canonical default:
	// DefaultTotalUncompressedCeiling (NFR-SEC-80).
	TotalUncompressedCeiling int64

	// EntryCeiling is the maximum number of entries, checked immediately
	// after the central directory is parsed, before any entry byte is
	// read. Canonical default: DefaultEntryCeiling (NFR-SEC-80).
	EntryCeiling int

	// DestDir is the scope root the archive extracts under. It is only
	// the lexical anchor for symlink-target containment math; this
	// package never opens it.
	DestDir string

	// TypePolicy is the per-scope opt-in deny list. The zero value denies
	// nothing: the canon default is classify-and-record only (ARC-03,
	// NFR-SEC-81).
	TypePolicy TypePolicy

	// Record, when non-nil, receives the classification of every
	// regular-file entry — after the sniff, before the policy gate, and
	// before any byte of that entry is staged — so the caller can record
	// it (NFR-SEC-81 classify-before-visibility). nil drops the records;
	// classification still runs for the policy gate.
	Record func(entryName string, result ClassificationResult)
}

// ClassificationResult is the recorded classification of one regular-file
// entry: the declared type, the magic-sniffed resolved type, and whether
// they disagree.
type ClassificationResult struct {
	// Declared is the type the archive claims for the entry (the entry
	// comment field on the day-one zip wire; may be empty).
	Declared string
	// Resolved is the magic-byte sniff result. Never empty — the sniff
	// always produces a value (application/octet-stream when nothing
	// matches).
	Resolved string
	// Mismatch is true when a non-empty Declared disagrees with Resolved.
	Mismatch bool
}

// TypePolicy is the per-scope content-type policy: an explicit deny list
// over resolved types. The zero value denies nothing — the model is
// deny-by-explicit-entry over an allow-all default, because the canon
// default is classify-and-record only (ARC-03); a denied resolved type is
// rejected before any of its bytes are staged.
type TypePolicy struct {
	deny map[string]struct{}
}

// DenyTypes returns a policy denying exactly the given resolved types.
func DenyTypes(types ...string) TypePolicy {
	deny := make(map[string]struct{}, len(types))
	for _, t := range types {
		deny[t] = struct{}{}
	}
	return TypePolicy{deny: deny}
}

// Denies reports whether the policy denies the resolved type.
func (p TypePolicy) Denies(resolved string) bool {
	_, ok := p.deny[resolved]
	return ok
}

// ExtractSink is the staging seam ValidateZip writes accepted entries
// into. It is defined here so this package imports no internal package;
// the engine (phase 8/10 wiring) implements it over its streaming write
// with temp-then-rename semantics. Entries reach the sink only after the
// lexical, ceiling, and policy checks pass — the sink never sees a
// rejected name or byte.
//
// Abort MUST discard everything staged since construction. The caller is
// responsible for calling Abort on any failure path (ValidateZip does so
// via defer); Abort after Commit, and a repeated Abort, are no-ops.
type ExtractSink interface {
	// StageEntry stages one regular-file entry. name is the cleaned,
	// validated scope-relative path; r streams the entry's bytes and must
	// be consumed fully; mode is the entry's file mode.
	StageEntry(ctx context.Context, name string, r io.Reader, mode fs.FileMode) error

	// MakeDir stages a directory entry. Idempotent: an existing directory
	// is not an error.
	MakeDir(ctx context.Context, name string) error

	// MakeSymlink stages a symlink entry whose target already passed
	// containment validation. Phase 12 NEVER calls it: on this shelf
	// every symlink entry is rejected (escaping target -> ErrSymlinkEscape,
	// inside-resolving target -> ErrSymlinkUnsupported), because staging
	// the target string through StageEntry would silently change
	// semantics — a reader would receive the link target text as file
	// content. The method is pinned now so the engine can implement it at
	// wiring time without an interface change.
	MakeSymlink(ctx context.Context, name, target string) error

	// Commit makes everything staged visible, atomically per archive.
	Commit(ctx context.Context) error

	// Abort discards everything staged since construction.
	Abort(ctx context.Context)
}

// ErrInvalidArchive — the staged bytes do not parse as a zip archive.
// Match it with errors.Is.
var ErrInvalidArchive = errors.New("ingest: invalid zip archive")

// ErrEntryCountExceeded — the archive's entry count exceeds the configured
// ceiling; rejected before any entry byte is read (NFR-SEC-80). Match it
// with errors.Is.
var ErrEntryCountExceeded = errors.New("ingest: entry count exceeds ceiling")

// ErrTotalExceeded — the running decompressed total crossed the configured
// ceiling mid-stream; the header-claimed size is never the control
// (NFR-SEC-80). Match it with errors.Is.
var ErrTotalExceeded = errors.New("ingest: uncompressed total exceeds ceiling")

// ErrInvalidEntry — the entry name fails the lexical check (NUL byte,
// backslash-smuggled separator, drive letter, URL scheme, absolute path,
// ".." escape, or the bare scope root). Match it with errors.Is.
var ErrInvalidEntry = errors.New("ingest: invalid or unsafe entry name")

// ErrSymlinkEscape — a symlink entry's target resolves outside the
// destination. Deliberately distinct from ErrInvalidEntry so a symlink
// reject is distinguishable from a traversal reject. Match it with
// errors.Is.
var ErrSymlinkEscape = errors.New("ingest: symlink target escapes destination")

// ErrSymlinkUnsupported — the symlink entry's target stays inside the
// destination, but this shelf stages no symlinks at all (fail-closed until
// the sink's MakeSymlink is implemented at wiring time). Match it with
// errors.Is.
var ErrSymlinkUnsupported = errors.New("ingest: symlink entries unsupported")

// ErrTypeDenied — the entry's resolved content type is denied by the
// per-scope policy; rejected before any of its bytes are staged
// (NFR-SEC-81). Match it with errors.Is.
var ErrTypeDenied = errors.New("ingest: content type denied by policy")

// ErrorCode is the sentinel class an ArchiveError carries and unwraps to;
// callers match it with errors.Is against the Err... sentinels above.
type ErrorCode = error

// ArchiveError is the structured rejection: the sentinel code plus the
// offending entry and the ceiling arithmetic where they apply. It unwraps
// to its Code, so errors.Is against the sentinels matches through it.
type ArchiveError struct {
	Code      ErrorCode // one of the Err... sentinels above
	EntryName string    // raw offending entry name, when one exists
	Type      string    // resolved content type, for ErrTypeDenied
	Count     int       // observed entry count, for ErrEntryCountExceeded
	Ceiling   int       // configured ceiling, for ErrEntryCountExceeded
}

// Error renders the sentinel text plus whichever structured fields apply.
func (e *ArchiveError) Error() string {
	msg := e.Code.Error()
	if e.EntryName != "" {
		msg = fmt.Sprintf("%s: entry %q", msg, e.EntryName)
	}
	if e.Type != "" {
		msg = fmt.Sprintf("%s: type %s", msg, e.Type)
	}
	if e.Count != 0 || e.Ceiling != 0 {
		msg = fmt.Sprintf("%s: %d > %d", msg, e.Count, e.Ceiling)
	}
	return msg
}

// Unwrap exposes the sentinel for errors.Is.
func (e *ArchiveError) Unwrap() error { return e.Code }
