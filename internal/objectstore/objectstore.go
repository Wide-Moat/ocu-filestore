// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package objectstore is the broker's single backend client — the only
// component in the deployment that speaks the backend protocol and signs
// backend requests (NFR-SEC-25). The backend engine is a pluggable adapter
// (architecture repo ADR-0010): a local-volume engine (the solo reference,
// a host filesystem permission, no network leg) and an S3 engine, both
// present from day one.
//
// PENDING-PHASE-7(engine-leg-egress): a network engine's backend leg is a
// single governed egress hop dialed with this package's own host-local backend
// credential. The guest-path storage lane (the fixed-proxy transport that
// formerly carried the guest data path under ADR-0011) is retired: the guest
// path is now guest -> edge -> service direct HTTPS, and the service is the only
// thing that speaks the backend protocol. Whether the engine's OWN backend dial
// retains an egress proxy is an ADR-0011-vs-new-model reconciliation not yet
// frozen in component-04 canon (see docs/pending-phase7.md); a direct backend
// dial that bypasses the engine's single client is still refused (NFR-SEC-16).
// Path resolution happens here, inside the host-attested filesystem_id
// prefix: traversal, symlink, absolute-path, and URL-shaped handles are
// rejected before any backend call (NFR-SEC-25). The credential never
// leaves this package.
package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

// EngineKind names a backend engine.
type EngineKind string

const (
	// LocalVolume exercises a host filesystem permission, not a network
	// credential; it opens no network leg, so the egress-hop rule does not
	// apply to it.
	LocalVolume EngineKind = "local-volume"
	// S3 is the network engine; its backend leg is a single governed egress
	// hop dialed with this package's own host-local credential.
	// PENDING-PHASE-7(engine-leg-egress): whether that hop retains an egress
	// proxy is an unfrozen ADR-0011-vs-new-model reconciliation.
	S3 EngineKind = "s3"
)

// ErrUnknownEngine is the sentinel ParseEngine wraps when the configured
// engine name is not a known kind. Never a silent default. Match it with
// errors.Is.
var ErrUnknownEngine = errors.New("objectstore: unknown backend engine")

// ParseEngine maps a deployment-config string to an EngineKind, wrapping
// ErrUnknownEngine and listing the valid kinds on an unknown value.
func ParseEngine(s string) (EngineKind, error) {
	switch EngineKind(s) {
	case LocalVolume, S3:
		return EngineKind(s), nil
	default:
		return "", fmt.Errorf("%w %q (valid: %s, %s)", ErrUnknownEngine, s, LocalVolume, S3)
	}
}

// ErrAlreadyExists is the overwrite-refusal sentinel: the destination of a
// write/copy/move already exists and the caller did not set overwrite.
// Match it with errors.Is.
var ErrAlreadyExists = errors.New("objectstore: object already exists")

// ErrNotADirectory is the lifecycle sentinel: a scope path exists but is not
// a directory, so the scope cannot be torn down or reused. Match it with
// errors.Is.
var ErrNotADirectory = errors.New("objectstore: path is not a directory")

// ErrInvalidRange is the ReadRange-argument sentinel: a negative offset or
// negative length is a malformed window. Both engines refuse it identically
// (the same hostile {offset,length} must not succeed on one engine and error
// on the other). Match it with errors.Is.
var ErrInvalidRange = errors.New("objectstore: invalid read range")

// ErrTransient is the retryable backend-failure sentinel: the backend leg
// failed in a way that may succeed on a later attempt (backend 5xx, request
// timeout, transport-level connection failure) after the engine's own
// bounded retries were exhausted. Match it with errors.Is.
var ErrTransient = errors.New("objectstore: transient backend failure")

// ErrThrottled is the backend-pacing sentinel: the backend refused the
// request under load shedding and the engine's paced retries were exhausted;
// the caller may retry later with backoff. Match it with errors.Is.
var ErrThrottled = errors.New("objectstore: backend throttled")

// FileInfo carries the minimal metadata the broker's handlers need from
// stat/list verbs. It is an INTERNAL struct — the wire File shape and its
// field mapping are the wire layer's job, never modelled here.
type FileInfo struct {
	// Name is the entry's base name, no path prefix.
	Name string
	// Size is the object size in bytes.
	Size int64
	// ModTime is the last-modification time.
	ModTime time.Time
	// IsDir reports whether the entry is a directory.
	IsDir bool
}

// isPathEscape reports whether err carries an os.Root structural error
// wrapper — *fs.PathError (the openat family: Open, OpenFile, Stat, Mkdir,
// Remove, ...) or *os.LinkError (the renameat family: Rename). os.Root
// surfaces a containment escape through BOTH wrappers depending on the verb;
// this helper collapses the split into ONE caller-visible escape class so
// mapping code can never miss a rename escape by checking only
// *fs.PathError. The lexical sentinel ErrInvalidPath is deliberately NOT in
// this class — lexical rejection happens before any syscall and is mapped
// separately. Finer syscall-error discrimination (ENOENT vs escape) stays
// with errors.Is(err, fs.ErrNotExist) at the call site.
func isPathEscape(err error) bool {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return true
	}
	var le *os.LinkError
	return errors.As(err, &le)
}

// Engine is the pluggable backend seam (ADR-0010): the internal verb set the
// broker's handlers call, plus the scope lifecycle. This is the INTERNAL Go
// API — wire bodies and the contract's verb mapping are the wire layer's
// job.
//
// Every path argument is validated by the engine (ValidatePath, then os.Root
// containment) before any syscall — callers may pre-validate but the engine
// never trusts that. The ScopeID is host-attested and trusted; the path is
// not. Cross-scope copy/move never reaches the engine: a request naming a
// scope the caller does not hold is scope_mismatch territory upstream
// (NFR-SEC-43), so every verb here takes exactly one scope.
//
// Context contract: EVERY verb honors ctx and surfaces ctx.Err() through its
// returned error (errors.Is-matchable). A verb checks ctx at entry, so a
// caller that cancels before the verb starts gets an immediate abort, never a
// stray side effect. Long-running verbs abort PROMPTLY mid-operation: the
// streaming verbs (WriteStream, CopyFile, ReadRange) check between byte copies,
// and the recursive erase/remove verbs (ProvisionScope, TeardownScope,
// RemoveDir) check between directory entries so a teardown of a huge scope can
// be interrupted rather than blocking until the whole tree is walked. The
// remaining verbs are bounded single syscalls whose entry check is their only
// cancellation point. An aborted write never leaves a partial object visible at
// the destination path.
//
// Idempotency contract (per verb, for retry after an AMBIGUOUS failure —
// the caller saw an error but cannot know whether the backend applied the
// operation):
//
//   - ProvisionScope, TeardownScope, Stat, List, ReadRange, MakeDir,
//     RemoveFile, RemoveDir, CopyFile: idempotent — safe to re-invoke; the
//     re-invocation converges on the same end state (MakeDir on an existing
//     directory and RemoveFile on a removed file surface their usual
//     exists/not-exist errors, which the caller treats as convergence).
//   - WriteStream: NOT re-invokable with the same reader — the stream is
//     consumed; a retry needs a fresh reader from the source of truth.
//   - MoveFile, MoveDir: re-invokable only until the source delete commits;
//     the engine orders copy -> verify -> delete so a retry after any
//     failure never loses bytes (a surviving duplicate is the acceptable
//     failure mode, never a lost object).
type Engine interface {
	// Kind names the engine.
	Kind() EngineKind

	// ProvisionScope ensures the scope's storage scaffold exists at session
	// grant (create-if-absent, idempotent). It does NOT erase owner data; it
	// must run before any data verb on a fresh scope.
	ProvisionScope(ctx context.Context, scope ScopeID) error
	// TeardownScope erases ALL contents of the named scope — erase-before-reuse
	// (NFR-SEC-54). After it returns, no path written in the prior session is
	// readable. Callers: explicit owner-change grant only, never process
	// lifecycle (shutdown, restart, or composition failure).
	TeardownScope(ctx context.Context, scope ScopeID) error

	// List returns the entries of the named directory, ONE level only
	// (non-recursive); recursion is the caller's composition. The literal
	// path "." names the scope root.
	List(ctx context.Context, scope ScopeID, path string) ([]FileInfo, error)
	// Stat returns metadata for the named object.
	Stat(ctx context.Context, scope ScopeID, path string) (FileInfo, error)
	// MakeDir creates the named directory (single level).
	MakeDir(ctx context.Context, scope ScopeID, path string) error
	// MoveDir renames a directory within the scope. With overwrite false an
	// existing destination refuses with ErrAlreadyExists.
	MoveDir(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error
	// RemoveDir removes the named directory and its contents (recursive).
	RemoveDir(ctx context.Context, scope ScopeID, path string) error
	// CopyFile duplicates a file's bytes within the scope. With overwrite
	// false an existing destination refuses with ErrAlreadyExists.
	CopyFile(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error
	// MoveFile renames a file within the scope. With overwrite false an
	// existing destination refuses with ErrAlreadyExists.
	MoveFile(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error
	// RemoveFile removes the named file.
	RemoveFile(ctx context.Context, scope ScopeID, path string) error
	// ReadRange streams the half-open byte range [offset, offset+length)
	// of the named file into w; a range past EOF short-reads to EOF
	// without error.
	ReadRange(ctx context.Context, scope ScopeID, path string, offset, length int64, w io.Writer) error
	// WriteStream consumes r into the named file without whole-object
	// buffering; a partial write is never visible at the destination path.
	// With overwrite false an existing destination refuses with
	// ErrAlreadyExists.
	WriteStream(ctx context.Context, scope ScopeID, path string, r io.Reader, overwrite bool) error
}
