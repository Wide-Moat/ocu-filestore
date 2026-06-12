// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
)

// Engine is the consumer-side slice of the storage engine the namespace
// handlers call. It mirrors — byte-for-byte at the method level — the verbs
// the south-face ops need from the engine that lives on
// feat/local-volume-engine:internal/objectstore/objectstore.go (the Engine
// interface there). Following the consumer-seam discipline established by the
// dispatch spine, this package declares its own narrow view and the wiring
// phase binds the real implementation; nothing here imports
// internal/objectstore.
//
// The engine's scope type is a named objectstore type there; the seam uses a
// plain string. Path arguments are in the engine's relative convention
// ("." is the scope root, no leading slash) — the handler translates the
// guest's leading-slash convention through enginePath before any call.
type Engine interface {
	// List returns one level of entries under path ("." = scope root).
	List(ctx context.Context, scope string, path string) ([]FileInfo, error)
	// Stat returns metadata for a single object.
	Stat(ctx context.Context, scope string, path string) (FileInfo, error)
	// MakeDir creates a single directory level (Mkdir, not MkdirAll); a
	// missing parent refuses.
	MakeDir(ctx context.Context, scope string, path string) error
	// MoveDir moves a directory; an existing destination with overwrite
	// false refuses.
	MoveDir(ctx context.Context, scope string, src, dst string, overwrite bool) error
	// RemoveDir removes a directory subtree (always recursive); a missing
	// path is a no-op.
	RemoveDir(ctx context.Context, scope string, path string) error
	// CopyFile copies a file; an existing destination with overwrite false
	// refuses.
	CopyFile(ctx context.Context, scope string, src, dst string, overwrite bool) error
	// MoveFile moves a file; an existing destination with overwrite false
	// refuses.
	MoveFile(ctx context.Context, scope string, src, dst string, overwrite bool) error
	// RemoveFile removes a single file.
	RemoveFile(ctx context.Context, scope string, path string) error
	// ReadRange streams the half-open window [offset, offset+length) of the
	// object at path into w. The window is half-open; a range past EOF
	// short-reads to EOF WITHOUT error (the engine owns the EOF contract — the
	// handler never re-clamps). It mirrors the like-named verb on
	// feat/local-volume-engine:internal/objectstore/objectstore.go (the Engine
	// interface there), with the named ScopeID narrowed to a plain string per
	// the consumer-seam discipline.
	ReadRange(ctx context.Context, scope string, path string, offset, length int64, w io.Writer) error
	// WriteStream consumes r into the object at path WITHOUT whole-object
	// buffering. A partial or aborted write is NEVER visible at the
	// destination path (temp+rename invisibility); overwrite=false against an
	// existing destination refuses errAlreadyExists without consuming r. It
	// mirrors the like-named verb on
	// feat/local-volume-engine:internal/objectstore/objectstore.go (the Engine
	// interface there), with the named ScopeID narrowed to a plain string per
	// the consumer-seam discipline.
	WriteStream(ctx context.Context, scope string, path string, r io.Reader, overwrite bool) error
}

// FileInfo mirrors objectstore.FileInfo: the one-level listing/stat record
// the engine returns.
type FileInfo struct {
	// Name is the final path component (no separators).
	Name string
	// Size is the object size in bytes (0 for directories).
	Size int64
	// ModTime is the object's last-modified time.
	ModTime time.Time
	// IsDir distinguishes a directory entry from a file entry.
	IsDir bool
}

// Consumer-side mirrors of the engine's typed sentinels. Each mirrors the
// like-named objectstore sentinel; the wiring phase maps the real sentinels
// onto these (or replaces the errors.Is targets) when the engine package
// merges. The MakeDir EEXIST / ENOENT cases do NOT use these — the engine
// surfaces those as a raw *fs.PathError wrapping fs.ErrExist / fs.ErrNotExist,
// classified by denyClassForEngineErr through the standard library sentinels.
var (
	// errAlreadyExists mirrors objectstore.ErrAlreadyExists: the explicit
	// destination-collision sentinel on Move/Copy with overwrite false.
	// Match it with errors.Is.
	errAlreadyExists = errors.New("southface: destination already exists")

	// errInvalidPath mirrors objectstore.ErrInvalidPath: the lexical-reject
	// sentinel raised pre-syscall for a NUL/URL/absolute/dot-dot/empty path.
	// Match it with errors.Is.
	errInvalidPath = errors.New("southface: invalid path")
)

// ErrAlreadyExists and ErrInvalidPath are the EXPORTED aliases of the two
// engine mirror sentinels above. They are the SAME error values (errors.Is
// matches identically), exported so the composition layer's engine adapter
// can remap the real objectstore typed sentinels onto these mirrors (Option
// A) without southface importing internal/objectstore — the consumer-seam
// isolation is preserved. The unexported names remain the in-package
// classification targets; the deny mapper is unchanged.
var (
	// ErrAlreadyExists is the exported alias of errAlreadyExists.
	ErrAlreadyExists = errAlreadyExists
	// ErrInvalidPath is the exported alias of errInvalidPath.
	ErrInvalidPath = errInvalidPath
)

// isPathEscape mirrors the engine's containment-escape collapse helper: an
// escape surfaces from the syscall layer as a *fs.PathError or *os.LinkError.
// It is the LAST branch denyClassForEngineErr consults — the typed and
// standard-library sentinels are tested first so a benign EEXIST or ENOENT
// (which is also a *fs.PathError) is never misclassified as a security escape
// (Pitfall 2).
func isPathEscape(err error) bool {
	var pathErr *fs.PathError
	var linkErr *os.LinkError
	return errors.As(err, &pathErr) || errors.As(err, &linkErr)
}

// enginePath converts the guest's POSIX leading-slash convention to the
// engine's relative convention: "/" and "" become ".", a single leading "/"
// is stripped ("/a/b" -> "a/b"), and an already-relative path passes through
// ("a/b" -> "a/b"). It normalizes the slash only; the engine's own path
// validation is the authority on rejection. This translation runs before
// every engine call and is the single place the two conventions reconcile —
// the highest-risk detail in the namespace surface (Pitfall 1).
func enginePath(guestPath string) string {
	p := strings.TrimPrefix(guestPath, "/")
	if p == "" {
		return "."
	}
	return p
}

// guestPath is the inverse of enginePath for emitting listing responses: it
// stamps the guest's leading-slash convention back onto an engine-relative
// path. The scope root "." becomes "/"; any other relative path gains a
// single leading "/". Listing responses carry guest-convention paths so the
// guest mount re-uses them directly.
func guestPath(rel string) string {
	if rel == "." || rel == "" {
		return "/"
	}
	return "/" + strings.TrimPrefix(rel, "/")
}

// denyClassForEngineErr maps an engine error to a deny class in EXACTLY this
// order (the order is load-bearing — see Pitfall 2):
//
//  1. errAlreadyExists OR fs.ErrExist -> denyAlreadyExists
//  2. fs.ErrNotExist                  -> denyNotFound
//  3. errInvalidPath OR isPathEscape  -> denyNotFound (wire degrade, D8)
//  4. anything else                   -> denyInternal
//
// MakeDir surfaces EEXIST, missing-parent ENOENT, AND a containment escape ALL
// as *fs.PathError, and isPathEscape matches any *fs.PathError; testing the
// fs.ErrExist / fs.ErrNotExist sentinels first guarantees a benign
// already-exists or not-found is never recorded as a security escape. The
// invalid-path / escape branch degrades the WIRE reason to not_found
// (anti-enumeration, D8); the audited TRUTH for that case is recorded
// separately by the handler's deny-audit event.
func denyClassForEngineErr(err error) string {
	switch {
	case errors.Is(err, errAlreadyExists), errors.Is(err, fs.ErrExist):
		return denyAlreadyExists
	case errors.Is(err, fs.ErrNotExist):
		return denyNotFound
	case errors.Is(err, errInvalidPath), isPathEscape(err):
		return denyNotFound
	default:
		return denyInternal
	}
}
