// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
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

	// errBackendThrottled mirrors objectstore.ErrThrottled: the backend
	// refused the request under load shedding and the engine's paced retries
	// were exhausted — the caller may retry with backoff. Match it with
	// errors.Is.
	errBackendThrottled = errors.New("southface: backend throttled")

	// errBackendTransient mirrors objectstore.ErrTransient: a retryable
	// backend failure (backend 5xx, request timeout, transport-level
	// connection failure) survived the engine's bounded retries — the caller
	// may retry. Match it with errors.Is.
	errBackendTransient = errors.New("southface: transient backend failure")

	// errNotADirectory mirrors objectstore.ErrNotADirectory: the engine
	// sentinel raised when a List (or scope-lifecycle call) targets a path
	// that exists but is a file, not a directory. Both local and S3 engines
	// return this sentinel on the same edge; it classifies as denyMalformed
	// (invalid_argument/400) because the client named a wrong-kind path —
	// a request fault, not a backend failure or a missing resource.
	// Match it with errors.Is.
	errNotADirectory = errors.New("southface: path is not a directory")

	// errInvalidRange mirrors objectstore.ErrInvalidRange: the ReadRange
	// pre-flight sentinel raised for a negative offset or negative length.
	// It classifies as denyMalformed (invalid_argument/400): the client
	// supplied a malformed window that is a request fault regardless of which
	// engine is bound. Match it with errors.Is.
	errInvalidRange = errors.New("southface: invalid read range")
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
	// ErrBackendThrottled is the exported alias of errBackendThrottled.
	ErrBackendThrottled = errBackendThrottled
	// ErrBackendTransient is the exported alias of errBackendTransient.
	ErrBackendTransient = errBackendTransient
	// ErrNotADirectory is the exported alias of errNotADirectory.
	ErrNotADirectory = errNotADirectory
	// ErrInvalidRange is the exported alias of errInvalidRange.
	ErrInvalidRange = errInvalidRange
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

// canonicalizePath returns the single canonical in-scope form of a
// guest-supplied wire path, joined under the credential-intent's subtree, or
// errInvalidPath. It is the wire-boundary obligation the dispatch spine
// discharges ONCE after STAGE 1b and before STAGE 2 authz (bypass-01/03,
// ADR-0029 inv-10): the cleaned form it returns is what authz, the downloadable
// tag, the engine read/write, the uuid store, and the audit record ALL see, so
// the layer that decides downloadable can never disagree with the layer that
// reads the bytes.
//
// Its job is precisely to make authz-path == engine-path: it rejects the
// unsafe lexical classes objectstore.ValidatePath rejects that can change which
// object a path names — NUL byte, URL-shaped handle, and an absolute/".."
// path that escapes the scope root — and applies path.Clean so redundant and
// traversal segments are collapsed BEFORE any path-aware decision. It maps the
// guest leading-slash convention to a single canonical guest form: the guest
// "/a/b" canonicalizes to "/a/b" and trims through enginePath to the engine
// "a/b" that objectstore.ValidatePath cleans to the identical "a/b".
//
// subtree is the engine-relative form of the intent-derived subtree with NO
// leading slash (e.g. "outputs" for write, "uploads" for read); an empty
// subtree disables the join (static-path mode) and preserves the pre-ADR-0029
// behaviour verbatim. When a subtree is supplied it is prepended BEFORE the
// path.Clean and the escape check becomes a subtree-containment check: the
// cleaned result must be the subtree root ("/outputs") or lie beneath it
// ("/outputs/..."). This ordering is load-bearing (ADR-0029 inv-10): the join
// happens before Clean, so "uploads/../x" cleans to "/x", which fails the
// "/uploads/" containment prefix and is refused — the exact hole a bare "/.."
// reject leaves open once a subtree is prepended. The returned canonical form
// carries the subtree ("/outputs/uploads/x"); enginePath trims it to the
// engine-relative "outputs/uploads/x" the backend object lands at.
//
// The two lexical rejects (NUL byte, URL scheme) run on the RAW guest input
// BEFORE the join, so a smuggled "s3://..." or NUL-bearing leg dies before it
// can be prefixed with a subtree.
//
// Unlike the engine-side ValidatePath it does NOT reject the scope root itself
// (canonical "/") or enforce the per-path component cap: those are OP-specific
// concerns the handlers and the engine already enforce with their own wire
// classes (a listDirectory of the root is legitimate; a file open of the root
// or an over-deep path is refused downstream — not_found / the walk-depth cap —
// not a boundary invalid_argument). The boundary's only contract is the
// authz==engine path identity. southface declares its own mirror so the
// consumer-seam isolation (no objectstore import) is preserved, exactly as it
// mirrors errInvalidPath and the other engine sentinels.
func canonicalizePath(guest, subtree string) (string, error) {
	// The lexical rejects run on the RAW guest input BEFORE the join: a NUL
	// byte or a URL-shaped handle must die before it can be prefixed with the
	// subtree (a "s3://bucket/key" leg smuggled through the path field would
	// otherwise become "/outputs/s3://bucket/key" and lose its scheme shape to
	// path.Clean's "//"-deduplication).
	if strings.ContainsRune(guest, '\x00') {
		return "", errInvalidPath
	}
	if hasURLScheme(guest) {
		return "", errInvalidPath
	}
	// Prepend the intent-derived subtree (if any) BEFORE path.Clean, then anchor
	// at the scope root so a leading-slash path and a relative path clean
	// identically. With subtree "outputs" the guest "/x" and "x" both become the
	// pre-clean "outputs/x"; a residual ".." surfaces as a segment path.Clean
	// keeps, caught by the containment check below.
	rel := strings.TrimPrefix(guest, "/")
	if subtree != "" {
		rel = subtree + "/" + rel
	}
	clean := path.Clean("/" + rel)
	if subtree != "" {
		// Subtree-containment check (ADR-0029 inv-10): the cleaned result must be
		// the subtree root or lie beneath it on a path boundary. This SUBSUMES the
		// bare "/.." reject: "uploads/../x" cleans to "/x", which is neither
		// "/uploads" nor under "/uploads/", so it is refused — the escape a bare
		// "/.." check would miss once the subtree is prepended.
		base := "/" + subtree
		if clean != base && !strings.HasPrefix(clean, base+"/") {
			return "", errInvalidPath
		}
	} else if clean == "/.." || strings.HasPrefix(clean, "/../") {
		// Static-path mode (join disabled): the unchanged pre-ADR-0029 behaviour.
		// A residual ".." component after Clean means the path tried to escape the
		// scope root — the bypass-01 class. Refuse it (the engine would also reject
		// it, but the egress axis must be decided on the CLEANED in-scope form, so
		// the boundary refuses an escape outright rather than pass it downstream).
		return "", errInvalidPath
	}
	return clean, nil
}

// hasURLScheme reports whether s begins with an RFC-3986 scheme followed by
// "://". It mirrors the engine-side objectstore check and must run on the raw
// input BEFORE path.Clean, which deduplicates "//" and would hide the scheme
// shape — blocking a backend address (e.g. "s3://bucket/key") smuggled through
// the path field.
func hasURLScheme(s string) bool {
	i := 0
	isAlpha := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	if i >= len(s) || !isAlpha(s[i]) {
		return false
	}
	i++
	for i < len(s) && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '+' || s[i] == '-' || s[i] == '.') {
		i++
	}
	return i+2 < len(s) && s[i] == ':' && s[i+1] == '/' && s[i+2] == '/'
}

// enginePath converts a CANONICAL guest leading-slash path to the engine's
// relative convention: "/" and "" become ".", a single leading "/" is stripped
// ("/a/b" -> "a/b"), and an already-relative path passes through. It normalizes
// the slash only — the path it receives has already been through
// canonicalizePath at the wire boundary, so it carries no traversal or
// redundant segments; the engine's own ValidatePath re-validates as
// defense-in-depth (Pitfall 1).
func enginePath(guestPath string) string {
	p := strings.TrimPrefix(guestPath, "/")
	if p == "" {
		return "."
	}
	return p
}

// resolverRequest returns a copy of req with Path normalised to the
// engine-relative convention (no leading slash) for the resolver and its
// StoredTagFunc (ADR-0029 inv-5). The stored downloadable tag is a raw string
// prefix match, so the leading-slash convention is load-bearing: the south face
// carries the guest leading-slash form ("/outputs/x") through env.Path for the
// audit ObjectHandle and the uuid store, while the north Files-API plane passes
// engine-relative ("outputs/x"); normalising the resolver's view to
// engine-relative gives BOTH planes one convention at the tag boundary, so a
// single configured downloadable prefix ("outputs") matches identically on both.
// The normalised path names the SAME object env.Path names — enginePath only
// strips the leading slash — so authz-path == engine-path is preserved.
func resolverRequest(req ResolveRequest) ResolveRequest {
	req.Path = enginePath(req.Path)
	return req
}

// guestPathFromRel is the inverse of enginePath for emitting listing responses

// and for keying the uuid store off an engine-relative path: it stamps the
// guest's leading-slash convention back onto an engine-relative path. The scope
// root "." becomes "/"; any other relative path gains a single leading "/".
// Renamed from the former "guestPath" so it can never be mistaken for the
// canonicalizer — it normalizes the slash convention only and does NOT clean
// traversal segments; every path reaching it has already been canonicalized at
// the wire boundary (bypass-03).
func guestPathFromRel(rel string) string {
	if rel == "." || rel == "" {
		return "/"
	}
	return "/" + strings.TrimPrefix(rel, "/")
}

// guestDisplayPath is the engine->guest emit-boundary counterpart to
// canonicalizePath's guest->engine join (ADR-0029 round-trip symmetry): it strips
// the active intent subtree from an engine-relative path and returns the guest
// leading-slash form, so a path the read plane REPORTS is one the guest can
// re-address without a double-join. The store, cursor, download re-canon, and
// audit keep the JOINED engine form; ONLY the wire Path field a south response
// echoes is stripped. subtree is engine-relative with no leading slash
// ("uploads", "outputs"); "" (static-path mode) makes this identical to
// guestPathFromRel.
//
// The strip is anchored and boundary-checked (strip only when rel equals the
// subtree or lies beneath it on a "/" boundary — "uploads2/x" is NOT stripped)
// and applied AT MOST ONCE, so the engine object "uploads/uploads/x" emits
// "/uploads/x" and a guest re-address re-joins it back to "uploads/uploads/x".
func guestDisplayPath(rel, subtree string) string {
	if subtree == "" {
		return guestPathFromRel(rel)
	}
	r := strings.TrimPrefix(rel, "/")
	switch {
	case r == subtree:
		// The subtree root itself surfaces as the guest scope root.
		return "/"
	case strings.HasPrefix(r, subtree+"/"):
		return guestPathFromRel(strings.TrimPrefix(r, subtree+"/"))
	default:
		// An engine-relative path outside the active subtree cannot occur under an
		// intent-rooted walk (the walk is rooted at the subtree). Falling through to
		// the joined form here would reopen the leak, so this branch is an internal
		// inconsistency the round-trip keystone is built to catch.
		return guestPathFromRel(rel)
	}
}

// denyClassForEngineErr maps an engine error to a deny class in EXACTLY this
// order (the order is load-bearing — see Pitfall 2):
//
//  0. context.Canceled / DeadlineExceeded -> denyAborted (T2-5, RES-03)
//  1. errAlreadyExists OR fs.ErrExist     -> denyAlreadyExists
//  2. fs.ErrNotExist                      -> denyNotFound
//  3. errBackendThrottled                 -> denyThrottle
//  4. errBackendTransient                 -> denyBackendUnavailable
//  5. errInvalidPath OR isPathEscape      -> denyNotFound (wire degrade, D8)
//  6. anything else                       -> denyInternal
//
// Context cancellation / deadline are classified FIRST (step 0): a client
// disconnect or deadline is a clean "aborted/canceled" verdict, not a
// generic error that would pollute the audit chain or be misclassified as a
// backend transient (RES-03).
//
// MakeDir surfaces EEXIST, missing-parent ENOENT, AND a containment escape ALL
// as *fs.PathError, and isPathEscape matches any *fs.PathError; testing the
// fs.ErrExist / fs.ErrNotExist sentinels first guarantees a benign
// already-exists or not-found is never recorded as a security escape. The
// backend throttle/transient rows sit AFTER the fs sentinels (they are plain
// sentinels, never *fs.PathError, so the order there is free) and BEFORE the
// escape collapse, preserving the load-bearing tail. The invalid-path /
// escape branch degrades the WIRE reason to not_found (anti-enumeration,
// D8); the audited TRUTH for that case is recorded separately by the
// handler's deny-audit event.
func denyClassForEngineErr(err error) string {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return denyAborted
	case errors.Is(err, errAlreadyExists), errors.Is(err, fs.ErrExist):
		return denyAlreadyExists
	case errors.Is(err, fs.ErrNotExist):
		return denyNotFound
	case errors.Is(err, errNotADirectory):
		// A client listed a path that exists but is a file — a request fault,
		// not a missing resource. Classify as malformed (invalid_argument/400)
		// so the wire class signals the caller named a wrong-kind path.
		return denyMalformed
	case errors.Is(err, errInvalidRange):
		// A client supplied a negative read range — a malformed window.
		// Classify as denyMalformed (invalid_argument/400): a request fault.
		return denyMalformed
	case errors.Is(err, errBackendThrottled):
		return denyThrottle
	case errors.Is(err, errBackendTransient):
		return denyBackendUnavailable
	case errors.Is(err, errInvalidPath), isPathEscape(err):
		return denyNotFound
	default:
		return denyInternal
	}
}
