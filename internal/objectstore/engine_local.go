// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// stagingDirName is the broker-internal staging area at the scope root:
// every write streams into a temp name under it before committing into
// place. It is GUEST-INVISIBLE — never surfaced in a listing of the scope
// root, and unaddressable through any data verb (a reserved name) — and it
// is removed wholesale by the Provision/Teardown sweeps, so a partial write
// left by a crashed daemon never survives into a later session (SEC-54
// crash path).
const stagingDirName = ".ocu-staging"

// guestPath validates a caller-supplied data path (ValidatePath, lexical
// stage) and then refuses any path whose FIRST component names the
// broker-internal staging area: the guest must be unable to read, list,
// write, move, or remove anything under it. Deeper components with the same
// name are not reserved — the staging area lives only at the scope root.
func guestPath(p string) (string, error) {
	clean, err := ValidatePath(p)
	if err != nil {
		return "", err
	}
	first, _, _ := strings.Cut(clean, string(filepath.Separator))
	if first == stagingDirName {
		return "", fmt.Errorf("%w: %q is a broker-internal reserved name", ErrInvalidPath, stagingDirName)
	}
	return clean, nil
}

// localVolumeEngine is the ADR-0010 local-volume Engine: a host filesystem
// permission, no network leg. Every verb runs the caller's path through
// guestPath (ValidatePath lexical stage + the staging-area reservation) and
// then an os.Root method under the scope's ScopeRoot (containment stage) —
// no verb ever joins baseDir with caller input; the only trusted derivation
// is baseDir+ScopeID for the scope dir itself in
// ProvisionScope/TeardownScope.
//
// The engine opens a ScopeRoot per call and closes it on return. Per-call
// open is deliberate: it is leak-free without fd lifecycle tracking, and fd
// ceilings are the session-ceiling layer's concern, not this engine's. A
// cached-root variant can replace openScope later without touching any verb.
type localVolumeEngine struct {
	baseDir string
}

// NewLocalVolumeEngine returns the local-volume Engine rooted at baseDir.
// Scope directories live at baseDir/<scope> and are created by
// ProvisionScope at session grant.
func NewLocalVolumeEngine(baseDir string) Engine {
	return &localVolumeEngine{baseDir: baseDir}
}

func (e *localVolumeEngine) Kind() EngineKind { return LocalVolume }

// openScope opens a per-call containment root for the host-attested scope.
// The caller defers Close.
func (e *localVolumeEngine) openScope(id ScopeID) (*ScopeRoot, error) {
	return OpenScopeRoot(e.baseDir, id)
}

// scopePath derives the scope directory from the TRUSTED ScopeID only —
// never from any caller-supplied path (NFR-SEC-43). It is used exclusively
// by the lifecycle verbs; data verbs go through the ScopeRoot. Every caller
// runs validateScopeID before this join (defense-in-depth on the id shape).
func (e *localVolumeEngine) scopePath(id ScopeID) string {
	return filepath.Join(e.baseDir, string(id))
}

// ctxReader makes a byte stream cancellation-aware: every Read consults
// ctx.Err() first, so a long copy loop aborts within one chunk of a
// cancellation instead of running to stream EOF. The surfaced error IS
// ctx.Err() (errors.Is-matchable through the verb's wrap), per the Engine
// context contract.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// toFileInfo maps an os.FileInfo to the engine's minimal internal struct.
func toFileInfo(fi os.FileInfo) FileInfo {
	return FileInfo{
		Name:    fi.Name(),
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
		IsDir:   fi.IsDir(),
	}
}

// ProvisionScope prepares baseDir/<scope> at session grant — ERASE-AT-
// PROVISION (SEC-54 crash path, mirroring the s3 engine): a scope directory
// left behind by a daemon that crashed mid-session (its TeardownScope never
// ran) is erased before serving, so a restart never re-serves prior-session
// bytes. The same sweep removes any orphaned partial write in the staging
// area, which is then recreated empty. A symlinked or non-directory scope
// entry refuses BEFORE any removal, exactly as in TeardownScope (T-03-05).
// OpenScopeRoot refuses an absent directory, so this must run before any
// data verb on a fresh scope.
func (e *localVolumeEngine) ProvisionScope(_ context.Context, scope ScopeID) error {
	if err := validateScopeID(scope); err != nil {
		return err
	}
	scopePath := e.scopePath(scope)

	info, err := os.Lstat(scopePath)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: scope dir %q is a symbolic link, refusing provision", ErrInvalidPath, scope)
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: scope %q", ErrNotADirectory, scope)
		}
		if err := os.RemoveAll(scopePath); err != nil {
			return fmt.Errorf("objectstore: erase scope %q at provision: %w", scope, err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("objectstore: lstat scope %q: %w", scope, err)
	}

	if err := os.MkdirAll(scopePath, 0o700); err != nil {
		return fmt.Errorf("objectstore: provision scope %q: %w", scope, err)
	}
	if err := os.Mkdir(filepath.Join(scopePath, stagingDirName), 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("objectstore: provision staging area for %q: %w", scope, err)
	}
	return nil
}

// TeardownScope erases ALL contents of the scope directory and recreates it
// empty — erase-before-reuse (NFR-SEC-54): after it returns, a re-grant of
// the same filesystem_id reads fs.ErrNotExist for every prior path.
//
// SEC-54 boundary: this is an OS-level remove+recreate, NOT a cryptographic
// erase — the substrate is operator disk and freed blocks may persist until
// overwritten by unrelated writes. Crypto-erase (per-session DEK) is the
// deferred full-shelf arm.
//
// A symlinked scope entry is refused with ErrInvalidPath BEFORE any removal:
// os.RemoveAll on a symlink would erase the link target's contents, which
// may live outside baseDir (T-03-05). The erase runs from the parent via
// os.RemoveAll(scopePath) — os.Root.RemoveAll(".") is platform-unreliable
// for removing a root's own contents and is deliberately not used.
//
// The staging area goes down with the scope (it lives inside it) and is NOT
// recreated here: after teardown the scope directory is fully empty. The
// next ProvisionScope — or, defensively, the next write's on-demand
// creation — restores it.
func (e *localVolumeEngine) TeardownScope(_ context.Context, scope ScopeID) error {
	if err := validateScopeID(scope); err != nil {
		return err
	}
	scopePath := e.scopePath(scope)

	info, err := os.Lstat(scopePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Already gone — recreate so the scope is usable on re-grant.
			if err := os.MkdirAll(scopePath, 0o700); err != nil {
				return fmt.Errorf("objectstore: recreate scope %q: %w", scope, err)
			}
			return nil
		}
		return fmt.Errorf("objectstore: lstat scope %q: %w", scope, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: scope dir %q is a symbolic link, refusing teardown", ErrInvalidPath, scope)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: scope %q", ErrNotADirectory, scope)
	}

	if err := os.RemoveAll(scopePath); err != nil {
		return fmt.Errorf("objectstore: remove scope %q: %w", scope, err)
	}
	if err := os.MkdirAll(scopePath, 0o700); err != nil {
		return fmt.Errorf("objectstore: recreate scope %q: %w", scope, err)
	}

	// Best-effort parent fsync so the recreated entry is durable. On Linux
	// fsync on a directory fd is meaningful; darwin no-ops it. The erase
	// itself already completed, so a sync failure never fails the teardown.
	if parent, err := os.Open(e.baseDir); err == nil {
		_ = parent.Sync()
		_ = parent.Close()
	}
	return nil
}

// List returns ONE level of the named directory — non-recursive by design;
// recursion is the caller's composition. The literal path "." names the
// scope root: ValidatePath rejects "." because a data path must name an
// object inside the scope, so the scope root is special-cased here — it is
// the containment root itself and cannot escape.
func (e *localVolumeEngine) List(_ context.Context, scope ScopeID, path string) ([]FileInfo, error) {
	sr, err := e.openScope(scope)
	if err != nil {
		return nil, err
	}
	defer sr.Close()

	cleanPath := "."
	if path != "." {
		cleanPath, err = guestPath(path)
		if err != nil {
			return nil, err
		}
	}

	entries, err := fs.ReadDir(sr.root.FS(), cleanPath)
	if err != nil {
		return nil, fmt.Errorf("objectstore: list: %w", err)
	}
	out := make([]FileInfo, 0, len(entries))
	for _, entry := range entries {
		if cleanPath == "." && entry.Name() == stagingDirName {
			// The broker-internal staging area is guest-invisible: it never
			// appears in a listing of the scope root (SEC-54).
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("objectstore: list entry %q: %w", entry.Name(), err)
		}
		out = append(out, toFileInfo(info))
	}
	return out, nil
}

// Stat returns metadata for the named object.
func (e *localVolumeEngine) Stat(_ context.Context, scope ScopeID, path string) (FileInfo, error) {
	sr, err := e.openScope(scope)
	if err != nil {
		return FileInfo{}, err
	}
	defer sr.Close()

	cleanPath, err := guestPath(path)
	if err != nil {
		return FileInfo{}, err
	}
	info, err := sr.root.Stat(cleanPath)
	if err != nil {
		return FileInfo{}, fmt.Errorf("objectstore: stat: %w", err)
	}
	return toFileInfo(info), nil
}

// MakeDir creates the named directory, single level (Mkdir, not MkdirAll):
// a missing parent refuses, mirroring POSIX mkdir semantics.
func (e *localVolumeEngine) MakeDir(_ context.Context, scope ScopeID, path string) error {
	sr, err := e.openScope(scope)
	if err != nil {
		return err
	}
	defer sr.Close()

	cleanPath, err := guestPath(path)
	if err != nil {
		return err
	}
	if err := sr.root.Mkdir(cleanPath, 0o700); err != nil {
		return fmt.Errorf("objectstore: mkdir: %w", err)
	}
	return nil
}

// MoveDir renames a directory within the scope. See renameWithin for the
// overwrite and escape semantics.
func (e *localVolumeEngine) MoveDir(_ context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	return e.renameWithin(scope, src, dst, overwrite)
}

// MoveFile renames a file within the scope. See renameWithin for the
// overwrite and escape semantics.
func (e *localVolumeEngine) MoveFile(_ context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	return e.renameWithin(scope, src, dst, overwrite)
}

// renameWithin is the shared move verb: both paths validate lexically, then
// the os.Root verbs confine BOTH ends — an escaping end surfaces as
// *os.LinkError, which isPathEscape normalizes into the one caller-visible
// escape class (T-03-04). With overwrite true a file destination is
// replaced (a non-empty directory destination still refuses at the OS
// layer, per rename(2)).
//
// With overwrite FALSE the no-replace commit is ATOMIC for files: the
// source is link(2)-ed under the destination name — link fails EEXIST if
// the destination exists, with no stat-then-rename TOCTOU window for a
// concurrent writer to slip into — then the source name is unlinked.
// Directories cannot be hard-linked, so a directory move keeps the
// existence pre-check + rename; rename(2) onto a NON-EMPTY directory still
// refuses at the OS layer, leaving only an empty-directory destination
// replaceable in that residual window (the wire moveDirectory op carries no
// overwrite knob and always runs overwrite=false).
func (e *localVolumeEngine) renameWithin(scope ScopeID, src, dst string, overwrite bool) error {
	sr, err := e.openScope(scope)
	if err != nil {
		return err
	}
	defer sr.Close()

	cleanSrc, err := guestPath(src)
	if err != nil {
		return err
	}
	cleanDst, err := guestPath(dst)
	if err != nil {
		return err
	}

	if overwrite {
		if err := sr.root.Rename(cleanSrc, cleanDst); err != nil {
			return fmt.Errorf("objectstore: rename: %w", err)
		}
		return nil
	}

	info, err := sr.root.Lstat(cleanSrc)
	if err != nil {
		return fmt.Errorf("objectstore: stat source: %w", err)
	}
	if info.IsDir() {
		// Directory no-replace: pre-check + rename (see the verb comment for
		// the residual empty-directory window).
		if _, err := sr.root.Stat(cleanDst); err == nil {
			return ErrAlreadyExists
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("objectstore: stat destination: %w", err)
		}
		if err := sr.root.Rename(cleanSrc, cleanDst); err != nil {
			return fmt.Errorf("objectstore: rename: %w", err)
		}
		return nil
	}

	// File no-replace: atomic link-then-unlink. EEXIST is the loser of a
	// concurrent race and maps to the typed collision sentinel.
	if err := sr.root.Link(cleanSrc, cleanDst); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrAlreadyExists
		}
		return fmt.Errorf("objectstore: link: %w", err)
	}
	if err := sr.root.Remove(cleanSrc); err != nil {
		// The destination link landed but the source could not be unlinked:
		// roll the link back so the move is never half-applied.
		_ = sr.root.Remove(cleanDst)
		return fmt.Errorf("objectstore: unlink source after link: %w", err)
	}
	return nil
}

// RemoveDir removes the named directory AND its contents — recursive by
// default (RemoveAll), chosen because the wire verb tears down a subtree and
// a non-recursive rmdir is expressible as List+guard by the caller if ever
// needed. Removing a missing path is a no-op, per RemoveAll semantics.
func (e *localVolumeEngine) RemoveDir(_ context.Context, scope ScopeID, path string) error {
	sr, err := e.openScope(scope)
	if err != nil {
		return err
	}
	defer sr.Close()

	cleanPath, err := guestPath(path)
	if err != nil {
		return err
	}
	if err := sr.root.RemoveAll(cleanPath); err != nil {
		return fmt.Errorf("objectstore: remove dir: %w", err)
	}
	return nil
}

// RemoveFile removes the named file (or empty directory, per remove(2)).
func (e *localVolumeEngine) RemoveFile(_ context.Context, scope ScopeID, path string) error {
	sr, err := e.openScope(scope)
	if err != nil {
		return err
	}
	defer sr.Close()

	cleanPath, err := guestPath(path)
	if err != nil {
		return err
	}
	if err := sr.root.Remove(cleanPath); err != nil {
		return fmt.Errorf("objectstore: remove file: %w", err)
	}
	return nil
}

// CopyFile duplicates a file's bytes within the scope as a composed stream
// (no native copy verb exists on the containment root): open source, write
// into a unique temp name, commit into place. The destination is therefore
// atomic exactly like WriteStream. With overwrite false an existing
// destination refuses with ErrAlreadyExists — enforced ATOMICALLY at the
// link commit (no stat-then-rename TOCTOU); the early Stat is a fast-path
// reject only, sparing the byte copy.
func (e *localVolumeEngine) CopyFile(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	sr, err := e.openScope(scope)
	if err != nil {
		return err
	}
	defer sr.Close()

	cleanDst, err := guestPath(dst)
	if err != nil {
		return err
	}
	if !overwrite {
		if _, err := sr.root.Stat(cleanDst); err == nil {
			return ErrAlreadyExists
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("objectstore: stat destination: %w", err)
		}
	}

	cleanSrc, err := guestPath(src)
	if err != nil {
		return err
	}
	srcF, err := sr.root.Open(cleanSrc) // contained open
	if err != nil {
		return err
	}
	defer srcF.Close()

	return writeTempAndCommit(sr, cleanDst, ctxReader{ctx: ctx, r: srcF}, overwrite)
}

// ReadRange streams the half-open byte range [offset, offset+length) of the
// named file into w. A range extending past EOF short-reads to EOF without
// error (io.LimitReader absorbs the EOF); an offset at or past EOF yields
// zero bytes without error. No whole-object buffering.
func (e *localVolumeEngine) ReadRange(ctx context.Context, scope ScopeID, path string, offset, length int64, w io.Writer) error {
	sr, err := e.openScope(scope)
	if err != nil {
		return err
	}
	defer sr.Close()

	cleanPath, err := guestPath(path)
	if err != nil {
		return err
	}
	f, err := sr.root.Open(cleanPath) // contained open
	if err != nil {
		return err
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("objectstore: seek: %w", err)
		}
	}
	if _, err := io.Copy(w, ctxReader{ctx: ctx, r: io.LimitReader(f, length)}); err != nil {
		return fmt.Errorf("objectstore: read range: %w", err)
	}
	return nil
}

// WriteStream consumes r into the named file without whole-object buffering
// — size ceilings are the caller's layer, never re-implemented here. The
// bytes land in a unique temp name and commit into place, so a partial
// write is invisible at the destination and removed on any error path
// (T-03-03). With overwrite false an existing destination refuses with
// ErrAlreadyExists — enforced ATOMICALLY at the link commit (no
// stat-then-rename TOCTOU: of two concurrent overwrite=false writers
// exactly one wins); the early Stat is a fast-path reject only, sparing the
// stream consumption.
func (e *localVolumeEngine) WriteStream(ctx context.Context, scope ScopeID, path string, r io.Reader, overwrite bool) error {
	sr, err := e.openScope(scope)
	if err != nil {
		return err
	}
	defer sr.Close()

	cleanPath, err := guestPath(path)
	if err != nil {
		return err
	}

	if !overwrite {
		if _, err := sr.root.Stat(cleanPath); err == nil {
			return ErrAlreadyExists
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("objectstore: stat destination: %w", err)
		}
	}

	return writeTempAndCommit(sr, cleanPath, ctxReader{ctx: ctx, r: r}, overwrite)
}

// writeTempAndCommit is the shared atomic-write tail for WriteStream and
// CopyFile: stream into a process-unique temp name inside the broker-
// internal staging area at the scope root (guest-invisible: never listed,
// unaddressable, and swept by Provision/Teardown so a crashed partial write
// never survives into a later session — SEC-54), fsync, then commit into
// place. The staging area and the destination live in the same scope
// directory tree on one filesystem, so the rename/link commit is atomic.
// The random suffix prevents temp-name collision under concurrent writes to
// the same destination (T-03-06). On ANY error the temp is removed; on
// success no temp remains. cleanDst has already passed the guest-path
// validation — containment of the temp name itself is still enforced by
// the root on open.
//
// The commit is replace-aware: with replace true the temp RENAMES into
// place (replacing an existing destination); with replace false the temp is
// LINK(2)-ed under the destination name — link fails EEXIST if the
// destination exists, making the no-replace decision atomic at the kernel
// (no stat-then-rename TOCTOU) — and the temp name is then removed by the
// deferred cleanup.
func writeTempAndCommit(sr *ScopeRoot, cleanDst string, r io.Reader, replace bool) error {
	// On-demand staging creation: a teardown leaves the scope fully empty,
	// and the next write restores the area without requiring a re-provision.
	if err := sr.root.Mkdir(stagingDirName, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("objectstore: create staging area: %w", err)
	}
	tmpName := filepath.Join(stagingDirName,
		filepath.Base(cleanDst)+".tmp."+strconv.FormatUint(rand.Uint64(), 36))

	f, err := sr.root.OpenFile(tmpName, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("objectstore: create temp: %w", err)
	}

	cleanup := true
	defer func() {
		_ = f.Close() // no-op after the explicit Close below
		if cleanup {
			_ = sr.root.Remove(tmpName)
		}
	}()

	if _, err := io.Copy(f, r); err != nil {
		return fmt.Errorf("objectstore: write stream: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("objectstore: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("objectstore: close temp: %w", err)
	}

	if !replace {
		// Atomic no-replace commit: exactly one concurrent writer's link
		// lands; every loser observes EEXIST -> the typed collision
		// sentinel. cleanup stays true — the temp NAME is removed either
		// way (on success the bytes now live under cleanDst).
		if err := sr.root.Link(tmpName, cleanDst); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return ErrAlreadyExists
			}
			return fmt.Errorf("objectstore: link into place: %w", err)
		}
		return nil
	}

	if err := sr.root.Rename(tmpName, cleanDst); err != nil {
		// cleanup is still true — the deferred Remove reclaims the temp.
		return fmt.Errorf("objectstore: rename into place: %w", err)
	}
	cleanup = false
	return nil
}
