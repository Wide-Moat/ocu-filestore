// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProvisionScope_DirtyScopePreserved pins the create-if-absent branch of
// ProvisionScope: an existing scope directory left dirty by a prior session is
// NOT erased — its contents survive re-provision. ProvisionScope only ensures
// the directory exists and the staging area is reset; it never touches owner data.
func TestProvisionScope_DirtyScopePreserved(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID("dirty")

	scopeDir := filepath.Join(base, string(scope))
	if err := os.MkdirAll(filepath.Join(scopeDir, "old", "deep"), 0o700); err != nil {
		t.Fatalf("seed dirty scope: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scopeDir, "old", "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("seed stale file: %v", err)
	}

	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope over dirty: %v", err)
	}
	// The prior tree SURVIVES — owner data is never erased at provision.
	if _, err := os.Stat(filepath.Join(scopeDir, "old", "stale.txt")); err != nil {
		t.Fatalf("stale.txt after provision = %v, want still present (owner data must survive)", err)
	}
	// The provisioned scope still serves a normal write.
	if _, err := eng.WriteStream(ctx, scope, "fresh.txt", strings.NewReader("fresh"), false); err != nil {
		t.Fatalf("WriteStream after provision: %v", err)
	}
}

// TestProvisionScope_OwnerDataPreservedOnReProvision (N2-local) pins that
// ProvisionScope is safe to call on an already-provisioned, live scope:
// owner bytes written via the engine API survive a second ProvisionScope call
// and remain readable. Only the staging area is swept; the owner's files are
// never touched.
func TestProvisionScope_OwnerDataPreservedOnReProvision(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID("reprovision")

	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope (first): %v", err)
	}
	if _, err := eng.WriteStream(ctx, scope, "owner.bin", strings.NewReader("OWNER"), false); err != nil {
		t.Fatalf("WriteStream (owner): %v", err)
	}
	if err := eng.MakeDir(ctx, scope, "subdir"); err != nil {
		t.Fatalf("MakeDir (subdir): %v", err)
	}
	if _, err := eng.WriteStream(ctx, scope, "subdir/deep.bin", strings.NewReader("DEEP"), false); err != nil {
		t.Fatalf("WriteStream (deep): %v", err)
	}

	// Re-provision: must be idempotent, never evict owner data.
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope (second): %v", err)
	}
	for _, p := range []string{"owner.bin", "subdir", "subdir/deep.bin"} {
		if _, err := eng.Stat(ctx, scope, p); err != nil {
			t.Fatalf("Stat(%q) after re-provision = %v, want still present", p, err)
		}
	}
	var b strings.Builder
	if err := eng.ReadRange(ctx, scope, "owner.bin", 0, 16, &b); err != nil || b.String() != "OWNER" {
		t.Fatalf("ReadRange(owner.bin) = %q, %v; want OWNER", b.String(), err)
	}
}

// TestProvisionScope_SymlinkRefused pins the T-03-05 guard on the PROVISION
// path (the teardown twin is already pinned): a symlinked scope entry is
// refused with ErrInvalidPath before any RemoveAll, and the link target's
// contents survive — provision never follows the link into an erase.
func TestProvisionScope_SymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)

	outside := t.TempDir()
	keep := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(keep, []byte("must survive"), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "linked")); err != nil {
		t.Fatalf("plant scope symlink: %v", err)
	}

	if err := eng.ProvisionScope(ctx, ScopeID("linked")); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("ProvisionScope on symlinked scope = %v, want ErrInvalidPath", err)
	}
	if got, err := os.ReadFile(keep); err != nil || string(got) != "must survive" {
		t.Fatalf("symlink target damaged by provision: content=%q err=%v", got, err)
	}
}

// TestProvisionScope_NotADirectory pins the non-directory branch of
// ProvisionScope: a plain file occupying the scope entry refuses
// ErrNotADirectory before any erase, and the file is left intact.
func TestProvisionScope_NotADirectory(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)

	entry := filepath.Join(base, "plainfile")
	if err := os.WriteFile(entry, []byte("not a dir"), 0o644); err != nil {
		t.Fatalf("write plain file: %v", err)
	}
	if err := eng.ProvisionScope(ctx, ScopeID("plainfile")); !errors.Is(err, ErrNotADirectory) {
		t.Fatalf("ProvisionScope on plain file = %v, want ErrNotADirectory", err)
	}
	if got, err := os.ReadFile(entry); err != nil || string(got) != "not a dir" {
		t.Fatalf("plain file after refused provision: content=%q err=%v", got, err)
	}
}

// TestRenameWithin_FileDestExistsNoReplace pins the no-replace file move
// collision: an overwrite=false MoveFile onto an existing destination refuses
// with ErrAlreadyExists (the atomic link-then-unlink loser), and BOTH the
// source and the pre-existing destination survive intact.
func TestRenameWithin_FileDestExistsNoReplace(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID("rn")
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}
	if _, err := eng.WriteStream(ctx, scope, "src.txt", strings.NewReader("source"), false); err != nil {
		t.Fatalf("WriteStream src: %v", err)
	}
	if _, err := eng.WriteStream(ctx, scope, "dst.txt", strings.NewReader("existing"), false); err != nil {
		t.Fatalf("WriteStream dst: %v", err)
	}

	if err := eng.MoveFile(ctx, scope, "src.txt", "dst.txt", false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("MoveFile(no-replace onto existing) = %v, want ErrAlreadyExists", err)
	}
	// Source survived (the loser never unlinks its source).
	var sb strings.Builder
	if err := eng.ReadRange(ctx, scope, "src.txt", 0, 64, &sb); err != nil || sb.String() != "source" {
		t.Fatalf("source after refused move = %q, %v; want %q", sb.String(), err, "source")
	}
	// Destination untouched.
	var db strings.Builder
	if err := eng.ReadRange(ctx, scope, "dst.txt", 0, 64, &db); err != nil || db.String() != "existing" {
		t.Fatalf("destination after refused move = %q, %v; want %q", db.String(), err, "existing")
	}
}

// TestRenameWithin_LinkRollback pins the half-applied-move rollback branch of
// the no-replace file move: when the destination link lands but the source
// unlink fails, the engine removes the link so the move is NEVER half-applied
// (a duplicate is not left behind). The unlink failure is forced by making the
// source's parent directory non-writable (POSIX requires write on the parent
// to unlink a child) — a real filesystem fault, not a mock.
func TestRenameWithin_LinkRollback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX parent-write unlink semantics not applicable on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses the parent-write permission fault")
	}
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID("rollback")
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}
	// Source lives in a subdirectory whose write bit we strip; the
	// destination lives at the scope root so the link itself succeeds.
	if err := eng.MakeDir(ctx, scope, "src"); err != nil {
		t.Fatalf("MakeDir(src): %v", err)
	}
	if _, err := eng.WriteStream(ctx, scope, "src/f.txt", strings.NewReader("payload"), false); err != nil {
		t.Fatalf("WriteStream(src/f.txt): %v", err)
	}

	srcDir := filepath.Join(base, string(scope), "src")
	if err := os.Chmod(srcDir, 0o500); err != nil { // r-x: no write -> unlink fails
		t.Fatalf("chmod src dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(srcDir, 0o700) })

	err := eng.MoveFile(ctx, scope, "src/f.txt", "dst.txt", false)
	if err == nil {
		t.Fatal("MoveFile with unremovable source = nil, want unlink-source failure")
	}
	if !strings.Contains(err.Error(), "unlink source after link") {
		t.Fatalf("MoveFile error = %v, want unlink-source-after-link rollback", err)
	}
	// Rollback removed the landed link: the destination must NOT exist (no
	// duplicate left behind).
	if _, err := os.Stat(filepath.Join(base, string(scope), "dst.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("destination after rollback = %v, want fs.ErrNotExist (link rolled back)", err)
	}
	// The source still exists (the move was refused, not half-applied).
	if _, err := os.Stat(filepath.Join(srcDir, "f.txt")); err != nil {
		t.Fatalf("source after rollback = %v, want intact", err)
	}
}

// TestRenameWithin_DirDestExistsNoReplace pins the directory no-replace
// pre-check: a directory move onto an existing destination directory refuses
// with ErrAlreadyExists and the source directory survives.
func TestRenameWithin_DirDestExistsNoReplace(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID("dirmove")
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}
	if err := eng.MakeDir(ctx, scope, "from"); err != nil {
		t.Fatalf("MakeDir(from): %v", err)
	}
	if err := eng.MakeDir(ctx, scope, "to"); err != nil {
		t.Fatalf("MakeDir(to): %v", err)
	}
	if err := eng.MoveDir(ctx, scope, "from", "to", false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("MoveDir(no-replace onto existing dir) = %v, want ErrAlreadyExists", err)
	}
	if fi, err := eng.Stat(ctx, scope, "from"); err != nil || !fi.IsDir {
		t.Fatalf("source dir after refused move = %+v, %v; want intact dir", fi, err)
	}
}

// TestWriteTempAndCommit_RecreatesStagingAfterTeardown pins the on-demand
// staging restoration branch of writeTempAndCommit: after a teardown leaves
// the scope fully empty (no staging area), the next write recreates the
// staging area on demand rather than failing.
func TestWriteTempAndCommit_RecreatesStagingAfterTeardown(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID("staging")

	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}
	if err := eng.TeardownScope(ctx, scope); err != nil {
		t.Fatalf("TeardownScope: %v", err)
	}
	// After teardown the scope dir exists but is fully empty (no staging).
	scopeDir := filepath.Join(base, string(scope))
	if _, err := os.Stat(filepath.Join(scopeDir, stagingDirName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("staging area after teardown = %v, want absent", err)
	}

	// The next write recreates the staging area on demand and commits.
	if _, err := eng.WriteStream(ctx, scope, "after.txt", strings.NewReader("after teardown"), false); err != nil {
		t.Fatalf("WriteStream after teardown: %v", err)
	}
	if _, err := os.Stat(filepath.Join(scopeDir, stagingDirName)); err != nil {
		t.Fatalf("staging area after on-demand write = %v, want recreated", err)
	}
	var b strings.Builder
	if err := eng.ReadRange(ctx, scope, "after.txt", 0, 64, &b); err != nil || b.String() != "after teardown" {
		t.Fatalf("written content = %q, %v; want %q", b.String(), err, "after teardown")
	}
}

// TestReadRange_SeekErrorOnDirectory pins ReadRange's open-target refusal: a
// directory target cannot be range-read — the contained Open (or the copy)
// surfaces an error rather than streaming directory bytes.
func TestReadRange_DirectoryTarget(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID("rr")
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}
	if err := eng.MakeDir(ctx, scope, "adir"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	var b strings.Builder
	if err := eng.ReadRange(ctx, scope, "adir", 0, 64, &b); err == nil {
		t.Fatal("ReadRange on a directory = nil, want a read error")
	}
}
