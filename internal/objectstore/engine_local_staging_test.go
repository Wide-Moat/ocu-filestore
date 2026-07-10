// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalEngine_CrashRestartPreservesOwnerData pins the create-if-absent
// crash path (T1-10): a daemon that crashed mid-session never ran
// TeardownScope, so the scope directory is dirty when the restarted daemon
// provisions it again. ProvisionScope on an existing scope PRESERVES owner
// data — the prior session's bytes must still Stat OK and be readable after
// re-provision, so the owner is never evicted by a process restart.
func TestLocalEngine_CrashRestartPreservesOwnerData(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	scope := ScopeID("fs-crash-01")

	// Session one: provision, write, then CRASH — no TeardownScope.
	eng := NewLocalVolumeEngine(base)
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope (session one): %v", err)
	}
	if err := eng.WriteStream(ctx, scope, "secret.bin", bytes.NewReader([]byte("PRIORSESSION")), false); err != nil {
		t.Fatalf("WriteStream (session one): %v", err)
	}
	if err := eng.MakeDir(ctx, scope, "d"); err != nil {
		t.Fatalf("MakeDir (session one): %v", err)
	}
	if err := eng.WriteStream(ctx, scope, "d/deep.bin", bytes.NewReader([]byte("DEEP")), false); err != nil {
		t.Fatalf("WriteStream deep (session one): %v", err)
	}

	// Restart: a fresh engine instance re-provisions the SAME scope.
	restarted := NewLocalVolumeEngine(base)
	if err := restarted.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope (restart): %v", err)
	}

	// Owner data SURVIVES re-provision — a process restart must not evict data.
	for _, p := range []string{"secret.bin", "d", "d/deep.bin"} {
		if _, err := restarted.Stat(ctx, scope, p); err != nil {
			t.Fatalf("Stat(%q after crash re-provision) = %v, want still present (owner data must survive)", p, err)
		}
	}
	// The re-provisioned scope also serves fresh writes.
	if err := restarted.WriteStream(ctx, scope, "fresh.bin", bytes.NewReader([]byte("FRESH")), false); err != nil {
		t.Fatalf("WriteStream after re-provision: %v", err)
	}
}

// TestLocalEngine_ProvisionSweepsOrphanedStaging pins the crash-sweep half:
// a partial write orphaned in the staging area by a crashed daemon (the
// temp never committed, never cleaned) is removed by the next provision.
func TestLocalEngine_ProvisionSweepsOrphanedStaging(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	scope := ScopeID("fs-orphan-01")
	eng := NewLocalVolumeEngine(base)
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}

	// Simulate the crash leftover directly on disk.
	orphan := filepath.Join(base, string(scope), stagingDirName, "victim.bin.tmp.deadbeef")
	if err := os.WriteFile(orphan, []byte("HALFWRITTEN"), 0o600); err != nil {
		t.Fatalf("plant orphan temp: %v", err)
	}

	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("re-ProvisionScope: %v", err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("orphaned staging temp survived the provision sweep: %v", err)
	}
	// The staging area itself is back, empty, ready to serve.
	staged, err := os.ReadDir(filepath.Join(base, string(scope), stagingDirName))
	if err != nil {
		t.Fatalf("read staging area after sweep: %v", err)
	}
	if len(staged) != 0 {
		t.Fatalf("staging area not empty after sweep: %d entries", len(staged))
	}
}

// TestLocalEngine_StagingInvisibleToGuest pins the guest-invisibility of the
// staging area: it exists on disk (backend truth), yet it never appears in a
// listing of the scope root and is unaddressable through EVERY data verb —
// read, write, list, stat, move (either end), copy (either end), mkdir, and
// remove all refuse with ErrInvalidPath.
func TestLocalEngine_StagingInvisibleToGuest(t *testing.T) {
	ctx := context.Background()
	eng, base, scope := newLocalEngine(t)

	// A write exercises the staging area for real.
	if err := eng.WriteStream(ctx, scope, "visible.txt", strings.NewReader("guest bytes"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}

	// Backend truth: the staging dir IS on disk...
	if fi, err := os.Lstat(filepath.Join(base, string(scope), stagingDirName)); err != nil || !fi.IsDir() {
		t.Fatalf("staging dir missing on disk (fi=%v err=%v); the invisibility must be a filter, not absence", fi, err)
	}
	// ...and the guest listing of the scope root never shows it.
	entries, err := eng.List(ctx, scope, ".")
	if err != nil {
		t.Fatalf("List(.): %v", err)
	}
	for _, fi := range entries {
		if fi.Name == stagingDirName {
			t.Fatalf("List(.) surfaced the staging area %q (SEC-54 guest-invisibility)", fi.Name)
		}
	}
	if len(entries) != 1 || entries[0].Name != "visible.txt" {
		t.Fatalf("List(.) = %+v, want exactly [visible.txt]", entries)
	}

	// Every data verb refuses to address the reserved name.
	stagedPath := stagingDirName + "/x"
	var sink bytes.Buffer
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"List", func() error { _, err := eng.List(ctx, scope, stagingDirName); return err }},
		{"Stat", func() error { _, err := eng.Stat(ctx, scope, stagingDirName); return err }},
		{"StatChild", func() error { _, err := eng.Stat(ctx, scope, stagedPath); return err }},
		{"MakeDir", func() error { return eng.MakeDir(ctx, scope, stagingDirName+"/evil") }},
		{"WriteStream", func() error {
			return eng.WriteStream(ctx, scope, stagedPath, strings.NewReader("x"), true)
		}},
		{"ReadRange", func() error { return eng.ReadRange(ctx, scope, stagedPath, 0, 1, &sink) }},
		{"RemoveFile", func() error { return eng.RemoveFile(ctx, scope, stagedPath) }},
		{"RemoveDir", func() error { return eng.RemoveDir(ctx, scope, stagingDirName) }},
		{"MoveFileSrc", func() error { return eng.MoveFile(ctx, scope, stagedPath, "out.txt", false) }},
		{"MoveFileDst", func() error { return eng.MoveFile(ctx, scope, "visible.txt", stagedPath, false) }},
		{"MoveDirSrc", func() error { return eng.MoveDir(ctx, scope, stagingDirName, "out", false) }},
		{"CopyFileSrc", func() error { return eng.CopyFile(ctx, scope, stagedPath, "out.txt", false) }},
		{"CopyFileDst", func() error { return eng.CopyFile(ctx, scope, "visible.txt", stagedPath, false) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("%s(%s...) = %v, want ErrInvalidPath (reserved name)", tc.name, stagingDirName, err)
			}
		})
	}

	// A DEEPER component with the same name is NOT reserved: the area lives
	// only at the scope root, and a guest dir legitimately named like it
	// elsewhere stays fully usable.
	if err := eng.MakeDir(ctx, scope, "d"); err != nil {
		t.Fatalf("MakeDir(d): %v", err)
	}
	nested := "d/" + stagingDirName
	if err := eng.MakeDir(ctx, scope, nested); err != nil {
		t.Fatalf("MakeDir(%q) = %v, want nil (only the root name is reserved)", nested, err)
	}
	if err := eng.WriteStream(ctx, scope, nested+"/f.txt", strings.NewReader("ok"), false); err != nil {
		t.Fatalf("WriteStream(%q/f.txt) = %v, want nil", nested, err)
	}
}

// TestLocalEngine_TeardownLeavesScopeFullyEmpty pins the stop-path shape the
// live e2e asserts: after TeardownScope the scope directory exists and holds
// NOTHING — not even the staging area (it is restored on demand by the next
// write, or by the next provision).
func TestLocalEngine_TeardownLeavesScopeFullyEmpty(t *testing.T) {
	ctx := context.Background()
	eng, base, scope := newLocalEngine(t)

	if err := eng.WriteStream(ctx, scope, "f.txt", strings.NewReader("x"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := eng.TeardownScope(ctx, scope); err != nil {
		t.Fatalf("TeardownScope: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(base, string(scope)))
	if err != nil {
		t.Fatalf("read scope dir after teardown: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("scope dir after teardown = %v, want fully empty", names)
	}

	// Defensive on-demand restore: a write straight after teardown (no
	// re-provision) recreates the staging area and succeeds.
	if err := eng.WriteStream(ctx, scope, "g.txt", strings.NewReader("y"), false); err != nil {
		t.Fatalf("WriteStream after teardown (on-demand staging) = %v, want nil", err)
	}
}
