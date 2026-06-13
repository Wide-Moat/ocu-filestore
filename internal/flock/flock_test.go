// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package flock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestAcquireAndRelease verifies the basic lock lifecycle:
//   - First Acquire succeeds.
//   - Second Acquire on the same path while the first is held returns
//     ErrAlreadyRunning (the audit-chain interleaving guard).
//   - After Release, a new Acquire on the same path succeeds.
func TestAcquireAndRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ocu-filestored.lock")

	// First acquisition must succeed.
	l1, err := Acquire(path)
	if err != nil {
		t.Fatalf("first Acquire = %v, want nil error", err)
	}

	// Second acquisition on the SAME path while l1 is held must return
	// ErrAlreadyRunning — another daemon instance must be refused.
	l2, err := Acquire(path)
	if !errors.Is(err, ErrAlreadyRunning) {
		if l2 != nil {
			l2.Release()
		}
		t.Fatalf("second Acquire = %v, want ErrAlreadyRunning", err)
	}
	if l2 != nil {
		t.Fatalf("second Acquire returned a non-nil Lock with ErrAlreadyRunning")
	}

	// Release the first lock.
	l1.Release()

	// After release, a fresh acquisition must succeed.
	l3, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire after Release = %v, want nil error", err)
	}
	l3.Release()
}

// TestAcquireFailsOnBadPath verifies that an uncreateable path (a directory
// that does not exist and cannot be created because the parent is read-only)
// returns an OS error, NOT ErrAlreadyRunning — the caller needs to
// distinguish a configuration error from a running-instance conflict.
func TestAcquireFailsOnBadPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent-dir", ".ocu-filestored.lock")
	l, err := Acquire(path)
	if err == nil {
		l.Release()
		t.Fatal("Acquire on a bad path returned nil error, want an OS error")
	}
	if errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("Acquire on a bad path returned ErrAlreadyRunning, want an OS-level error (e.g. ENOENT)")
	}
}

// TestReleaseIsIdempotent verifies that calling Release twice does not panic
// or return an error — the daemon's shutdown path may call Close on a Lock
// that is already released.
func TestReleaseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ocu-filestored.lock")

	l, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire = %v", err)
	}
	l.Release()
	l.Release() // must not panic
}

// TestLockFileIsCreated verifies that Acquire creates the lock file on disk
// so operators can observe it (and so that stale-lock cleanup is predictable).
func TestLockFileIsCreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ocu-filestored.lock")

	l, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire = %v", err)
	}
	defer l.Release()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("lock file %q was not created on disk", path)
	}
}
