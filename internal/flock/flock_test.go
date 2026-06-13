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

// auditLockSuffix mirrors the daemon's suffix for the audit-chain lock file
// (see cmd/ocu-filestored/main.go). The audit-chain lock is keyed on the
// audit-sink path itself so the lock names the resource it protects.
const auditLockSuffix = ".lock"

// TestAuditSinkLockKeyedOnSinkNotSocketDir reproduces flock-01: the
// audit-chain guard must be keyed on the -audit-sink resource, NOT on the
// -south-socket-dir. Two daemons pointed at the SAME audit sink but DIFFERENT
// socket directories must collide — otherwise both start and corrupt the one
// audit hash chain. The lock file is the sink path plus auditLockSuffix, so a
// shared sink yields a shared lock file regardless of socket directory.
func TestAuditSinkLockKeyedOnSinkNotSocketDir(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "audit.jsonl")

	// Daemon A: shared sink, socket dir A (irrelevant to the audit lock).
	lockA := sink + auditLockSuffix
	la, err := Acquire(lockA)
	if err != nil {
		t.Fatalf("daemon A audit-lock Acquire = %v, want nil", err)
	}
	defer la.Release()

	// Daemon B: SAME sink, DIFFERENT socket dir. Its audit lock file is
	// derived from the same sink path, so it must collide with daemon A.
	lockB := sink + auditLockSuffix
	lb, err := Acquire(lockB)
	if !errors.Is(err, ErrAlreadyRunning) {
		if lb != nil {
			lb.Release()
		}
		t.Fatalf("daemon B (same audit-sink, different socket-dir) audit-lock Acquire = %v, want ErrAlreadyRunning", err)
	}
	if lb != nil {
		t.Fatal("daemon B audit-lock returned a non-nil Lock alongside ErrAlreadyRunning")
	}
}

// TestDistinctAuditSinksDoNotCollide verifies that two daemons pointed at
// DIFFERENT audit sinks each take a DISTINCT audit-chain lock and both
// succeed — independent chains must not block one another.
func TestDistinctAuditSinksDoNotCollide(t *testing.T) {
	dir := t.TempDir()
	sink1 := filepath.Join(dir, "audit-1.jsonl")
	sink2 := filepath.Join(dir, "audit-2.jsonl")

	l1, err := Acquire(sink1 + auditLockSuffix)
	if err != nil {
		t.Fatalf("sink1 audit-lock Acquire = %v, want nil", err)
	}
	defer l1.Release()

	l2, err := Acquire(sink2 + auditLockSuffix)
	if err != nil {
		t.Fatalf("sink2 audit-lock Acquire (distinct sink) = %v, want nil — distinct chains must not block", err)
	}
	defer l2.Release()
}

// TestSameSinkSameSocketDirStillCollides verifies the default double-start
// (identical -audit-sink AND identical -south-socket-dir) is still refused:
// the audit lock alone already collides on the shared sink path.
func TestSameSinkSameSocketDirStillCollides(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "audit.jsonl")

	la, err := Acquire(sink + auditLockSuffix)
	if err != nil {
		t.Fatalf("first audit-lock Acquire = %v, want nil", err)
	}
	defer la.Release()

	lb, err := Acquire(sink + auditLockSuffix)
	if !errors.Is(err, ErrAlreadyRunning) {
		if lb != nil {
			lb.Release()
		}
		t.Fatalf("second audit-lock Acquire (same sink, same socket-dir) = %v, want ErrAlreadyRunning", err)
	}
	if lb != nil {
		t.Fatal("second audit-lock returned a non-nil Lock alongside ErrAlreadyRunning")
	}
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
