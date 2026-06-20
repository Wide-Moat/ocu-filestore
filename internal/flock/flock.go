// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package flock provides a single-instance advisory lock backed by an
// exclusive LOCK_NB flock(2) on a lock file that names a specific resource.
// Acquiring the lock for a resource before using it guarantees that only one
// daemon holds that resource at a time. The daemon takes one lock per shared
// resource it must protect (T2-7, LIFE-07):
//
//   - The audit hash chain: a lock keyed on the audit-sink file. Two daemons
//     pointed at the same sink would interleave appends and corrupt the
//     chain's hash linkage, so they must collide on this lock regardless of
//     any other flag — the sink is the resource, so the lock is keyed on it.
//   - The south-face bind address: a lock keyed on that resource. Two daemons
//     binding the same TCP listen address would clash on bind, so the default
//     double-start (same bind address) collides here. (Under REST/TLS the south
//     face binds a TCP port, not a unix socket; this lock is keyed on the bind
//     resource, whatever its concrete form.)
//
// Because each lock names its own resource, a collision on either resource is
// sufficient to refuse a second start, and neither guarantee depends on the
// other flag matching.
//
// flock(2) is available on both Linux and darwin (this project's dev+prod
// platforms). LOCK_NB makes the attempt non-blocking: a locked file returns
// ErrAlreadyRunning immediately instead of blocking until the holder exits.
// The lock is held by the process for its entire lifetime; it is released
// automatically by the kernel when the process exits, even on SIGKILL, so
// there is no stale-lock problem.
package flock

import (
	"errors"
	"os"
	"syscall"
)

// ErrAlreadyRunning is returned by Acquire when another daemon holds the
// lock. It is the single sentinel callers outside the package (e.g. main.go)
// match against with errors.Is.
var ErrAlreadyRunning = errors.New("flock: another instance is already running (lock held)")

// Lock is an exclusive advisory lock on a lock file. The zero value is
// invalid; use Acquire to obtain a Lock.
type Lock struct {
	f *os.File
}

// Acquire opens (or creates) the lock file at path and attempts to take an
// exclusive non-blocking flock. If another process holds the lock, it returns
// ErrAlreadyRunning. Any other OS error propagates as-is (e.g. permission
// denied creating the file).
//
// Callers MUST call Release when the daemon shuts down so the file descriptor
// is closed cleanly; the kernel also releases the lock automatically on
// process exit.
func Acquire(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		_ = f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release closes the file descriptor, which releases the flock and removes
// the hold. It is idempotent: a second call is a no-op.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = l.f.Close()
	l.f = nil
}
