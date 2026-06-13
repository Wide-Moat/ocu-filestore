// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package flock provides a single-instance advisory lock backed by an
// exclusive LOCK_NB flock(2) on a well-known lock file. Taking the lock
// before binding any socket guarantees that only one daemon writes to the
// same audit hash chain and the same scope's socket directory at a time —
// two concurrent daemons would interleave audit writes and corrupt the
// chain's hash linkage (T2-7, LIFE-07).
//
// flock(2) is available on both Linux and darwin (this project's dev+prod
// platforms). LOCK_NB makes the attempt non-blocking: a locked file returns
// errAlreadyRunning immediately instead of blocking until the holder exits.
// The lock is held by the process for its entire lifetime; it is released
// automatically by the kernel when the process exits, even on SIGKILL, so
// there is no stale-lock problem.
package flock

import (
	"errors"
	"os"
	"syscall"
)

// errAlreadyRunning is returned by Acquire when another daemon holds the
// lock. Match it with errors.Is.
var errAlreadyRunning = errors.New("flock: another instance is already running (lock held)")

// ErrAlreadyRunning is the exported alias for errAlreadyRunning, accessible
// to callers outside the package (e.g. main.go) without importing an
// otherwise-internal symbol. The values are identical; errors.Is matches.
var ErrAlreadyRunning = errAlreadyRunning

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
			return nil, errAlreadyRunning
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
