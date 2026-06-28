// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// skipIfRoot skips tests that depend on a POSIX permission fault, which the
// superuser bypasses, and on platforms without the relevant semantics. Mirrors
// the audit sink's helper of the same name.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission-fault semantics not applicable on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses the permission fault")
	}
}

// faultSyncer wraps the store's write seam, failing Write or Sync on demand
// while delegating the other call to the real implementation. It mirrors the
// audit sink's faultSyncer.
type faultSyncer struct {
	ws        writeSyncer
	failWrite bool
	failSync  bool
}

func (f *faultSyncer) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("injected write fault")
	}
	return f.ws.Write(p)
}

func (f *faultSyncer) Sync() error {
	if f.failSync {
		return errors.New("injected sync fault")
	}
	return f.ws.Sync()
}

// completeLines returns the count of newline-terminated lines in the log file.
func completeLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if len(data) == 0 {
		return 0
	}
	return strings.Count(string(data), "\n")
}

// TestPutLatchesAfterFault pins the post-error latch: any write or sync fault
// permanently fails the store — every later Put returns ErrStoreUnavailable
// WITHOUT writing, even after the underlying fault is gone. Mirrors the audit
// sink's TestMandateLatchesAfterFault. Reads still resolve from the map.
func TestPutLatchesAfterFault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault faultSyncer
	}{
		{"write fault", faultSyncer{failWrite: true}},
		{"sync fault", faultSyncer{failSync: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, s := newTestStore(t)
			base, err := s.Put(context.Background(), samplePut("fs-A", "base"))
			if err != nil {
				t.Fatalf("baseline Put: %v", err)
			}

			fault := tc.fault
			fault.ws = s.f
			s.w = &fault
			if _, err := s.Put(context.Background(), samplePut("fs-A", "x")); !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("Put under fault = %v, want ErrStoreUnavailable", err)
			}
			if !s.Latched() {
				t.Fatal("store not latched after a write/sync fault")
			}
			linesAfterFault := completeLines(t, path)

			// Underlying problem fixed — the latch must still refuse and must not
			// touch the file.
			s.w = s.f
			if _, err := s.Put(context.Background(), samplePut("fs-A", "y")); !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("Put after fault cleared = %v, want ErrStoreUnavailable (latched)", err)
			}
			if got := completeLines(t, path); got != linesAfterFault {
				t.Fatalf("latched Put wrote to the file: %d lines, want %d", got, linesAfterFault)
			}

			// A latched store stays READ-resolvable: the baseline record still
			// resolves from the in-memory map.
			if _, err := s.Get(context.Background(), base.FileID, "fs-A"); err != nil {
				t.Fatalf("latched store denied a read: %v, want the record", err)
			}

			// Restart recovers: a fresh store re-scans the log and serves.
			if err := s.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			s2, err := NewDiskStore(path)
			if err != nil {
				t.Fatalf("NewDiskStore restart: %v", err)
			}
			t.Cleanup(func() { _ = s2.Close() })
			if _, err := s2.Put(context.Background(), samplePut("fs-A", "after")); err != nil {
				t.Fatalf("Put after restart: %v", err)
			}
		})
	}
}

// TestOnLatchFiresExactlyOnce pins the on-latch callback contract: it fires
// EXACTLY ONCE on the transition to latched and never again. Mirrors the audit
// sink's TestFileSinkOnLatchFiresExactlyOnce.
func TestOnLatchFiresExactlyOnce(t *testing.T) {
	_, s := newTestStore(t)
	count := 0
	s.SetOnLatch(func() { count++ })

	// Healthy Put: callback must not fire.
	if _, err := s.Put(context.Background(), samplePut("fs-A", "a")); err != nil {
		t.Fatalf("healthy Put: %v", err)
	}
	if count != 0 {
		t.Fatalf("onLatch fired before any fault: count=%d, want 0", count)
	}

	// Inject fault: the first failed Put fires the callback once.
	fault := &faultSyncer{ws: s.f, failWrite: true}
	s.w = fault
	if _, err := s.Put(context.Background(), samplePut("fs-A", "b")); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("faulting Put = %v, want ErrStoreUnavailable", err)
	}
	if count != 1 {
		t.Fatalf("onLatch after first fault: count=%d, want 1", count)
	}

	// Fault cleared; latch remains — follow-up Puts must not re-fire.
	s.w = s.f
	for i := 0; i < 3; i++ {
		_, _ = s.Put(context.Background(), samplePut("fs-A", "c"))
	}
	if count != 1 {
		t.Fatalf("onLatch after follow-up Puts: count=%d, want 1 (fires exactly once)", count)
	}
}

// TestNewDiskStore_StatErrorFailsClosed pins the stat-failure branch: a path
// under an unreadable directory yields a non-IsNotExist stat error and the
// constructor fails closed. Mirrors the audit sink's equivalent.
func TestNewDiskStore_StatErrorFailsClosed(t *testing.T) {
	skipIfRoot(t)
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod 000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := NewDiskStore(filepath.Join(dir, "handles.jsonl")); err == nil {
		t.Fatal("NewDiskStore under unreadable dir = nil, want fail-closed")
	} else if !strings.Contains(err.Error(), "handlestore:") {
		t.Fatalf("error = %v, want a handlestore-wrapped failure", err)
	}
}

// TestNewDiskStore_OpenErrorFailsClosed pins the open-failure branch: a
// not-yet-existing path inside a read-only directory cannot be created.
func TestNewDiskStore_OpenErrorFailsClosed(t *testing.T) {
	skipIfRoot(t)
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("mkdir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := NewDiskStore(filepath.Join(dir, "handles.jsonl")); err == nil {
		t.Fatal("NewDiskStore in read-only dir = nil, want open failure")
	} else if !strings.Contains(err.Error(), "open log") {
		t.Fatalf("error = %v, want an open-log failure", err)
	}
}

// TestNewDiskStore_ReplayOpenErrorFailsClosed pins the existing-file branch
// where the append handle opens but the read handle for replay cannot.
func TestNewDiskStore_ReplayOpenErrorFailsClosed(t *testing.T) {
	skipIfRoot(t)
	path := filepath.Join(t.TempDir(), "handles.jsonl")
	if err := os.WriteFile(path, []byte(`{"op":"put","record":{"file_id":"x"}}`+"\n"), 0o200); err != nil {
		t.Fatalf("seed write-only file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	if _, err := NewDiskStore(path); err == nil {
		t.Fatal("NewDiskStore on unreadable non-empty file = nil, want replay-open failure")
	} else if !strings.Contains(err.Error(), "open log for replay") {
		t.Fatalf("error = %v, want a replay-open failure", err)
	}
}

// TestSyncDir_ToleratesAndPropagates pins syncDir: a healthy directory syncs
// without error; an unopenable directory yields a propagated open error (not a
// tolerated EINVAL/ENOTSUP). Mirrors the audit sink's equivalent.
func TestSyncDir_ToleratesAndPropagates(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir(healthy dir) = %v, want nil", err)
	}

	skipIfRoot(t)
	locked := filepath.Join(t.TempDir(), "noopen")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	parent := filepath.Dir(locked)
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatalf("chmod parent 000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	if err := syncDir(locked); err == nil {
		t.Fatal("syncDir(unopenable dir) = nil, want a propagated open error")
	} else if !strings.Contains(err.Error(), "open log directory") {
		t.Fatalf("syncDir error = %v, want open-log-directory failure", err)
	}
}
