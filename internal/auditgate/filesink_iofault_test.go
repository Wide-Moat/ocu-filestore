// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// errReader returns a fixed non-EOF error on the first Read — a fault
// injector for chainScan's read-error path. Not a mock of any service: it
// stands in for a failing io.Reader (e.g. a disk read error mid-scan).
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// skipIfRoot skips tests that depend on a POSIX permission fault, which the
// superuser bypasses, and on platforms without the relevant semantics.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission-fault semantics not applicable on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses the permission fault")
	}
}

// TestNewFileSink_StatErrorFailsClosed pins the constructor's stat-failure
// branch: a path whose parent directory is unreadable yields a stat error
// that is NOT IsNotExist, and the constructor fails closed (the broker must
// not start on an unverifiable sink). A real directory-permission fault, not
// a mock.
func TestNewFileSink_StatErrorFailsClosed(t *testing.T) {
	skipIfRoot(t)
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil { // no search/read -> stat under it fails
		t.Fatalf("chmod 000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, err := NewFileSink(filepath.Join(dir, "audit.jsonl"))
	if err == nil {
		t.Fatal("NewFileSink under unreadable dir = nil, want a fail-closed error")
	}
	if !strings.Contains(err.Error(), "auditgate:") {
		t.Fatalf("NewFileSink error = %v, want an auditgate-wrapped failure", err)
	}
}

// TestNewFileSink_OpenErrorFailsClosed pins the constructor's open-failure
// branch: a not-yet-existing sink path inside a read-only directory cannot be
// created (O_CREATE fails), and the constructor fails closed.
func TestNewFileSink_OpenErrorFailsClosed(t *testing.T) {
	skipIfRoot(t)
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o500); err != nil { // r-x: stat-not-exist ok, create denied
		t.Fatalf("mkdir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, err := NewFileSink(filepath.Join(dir, "audit.jsonl"))
	if err == nil {
		t.Fatal("NewFileSink in read-only dir = nil, want open failure")
	}
	if !strings.Contains(err.Error(), "open sink") {
		t.Fatalf("NewFileSink error = %v, want an open-sink failure", err)
	}
}

// TestNewFileSink_ChainScanOpenErrorFailsClosed pins the existing-file branch
// where the append handle opens (write permission) but the read handle used
// for the chain scan cannot (no read permission). The constructor must fail
// closed rather than start serving without verifying the existing chain.
func TestNewFileSink_ChainScanOpenErrorFailsClosed(t *testing.T) {
	skipIfRoot(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// A non-empty, write-only file: O_APPEND|O_WRONLY succeeds, os.Open (read)
	// fails -> the chain-scan open error path.
	if err := os.WriteFile(path, []byte("{\"prev_hash\":\"x\"}\n"), 0o200); err != nil {
		t.Fatalf("seed write-only file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err := NewFileSink(path)
	if err == nil {
		t.Fatal("NewFileSink on unreadable non-empty file = nil, want chain-scan open failure")
	}
	if !strings.Contains(err.Error(), "chain scan") {
		t.Fatalf("NewFileSink error = %v, want a chain-scan open failure", err)
	}
}

// TestNewFileSink_BrokenChainFailsClosed pins the invalid-chain branch: an
// existing non-empty file whose first record's prev_hash does not link to
// genesis is a tampered chain, and the constructor refuses to start.
func TestNewFileSink_BrokenChainFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("{\"prev_hash\":\"deadbeef\"}\n"), 0o600); err != nil {
		t.Fatalf("seed broken chain: %v", err)
	}
	_, err := NewFileSink(path)
	if err == nil {
		t.Fatal("NewFileSink on broken chain = nil, want refusal")
	}
	if !strings.Contains(err.Error(), "existing chain invalid") {
		t.Fatalf("NewFileSink error = %v, want existing-chain-invalid refusal", err)
	}
}

// TestSyncDir_ToleratesAndPropagates pins syncDir's two outcomes against the
// real filesystem: a normal directory syncs without error (the tolerated
// EINVAL/ENOTSUP on platforms that no-op directory fsync is also nil), while
// an unreadable directory yields an open error that must propagate (it is not
// a tolerated EINVAL/ENOTSUP).
func TestSyncDir_ToleratesAndPropagates(t *testing.T) {
	// Healthy directory: syncDir returns nil on every supported platform.
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir(healthy dir) = %v, want nil", err)
	}

	skipIfRoot(t)
	locked := filepath.Join(t.TempDir(), "noopen")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Strip the parent's search bit so opening the child directory fails with
	// EACCES (not a tolerated EINVAL/ENOTSUP).
	parent := filepath.Dir(locked)
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatalf("chmod parent 000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	if err := syncDir(locked); err == nil {
		t.Fatal("syncDir(unopenable dir) = nil, want a propagated open error")
	} else if !strings.Contains(err.Error(), "open sink directory") {
		t.Fatalf("syncDir error = %v, want open-sink-directory failure", err)
	}
}

// TestVerify_OpenErrorPropagates pins Verify's open-failure branch: an
// existing but unreadable audit file is NOT a missing file (which returns
// nil) — the open error propagates so a verification can never pass silently
// on a file it could not read.
func TestVerify_OpenErrorPropagates(t *testing.T) {
	skipIfRoot(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("{\"prev_hash\":\"x\"}\n"), 0o000); err != nil {
		t.Fatalf("seed unreadable file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	if err := Verify(path); err == nil {
		t.Fatal("Verify(unreadable file) = nil, want a propagated open error")
	} else if !strings.Contains(err.Error(), "verify open") {
		t.Fatalf("Verify error = %v, want a verify-open failure", err)
	}
}

// TestChainScan_ReadErrorPropagates pins chainScan's read-error branch via a
// faulting reader: a non-EOF read error mid-scan is wrapped and returned (the
// scan never treats a read fault as a clean end-of-stream).
func TestChainScan_ReadErrorPropagates(t *testing.T) {
	sentinel := errors.New("injected disk read fault")
	_, lines, torn, err := chainScan(errReader{err: sentinel})
	if err == nil {
		t.Fatal("chainScan(faulting reader) = nil error, want a wrapped read fault")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("chainScan error = %v, want it to wrap the injected fault", err)
	}
	if !strings.Contains(err.Error(), "chain read") {
		t.Fatalf("chainScan error = %v, want a chain-read wrapping", err)
	}
	if lines != 0 || torn != 0 {
		t.Fatalf("chainScan(faulting reader) lines=%d torn=%d, want 0, 0", lines, torn)
	}
}
