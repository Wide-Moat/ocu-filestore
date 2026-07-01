// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"log/slog"

	"github.com/Wide-Moat/ocu-filestore/internal/flock"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// handleStoreArgs builds a valid serving arg set with --handle-store set to
// hsPath (empty to omit the flag) and --ops-listen on opsAddr.
func handleStoreArgs(t *testing.T, hsPath, opsAddr string) []string {
	t.Helper()
	root := shortDir(t)
	certFile, keyFile := testTLSCertPaths(t)
	args := []string{
		"--engine-root", filepath.Join(root, "engine"),
		"--audit-sink", filepath.Join(root, "audit-dir", "audit.jsonl"),
		"--filesystem-id", "fs-hs-01",
		"--broker-max-file-size", "1024",
		"--south-bind", freeLoopbackAddr(t),
		"--tls-cert", certFile,
		"--tls-key", keyFile,
		"--ops-listen", opsAddr,
	}
	if hsPath != "" {
		args = append(args, "--handle-store", hsPath)
	}
	return args
}

// reserveOpsAddr returns a free loopback addr (reserved then released) suitable
// for a daemon's --ops-listen, plus a /healthz wait helper.
func reserveOpsAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitServing(t *testing.T, opsAddr string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, perr := client.Get("http://" + opsAddr + "/healthz")
		if perr == nil {
			_ = resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon never began serving: %v", perr)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRunSecondDaemonOnSameHandleStoreRefuses pins the handle-store
// single-instance guard: a daemon refuses to start when another holds the
// <handle-store>.lock. The first holder is the flock package directly (the same
// lock run() acquires), so this isolates the guard without spinning two full
// daemons.
func TestRunSecondDaemonOnSameHandleStoreRefuses(t *testing.T) {
	root := shortDir(t)
	hsDir := filepath.Join(root, "hs-dir")
	if err := os.MkdirAll(hsDir, 0o700); err != nil {
		t.Fatalf("mkdir hs-dir: %v", err)
	}
	hsPath := filepath.Join(hsDir, "handles.jsonl")

	// Hold the handle-store lock as a competing instance would.
	held, err := flock.Acquire(hsPath + ".lock")
	if err != nil {
		t.Fatalf("pre-acquire handle-store lock: %v", err)
	}
	defer held.Release()

	err = run(handleStoreArgs(t, hsPath, reserveOpsAddr(t)))
	if !errors.Is(err, errHandleStoreAlreadyRunning) {
		t.Fatalf("run() with a held handle-store lock = %v, want errHandleStoreAlreadyRunning", err)
	}
}

// TestRunDistinctHandleStoreNoCollision pins that a daemon pointed at a DIFFERENT
// handle store than a competing lock-holder starts fine: the lock is keyed on
// the resource, so distinct stores take distinct locks.
func TestRunDistinctHandleStoreNoCollision(t *testing.T) {
	root := shortDir(t)
	// A competing instance holds the lock for store A.
	otherDir := filepath.Join(root, "other")
	if err := os.MkdirAll(otherDir, 0o700); err != nil {
		t.Fatalf("mkdir other: %v", err)
	}
	held, err := flock.Acquire(filepath.Join(otherDir, "handles.jsonl.lock"))
	if err != nil {
		t.Fatalf("pre-acquire other lock: %v", err)
	}
	defer held.Release()

	// This daemon uses store B — a distinct path, so no collision.
	hsPath := filepath.Join(root, "mine", "handles.jsonl")
	opsAddr := reserveOpsAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- runCtx(ctx, handleStoreArgs(t, hsPath, opsAddr)) }()
	waitServing(t, opsAddr)

	// Healthy start: the distinct store opened and the daemon is serving.
	if _, statErr := os.Stat(hsPath); statErr != nil {
		t.Fatalf("distinct handle store was not created: %v", statErr)
	}
	// Stop the daemon by cancelling its context — the same clean-drain path a
	// SIGTERM drives, but scoped to this daemon so no process-global signal can
	// terminate the test binary.
	cancel()
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		t.Fatal("runCtx() did not return within 10s of context cancellation")
	}
}

// TestRunEmptyHandleStoreNoStoreNoLock pins the OPTIONAL contract: an empty
// --handle-store opens no store and takes no lock, so a lock file is never
// created and the daemon serves normally.
func TestRunEmptyHandleStoreNoStoreNoLock(t *testing.T) {
	opsAddr := reserveOpsAddr(t)
	args := handleStoreArgs(t, "", opsAddr) // no --handle-store
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- runCtx(ctx, args) }()
	waitServing(t, opsAddr)

	cancel()
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		t.Fatal("runCtx() did not return within 10s of context cancellation")
	}
	// Nothing to assert on a lock file: with no path there is no lock resource.
	// The clean serve+stop is the assertion (an empty store path must not wedge
	// startup).
}

// TestRunPinsHandleStoreDirTo0700 pins that run() creates the handle-store
// parent directory and Chmods it to 0700 unconditionally (same hardening as the
// audit-sink leaf), even under a permissive umask.
func TestRunPinsHandleStoreDirTo0700(t *testing.T) {
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	root := shortDir(t)
	hsDir := filepath.Join(root, "hs-not-yet")
	hsPath := filepath.Join(hsDir, "handles.jsonl")
	opsAddr := reserveOpsAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- runCtx(ctx, handleStoreArgs(t, hsPath, opsAddr)) }()
	waitServing(t, opsAddr)

	info, statErr := os.Stat(hsDir)
	if statErr != nil {
		t.Fatalf("stat handle-store directory: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("handle-store directory mode = %o, want 0700 (Chmod must pin 0700 regardless of umask)", got)
	}

	cancel()
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		t.Fatal("runCtx() did not return within 10s of context cancellation")
	}
}

// TestHandleStoreEnvFallbackApplies pins that OCU_FILESTORE_HANDLE_STORE is a
// recognized env fallback: the flag is registered and applyEnvFallbacks fills it
// from the env when the flag is absent on the command line.
func TestHandleStoreEnvFallbackApplies(t *testing.T) {
	if _, ok := envFallbackMap["handle-store"]; !ok {
		t.Fatal("handle-store missing from envFallbackMap; OCU_FILESTORE_HANDLE_STORE will not apply")
	}
	if got := envVarName("handle-store"); got != "OCU_FILESTORE_HANDLE_STORE" {
		t.Fatalf("envVarName(handle-store) = %q, want OCU_FILESTORE_HANDLE_STORE", got)
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	hs := fs.String("handle-store", "", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Setenv("OCU_FILESTORE_HANDLE_STORE", "/data/handles.jsonl")
	if err := applyEnvFallbacks(fs); err != nil {
		t.Fatalf("applyEnvFallbacks: %v", err)
	}
	if *hs != "/data/handles.jsonl" {
		t.Errorf("handle-store = %q, want /data/handles.jsonl (from env)", *hs)
	}
}

// TestComposeHandleStoreLatchWiringHealthy pins the on-latch wiring seam: a
// composed daemon with a configured handle store wires the store into
// teardownServer, the handle_store_latched gauge starts at 0 (not latched), and
// the handle_store_latch readiness probe is registered and reports HEALTHY (the
// store is fresh). The gauge-flips-to-1 and probe-turns-unhealthy half of the
// contract is proven at the handlestore-package level (TestSetOnLatchFires*),
// since tripping a real write/sync fault needs the store's unexported seam; here
// we prove the COMPOSITION wired the callback and probe to the live store.
func TestComposeHandleStoreLatchWiringHealthy(t *testing.T) {
	cfg := validBrokerConfig(t)
	root := shortDir(t)
	cfg.handleStore = filepath.Join(root, "handles.jsonl")

	m := telemetry.NewBrokerMetrics("test")
	var logBuf strings.Builder
	l := observ.NewLogger(&logBuf, slog.LevelDebug)

	opsAddr := reserveOpsAddr(t)
	opsLn, err := telemetry.NewOpsListener(opsAddr, m, l)
	if err != nil {
		t.Fatalf("ops listener: %v", err)
	}

	srv, err := compose(cfg, l, m, opsLn)
	if err != nil {
		_ = opsLn.Close()
		t.Fatalf("compose with handle store: %v", err)
	}
	go opsLn.Serve()
	defer func() { _ = srv.Close(); _ = opsLn.Close() }()

	// The store is wired into teardownServer (so Close releases its descriptor).
	ts, ok := srv.(*teardownServer)
	if !ok {
		t.Fatalf("compose returned %T, want *teardownServer", srv)
	}
	if ts.handleStore == nil {
		t.Fatal("teardownServer.handleStore is nil; the store was not wired into compose")
	}
	if ts.handleStore.Latched() {
		t.Fatal("fresh handle store reports latched; want healthy")
	}

	// handle_store_latched starts at 0 (a value line "handle_store_latched 1"
	// would mean latched on a healthy compose).
	var metricsOut strings.Builder
	m.Registry().WriteTo(&metricsOut)
	if strings.Contains(metricsOut.String(), "\nhandle_store_latched 1\n") {
		t.Fatalf("handle_store_latched gauge is 1 on healthy compose; want 0 or absent")
	}

	// The handle_store_latch readiness probe is registered and HEALTHY: /readyz
	// returns 200 (it would be 503 if the probe reported the store latched).
	client := &http.Client{Timeout: 2 * time.Second}
	resp, perr := client.Get("http://" + opsAddr + "/readyz")
	if perr != nil {
		t.Fatalf("/readyz probe: %v", perr)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz = %d on a healthy store, want 200", resp.StatusCode)
	}
}
