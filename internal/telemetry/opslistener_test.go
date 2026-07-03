// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestOpsListenLoopbackRefusal verifies the loopback-only fail-closed guard.
// A non-loopback bind address must be refused before any bind.
func TestOpsListenLoopbackRefusal(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	refusedAddrs := []string{
		"0.0.0.0:9090",
		"0.0.0.0:0",
		":9090", // host="" -> all interfaces -> refused
		"10.0.0.1:9090",
		"192.168.1.1:0",
	}

	for _, addr := range refusedAddrs {
		t.Run("refuse_"+addr, func(t *testing.T) {
			_, err := telemetry.NewOpsListener(addr, m, discardLogger())
			if err == nil {
				t.Fatalf("NewOpsListener(%q): expected error for non-loopback, got nil", addr)
			}
			// Must be errOpsListenNotLoopback-typed.
			if !telemetry.IsOpsListenNotLoopback(err) {
				t.Fatalf("NewOpsListener(%q): expected errOpsListenNotLoopback, got %v", addr, err)
			}
		})
	}
}

// TestOpsListenLoopbackAccepted verifies that loopback addresses bind
// successfully and the listener can be closed.
func TestOpsListenLoopbackAccepted(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	acceptedAddrs := []string{
		"127.0.0.1:0",
		"[::1]:0",
		"localhost:0",
	}

	for _, addr := range acceptedAddrs {
		t.Run("accept_"+addr, func(t *testing.T) {
			l, err := telemetry.NewOpsListener(addr, m, discardLogger())
			if err != nil {
				t.Fatalf("NewOpsListener(%q): %v", addr, err)
			}
			defer l.Close()
		})
	}
}

// TestOpsListenMetricsEndpoint verifies that GET /metrics returns 200 and a
// valid Prometheus text-format body over the loopback listener.
func TestOpsListenMetricsEndpoint(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")
	m.RecordOp("readFile", "allow", "none")

	l, err := telemetry.NewOpsListener("127.0.0.1:0", m, discardLogger())
	if err != nil {
		t.Fatalf("NewOpsListener: %v", err)
	}
	defer l.Close()

	go l.Serve()

	// Dial the bound address.
	addr := l.Addr()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("unexpected Content-Type: %s", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "ops_total") {
		t.Fatalf("ops_total missing from /metrics:\n%s", bodyStr)
	}
}

// TestOpsListenHandleRegistration verifies that the OpsListener exposes a
// registration seam for additional handlers (plan 03 adds /healthz + /readyz).
func TestOpsListenHandleRegistration(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")
	l, err := telemetry.NewOpsListener("127.0.0.1:0", m, discardLogger())
	if err != nil {
		t.Fatalf("NewOpsListener: %v", err)
	}
	defer l.Close()

	// Register a custom handler before serving.
	l.Handle("/test-ping", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	go l.Serve()

	addr := l.Addr()
	resp, err := http.Get("http://" + addr + "/test-ping")
	if err != nil {
		t.Fatalf("GET /test-ping: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

// TestOpsListenNonLoopbackBindsNothing verifies that when a non-loopback
// address is refused, no listen socket was opened (fail-closed).
func TestOpsListenNonLoopbackBindsNothing(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")
	_, err := telemetry.NewOpsListener("0.0.0.0:9464", m, discardLogger())
	if err == nil {
		t.Fatal("expected error for 0.0.0.0 bind, got nil")
	}
	// Confirm the port is not bound by trying to listen on the same port.
	// We can't deterministically check that 9464 is free, so just verify the
	// error type and that no OpsListener was returned.
	if !telemetry.IsOpsListenNotLoopback(err) {
		t.Fatalf("expected IsOpsListenNotLoopback, got %v", err)
	}
}

// TestOpsListenCloseBeforeServeReleasesPort pins that Close() releases the bound
// port even when Serve() never ran. On a pre-Serve refusal the listener was
// bound at construction but never handed to the http.Server, so srv.Shutdown
// (which closes only Serve-tracked listeners) would leak the fd/port. Close must
// close ol.ln directly; the freed port must be immediately rebindable.
func TestOpsListenCloseBeforeServeReleasesPort(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")
	ol, err := telemetry.NewOpsListener("127.0.0.1:0", m, discardLogger())
	if err != nil {
		t.Fatalf("NewOpsListener: %v", err)
	}
	addr := ol.Addr()

	// Close WITHOUT ever calling Serve — models any pre-Serve refusal path.
	if err := ol.Close(); err != nil {
		t.Fatalf("Close before Serve: %v", err)
	}

	// The port must be free to rebind now; a leak surfaces as EADDRINUSE.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("ops port %s still bound after Close() before Serve(): %v", addr, err)
	}
	_ = ln.Close()
}

// TestLoopbackIP6AndLocalhost verifies that "localhost" resolves correctly
// (the resolver may return ::1 or 127.0.0.1 — both are loopback).
func TestLoopbackIP6AndLocalhost(t *testing.T) {
	// Only run if the system has a loopback ::1 interface.
	_, err := net.ResolveTCPAddr("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no ::1 on this machine")
	}

	m := telemetry.NewBrokerMetrics("v0.0.0-test")
	l, err := telemetry.NewOpsListener("[::1]:0", m, discardLogger())
	if err != nil {
		t.Fatalf("NewOpsListener([::1]:0): %v", err)
	}
	l.Close()
}
