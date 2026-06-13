// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
)

// errOpsListenNotLoopback is returned when the caller supplies a non-loopback
// bind address for the ops listener. The ops listener is loopback-only because
// /metrics carries no authentication; the loopback guard is the access control.
// Binding to a routable interface without authentication is a security defect
// (T-14-05).
var errOpsListenNotLoopback = errors.New("telemetry: ops listener bind address is not a loopback address — refuse fail-closed (use 127.0.0.1, ::1, or localhost)")

// IsOpsListenNotLoopback reports whether err is (or wraps) errOpsListenNotLoopback.
func IsOpsListenNotLoopback(err error) bool {
	return errors.Is(err, errOpsListenNotLoopback)
}

// isLoopbackAddr parses addr (host:port) and returns true iff the host part
// resolves to a loopback address (127.0.0.0/8 or ::1). An empty host (the form
// ":port") is REFUSED because it binds all interfaces — fail-closed.
func isLoopbackAddr(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("telemetry: parse ops-listen address %q: %w", addr, err)
	}
	if host == "" {
		// ":port" binds all interfaces — refused.
		return false, nil
	}

	// "localhost" is an allowed alias; resolve it.
	if host == "localhost" {
		return true, nil
	}

	// Parse the literal IP.
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback(), nil
	}

	// Not an IP literal — resolve the hostname and require EVERY resolved
	// address to be loopback. A hostname whose first record is loopback but
	// which also resolves to a routable interface must be refused: net.Listen
	// may bind an address the check would otherwise never inspect, exposing the
	// unauthenticated /metrics endpoint. Reject on any non-loopback or
	// unparseable record (fail-closed).
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return false, nil
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || !ip.IsLoopback() {
			return false, nil
		}
	}
	return true, nil
}

// OpsListener is a loopback-only HTTP listener serving the ops plane
// (/metrics and, after plan-03 registers them, /healthz + /readyz). Obtain
// it via NewOpsListener; do not construct directly.
type OpsListener struct {
	srv    *http.Server
	mux    *http.ServeMux
	ln     net.Listener
	logger *slog.Logger
}

// ValidateOpsListenAddr validates that addr is a loopback address suitable
// for the ops listener, without binding a socket. An empty addr returns nil
// (empty disables the listener). A non-loopback or unparseable addr returns
// errOpsListenNotLoopback.
func ValidateOpsListenAddr(addr string) error {
	if addr == "" {
		return nil
	}
	ok, err := isLoopbackAddr(addr)
	if err != nil {
		return fmt.Errorf("%w: %v", errOpsListenNotLoopback, err)
	}
	if !ok {
		return fmt.Errorf("%w: %s", errOpsListenNotLoopback, addr)
	}
	return nil
}

// NewOpsListener creates an OpsListener bound to addr. addr must resolve to a
// loopback address; any non-loopback addr returns errOpsListenNotLoopback and
// binds nothing (fail-closed). An empty addr is refused too — use
// "127.0.0.1:9464" or the caller's own default.
//
// The /metrics handler is registered immediately; callers may call Handle to
// register additional routes before calling Serve.
func NewOpsListener(addr string, metrics *BrokerMetrics, logger *slog.Logger) (*OpsListener, error) {
	ok, err := isLoopbackAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errOpsListenNotLoopback, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s", errOpsListenNotLoopback, addr)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("telemetry: ops listener bind %q: %w", addr, err)
	}

	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	mux := http.NewServeMux()
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          observ.ErrorLog(logger),
	}

	ol := &OpsListener{srv: srv, mux: mux, ln: ln, logger: logger}

	// Register /metrics handler.
	reg := metrics.Registry()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		// Status and headers are already committed by the first WriteTo write,
		// so a mid-scrape failure cannot change the HTTP status; the scraper
		// detects the truncated body and the missing `up` sample. Log it at
		// DEBUG so a flapping scrape connection does not spam the error stream.
		if _, err := reg.WriteTo(w); err != nil {
			ol.logger.Debug("metrics scrape write aborted", slog.String("err", err.Error()))
		}
	})

	return ol, nil
}

// Handle registers a handler for the given pattern on the ops listener mux.
// Call before Serve; pattern semantics follow http.ServeMux.
func (ol *OpsListener) Handle(pattern string, h http.Handler) {
	ol.mux.Handle(pattern, h)
}

// Addr returns the network address the listener is bound to (e.g.
// "127.0.0.1:9464"). Call after NewOpsListener.
func (ol *OpsListener) Addr() string {
	return ol.ln.Addr().String()
}

// Serve starts the ops listener and blocks until Close is called. Call in a
// goroutine. An http.ErrServerClosed is swallowed (expected on Close); any
// other error is logged and dropped (the ops listener is fail-safe — a broken
// metrics endpoint does not stop the broker).
func (ol *OpsListener) Serve() {
	ol.logger.Info("ops listener serving", slog.String("addr", ol.Addr()))
	if err := ol.srv.Serve(ol.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		ol.logger.Error("ops listener error", slog.String("err", err.Error()))
	}
}

// Close shuts down the ops listener gracefully.
func (ol *OpsListener) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ol.srv.Shutdown(ctx)
}
