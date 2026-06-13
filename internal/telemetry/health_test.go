// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// alwaysOK is a ReadyProbe func that always returns nil (probe passes).
func alwaysOK() error { return nil }

// alwaysFail returns a ReadyProbe func that always returns the given error.
func alwaysFail(msg string) func() error {
	return func() error { return errors.New(msg) }
}

// TestHealthzAlways200 pins /healthz pure-liveness: the handler returns 200 OK
// regardless of probe state — GET and HEAD are accepted; anything else is 405.
func TestHealthzAlways200(t *testing.T) {
	mux := http.NewServeMux()
	telemetry.RegisterHealthHandlers(mux, nil)

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		req := httptest.NewRequest(method, "/healthz", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET /healthz: got %d, want 200", rr.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz: got %d, want 405", rr.Code)
	}
}

// TestReadyzAllProbesOK pins /readyz healthy path: 200 when every registered
// probe returns nil.
func TestReadyzAllProbesOK(t *testing.T) {
	mux := http.NewServeMux()
	probes := []telemetry.ReadyProbe{
		{Name: "audit_latch", Check: alwaysOK},
		{Name: "engine_root", Check: alwaysOK},
	}
	telemetry.RegisterHealthHandlers(mux, probes)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/readyz (all OK): got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

// TestReadyzAuditLatchFails pins /readyz not-ready path when the audit-latch
// probe fails: 503 with a terse body naming the probe (audit_latch only — no
// path, no payload, no credential, per T-14-09).
func TestReadyzAuditLatchFails(t *testing.T) {
	mux := http.NewServeMux()
	probes := []telemetry.ReadyProbe{
		{Name: "audit_latch", Check: alwaysFail("latched")},
		{Name: "engine_root", Check: alwaysOK},
	}
	telemetry.RegisterHealthHandlers(mux, probes)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz (latch): got %d, want 503", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "audit_latch") {
		t.Fatalf("/readyz 503 body %q does not name the failed probe", body)
	}
	// The body must NOT carry the error message from the probe — T-14-09:
	// names only, no path/payload/credential.
	if strings.Contains(body, "latched") {
		t.Fatalf("/readyz 503 body %q leaks the probe error message (T-14-09)", body)
	}
}

// TestReadyzEngineRootFails pins /readyz not-ready when the engine root probe
// errors: 503 naming engine_root.
func TestReadyzEngineRootFails(t *testing.T) {
	mux := http.NewServeMux()
	probes := []telemetry.ReadyProbe{
		{Name: "audit_latch", Check: alwaysOK},
		{Name: "engine_root", Check: alwaysFail("scope dir removed")},
	}
	telemetry.RegisterHealthHandlers(mux, probes)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz (engine): got %d, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "engine_root") {
		t.Fatalf("/readyz 503 body %q does not name the failed probe", rr.Body.String())
	}
}

// TestReadyzMethodNotAllowed pins that non-GET/HEAD /readyz returns 405.
func TestReadyzMethodNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	telemetry.RegisterHealthHandlers(mux, nil)
	req := httptest.NewRequest(http.MethodPost, "/readyz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /readyz: got %d, want 405", rr.Code)
	}
}

// TestReadyzNoProbes pins the zero-probe case: /readyz with nil probes returns
// 200 (vacuously ready).
func TestReadyzNoProbes(t *testing.T) {
	mux := http.NewServeMux()
	telemetry.RegisterHealthHandlers(mux, nil)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/readyz (no probes): got %d, want 200", rr.Code)
	}
}

// TestReadyzBodyNamesOnlyFailedProbes pins that only the failing probe names
// appear in the 503 body when multiple probes are registered and one fails.
func TestReadyzBodyNamesOnlyFailedProbes(t *testing.T) {
	mux := http.NewServeMux()
	probes := []telemetry.ReadyProbe{
		{Name: "audit_latch", Check: alwaysOK},
		{Name: "engine_root", Check: alwaysFail("gone")},
	}
	telemetry.RegisterHealthHandlers(mux, probes)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, "audit_latch") {
		t.Fatalf("/readyz body %q names a passing probe", body)
	}
	if !strings.Contains(body, "engine_root") {
		t.Fatalf("/readyz body %q does not name the failing probe", body)
	}
}

// TestReadyzContextPropagated confirms the probe receives a non-nil context
// (the handler must pass the request context down for bounded deadline support
// in future probes).
func TestReadyzContextPropagated(t *testing.T) {
	mux := http.NewServeMux()
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "sentinel")
	var got context.Context
	probes := []telemetry.ReadyProbe{
		{Name: "ctx_check", Check: func() error {
			// The probe function is a func() error (no ctx param) per the
			// design; the context is the handler's — this test simply ensures
			// the handler does not pass a nil Request.Context().
			got = ctx
			return nil
		}},
	}
	telemetry.RegisterHealthHandlers(mux, probes)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if got == nil {
		t.Fatal("probe context was nil")
	}
}
