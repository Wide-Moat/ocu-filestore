// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// TestRESTDeny pins the A3 unary deny writer: every deny class maps to its
// authoritative HTTP status (via the surviving statusForWireCode table), the
// JSON BoundedReason {reason_code, message} diagnostic body, and the
// x-deny-reason header gated to authorization verdicts only.
func TestRESTDeny(t *testing.T) {
	reasonRE := regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

	// Every deny class the broker can produce, with its expected authoritative
	// HTTP status and whether it carries the x-deny-reason truth header. The
	// status column is the A3 map; the header column is the surviving deny-table
	// gating (authorization verdicts only).
	for _, tc := range []struct {
		name       string
		class      string
		wantStatus int
		wantHeader bool
	}{
		{"scope_mismatch -> 403 + header", denyScopeMismatch, http.StatusForbidden, true},
		{"intent_denied -> 403 + header", denyIntentDenied, http.StatusForbidden, true},
		{"not_downloadable -> 403 + header", denyNotDownloadable, http.StatusForbidden, true},
		{"lease_expired -> 401 + header", denyLeaseExpired, http.StatusUnauthorized, true},
		{"size_exceeded -> 400, no header", denySizeExceeded, http.StatusBadRequest, false},
		{"malformed -> 400, no header", denyMalformed, http.StatusBadRequest, false},
		{"dir_not_empty -> 400, no header", denyDirNotEmpty, http.StatusBadRequest, false},
		{"not_found -> 404, no header", denyNotFound, http.StatusNotFound, false},
		{"throttle -> 429, no header", denyThrottle, http.StatusTooManyRequests, false},
		{"audit_down -> 503, no header", denyAuditDown, http.StatusServiceUnavailable, false},
		{"backend_unavailable -> 503, no header", denyBackendUnavailable, http.StatusServiceUnavailable, false},
		{"already_exists -> 409, no header", denyAlreadyExists, http.StatusConflict, false},
		{"aborted -> 409, no header", denyAborted, http.StatusConflict, false},
		{"unimplemented -> 501, no header", denyUnimplemented, http.StatusNotImplemented, false},
		{"internal -> 500, no header", denyInternal, http.StatusInternalServerError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := mapDeny(tc.class)
			w := httptest.NewRecorder()
			writeRESTDeny(w, v, "diagnostic message")

			// Status is authoritative and matches the A3 map.
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			// Content-Type is application/json.
			if ct := w.Header().Get("Content-Type"); ct != contentTypeJSON {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}

			// Body is a BoundedReason {reason_code, message}: exactly those two
			// keys, a pattern-valid reason_code, and the verbatim message.
			var raw map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
				t.Fatalf("body not JSON: %v (%q)", err, w.Body.String())
			}
			if len(raw) != 2 {
				t.Fatalf("body key set = %v, want exactly {reason_code, message}", raw)
			}
			var br boundedReason
			if err := json.Unmarshal(w.Body.Bytes(), &br); err != nil {
				t.Fatalf("body not a BoundedReason: %v", err)
			}
			if !reasonRE.MatchString(br.ReasonCode) {
				t.Fatalf("reason_code %q is not pattern-valid", br.ReasonCode)
			}
			// The reason_code is the uppercased wire code (the preferred default
			// vocabulary for the common verdicts).
			if want := strings.ToUpper(v.WireCode); br.ReasonCode != want {
				t.Fatalf("reason_code = %q, want %q", br.ReasonCode, want)
			}
			if br.Message != "diagnostic message" {
				t.Fatalf("message = %q, want %q", br.Message, "diagnostic message")
			}

			// x-deny-reason is gated to authorization verdicts only, and carries
			// the broker-resolved AUDIT truth (never the wire code).
			gotHeader := w.Header().Get(denyReasonHeader) != ""
			if gotHeader != tc.wantHeader {
				t.Fatalf("x-deny-reason present = %v, want %v", gotHeader, tc.wantHeader)
			}
			if tc.wantHeader && w.Header().Get(denyReasonHeader) != v.AuditReason {
				t.Fatalf("x-deny-reason = %q, want the audit truth %q", w.Header().Get(denyReasonHeader), v.AuditReason)
			}
		})
	}
}

// TestRESTDenyDegradeCarriesTruthHeader pins the audited-truth vs wire-reason
// split on the REST writer: a scope_mismatch degraded to a not_found wire class
// still carries the x-deny-reason TRUTH header (scope_mismatch), because the
// wire CODE is permission-class-gated by the verdict's WireHeader, and the body
// reason_code reflects the degraded wire code (not_found -> NOT_FOUND).
//
// The degrade keeps the header gating with the AUDIT truth: mapDenyDegraded
// preserves the wire class's header flag. A scope_mismatch->not_found degrade
// therefore drops the header (not_found is not header-gated) — anti-enumeration:
// a degraded-to-404 deny carries no truth header on the wire.
func TestRESTDenyDegradeDropsHeaderOnNotFound(t *testing.T) {
	v := mapDenyDegraded(denyScopeMismatch, denyNotFound)
	w := httptest.NewRecorder()
	writeRESTDeny(w, v, "object not found")

	if w.Code != http.StatusNotFound {
		t.Fatalf("degraded status = %d, want 404", w.Code)
	}
	// The wire body reason_code is the DEGRADED wire code, never the truth.
	br := decodeErrBody(t, w)
	if br.Code != wireCodeNotFound {
		t.Fatalf("degraded reason_code lowercases to %q, want %q", br.Code, wireCodeNotFound)
	}
	// not_found is not header-gated: no truth header leaks on a degraded-to-404.
	if w.Header().Get(denyReasonHeader) != "" {
		t.Fatalf("x-deny-reason present on a degraded not_found, want none (anti-enumeration)")
	}
}

// TestRESTDenyClampsMessage pins the BoundedReason.message ceiling: a message
// longer than boundedReasonMessageMax is truncated on the wire so a deny body
// can never blow the contract's maxLength.
func TestRESTDenyClampsMessage(t *testing.T) {
	long := strings.Repeat("x", boundedReasonMessageMax+100)
	w := httptest.NewRecorder()
	writeRESTDeny(w, mapDeny(denyInternal), long)

	var br boundedReason
	if err := json.Unmarshal(w.Body.Bytes(), &br); err != nil {
		t.Fatalf("body not a BoundedReason: %v", err)
	}
	if len(br.Message) != boundedReasonMessageMax {
		t.Fatalf("clamped message length = %d, want %d", len(br.Message), boundedReasonMessageMax)
	}
}
