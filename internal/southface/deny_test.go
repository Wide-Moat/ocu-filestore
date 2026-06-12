// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"errors"
	"regexp"
	"testing"
)

// TestDenyMapperTable pins every row of the deny mapping: deny class to
// Connect wire code, HTTP status, and x-deny-reason header presence. The
// header appears only on authorization verdicts (permission_denied and
// unauthenticated); capacity, conflict, registry, and system states carry
// none.
func TestDenyMapperTable(t *testing.T) {
	for _, tc := range []struct {
		class      string
		wantCode   string
		wantStatus int
		wantHeader bool
	}{
		{denyScopeMismatch, wireCodePermissionDenied, 403, true},
		{denyIntentDenied, wireCodePermissionDenied, 403, true},
		{denyNotDownloadable, wireCodePermissionDenied, 403, true},
		{denyLeaseExpired, wireCodeUnauthenticated, 401, true},
		{denySizeExceeded, wireCodeInvalidArgument, 400, false},
		{denyMalformed, wireCodeInvalidArgument, 400, false},
		{denyNotFound, wireCodeNotFound, 404, false},
		{denyThrottle, wireCodeResourceExhausted, 429, false},
		{denyAuditDown, wireCodeUnavailable, 503, false},
		{denyAlreadyExists, wireCodeAlreadyExists, 409, false},
		{denyAborted, wireCodeAborted, 409, false},
		{denyUnimplemented, wireCodeUnimplemented, 501, false},
		{denyInternal, wireCodeInternal, 500, false},
	} {
		t.Run(tc.class, func(t *testing.T) {
			v := mapDeny(tc.class)
			if v.AuditReason != tc.class {
				t.Fatalf("mapDeny(%q).AuditReason = %q, want %q", tc.class, v.AuditReason, tc.class)
			}
			if v.WireCode != tc.wantCode {
				t.Fatalf("mapDeny(%q).WireCode = %q, want %q", tc.class, v.WireCode, tc.wantCode)
			}
			if v.WireStatus != tc.wantStatus {
				t.Fatalf("mapDeny(%q).WireStatus = %d, want %d", tc.class, v.WireStatus, tc.wantStatus)
			}
			if v.WireHeader != tc.wantHeader {
				t.Fatalf("mapDeny(%q).WireHeader = %v, want %v", tc.class, v.WireHeader, tc.wantHeader)
			}
			if v.CorrelationID != "" {
				t.Fatalf("mapDeny(%q).CorrelationID = %q, want empty (truth == wire)", tc.class, v.CorrelationID)
			}
		})
	}
}

// TestDenyMapperUnknownClassFailsClosed pins that an unknown deny class maps
// to internal/500 with no header — a wiring mistake never leaks a permissive
// or unmapped response.
func TestDenyMapperUnknownClassFailsClosed(t *testing.T) {
	v := mapDeny("no_such_class")
	if v.WireCode != wireCodeInternal || v.WireStatus != 500 || v.WireHeader {
		t.Fatalf("mapDeny(unknown) = %+v, want internal/500/no header", v)
	}
}

// TestDenyMapperAuditTruthSplit pins the audited-truth vs wire-reason split:
// when the wire reason degrades away from the broker-resolved truth (e.g.
// audited scope_mismatch presented as not_found for anti-enumeration), the
// verdict carries the truth in AuditReason, the degraded code on the wire,
// and a correlation id linking the two.
func TestDenyMapperAuditTruthSplit(t *testing.T) {
	v := mapDenyDegraded(denyScopeMismatch, denyNotFound)
	if v.AuditReason != denyScopeMismatch {
		t.Fatalf("AuditReason = %q, want %q (broker truth)", v.AuditReason, denyScopeMismatch)
	}
	if v.WireCode != wireCodeNotFound || v.WireStatus != 404 {
		t.Fatalf("wire = %q/%d, want not_found/404 (degraded)", v.WireCode, v.WireStatus)
	}
	if v.WireHeader {
		t.Fatalf("WireHeader = true, want false (not_found carries no x-deny-reason)")
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(v.CorrelationID) {
		t.Fatalf("CorrelationID = %q, want 32-char lowercase hex", v.CorrelationID)
	}

	// When truth and wire agree the correlation id may be (and is) empty.
	same := mapDenyDegraded(denyScopeMismatch, denyScopeMismatch)
	if same.CorrelationID != "" {
		t.Fatalf("CorrelationID = %q, want empty when truth == wire", same.CorrelationID)
	}
	if same.AuditReason != denyScopeMismatch || same.WireCode != wireCodePermissionDenied || !same.WireHeader {
		t.Fatalf("agreeing verdict = %+v, want plain scope_mismatch mapping", same)
	}
}

// TestCorrelationID pins the correlation id shape: 32-char lowercase hex,
// distinct across calls.
func TestCorrelationID(t *testing.T) {
	a := newCorrelationID()
	b := newCorrelationID()
	hexRe := regexp.MustCompile(`^[0-9a-f]{32}$`)
	if !hexRe.MatchString(a) || !hexRe.MatchString(b) {
		t.Fatalf("newCorrelationID() = %q, %q; want 32-char lowercase hex", a, b)
	}
	if a == b {
		t.Fatalf("two correlation ids are equal: %q", a)
	}
}

// TestDenyClassForErr pins the sentinel-to-class mapping the pipeline uses:
// each consumer-side seam sentinel names exactly one deny class; an unknown
// error fails closed to internal.
func TestDenyClassForErr(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"scope mismatch", ErrScopeMismatch, denyScopeMismatch},
		{"intent denied", ErrIntentDenied, denyIntentDenied},
		{"not downloadable", ErrNotDownloadable, denyNotDownloadable},
		{"lease expired", ErrLeaseExpired, denyLeaseExpired},
		{"size exceeded", ErrSizeExceeded, denySizeExceeded},
		{"throttle", ErrThrottleExceeded, denyThrottle},
		{"bytes ceiling", ErrBytesExceeded, denyThrottle},
		{"fd ceiling", ErrFDExceeded, denyThrottle},
		{"audit down", ErrAuditUnavailable, denyAuditDown},
		{"unknown error", errors.New("southface: unmapped failure"), denyInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := denyClassForErr(tc.err); got != tc.want {
				t.Fatalf("denyClassForErr(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
