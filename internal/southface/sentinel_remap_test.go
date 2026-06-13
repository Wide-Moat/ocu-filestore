// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
)

// TestSentinelClassifiesToD4Verdict is the WIRE-SENTINEL spine-side pin: every
// southface mirror sentinel classifies through denyClassForErr to its expected
// D4 verdict (audit reason, wire code, HTTP status, x-deny-reason header
// gating). The x-deny-reason header is present ONLY on the authz verdicts
// (scope_mismatch / intent_denied / not_downloadable / lease_expired);
// capacity, size, and conflict states carry no header (D4/n3).
//
// The Wave-2 broker adapters remap the REAL seam sentinels onto these mirrors;
// this table locks the contract those adapters remap onto.
func TestSentinelClassifiesToD4Verdict(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantReason string
		wantCode   string
		wantStatus int
		wantHeader bool
	}{
		// Authz verdicts — the only rows that carry x-deny-reason (n3).
		{"scope_mismatch", ErrScopeMismatch, denyScopeMismatch, wireCodePermissionDenied, 403, true},
		{"intent_denied", ErrIntentDenied, denyIntentDenied, wireCodePermissionDenied, 403, true},
		{"not_downloadable", ErrNotDownloadable, denyNotDownloadable, wireCodePermissionDenied, 403, true},
		{"lease_expired", ErrLeaseExpired, denyLeaseExpired, wireCodeUnauthenticated, 401, true},
		// Audit fail-closed — unavailable, no header.
		{"audit_down", ErrAuditUnavailable, denyAuditDown, wireCodeUnavailable, 503, false},
		// Size — invalid_argument, no header.
		{"size_exceeded", ErrSizeExceeded, denySizeExceeded, wireCodeInvalidArgument, 400, false},
		// Capacity — resource_exhausted, no header (n3).
		{"throttle", ErrThrottleExceeded, denyThrottle, wireCodeResourceExhausted, 429, false},
		{"bytes", ErrBytesExceeded, denyThrottle, wireCodeResourceExhausted, 429, false},
		{"fd", ErrFDExceeded, denyThrottle, wireCodeResourceExhausted, 429, false},
		// Non-vacuity counter: an unknown error is NOT all-pass — it fails
		// closed to internal/500 with no header.
		{"non_sentinel", errors.New("boom"), denyInternal, wireCodeInternal, 500, false},
		// Wrapped sentinel still classifies (errors.Is through the wrap).
		{"wrapped_scope_mismatch", fmt.Errorf("ctx: %w", ErrScopeMismatch), denyScopeMismatch, wireCodePermissionDenied, 403, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := mapDeny(denyClassForErr(tc.err))
			if v.AuditReason != tc.wantReason {
				t.Fatalf("AuditReason = %q, want %q", v.AuditReason, tc.wantReason)
			}
			if v.WireCode != tc.wantCode {
				t.Fatalf("WireCode = %q, want %q", v.WireCode, tc.wantCode)
			}
			if v.WireStatus != tc.wantStatus {
				t.Fatalf("WireStatus = %d, want %d", v.WireStatus, tc.wantStatus)
			}
			if v.WireHeader != tc.wantHeader {
				t.Fatalf("WireHeader = %v, want %v", v.WireHeader, tc.wantHeader)
			}
		})
	}
}

// TestEngineSentinelClassifiesToD4Verdict pins denyClassForEngineErr and its
// LOAD-BEARING ordering (Pitfall 3): the already-exists / not-exist sentinels
// are tested BEFORE isPathEscape, so a benign EEXIST (which is also a
// *fs.PathError) is never misclassified as a security escape. A non-sentinel
// error is the non-vacuity counter -> denyInternal.
func TestEngineSentinelClassifiesToD4Verdict(t *testing.T) {
	// A *fs.PathError wrapping fs.ErrExist is BOTH an already-exists sentinel
	// AND a path-escape match; the ordering must classify it as already_exists.
	eexistPathErr := &fs.PathError{Op: "mkdirat", Path: "dup", Err: fs.ErrExist}
	enoentPathErr := &fs.PathError{Op: "openat", Path: "ghost", Err: fs.ErrNotExist}
	escapePathErr := &fs.PathError{Op: "openat", Path: "x", Err: errors.New("path escapes from parent")}
	escapeLinkErr := &os.LinkError{Op: "renameat", Old: "a", New: "../b", Err: errors.New("path escapes from parent")}

	for _, tc := range []struct {
		name      string
		err       error
		wantClass string
	}{
		{"errAlreadyExists_sentinel", errAlreadyExists, denyAlreadyExists},
		{"fs_ErrExist", fs.ErrExist, denyAlreadyExists},
		{"eexist_path_error_not_escape", eexistPathErr, denyAlreadyExists},
		{"fs_ErrNotExist", fs.ErrNotExist, denyNotFound},
		{"enoent_path_error", enoentPathErr, denyNotFound},
		{"errInvalidPath_degrades", errInvalidPath, denyNotFound},
		{"escape_path_error_degrades", escapePathErr, denyNotFound},
		{"escape_link_error_degrades", escapeLinkErr, denyNotFound},
		// Non-vacuity counter.
		{"non_sentinel", errors.New("boom"), denyInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := denyClassForEngineErr(tc.err); got != tc.wantClass {
				t.Fatalf("denyClassForEngineErr(%v) = %q, want %q", tc.err, got, tc.wantClass)
			}
		})
	}
}
