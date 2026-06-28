// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package denywire is the shared deny-verdict mapper consumed by BOTH the south
// face (the guest-mount RPC plane) and the north Files-API handler. It owns the
// one canonical mapping from a deny-class audit token (internal/denyclass) to
// its Connect wire code, HTTP status, and x-deny-reason header gating, plus the
// REST deny writer that renders a DenyVerdict to an http.ResponseWriter.
//
// Before this package existed, the south face owned the mapping inline. The
// north Files-API plane needs the SAME mapping — an independent re-derivation
// would be a second copy free to drift. Factoring the mapping here, behind a
// cross-package parity test that pins south's behaviour byte-identical against
// an INDEPENDENT golden anchor (not derived from this table), keeps a single
// source of truth without a vacuous "two derivations of one source agree" guard.
//
// The deny vocabulary itself lives in the zero-dependency internal/denyclass
// leaf; this package maps those tokens to the wire. It imports only denyclass
// and the standard library.
package denywire

import "github.com/Wide-Moat/ocu-filestore/internal/denyclass"

// Connect wire codes (closed set). These are the only values DenyVerdict.WireCode
// may take; statusForWireCode maps each to its HTTP status.
const (
	WireCodeInvalidArgument   = "invalid_argument"
	WireCodeUnauthenticated   = "unauthenticated"
	WireCodePermissionDenied  = "permission_denied"
	WireCodeNotFound          = "not_found"
	WireCodeAlreadyExists     = "already_exists"
	WireCodeAborted           = "aborted"
	WireCodeResourceExhausted = "resource_exhausted"
	WireCodeUnimplemented     = "unimplemented"
	WireCodeUnavailable       = "unavailable"
	WireCodeInternal          = "internal"
)

// DenyVerdict is the deny mapper's output — the single source of truth for every
// refusal a face writes. AuditReason is the broker-resolved TRUTH that goes into
// the audit record; WireCode/WireStatus are what the caller sees and MAY degrade
// away from the truth (anti-enumeration); WireHeader gates the x-deny-reason
// header to authorization verdicts only; CorrelationID links the audited record
// to the wire response whenever truth and wire differ.
type DenyVerdict struct {
	// AuditReason is the broker-resolved truth, named in the denyclass
	// vocabulary.
	AuditReason string
	// WireCode is the Connect error code written to the caller.
	WireCode string
	// WireStatus is the HTTP status derived from WireCode.
	WireStatus int
	// WireHeader is true only when the response carries
	// x-deny-reason: AuditReason — authorization verdicts (permission_denied,
	// unauthenticated) and nothing else.
	WireHeader bool
	// CorrelationID is a request-scoped id, set by the caller when AuditReason
	// and the wire-visible reason differ; empty when they agree.
	CorrelationID string
}

// denyRow is one row of the deny mapping table.
type denyRow struct {
	wireCode string
	header   bool
}

// denyTable maps every deny class to its Connect wire code and header gating.
// The header is true only for rows whose wire code is permission_denied or
// unauthenticated. Its key set MUST equal denyclass.DenyClasses() — the south
// drift guard (TestDenyTableMatchesSharedVocabulary) and the parity test both
// pin that, so a new deny class added to the shared vocabulary without a row
// here fails loudly.
var denyTable = map[string]denyRow{
	denyclass.ScopeMismatch:      {WireCodePermissionDenied, true},
	denyclass.IntentDenied:       {WireCodePermissionDenied, true},
	denyclass.NotDownloadable:    {WireCodePermissionDenied, true},
	denyclass.LeaseExpired:       {WireCodeUnauthenticated, true},
	denyclass.SizeExceeded:       {WireCodeInvalidArgument, false},
	denyclass.Malformed:          {WireCodeInvalidArgument, false},
	denyclass.DirNotEmpty:        {WireCodeInvalidArgument, false},
	denyclass.NotFound:           {WireCodeNotFound, false},
	denyclass.Throttle:           {WireCodeResourceExhausted, false},
	denyclass.AuditDown:          {WireCodeUnavailable, false},
	denyclass.BackendUnavailable: {WireCodeUnavailable, false},
	denyclass.AlreadyExists:      {WireCodeAlreadyExists, false},
	denyclass.Aborted:            {WireCodeAborted, false},
	denyclass.Unimplemented:      {WireCodeUnimplemented, false},
	denyclass.Internal:           {WireCodeInternal, false},
}

// StatusForWireCode derives the HTTP status from a Connect wire code (closed
// set). An unknown code is a wiring bug and maps to 500.
func StatusForWireCode(code string) int {
	switch code {
	case WireCodeInvalidArgument:
		return 400
	case WireCodeUnauthenticated:
		return 401
	case WireCodePermissionDenied:
		return 403
	case WireCodeNotFound:
		return 404
	case WireCodeAlreadyExists, WireCodeAborted:
		return 409
	case WireCodeResourceExhausted:
		return 429
	case WireCodeUnimplemented:
		return 501
	case WireCodeUnavailable:
		return 503
	default:
		return 500
	}
}

// MapDeny maps a deny class to its verdict with the wire reason equal to the
// audited truth (no degrade, no correlation id). An unknown class fails closed
// to internal/500 with no header.
func MapDeny(class string) DenyVerdict {
	row, ok := denyTable[class]
	if !ok {
		return DenyVerdict{
			AuditReason: class,
			WireCode:    WireCodeInternal,
			WireStatus:  500,
			WireHeader:  false,
		}
	}
	return DenyVerdict{
		AuditReason: class,
		WireCode:    row.wireCode,
		WireStatus:  StatusForWireCode(row.wireCode),
		WireHeader:  row.header,
	}
}

// MapDenyDegraded builds the verdict for the audited-truth vs wire-reason split:
// the audit record carries auditReason (the broker-resolved TRUTH); the wire
// carries wireClass's code, status, and header gating. The CorrelationID is NOT
// auto-minted here; callers set it to the per-request id so the audit record,
// the response correlation header, and the log line all share ONE id. A caller
// that does not set CorrelationID explicitly gets an empty string.
func MapDenyDegraded(auditReason, wireClass string) DenyVerdict {
	v := MapDeny(wireClass)
	v.AuditReason = auditReason
	return v
}
