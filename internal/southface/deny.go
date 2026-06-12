// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// Deny classes. The first six are the contract's deny vocabulary — the only
// values that may ever surface in an x-deny-reason header. The rest are
// capacity, conflict, registry, and system states that never carry the
// header; their names exist for the audit record and the wire-code mapping
// only.
const (
	denyScopeMismatch   = "scope_mismatch"
	denyIntentDenied    = "intent_denied"
	denyNotDownloadable = "not_downloadable"
	denyLeaseExpired    = "lease_expired"
	denySizeExceeded    = "size_exceeded"
	denyNotFound        = "not_found"

	denyMalformed     = "malformed_envelope"
	denyThrottle      = "throttle"
	denyAuditDown     = "audit_down"
	denyAlreadyExists = "already_exists"
	denyAborted       = "aborted"
	denyUnimplemented = "unimplemented"
	denyInternal      = "internal"
)

// Connect wire codes (closed set).
const (
	wireCodeInvalidArgument   = "invalid_argument"
	wireCodeUnauthenticated   = "unauthenticated"
	wireCodePermissionDenied  = "permission_denied"
	wireCodeNotFound          = "not_found"
	wireCodeAlreadyExists     = "already_exists"
	wireCodeAborted           = "aborted"
	wireCodeResourceExhausted = "resource_exhausted"
	wireCodeUnimplemented     = "unimplemented"
	wireCodeUnavailable       = "unavailable"
	wireCodeInternal          = "internal"
)

// DenyVerdict is the deny mapper's output — the single source of truth for
// every refusal the spine writes. AuditReason is the broker-resolved TRUTH
// that goes into the audit record; WireCode/WireStatus are what the caller
// sees and MAY degrade away from the truth (anti-enumeration); WireHeader
// gates the x-deny-reason header to authorization verdicts only;
// CorrelationID links the audited record to the wire response whenever
// truth and wire differ.
type DenyVerdict struct {
	// AuditReason is the broker-resolved truth, named in the deny class
	// vocabulary above.
	AuditReason string
	// WireCode is the Connect error code written to the caller.
	WireCode string
	// WireStatus is the HTTP status derived from WireCode.
	WireStatus int
	// WireHeader is true only when the response carries
	// x-deny-reason: AuditReason — authorization verdicts
	// (permission_denied, unauthenticated) and nothing else.
	WireHeader bool
	// CorrelationID is a 32-char lowercase hex id, set when AuditReason
	// and the wire-visible reason differ; empty when they agree.
	CorrelationID string
}

// denyRow is one row of the deny mapping table.
type denyRow struct {
	wireCode string
	header   bool
}

// denyTable maps every deny class to its Connect wire code and header
// gating. The header is true only for rows whose wire code is
// permission_denied or unauthenticated.
var denyTable = map[string]denyRow{
	denyScopeMismatch:   {wireCodePermissionDenied, true},
	denyIntentDenied:    {wireCodePermissionDenied, true},
	denyNotDownloadable: {wireCodePermissionDenied, true},
	denyLeaseExpired:    {wireCodeUnauthenticated, true},
	denySizeExceeded:    {wireCodeInvalidArgument, false},
	denyMalformed:       {wireCodeInvalidArgument, false},
	denyNotFound:        {wireCodeNotFound, false},
	denyThrottle:        {wireCodeResourceExhausted, false},
	denyAuditDown:       {wireCodeUnavailable, false},
	denyAlreadyExists:   {wireCodeAlreadyExists, false},
	denyAborted:         {wireCodeAborted, false},
	denyUnimplemented:   {wireCodeUnimplemented, false},
	denyInternal:        {wireCodeInternal, false},
}

// statusForWireCode derives the HTTP status from a Connect wire code
// (closed set). An unknown code is a wiring bug and maps to 500.
func statusForWireCode(code string) int {
	switch code {
	case wireCodeInvalidArgument:
		return 400
	case wireCodeUnauthenticated:
		return 401
	case wireCodePermissionDenied:
		return 403
	case wireCodeNotFound:
		return 404
	case wireCodeAlreadyExists, wireCodeAborted:
		return 409
	case wireCodeResourceExhausted:
		return 429
	case wireCodeUnimplemented:
		return 501
	case wireCodeUnavailable:
		return 503
	default:
		return 500
	}
}

// mapDeny maps a deny class to its verdict with the wire reason equal to
// the audited truth (no degrade, no correlation id). An unknown class fails
// closed to internal/500 with no header.
func mapDeny(class string) DenyVerdict {
	row, ok := denyTable[class]
	if !ok {
		return DenyVerdict{
			AuditReason: class,
			WireCode:    wireCodeInternal,
			WireStatus:  500,
			WireHeader:  false,
		}
	}
	return DenyVerdict{
		AuditReason: class,
		WireCode:    row.wireCode,
		WireStatus:  statusForWireCode(row.wireCode),
		WireHeader:  row.header,
	}
}

// mapDenyDegraded builds the verdict for the audited-truth vs wire-reason
// split: the audit record carries auditReason (the broker-resolved TRUTH);
// the wire carries wireClass's code, status, and header gating. When the
// two differ, a correlation id links the audited record to the wire
// response. The degrade itself (e.g. cross-scope uuid presented as
// not_found) is handler-phase behaviour; the spine carries the split now so
// the API is fixed.
func mapDenyDegraded(auditReason, wireClass string) DenyVerdict {
	v := mapDeny(wireClass)
	v.AuditReason = auditReason
	if auditReason != wireClass {
		v.CorrelationID = newCorrelationID()
	}
	return v
}

// denyClassForErr names the deny class for a consumer-side seam sentinel.
// An error outside the known sentinel set is a wiring fault and fails
// closed to internal.
func denyClassForErr(err error) string {
	switch {
	case errors.Is(err, ErrScopeMismatch):
		return denyScopeMismatch
	case errors.Is(err, ErrIntentDenied):
		return denyIntentDenied
	case errors.Is(err, ErrNotDownloadable):
		return denyNotDownloadable
	case errors.Is(err, ErrLeaseExpired):
		return denyLeaseExpired
	case errors.Is(err, ErrSizeExceeded):
		return denySizeExceeded
	case errors.Is(err, ErrThrottleExceeded),
		errors.Is(err, ErrBytesExceeded),
		errors.Is(err, ErrFDExceeded):
		return denyThrottle
	case errors.Is(err, ErrAuditUnavailable):
		return denyAuditDown
	default:
		return denyInternal
	}
}

// newCorrelationID returns a 32-char lowercase hex id from 16 bytes of
// crypto/rand. A failing kernel CSPRNG is unrecoverable — fail loud.
func newCorrelationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("southface: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
