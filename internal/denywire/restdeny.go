// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package denywire

import (
	"encoding/json"
	"net/http"
	"strings"
)

// The deny verdict is the HTTP status (authoritative) plus a BoundedReason
// {reason_code, message} diagnostic body. The HTTP status is the ONLY thing a
// caller keys behaviour on (401|403 -> permission, 404 -> not_found incl. the
// anti-enumeration degrade, 409 -> already_exists, 400|422 -> invalid, 429|503
// -> retryable, else -> permanent); the body is DIAGNOSTIC only and never drives
// the mapping. The reason_code is a pattern-validated OPEN string
// (^[A-Z][A-Z0-9_]{1,63}$), not an enum. This writer is the shared pre-byte
// refusal path for BOTH faces — the south RPC plane delegates to it, and the
// north Files-API handler calls it directly.

// contentTypeJSON is the deny body content type. It is the literal both faces
// emit; declaring it here keeps the writer free of any south-package import.
const contentTypeJSON = "application/json"

// BoundedReasonMessageMax is the BoundedReason.message length ceiling (the
// contract's maxLength). A longer diagnostic is truncated to this many bytes
// before it reaches the wire.
const BoundedReasonMessageMax = 256

// DenyReasonHeader is the response header name carrying the broker-resolved
// audit TRUTH on authorization verdicts only (permission_denied /
// unauthenticated). It is gated by DenyVerdict.WireHeader — an
// anti-enumeration-degraded verdict carries no truth header.
const DenyReasonHeader = "x-deny-reason"

// boundedReason is the diagnostic deny body: a pattern-validated open
// reason_code and a bounded human-readable message. The HTTP status is
// authoritative; this body is diagnostic only.
type boundedReason struct {
	// ReasonCode is a pattern-validated open string matching
	// ^[A-Z][A-Z0-9_]{1,63}$ — NOT an enum. It is derived from the verdict's
	// wire code (uppercased) so the default vocabulary is emitted for the common
	// verdicts, while remaining an open string the contract does not close.
	ReasonCode string `json:"reason_code"`
	// Message is a bounded human-readable diagnostic, clamped to
	// BoundedReasonMessageMax bytes so a deny body can never blow the wire.
	Message string `json:"message"`
}

// ReasonCodeForVerdict derives the BoundedReason.reason_code from a verdict's
// wire code: the lowercase closed Connect-code set is mapped to its uppercase
// token (permission_denied -> PERMISSION_DENIED, not_found -> NOT_FOUND, ...),
// which is pattern-valid and is the preferred default vocabulary. The
// reason_code is DIAGNOSTIC only. An empty or unexpected wire code falls back to
// INTERNAL so the body is always pattern-valid.
func ReasonCodeForVerdict(v DenyVerdict) string {
	code := strings.ToUpper(v.WireCode)
	if code == "" {
		return "INTERNAL"
	}
	return code
}

// BoundedReason clamps a diagnostic message to BoundedReasonMessageMax bytes so
// the BoundedReason body can never exceed the contract's maxLength. It is
// exported so a caller that wants the clamped value (e.g. a test) shares the one
// implementation.
func BoundedReason(message string) string {
	if len(message) <= BoundedReasonMessageMax {
		return message
	}
	return message[:BoundedReasonMessageMax]
}

// WriteRESTDeny writes a REST deny response from a DenyVerdict: the
// authoritative HTTP status (DenyVerdict.WireStatus), the application/json
// BoundedReason {reason_code, message} diagnostic body, and — only when the
// verdict gates it (permission_denied / unauthenticated) — the x-deny-reason
// header carrying the broker-resolved audit truth.
//
// x-request-id is NOT set here: the caller stamps it on the response header
// before any deny path runs, so it is already queued on w.Header() and surfaces
// on every response — allow and deny alike.
func WriteRESTDeny(w http.ResponseWriter, v DenyVerdict, message string) {
	if v.WireHeader {
		w.Header().Set(DenyReasonHeader, v.AuditReason)
	}
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(v.WireStatus)
	_ = json.NewEncoder(w).Encode(boundedReason{
		ReasonCode: ReasonCodeForVerdict(v),
		Message:    BoundedReason(message),
	})
}
