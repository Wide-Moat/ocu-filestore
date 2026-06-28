// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"net/http"

	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
)

// PHASE-7(A3-deny): frozen @ canon-rev a030b7be914b: the deny verdict is the HTTP status (authoritative)
// contract FORM ratified by #292 @ a030b7be914b; governing ADR remains status:proposed — freezes the wire FORM, not ADR acceptance
// plus a BoundedReason {reason_code, message} diagnostic body. The HTTP status
// is the ONLY thing a caller keys behaviour on (401|403 -> permission, 404 ->
// not_found incl. the anti-enumeration degrade, 409 -> already_exists, 400|422
// -> invalid, 429|503 -> retryable, else -> permanent); the body is DIAGNOSTIC
// only and never drives the mapping. The reason_code is a pattern-validated
// OPEN string (^[A-Z][A-Z0-9_]{1,63}$), not an enum — the default vocabulary
// (SCOPE_MISMATCH / INTENT_DENIED / NOT_DOWNLOADABLE / LEASE_EXPIRED /
// SIZE_EXCEEDED / NOT_FOUND) is preferred for log consistency but any
// pattern-valid token is legal. Sibling-proven, frozen pending #292.
//
// This file is the REST deny writer for EVERY op: the 16 unary-JSON ops and the
// two data-plane ops (multipart fileUpload / octet-stream fileDownload) all
// write their pre-byte refusal through it. It is the sole replacement for the
// retired Connect error writer. The status comes from the SURVIVING deny.go
// DenyVerdict.WireStatus (derived via statusForWireCode) — this writer never
// reimplements the status table.

// boundedReason is the diagnostic deny body: a pattern-validated open
// reason_code and a bounded human-readable message. The HTTP status is
// authoritative; this body is diagnostic only. It is the BoundedReason envelope
// the contract pins for a deny.
type boundedReason struct {
	// ReasonCode is a pattern-validated open string matching
	// ^[A-Z][A-Z0-9_]{1,63}$ — NOT an enum. It is derived from the verdict's
	// wire code (uppercased) so the default vocabulary is emitted for the common
	// verdicts, while remaining an open string the contract does not close.
	ReasonCode string `json:"reason_code"`
	// Message is a bounded human-readable diagnostic, clamped to
	// boundedReasonMessageMax bytes so a deny body can never blow the wire.
	Message string `json:"message"`
}

// boundedReasonMessageMax is the BoundedReason.message length ceiling (the
// contract's maxLength). It aliases the shared denywire ceiling so the two faces
// can never disagree on the clamp.
const boundedReasonMessageMax = denywire.BoundedReasonMessageMax

// denyReasonHeader is the response header name carrying the broker-resolved
// audit TRUTH on authorization verdicts only (permission_denied /
// unauthenticated). It is gated by DenyVerdict.WireHeader exactly as the Connect
// path gated it — an anti-enumeration-degraded verdict carries no truth header.
// It aliases the shared denywire header name.
const denyReasonHeader = denywire.DenyReasonHeader

// reasonCodeForVerdict derives the BoundedReason.reason_code from a verdict's
// wire code: the lowercase closed Connect-code set is mapped to its
// uppercase token (permission_denied -> PERMISSION_DENIED, not_found ->
// NOT_FOUND, ...), which is pattern-valid (^[A-Z][A-Z0-9_]{1,63}$) and is the
// preferred default vocabulary. The reason_code is DIAGNOSTIC only; a caller
// never keys behaviour on it. It delegates to the shared denywire derivation.
func reasonCodeForVerdict(v DenyVerdict) string {
	return denywire.ReasonCodeForVerdict(toDenywire(v))
}

// writeRESTDeny writes a REST deny response from a DenyVerdict: the
// authoritative HTTP status (DenyVerdict.WireStatus), the application/json
// BoundedReason {reason_code, message} diagnostic body, and — only when the
// verdict gates it (permission_denied / unauthenticated) — the x-deny-reason
// header carrying the broker-resolved audit truth. It is the single pre-byte
// refusal path for every op: the 16 unary-JSON ops and the two data-plane ops.
// It delegates to the shared denywire writer, so the wire form is byte-identical
// to the north Files-API plane's deny responses (the parity test pins this).
//
// x-request-id is NOT set here: ServeHTTP stamps it on the response header at
// STAGE 0 before any deny path runs, so it is already queued on w.Header() and
// surfaces on every response — allow and deny alike.
func writeRESTDeny(w http.ResponseWriter, v DenyVerdict, message string) {
	denywire.WriteRESTDeny(w, toDenywire(v), message)
}
