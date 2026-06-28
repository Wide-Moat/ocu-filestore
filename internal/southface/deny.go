// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
)

// Deny classes. The token strings are owned by the shared, zero-dependency
// internal/denyclass package — the SINGLE source of truth consumed by both the
// south face (here) and the telemetry deny_class label enum. The local short
// names below are aliases for use throughout this package; adding a deny class
// happens in internal/denyclass, and the drift-guard test
// (TestDenyTableMatchesSharedVocabulary) fails if the denyTable below loses a
// class the shared vocabulary defines.
//
// The first six are the contract's deny vocabulary — the only values that may
// ever surface in an x-deny-reason header. The rest are capacity, conflict,
// registry, and system states that never carry the header; their names exist
// for the audit record and the wire-code mapping only.
const (
	denyScopeMismatch   = denyclass.ScopeMismatch
	denyIntentDenied    = denyclass.IntentDenied
	denyNotDownloadable = denyclass.NotDownloadable
	denyLeaseExpired    = denyclass.LeaseExpired
	denySizeExceeded    = denyclass.SizeExceeded
	denyNotFound        = denyclass.NotFound

	denyMalformed     = denyclass.Malformed
	denyThrottle      = denyclass.Throttle
	denyAuditDown     = denyclass.AuditDown
	denyAlreadyExists = denyclass.AlreadyExists
	denyAborted       = denyclass.Aborted
	denyUnimplemented = denyclass.Unimplemented
	denyInternal      = denyclass.Internal

	// denyDirNotEmpty is the audited TRUTH for a non-recursive removeDirectory
	// on a non-empty directory (phase 9, W1). It is a distinct audit-reason
	// token — NOT denyMalformed/"malformed_envelope" — so the durable record
	// names the real operational refusal; its WIRE class is
	// invalid_argument/400 with no x-deny-reason header (a request fault, not
	// an authorization verdict).
	denyDirNotEmpty = denyclass.DirNotEmpty

	// denyBackendUnavailable is the audited TRUTH for a transient backend
	// failure surviving the engine's bounded retries (a network engine's
	// backend leg failed; the caller may retry). It is a DISTINCT audited
	// truth from denyAuditDown — the audit gate is healthy; the storage
	// backend is not — though both map to the unavailable wire code.
	denyBackendUnavailable = denyclass.BackendUnavailable

	// denyclassNone is the deny_class label value an ALLOW outcome carries in
	// ops_total ("none"). It is the shared denyclass sentinel, used by the
	// streaming allow-recording path so the literal is not duplicated.
	denyclassNone = denyclass.None
)

// Connect wire codes (closed set). The token strings are owned by the shared
// internal/denywire package — the SINGLE source of the wire mapping consumed by
// both the south face (here) and the north Files-API handler. The local names
// below are aliases so the rest of this package (the deny table, the parity
// fixtures) reads unchanged; the parity test pins south behaviour byte-identical
// to denywire.
const (
	wireCodeInvalidArgument   = denywire.WireCodeInvalidArgument
	wireCodeUnauthenticated   = denywire.WireCodeUnauthenticated
	wireCodePermissionDenied  = denywire.WireCodePermissionDenied
	wireCodeNotFound          = denywire.WireCodeNotFound
	wireCodeAlreadyExists     = denywire.WireCodeAlreadyExists
	wireCodeAborted           = denywire.WireCodeAborted
	wireCodeResourceExhausted = denywire.WireCodeResourceExhausted
	wireCodeUnimplemented     = denywire.WireCodeUnimplemented
	wireCodeUnavailable       = denywire.WireCodeUnavailable
	wireCodeInternal          = denywire.WireCodeInternal
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
	denyScopeMismatch:      {wireCodePermissionDenied, true},
	denyIntentDenied:       {wireCodePermissionDenied, true},
	denyNotDownloadable:    {wireCodePermissionDenied, true},
	denyLeaseExpired:       {wireCodeUnauthenticated, true},
	denySizeExceeded:       {wireCodeInvalidArgument, false},
	denyMalformed:          {wireCodeInvalidArgument, false},
	denyDirNotEmpty:        {wireCodeInvalidArgument, false},
	denyNotFound:           {wireCodeNotFound, false},
	denyThrottle:           {wireCodeResourceExhausted, false},
	denyAuditDown:          {wireCodeUnavailable, false},
	denyBackendUnavailable: {wireCodeUnavailable, false},
	denyAlreadyExists:      {wireCodeAlreadyExists, false},
	denyAborted:            {wireCodeAborted, false},
	denyUnimplemented:      {wireCodeUnimplemented, false},
	denyInternal:           {wireCodeInternal, false},
}

// statusForWireCode derives the HTTP status from a Connect wire code
// (closed set). An unknown code is a wiring bug and maps to 500. It delegates
// to the shared denywire mapping so the south and north faces never re-derive
// the status table independently.
func statusForWireCode(code string) int {
	return denywire.StatusForWireCode(code)
}

// fromDenywire converts a shared denywire.DenyVerdict into the south-face
// DenyVerdict. The two structs are field-identical; the conversion exists only
// because south keeps its own named type (it carries the withStatus method the
// 405 path uses). The CorrelationID a caller later stamps is preserved by every
// south call site exactly as before — denywire never auto-mints one.
func fromDenywire(v denywire.DenyVerdict) DenyVerdict {
	return DenyVerdict{
		AuditReason:   v.AuditReason,
		WireCode:      v.WireCode,
		WireStatus:    v.WireStatus,
		WireHeader:    v.WireHeader,
		CorrelationID: v.CorrelationID,
	}
}

// toDenywire is the inverse of fromDenywire: it lowers a south DenyVerdict into
// the shared shape the denywire writer consumes.
func toDenywire(v DenyVerdict) denywire.DenyVerdict {
	return denywire.DenyVerdict{
		AuditReason:   v.AuditReason,
		WireCode:      v.WireCode,
		WireStatus:    v.WireStatus,
		WireHeader:    v.WireHeader,
		CorrelationID: v.CorrelationID,
	}
}

// mapDeny maps a deny class to its verdict with the wire reason equal to
// the audited truth (no degrade, no correlation id). An unknown class fails
// closed to internal/500 with no header. It delegates to the shared denywire
// mapper; the parity test pins the result byte-identical.
func mapDeny(class string) DenyVerdict {
	return fromDenywire(denywire.MapDeny(class))
}

// mapDenyDegraded builds the verdict for the audited-truth vs wire-reason
// split: the audit record carries auditReason (the broker-resolved TRUTH);
// the wire carries wireClass's code, status, and header gating. The
// CorrelationID is NOT auto-minted here; callers set it to the per-request
// id (T2-18) so the audit record, the x-request-id response header, and
// the log line all share ONE id rather than two. A caller that does not set
// CorrelationID explicitly gets an empty string — acceptable for code paths
// that do not have a request context (e.g., direct unit tests). It delegates
// to the shared denywire mapper.
func mapDenyDegraded(auditReason, wireClass string) DenyVerdict {
	return fromDenywire(denywire.MapDenyDegraded(auditReason, wireClass))
}

// denyClassForErr names the deny class for a consumer-side seam sentinel.
// context.Canceled and context.DeadlineExceeded are classified FIRST as
// denyAborted (T2-5, RES-03): a client disconnect or deadline is a clean
// "aborted/canceled" verdict, not a generic error that would pollute the
// audit chain or be misclassified as a backend transient. An error outside
// the known sentinel set is a wiring fault and fails closed to internal.
func denyClassForErr(err error) string {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return denyAborted
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
