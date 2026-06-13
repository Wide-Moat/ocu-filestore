// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package denyclass is the single source of truth for the broker's deny-class
// vocabulary — the closed set of audit-reason tokens that name every refusal
// the south face can record. It is a zero-dependency leaf package so that both
// the south face (which produces these tokens) and the telemetry package
// (which uses them as the ops_total{deny_class} label enum) consume ONE
// definition. There is no second hand-maintained mirror to drift: the south
// face's deny table is keyed by these constants and the telemetry label set is
// derived from All(). A new deny class is added here once.
package denyclass

// Deny-class audit-reason tokens. These are the only values that may appear as
// the broker-resolved AuditReason of a refusal and, in turn, as the deny_class
// label value of a denied ops_total sample. The first six are the contract's
// deny vocabulary (the only values that may surface in an x-deny-reason
// header); the rest are capacity, conflict, registry, and system states whose
// names exist for the durable audit record and the wire-code mapping only.
const (
	ScopeMismatch   = "scope_mismatch"
	IntentDenied    = "intent_denied"
	NotDownloadable = "not_downloadable"
	LeaseExpired    = "lease_expired"
	SizeExceeded    = "size_exceeded"
	NotFound        = "not_found"

	Malformed     = "malformed_envelope"
	Throttle      = "throttle"
	AuditDown     = "audit_down"
	AlreadyExists = "already_exists"
	Aborted       = "aborted"
	Unimplemented = "unimplemented"
	Internal      = "internal"

	// DirNotEmpty is the audited truth for a non-recursive removeDirectory on a
	// non-empty directory; a distinct audit-reason token from Malformed so the
	// durable record names the real operational refusal.
	DirNotEmpty = "directory_not_empty"

	// BackendUnavailable is the audited truth for a transient backend failure
	// surviving the engine's bounded retries — distinct from AuditDown (the
	// audit gate is healthy; the storage backend is not).
	BackendUnavailable = "backend_unavailable"
)

// None is the sentinel deny_class label value carried by an ALLOW outcome. It
// is not a deny class; it exists only so ops_total has a closed deny_class
// enum across both outcomes.
const None = "none"

// denyClasses is the canonical, ordered list of every deny-class token. Adding
// a deny class above and here is the ONLY edit needed: the south face's deny
// table is keyed by these constants and telemetry derives its label enum from
// All(). The drift-guard test in the south face asserts the deny table's key
// set equals this list.
var denyClasses = []string{
	ScopeMismatch,
	IntentDenied,
	NotDownloadable,
	LeaseExpired,
	SizeExceeded,
	NotFound,
	Malformed,
	Throttle,
	AuditDown,
	AlreadyExists,
	Aborted,
	Unimplemented,
	Internal,
	DirNotEmpty,
	BackendUnavailable,
}

// DenyClasses returns a copy of the closed deny-class vocabulary (excluding the
// allow sentinel None).
func DenyClasses() []string {
	cp := make([]string, len(denyClasses))
	copy(cp, denyClasses)
	return cp
}

// All returns a copy of every value the ops_total{deny_class} label may take:
// the allow sentinel None followed by the full deny-class vocabulary.
func All() []string {
	out := make([]string, 0, len(denyClasses)+1)
	out = append(out, None)
	out = append(out, denyClasses...)
	return out
}
