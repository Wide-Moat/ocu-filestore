// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
)

// This file declares the narrow consumer-side seams the dispatch spine
// needs. The seam packages live on their own unmerged branches, so this
// package mirrors only the method signatures it calls — byte-for-byte at
// the method level — and the daemon wiring binds the real implementations
// in the composition phase. Nothing here imports internal/authz,
// internal/auditgate, internal/ceilings, or internal/admission.

// Intent mirrors the authorization intent axis from
// feat/authz-resolver:internal/authz/authz.go (Intent string with
// read/write/preview constants). The values are the wire intent vocabulary
// from the file-ops contract.
type Intent string

const (
	// IntentRead mirrors authz.IntentRead.
	IntentRead Intent = "read"
	// IntentWrite mirrors authz.IntentWrite.
	IntentWrite Intent = "write"
	// IntentPreview mirrors authz.IntentPreview.
	IntentPreview Intent = "preview"
)

// ResolveRequest mirrors authz.Request from
// feat/authz-resolver:internal/authz/authz.go
// (Request{Filesystem FilesystemID; Path string; Intent Intent}).
// Filesystem is a plain string here; the wiring layer converts to the
// resolver's named FilesystemID type.
type ResolveRequest struct {
	// Filesystem is the request's filesystem scope hint — cross-checked
	// against the channel-bound scope before the resolver ever sees it
	// (NFR-SEC-43); the resolver re-checks it against caller evidence.
	Filesystem string
	// Path is the object path inside the scope.
	Path string
	// Intent is the requested intent axis value.
	Intent Intent
}

// Grant mirrors authz.Grant from
// feat/authz-resolver:internal/authz/authz.go (Grant{Downloadable bool}).
type Grant struct {
	// Downloadable is resolved at read, never stamped at write
	// (NFR-SEC-73).
	Downloadable bool
}

// CallerEvidence mirrors authz.CallerEvidence from
// feat/authz-resolver:internal/authz/resolver.go
// (CallerEvidence{Scope FilesystemID; GrantedIntents []Intent}): the
// face-established, host-attested identity. The dispatch spine builds it
// from the channel-bound session scope, never from any request field
// (NFR-SEC-43).
type CallerEvidence struct {
	// Scope is the host-attested filesystem_id bound to the session
	// channel at provision time.
	Scope string
	// GrantedIntents is the exhaustive intent grant set from session
	// provision; an absent intent is denied regardless of other fields.
	GrantedIntents []Intent
}

// Resolver is the consumer-side slice of authz.Resolver from
// feat/authz-resolver:internal/authz/authz.go
// (Resolve(ctx, caller any, req Request) (Grant, error)). The caller is
// opaque to the resolver exactly as on the real seam.
type Resolver interface {
	Resolve(ctx context.Context, caller any, req ResolveRequest) (Grant, error)
}

// Guard is the consumer-side slice of auditgate.Guard from
// feat/auditgate-file-sink:internal/auditgate/auditgate.go
// (Mandate(ctx, event any) error). A non-nil return denies the operation —
// fail-closed, no acknowledgement without a durable audit record
// (NFR-SEC-79).
type Guard interface {
	Mandate(ctx context.Context, event any) error
}

// CeilingsSession is the consumer-side slice of *ceilings.Session from
// feat/session-ceilings:internal/ceilings/ceilings.go (TryConsumeOp /
// AcquireBytes / ReleaseBytes / TryAcquireFD / ReleaseFD). Per-session
// ceilings throttle fail-closed per session, not broker-wide (NFR-SEC-46).
type CeilingsSession interface {
	TryConsumeOp() error
	AcquireBytes(n int64) error
	ReleaseBytes(n int64)
	TryAcquireFD() error
	ReleaseFD()
}

// CeilingsRegistry is the consumer-side slice of ceilings.Registry from
// feat/session-ceilings:internal/ceilings/ceilings.go
// (Session(key SessionKey) *Session; Release(key SessionKey)).
//
// ADAPTER NOTE for the wiring phase: the real ceilings.Registry.Session
// takes the named ceilings.SessionKey type and returns *ceilings.Session —
// it does NOT satisfy this interface directly. The composition layer wires
// it through a small named adapter (ceilingsAdapter) that converts the
// string key to ceilings.SessionKey and wraps *ceilings.Session in
// CeilingsSession; a bare assignment will not compile, and that is
// expected.
type CeilingsRegistry interface {
	Session(key string) CeilingsSession
	Release(key string)
}

// Consumer-side mirrors of the seam sentinels the deny mapper classifies.
// Each mirrors the like-named sentinel on its source branch; the wiring
// phase maps the real sentinels onto these (or replaces the errors.Is
// targets) when the seam packages merge.
var (
	// ErrScopeMismatch mirrors authz.ErrScopeMismatch
	// (feat/authz-resolver:internal/authz/authz.go). Match it with
	// errors.Is.
	ErrScopeMismatch = errors.New("southface: filesystem scope mismatch")

	// ErrIntentDenied mirrors authz.ErrIntentDenied. Match it with
	// errors.Is.
	ErrIntentDenied = errors.New("southface: intent denied for caller")

	// ErrNotDownloadable mirrors authz.ErrNotDownloadable. Match it with
	// errors.Is.
	ErrNotDownloadable = errors.New("southface: object not downloadable")

	// ErrLeaseExpired names the expired-session deny class: the channel's
	// provision lease no longer stands. No seam exports it yet; the
	// session lifecycle owner raises it. Match it with errors.Is.
	ErrLeaseExpired = errors.New("southface: session lease expired")

	// ErrAuditUnavailable mirrors auditgate.ErrAuditUnavailable
	// (feat/auditgate-file-sink:internal/auditgate/auditgate.go). Match it
	// with errors.Is.
	ErrAuditUnavailable = errors.New("southface: audit gate unavailable")

	// ErrSizeExceeded mirrors ceilings.ErrSizeExceeded
	// (feat/session-ceilings:internal/ceilings/ceilings.go). Match it with
	// errors.Is.
	ErrSizeExceeded = errors.New("southface: declared size exceeds ceiling")

	// ErrThrottleExceeded mirrors ceilings.ErrThrottleExceeded. Match it
	// with errors.Is.
	ErrThrottleExceeded = errors.New("southface: ops-per-second ceiling exceeded")

	// ErrBytesExceeded mirrors ceilings.ErrBytesExceeded. Match it with
	// errors.Is.
	ErrBytesExceeded = errors.New("southface: in-flight byte ceiling exceeded")

	// ErrFDExceeded mirrors ceilings.ErrFDExceeded. Match it with
	// errors.Is.
	ErrFDExceeded = errors.New("southface: file-descriptor ceiling exceeded")
)
