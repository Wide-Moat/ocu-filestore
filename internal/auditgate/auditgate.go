// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package auditgate is the fail-closed audit mandate both faces call:
// every file activity emits an OCSF File System Activity event (class_uid
// 1001) into the hash-chained pipeline BEFORE the operation is
// acknowledged, and an audit-write failure denies the operation
// (NFR-SEC-79). Both faces author the same event class under host-attested
// identity — the caller is never the authoritative author of its own audit
// event.
//
// The event field set is pinned by the file-artifact-api contract
// (FileActivityEvent); the scaffold keeps the event opaque rather than
// duplicating the contract's shape in Go until the audit-pipeline
// implementation PR freezes the encoding.
package auditgate

import (
	"context"
	"errors"
)

// ErrAuditUnavailable — the audit write did not durably complete, so the
// guarded operation is DENIED (fail-closed). Callers map it to a
// 503-class response; they never proceed without the record. Match it
// with errors.Is.
var ErrAuditUnavailable = errors.New("auditgate: audit write unavailable, operation denied")

// Guard mandates the audit record. Mandate returns only after the event is
// durably accepted by the pipeline; any failure is ErrAuditUnavailable and
// the caller must refuse the operation.
type Guard interface {
	Mandate(ctx context.Context, event any) error
}
