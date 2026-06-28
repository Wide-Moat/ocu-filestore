// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package handlestore is the durable Files-API file_id handle store (ADR-0023).
// It maps a broker-minted file_id to the record naming the stored object —
// scope, backend object reference, and the metadata a later read resolves
// against — and persists those mappings durably so a file_id survives a daemon
// restart (the ephemeral south-face objectIDStore does not; that store lives
// and dies with the session and is left untouched).
//
// The store is the file_id resolution authority. Two structural rules are
// baked into its shape and enforced below the Store seam, never in the caller:
//
//   - Scope binding: Get and Delete take the attested scope and resolve ONLY a
//     record whose scope is byte-equal. A cross-scope file_id is
//     indistinguishable from an absent one — both return ErrNotFound (the same
//     sentinel, carrying denyclass.NotFound) so an attacker cannot enumerate
//     other scopes' handles by probing file_ids (anti-enumeration).
//
//   - Fail-closed durability: a write/sync fault latches the store; subsequent
//     mutations return ErrStoreUnavailable without writing, mirroring the audit
//     gate's ErrAuditUnavailable contract (a mutation is acked only after its
//     record is on stable storage).
//
// The store carries no engine/byte dependency: it records and resolves handle
// metadata only. It is the single file_id authority — no second component
// resolves a file_id.
package handlestore

import (
	"context"
	"errors"
	"fmt"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
)

// Record is the durable handle row: a broker-minted file_id and the metadata a
// later read resolves against. Fields are append-only in declaration AND JSON
// order — the on-disk log is replayed by unmarshaling these tags, so a field
// may be ADDED at the end but never reordered or removed without breaking
// replay of existing logs.
type Record struct {
	// FileID is the broker-minted handle (objectid.New shape: 32 lowercase
	// hex). It is the store's primary key and the value the wire file_id path
	// presents.
	FileID string `json:"file_id"`
	// Scope is the attested filesystem scope the record is bound to
	// (southface.PeerScope.FilesystemID). Get/Delete resolve ONLY against a
	// byte-equal scope; it is never a wildcard.
	Scope string `json:"scope"`
	// ObjectRef is the backend object reference the engine uses to locate the
	// stored bytes. It is opaque to this store — the store carries no engine
	// dependency and never dereferences it.
	ObjectRef string `json:"object_ref"`
	// Filename is the caller-supplied display name for the stored object.
	Filename string `json:"filename"`
	// Mime is the caller-supplied content type.
	Mime string `json:"mime"`
	// Size is the stored object's byte length. It is store-recorded metadata,
	// not a fresh measurement.
	Size int64 `json:"size"`
	// CreatedAt is the store-clock timestamp the record was durably written,
	// RFC-3339 UTC. The store stamps it from its own clock on Put — never the
	// caller's value (the caller does not own the durable record's time).
	CreatedAt string `json:"created_at"`
	// DownloadablePolicyRef is an OPAQUE reference to the downloadable-policy
	// that governs whether this object may be read out. It is intentionally a
	// string, not a boolean: the read-side downloadable decision resolves the
	// policy at read time (NFR-SEC-73, "downloadable resolves at read, never
	// stamped at write"); baking a boolean here would be that forbidden stamp.
	// Its concrete meaning is deferred (Q2) — this phase stores and replays it
	// verbatim without interpreting it.
	DownloadablePolicyRef string `json:"downloadable_policy_ref"`
}

// AuditObjectHandle returns the value that populates OCSF
// FileActivityEvent.object_handle on the north path; the public file_id is
// NEVER logged in the handle field (ADR-0023 honesty-fix a). The audit record
// names the backend object reference the operation actually touched, not the
// caller-facing handle — so the durable activity log is honest about which
// stored object an event concerns while the public file_id stays out of the
// handle field.
func (r Record) AuditObjectHandle() string { return r.ObjectRef }

// PutInput is the caller-supplied content of a new handle. The store mints
// FileID and stamps CreatedAt itself, so neither appears here: a caller can
// neither choose its handle nor backdate its record.
type PutInput struct {
	// Scope is the attested filesystem scope the new record is bound to.
	Scope string
	// ObjectRef is the backend object reference for the stored bytes (opaque).
	ObjectRef string
	// Filename is the display name for the stored object.
	Filename string
	// Mime is the content type.
	Mime string
	// Size is the stored object's byte length.
	Size int64
	// DownloadablePolicyRef is the opaque downloadable-policy reference (Q2
	// deferred — not a boolean; see Record.DownloadablePolicyRef).
	DownloadablePolicyRef string
}

// ListInput parameterizes a scope-bound page of records. The fields are the
// minimal cursor surface the List wave (TASK 6, a LATER wave) fills in; they
// are declared now so the Store interface is stable.
type ListInput struct {
	// Scope is the attested filesystem scope to list within. List returns ONLY
	// records bound to this scope.
	Scope string
	// Cursor is an opaque continuation token from a prior ListPage, or empty to
	// start at the first page.
	Cursor string
	// Limit is the maximum number of records to return in this page; zero means
	// the store's default page size.
	Limit int
}

// ListPage is one scope-bound page of records plus the continuation cursor and
// the page bounds. Records is in the store's STABLE total order (CreatedAt,
// FileID) so the bounds and cursor are stable across a daemon restart/replay.
type ListPage struct {
	// Records is the page of records, all bound to the requested scope, in the
	// store's stable total order.
	Records []Record
	// NextCursor is the opaque token to pass as ListInput.Cursor for the next
	// page, or empty when this is the final page.
	NextCursor string
	// HasMore is true when at least one more record sorts after this page —
	// i.e. NextCursor is non-empty. It is the explicit "another page exists"
	// signal so a caller need not infer it from the cursor.
	HasMore bool
	// FirstID is the file_id of the first record on this page (empty page → "").
	// It names the lower bound of the page in the stable order.
	FirstID string
	// LastID is the file_id of the last record on this page (empty page → "").
	// It names the upper bound and is the value NextCursor encodes.
	LastID string
}

// Store is the durable file_id handle authority. Put records a new handle
// durably; Get and Delete are scope-bound (the attested scope must byte-match
// the record's scope, else ErrNotFound); List pages a scope's records; Close
// releases the durable handle; Latched reports a permanent write/sync fault.
//
// A latched store stays READ-resolvable: Get and List are served from the
// in-memory map and continue to work after a write fault, so an audited read
// is never collateral-denied by a mutation-path latch. Only the mutation paths
// (Put, Delete) fail closed with ErrStoreUnavailable once latched.
type Store interface {
	// Put mints a file_id, stamps CreatedAt from the store clock, durably
	// appends the record, and returns it. It returns ErrStoreUnavailable if the
	// store is latched or the durable write/sync fails (the record is NOT
	// acked).
	Put(ctx context.Context, in PutInput) (Record, error)
	// Get resolves a file_id to its record IFF the attested scope byte-matches
	// the record's scope. An absent OR cross-scope file_id returns ErrNotFound
	// (the SAME sentinel — anti-enumeration).
	Get(ctx context.Context, fileID, attestedScope string) (Record, error)
	// Delete tombstones a file_id IFF the attested scope byte-matches the
	// record's scope. An absent OR cross-scope file_id returns ErrNotFound (the
	// same sentinel as Get). A durable-write fault returns ErrStoreUnavailable.
	Delete(ctx context.Context, fileID, attestedScope string) error
	// List returns a scope-bound page of records.
	List(ctx context.Context, in ListInput) (ListPage, error)
	// Close releases the durable handle. It is idempotent.
	Close() error
	// Latched reports whether the store has permanently failed on a write/sync
	// fault. A latched store still serves Get and List from memory.
	Latched() bool
}

// ErrNotFound is the ONLY resolution-failure the file_id path emits. It carries
// the denyclass.NotFound audit token. It is returned identically for an absent
// file_id AND a cross-scope file_id: the two are indistinguishable on the wire
// so a probe cannot enumerate other scopes' handles (anti-enumeration). There
// is deliberately NO exported scope-mismatch error here — scope_mismatch is the
// credscope axis's token (the credential-bound-fsid-vs-request-fsid check), a
// structurally different decision; conflating the file_id resolution failure
// with it would leak that a probed handle exists in another scope.
var ErrNotFound = fmt.Errorf("handlestore: file_id not found [%s]", denyclass.NotFound)

// ErrStoreUnavailable is returned by the mutation paths (Put, Delete) when the
// store is latched after a durable write/sync fault. It mirrors the audit
// gate's ErrAuditUnavailable: a mutation is acked only after its record is on
// stable storage, and once the store can no longer trust file-vs-memory
// agreement it refuses every subsequent mutation without writing. Recovery is
// a daemon restart (NewDiskStore re-scans the log). It carries the
// denyclass.Internal audit token (a store fault is a broker-internal state, not
// a client deny class).
var ErrStoreUnavailable = fmt.Errorf("handlestore: store unavailable (latched) [%s]", denyclass.Internal)

// AuditReason extracts the durable audit-reason token an error should record:
// denyclass.NotFound for ErrNotFound and denyclass.Internal for
// ErrStoreUnavailable. It returns the empty string for any other (or nil)
// error so the caller can fall back to its own classification. Match is by
// errors.Is so a wrapped sentinel still classifies.
func AuditReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNotFound):
		return denyclass.NotFound
	case errors.Is(err, ErrStoreUnavailable):
		return denyclass.Internal
	default:
		return ""
	}
}
