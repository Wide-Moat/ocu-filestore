// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package filesapi is the north Files-API handler (ADR-0023): the five-endpoint
// /v1/files surface a host-leg (F9) caller reaches over a SEPARATE TLS listener
// (Mount B), never through the south guest-mount RPC spine. It resolves a
// broker-minted file_id through the durable handle store (internal/handlestore),
// re-derives the read authorization broker-side per request, audits before it
// acknowledges (NFR-SEC-79), and resolves downloadable AT READ (NFR-SEC-73).
//
// Two structural invariants are baked into this package's shape:
//
//   - KEYSTONE (anti-enumeration): a file_id that is unknown and one that
//     belongs to a foreign scope are INDISTINGUISHABLE on the wire — both are a
//     header-less, byte-identical 404. The store collapses both into
//     handlestore.ErrNotFound, and this handler has exactly ONE deny token for a
//     file_id-resolution failure; it is structurally incapable of returning 403
//     / forbidden / scope_mismatch on any file_id path. There is no branch that
//     distinguishes the two.
//
//   - WRITE plane: POST /v1/files (create) streams a multipart/form-data upload
//     into the engine and Puts a durable handle, mirroring the south upload
//     pipeline (declared-size pre-buffer reject, scope cross-check, canonicalize,
//     Resolve(write), audit-before-ack, the fd+in-flight-bytes ceilings, and the
//     io.Pipe -> engine.WriteStream over/under-declaration aborts). The scope
//     binding (ScopeSource) reads a host-attested filesystem_id field on the F9
//     request; the concrete F9 request shape is the ADR-0025 inter-component
//     contract (architect-agreed, pending the owner-gated canon merge).
//
// This package REUSES the south face's consumer-seam mirror types
// (southface.Resolver/Guard/Engine/CeilingsRegistry/PeerScope/...) rather than
// re-declaring them: there is one set of broker adapters, and Mount B wires the
// same ones the south face uses.
package filesapi

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// ErrSeamMissing is the fail-loud sentinel NewHandler returns when any required
// seam is nil. A half-wired handler must never bind a listener: a nil resolver,
// guard, engine, ceilings, store, or scope source is a composition defect, not a
// runtime condition, and is refused at construction. Match it with errors.Is.
var ErrSeamMissing = errors.New("filesapi: a required seam is nil")

// ErrMaxFileSizeUnset is the fail-loud sentinel NewHandler returns when Deps
// carries a non-positive MaxFileSize. The create path's pre-assembly size reject
// (NFR-SEC-46) needs a concrete whole-object ceiling; a zero or negative ceiling
// would admit an unbounded declared size, so it is a composition defect refused
// at construction rather than a runtime condition. Match it with errors.Is.
var ErrMaxFileSizeUnset = errors.New("filesapi: MaxFileSize must be a positive whole-object ceiling")

// Deps is the fully-wired seam set the Files-API handler needs. Every field is
// REQUIRED and non-nil — NewHandler validates each and refuses a half-wired
// handler. The seam types are the south face's consumer-side mirrors so the one
// set of broker adapters serves both planes.
type Deps struct {
	// Resolver re-derives the three-axis authorization per request, broker-side,
	// deny-by-default (NFR-SEC-73). The content path consults grant.Downloadable
	// AT READ.
	Resolver southface.Resolver
	// Guard is the fail-closed audit gate: every file activity emits an OCSF
	// record before the operation is acknowledged, and an audit-write failure
	// denies (NFR-SEC-79). A non-nil Mandate return DENIES.
	Guard southface.Guard
	// Engine is the storage engine the plane streams bytes through: the content
	// path reads (ReadRange / Stat) and the create path writes (WriteStream). The
	// one engine seam serves both the read and the write plane.
	Engine southface.Engine
	// Ceilings throttles per session (ops/s, in-flight bytes, fd slots),
	// fail-closed per session (NFR-SEC-46). The content path acquires an fd slot
	// around the engine read window.
	Ceilings southface.CeilingsRegistry
	// Store is the durable file_id handle authority (ADR-0023). It is the ONLY
	// file_id resolver; an absent OR cross-scope file_id returns the SAME
	// ErrNotFound (the keystone).
	Store handlestore.Store
	// Scope is the host-attested scope source for the F9 request (Q-F9AUTH,
	// FENCED placeholder pending ADR-0025). It derives the PeerScope from the
	// request's host-attested filesystem_id field — NOT a credential extractor
	// (the F9 host leg has no edge-injected Bearer).
	Scope ScopeSource
	// SizeCeiling bounds an inbound request body read so a hostile sender cannot
	// stream an unbounded body. On the create path it bounds the multipart
	// "params" FIELD read (the file PART carries the bulk bytes, bounded by
	// MaxFileSize instead); the read/delete paths carry no request body of
	// consequence.
	SizeCeiling int64
	// MaxFileSize is the WHOLE-OBJECT upload ceiling (NFR-SEC-46): the create
	// path refuses a declared_size_bytes strictly greater than this value BEFORE
	// staging any byte (the pre-assembly size reject). It is REQUIRED and must be
	// positive — NewHandler refuses a handler wired with MaxFileSize <= 0, so the
	// create plane is always live with a concrete ceiling (never silently
	// disabled). Its value is the control-plane's BrokerMaxFileSizeBytes, mirrored
	// from the same cfg.BrokerMaxFileSize the south face's whole-object ceiling
	// reads.
	MaxFileSize int64
	// CreateSubtree is the engine-relative subtree the north create joins every
	// uploaded object under (ADR-0029:46, the human->sandbox direction). Its value
	// is the deployment map's READ entry, injected at construction (the composition
	// root reads it off the resolved southface.SubtreeMap via ReadSubtree), so the
	// north create joins the SAME subtree the south read-mount joins — a File-Pane
	// upload lands where the agent's read plane looks. An EMPTY value disables the
	// join (static-path mode): the create writes at the scope root verbatim. The
	// default map is ON (read -> "uploads"), so an empty CreateSubtree is the rare
	// static-mode case, not the norm. NewHandler does NOT reject an empty value —
	// it is a valid static-mode configuration, not a missing seam.
	CreateSubtree string
	// Logger is the structured logger; a nil logger is normalised to a
	// discard-all logger so a handler never panics on a nil log.
	Logger *slog.Logger
}

// Handler is the north Files-API HTTP handler. It is constructed once by Mount B
// from a fully-wired Deps and serves the five /v1/files endpoints. It holds no
// per-request state; the per-request scope is derived from the ScopeSource on
// every call.
type Handler struct {
	deps Deps
}

// NewHandler validates that every required seam is non-nil and returns the
// Files-API handler, or ErrSeamMissing naming the first nil seam. A nil Logger
// is the one permitted nil — it is normalised to a discard logger. This is the
// fail-loud composition gate: a half-wired north plane is refused before it can
// bind a listener.
func NewHandler(deps Deps) (*Handler, error) {
	switch {
	case deps.Resolver == nil:
		return nil, errSeam("Resolver")
	case deps.Guard == nil:
		return nil, errSeam("Guard")
	case deps.Engine == nil:
		return nil, errSeam("Engine")
	case deps.Ceilings == nil:
		return nil, errSeam("Ceilings")
	case deps.Store == nil:
		return nil, errSeam("Store")
	case deps.Scope == nil:
		return nil, errSeam("Scope")
	}
	// The create path is always live; a non-positive whole-object ceiling would
	// leave its pre-assembly size reject toothless, so it is refused here (the
	// fail-loud composition gate, distinct from a nil seam).
	if deps.MaxFileSize <= 0 {
		return nil, ErrMaxFileSizeUnset
	}
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.DiscardHandler)
	}
	return &Handler{deps: deps}, nil
}

// errSeam wraps ErrSeamMissing with the name of the offending seam so the
// composition defect names exactly which dependency was left nil.
func errSeam(name string) error {
	return fmt.Errorf("%w: %s", ErrSeamMissing, name)
}
