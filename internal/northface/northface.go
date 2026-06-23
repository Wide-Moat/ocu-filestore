// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package northface is the dormant host-leg (F9) backend seam of the
// object-store service (component-04). It is NOT the client-facing face:
// per ADR-0015, the Web UI (component-08) owns the client file/artifact
// HTTP API, the embeddable SPA, and the preview-render path. The Web UI
// calls this service intra-deployment with a file-op intent AFTER it has
// done its own client-facing auth — embed-token verification (NFR-SEC-82),
// the first-party session, CSRF, and CSP frame-ancestors (NFR-SEC-83/84)
// all live there, not here. No client-facing secret or signing key crosses
// into this package.
//
// What this door does on an F9 call: it resolves the file_id through this
// component's own durable handle-store (internal/handlestore, ADR-0023) and
// re-derives the authorization scope per request at the route layer
// (route-layer scope-check). It holds no signing key — there is one storage
// door and this service is it (NFR-SEC-25). Storage-side ingest discipline
// still applies to the bodies this door accepts: over-ceiling bodies are
// rejected pre-buffer (NFR-SEC-78), archives validated pre-extraction
// (NFR-SEC-80), content classified on ingest (NFR-SEC-81) — these are
// storage-side guards, distinct from the client-facing flow.
//
// The F9 wire form is an inter-component contract with component-08 and is
// intentionally NOT designed here yet; the seam is stubbed on both sides
// pending that contract. This seam exists so the build order does not design
// the F9 host leg out.
package northface

import "errors"

// Op names one operation in the SUPERSEDED 7-op PoC file-artifact-api shape.
//
// Deprecated: ADR-0023 recut the public surface to the five Files-API
// endpoints on component-08 (the Web UI) plus the file_id handle-store here
// (internal/handlestore). This 7-op enum is dormant PoC scaffold; the real
// F9 op shape is the deferred inter-component contract with component-08 and
// is not designed in this package. The constants are retained (not deleted)
// pending that contract.
type Op string

const (
	OpUpload          Op = "upload"
	OpListFiles       Op = "listFiles"
	OpGetManifest     Op = "getManifest"
	OpDownload        Op = "download"
	OpDownloadArchive Op = "downloadArchive"
	OpPreviewRender   Op = "previewRender"
	OpDelete          Op = "delete"
)

// ErrNotImplemented is the scaffold sentinel: the north face has no
// implementation in this build. Match it with errors.Is.
var ErrNotImplemented = errors.New("northface: not implemented in this build")

// ErrEmbedTokenInvalid — the presented embed token fails signature,
// audience, or expiry verification; no session state is set (NFR-SEC-82).
// Match it with errors.Is.
//
// Deprecated: embed-token verification is a component-08 (Web UI)
// client-facing concern (NFR-SEC-82), not this backend door's — the Web UI
// authenticates the client before it ever makes an F9 call here. This
// sentinel is a dormant scaffold leftover; it is retained (not deleted)
// because symbol removal is a form change deferred to the F9 contract.
var ErrEmbedTokenInvalid = errors.New("northface: embed token invalid")

// Server is the dormant F9 host-leg backend seam. An implementation PR will
// bind it to the host-leg listener that component-08 (the Web UI) calls
// intra-deployment, doing file_id handle-resolution against this component's
// durable handle-store, a route-layer scope-check, and the audit gate in
// front of the object-store engine. It carries no client-facing auth (that
// is component-08's, per ADR-0015).
type Server interface {
	// Serve accepts host-leg (F9) connections until the context is
	// cancelled or a fatal listener error occurs.
	Serve() error
	// Close releases the listener; in-flight operations finish or fail
	// fail-closed, never half-acknowledged.
	Close() error
}
