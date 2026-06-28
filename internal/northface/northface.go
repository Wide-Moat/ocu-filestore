// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package northface is the host-leg (F9) backend door of the object-store
// service (component-04). It is NOT the client-facing face: per ADR-0015, the
// Web UI (component-08) owns the client file/artifact HTTP API, the embeddable
// SPA, and the preview-render path. The Web UI calls this service
// intra-deployment with a file-op intent AFTER it has done its own
// client-facing auth — embed-token verification (NFR-SEC-82), the first-party
// session, CSRF, and CSP frame-ancestors (NFR-SEC-83/84) all live there, not
// here. No client-facing secret or signing key crosses into this package.
//
// What this door does on an F9 call: it resolves the file_id through this
// component's own durable handle-store (internal/handlestore, ADR-0023) and
// re-derives the authorization scope per request at the route layer
// (route-layer scope-check). It holds no signing key — there is one storage
// door and this service is it (NFR-SEC-25).
//
// This package owns the Mount B LISTENER: a dedicated north TLS listener on a
// SEPARATE bind (--north-bind), reusing the south face's loaded certificate
// SOURCE, serving the internal/filesapi handler. The listener is a PHYSICAL
// trust boundary between the no-credential /v1/files plane and the
// egress-credential south mount RPC — Mount B is NOT a path-prefix on the south
// server and is NOT routed through the south restRouter or the STAGE-0..4
// pipeline. The Files-API request/response surface itself is the
// ADR-0023-frozen five endpoints; the broader F9 inter-component op wire form
// (beyond /v1/files) is the deferred ADR-0025 contract with component-08.
package northface

import "errors"

// ErrNotImplemented is the scaffold sentinel for a genuinely-unbuilt F9 verb
// (e.g. the create/upload body deferred to ADR-0025). Match it with errors.Is.
var ErrNotImplemented = errors.New("northface: not implemented in this build")

// Server is the F9 host-leg listener seam. Mount B implements it over a
// dedicated north TLS listener serving the injected filesapi handler; the
// daemon's dualServer fans Serve/Close across this north listener and the south
// listener. It carries no client-facing auth (that is component-08's, per
// ADR-0015).
type Server interface {
	// Serve binds the listener and accepts host-leg (F9) connections until
	// Close shuts the server down or a fatal listener error occurs.
	Serve() error
	// Close releases the listener; in-flight operations finish or fail
	// fail-closed, never half-acknowledged.
	Close() error
}
