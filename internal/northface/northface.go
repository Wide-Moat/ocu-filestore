// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package northface terminates the file/artifact HTTP API, the embeddable
// SPA, and the preview-render path — the data-plane-client face of the
// broker. The wire surface is the file-artifact-api contract in the
// architecture repo (operation set, route shape, auth/response envelope,
// and ceilings are pinned; per-operation bodies marked TBD there stay TBD
// here — this package never invents a body).
//
// Session rules: no request is accepted without a signature-valid,
// in-audience, unexpired peer-minted embed token before any session state
// is set (NFR-SEC-82); a missing/invalid session is a 401 with no anonymous
// fallback, every state-mutating call carries a server-validated CSRF
// token, and every UI/artifact response carries CSP frame-ancestors from
// the per-deployment allowlist (NFR-SEC-83/84). The ingress is distinct
// from any MCP listener; over-ceiling bodies are rejected pre-buffer
// (NFR-SEC-78), archives validated pre-extraction (NFR-SEC-80), content
// classified on ingest (NFR-SEC-81).
//
// No OCU upstream secret crosses to the browser. The SPA and preview-render
// build behind the deferred north-face tracking issue; the operation seam
// below exists so the south-face-first build order does not design them
// out.
package northface

import "errors"

// Op names one north-face operation, mirroring the file-artifact-api
// contract enum. The set is frozen there; adding an op is a contract change
// in the architecture repo first.
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
var ErrEmbedTokenInvalid = errors.New("northface: embed token invalid")

// Server is the north-face ingress seam. The implementation PR binds it to
// the file/UI listener (distinct from any MCP listener), wires embed-token
// verification, the first-party session, the authz resolver, and the audit
// gate in front of the object-store client.
type Server interface {
	// Serve accepts data-plane-client connections until the context is
	// cancelled or a fatal listener error occurs.
	Serve() error
	// Close releases the listener; in-flight operations finish or fail
	// fail-closed, never half-acknowledged.
	Close() error
}
