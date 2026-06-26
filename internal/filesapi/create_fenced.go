// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"log/slog"
	"net/http"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
)

// serveCreate serves POST /v1/files: FENCED -> 501 unimplemented.
//
// FENCED (pending ADR-0025): the create/upload request body is marked TBD in the
// frozen file-artifact-api contract, and CLAUDE.md forbids inventing a body and
// coding against it. So create is structurally unbuilt this build — it returns a
// clean 501 unimplemented rather than a half-invented surface. When ADR-0025
// freezes the upload body, the write path lands here (and the ScopeSource gains
// its concrete F9-request binding); until then the read/delete plane is the only
// live surface.
func (h *Handler) serveCreate(w http.ResponseWriter, _ *http.Request, reqLog *slog.Logger) {
	reqLog.Info("files-api create is fenced; returning 501 (upload body TBD pending ADR-0025)",
		slog.String("endpoint", "POST /v1/files"))
	denywire.WriteRESTDeny(w, denywire.MapDeny(denyclass.Unimplemented),
		"file create is not implemented in this build")
}
