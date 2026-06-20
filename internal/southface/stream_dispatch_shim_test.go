// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"log/slog"
	"net/http"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
)

// serveStreamingShim drives a streaming op through the SURVIVING serveStreaming
// method with the STAGE-0 prologue the retired ServeHTTP streaming branch used
// to run (mint the per-request correlation id, stamp x-request-id, derive the
// request-scoped logger, install the panic-recovery net, then dispatch the
// streaming op). It exists for THIS wave only.
//
// In Wave 4 the data-plane ops pivoted to the REST transports
// (serveUploadMultipart / serveDownloadOctetStream) and the dual-dispatch
// streaming branch was removed from ServeHTTP, so a streaming Connect request no
// longer reaches serveStreaming through ServeHTTP. The legacy Connect streaming
// tests in this package still exercise the serveStreaming ALGORITHM directly
// (the method survives until Wave 5 deletes the dead Connect transport
// wholesale), so they route through this shim instead of ServeHTTP. The shim is
// the test-only equivalent of the old ServeHTTP streaming-branch prologue; it
// touches no production code.
func serveStreamingShim(d *dispatcher, w http.ResponseWriter, r *http.Request) {
	reqID := newCorrelationID()
	w.Header().Set(requestIDHeader, reqID)
	reqLog := d.logger.With(slog.String(observ.KeyRequestID, reqID))
	defer d.recoverDispatch(w, &reqLog)()

	op, err := parseRoute(r.Method, r.URL.Path)
	if err != nil {
		// The legacy streaming requests always name a valid streaming route; a
		// route fault here is a test wiring bug, surfaced as a plain deny.
		d.denyWithLog(w, reqLog, mapDeny(denyMalformed), "unknown route")
		return
	}
	d.serveStreaming(w, r, op, reqID, reqLog)
}

// streamingShimHandler is the test-only http.Handler that the legacy Connect
// real-socket streaming tests bind to a provisionSession server. It routes the
// two data-plane ops (fileUpload/fileDownload) to serveStreamingShim — the
// surviving serveStreaming path with the retired ServeHTTP streaming-branch
// prologue — and delegates every other request to the dispatcher's unary
// ServeHTTP. It lets the real-socket per-frame-deadline tests keep driving the
// Connect framed transport over a live server without the production ServeHTTP
// dual-dispatch branch, which Wave 4 removed. It dies in Wave 5 with the rest of
// the dead Connect transport.
type streamingShimHandler struct{ d *dispatcher }

// ServeHTTP routes a streaming op through the shim and everything else through
// the dispatcher's unary spine.
func (h streamingShimHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op, err := parseRoute(r.Method, r.URL.Path)
	if err == nil && isStreamingOp(op) {
		serveStreamingShim(h.d, w, r)
		return
	}
	h.d.ServeHTTP(w, r)
}
