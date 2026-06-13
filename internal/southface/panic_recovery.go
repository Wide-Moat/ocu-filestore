// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
)

// recoverDispatch returns a deferred panic handler for ServeHTTP. The caller
// MUST use it as:
//
//	defer d.recoverDispatch(w, &reqLog)()
//
// where reqLog is the pointer to the request-scoped logger local variable.
// Using a pointer lets the closure capture the logger value AFTER it has been
// initialised at STAGE 0, even though the defer is registered before STAGE 0
// runs. On a nil pointer the base dispatcher logger is used instead.
//
// On a panic the handler:
//  1. Attempts a BEST-EFFORT audit Mandate for an internal-deny event so the
//     panic is audited per NFR-SEC-79 fail-closed intent. If the Mandate
//     itself panics or fails the attempt is abandoned.
//  2. Writes a structured internal deny to the response — the caller sees a
//     typed Connect error, never a naked connection drop or an unfinished
//     response.
//
// The function never panics. Any secondary panic inside the recovery body is
// caught by an inner recover so the outer HTTP server's connection draining
// sees a clean return.
//
// The LOCKED STAGE 0->4 in ServeHTTP is not modified — this wrapper is a pure
// additive safety net sitting outside the pipeline.
func (d *dispatcher) recoverDispatch(w http.ResponseWriter, reqLog **slog.Logger) func() {
	return func() {
		v := recover()
		if v == nil {
			return
		}

		// Resolve the logger: prefer the request-scoped one (which carries
		// the request_id) when it is already initialised, fall back to the
		// dispatcher base logger.
		l := d.logger
		if reqLog != nil && *reqLog != nil {
			l = *reqLog
		}

		// Log the panic at ERROR level (never the panic value — it may
		// contain request bytes).
		l.Error("dispatcher panic recovered; returning internal deny",
			slog.String(observ.KeyDenyClass, denyInternal),
		)

		// BEST-EFFORT deny audit: record the panic as an internal deny so
		// the audit chain reflects that the request did not succeed. Wrap in
		// a nested recovery so a panicking guard cannot undo the wire deny
		// written below.
		func() {
			defer func() { recover() }() //nolint:errcheck
			ev := auditEvent{
				Op:         "",
				DenyReason: denyInternal,
			}
			// context.Background() — the original request context may be
			// cancelled or panicking; use an independent context so the
			// Mandate has a chance to land.
			_ = d.guard.Mandate(context.Background(), mapAuditEvent(ev))
		}()

		// Write the structured wire deny. If WriteHeader has already been
		// called the write may be a no-op or produce a partial body — but
		// we must not drop the connection silently. Wrap in a nested
		// recovery for the same reason.
		func() {
			defer func() { recover() }() //nolint:errcheck
			writeConnectError(w, mapDeny(denyInternal), "internal error")
		}()
	}
}

// recoverWriteStream is the panic containment wrapper for the WriteStream pipe
// goroutine inside handleFileUpload. When the engine's WriteStream call panics
// the deferred recovery catches it, closes the pipe reader with an error so the
// producer side (pw.Write in the reassembly loop) unblocks immediately, and
// sends the sentinel on writeErrCh so the upload handler can drain and abort
// cleanly. This guarantees:
//
//   - No goroutine leak (the pipe goroutine exits).
//   - No torn object: the engine's temp+rename atomicity guarantees that an
//     aborted WriteStream writes nothing to the namespace.
//   - The upstream handler receives an error on writeErrCh and writes the
//     deny trailer as normal.
func recoverWriteStream(pr *io.PipeReader, writeErrCh chan<- error) {
	v := recover()
	if v == nil {
		return
	}
	// Close the read end with an internal error so a producer pw.Write
	// that is blocked waiting for the reader unblocks immediately.
	pr.CloseWithError(errInternalPanic)
	// Send the sentinel so the handler can drain writeErrCh and abort.
	writeErrCh <- errInternalPanic
}

// recoverReadStream is the panic containment wrapper for the ReadRange pipe
// goroutine inside handleFileDownload. A panicking engine.ReadRange is caught
// here; the pipe writer is closed with an error so the consumer loop unblocks
// and the error drains through readErrCh.
func recoverReadStream(pw *io.PipeWriter, readErrCh chan<- error) {
	v := recover()
	if v == nil {
		return
	}
	pw.CloseWithError(errInternalPanic)
	readErrCh <- errInternalPanic
}

// errInternalPanic is the sentinel sent on the pipe-error channel when a
// goroutine-level panic is recovered inside a streaming handler. The upload /
// download handler maps it through denyClassForEngineErr → denyInternal →
// wireCodeInternal, the same path as any other unrecognised engine error.
var errInternalPanic = &internalPanicError{}

type internalPanicError struct{}

func (*internalPanicError) Error() string {
	return "southface: internal panic in engine goroutine"
}
