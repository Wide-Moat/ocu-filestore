// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"net/http"
)

// handlerCtx carries everything a per-op handler needs after the spine's
// LOCKED pipeline has cleared the request: the request context (so a client
// disconnect cancels in-flight engine work), the response writer, the routed
// op, the buffered op body the handler strict-decodes (the spine already
// consumed the network body into the envelope at STAGE 1; the handler
// re-decodes the SAME bytes for the op-specific fields), the channel-bound
// PeerScope, the resolved authorization Grant (Downloadable), and the
// mandateDeny hook.
//
// mandateDeny lets a handler-stage operational refusal emit a SECOND deny
// audit event through the spine's guard BEFORE the wire deny is written,
// WITHOUT relocating the spine's pre-handler allow-Mandate into per-op code
// (phase-8 ordering preserved). It takes the broker-resolved audit TRUTH and
// the wire deny class (which MAY degrade away from the truth, D8); it emits
// the deny event then writes the Connect error. The handler returns after
// calling it.
type handlerCtx struct {
	// ctx is the REQUEST context: engine calls run under it so a client
	// disconnect or server shutdown cancels in-flight work (a recursive
	// listing of a hostile tree must not outlive its caller). A zero
	// handlerCtx (some unit tests construct one directly) falls back to
	// context.Background() through the ctxOrBackground accessor.
	ctx context.Context
	w   http.ResponseWriter
	op  Op
	// body is the buffered op body. A handler re-decodes it for op-specific
	// fields OTHER than the primary path (cursor, limit, source/destination,
	// range, overwrite). It MUST NOT take the primary path from here: the spine
	// canonicalized the path ONCE at the boundary (bypass-01/03) and the
	// authoritative cleaned form is canonPath below; re-decoding the raw path
	// from body would reintroduce the raw-vs-cleaned disagreement the boundary
	// fix closes.
	body []byte
	// canonPath is the single canonical primary path the spine cleaned at the
	// STAGE 1b->2 boundary. authz, the downloadable tag, the audit ObjectHandle,
	// the engine call, and the uuid store all derive from it, so a path-aware
	// decision can never disagree with the bytes touched. It is in the guest
	// leading-slash convention; enginePath trims it for the engine call.
	canonPath string
	// subtree is the ADR-0029 intent-derived subtree the spine joined into
	// canonPath (engine-relative, no leading slash — e.g. "uploads" for a read op,
	// "outputs" for a write op; "" in static-path mode). A listing emitter strips
	// this prefix from each entry's engine-relative path before reporting the guest
	// path, so a guest re-addressing a listed path does not double-join it (the
	// join is symmetric: canonicalizePath adds the subtree on the way in, the
	// emitter removes it on the way out). Consumers other than the listing emitter
	// do not need it — they address by canonPath (already joined) or by uuid.
	subtree string
	// canonSource and canonDest are the spine-canonicalized SECOND-LEG paths for
	// the two-path namespace ops (moveDirectory, copyFile, moveFile). The spine
	// cleans req.Source/req.Destination through the SAME canonicalizePath it
	// applies to the primary path at the STAGE 1b->2 boundary (crutch-04), BEFORE
	// authz and audit, so the authorized/audited leg is the exact leg the engine
	// touches — never a raw, un-canonicalized wire path. A canonicalize error on
	// either leg is denied denyMalformed at the spine and the handler is never
	// reached, symmetric with the primary path. Both are in the guest
	// leading-slash convention; the handler trims them through enginePath for the
	// engine call. They are empty for single-path ops, which never read them.
	canonSource string
	canonDest   string
	ps          PeerScope
	grant       Grant

	mandateDeny func(auditReason, wireClass, message string)
}

// ctxOrBackground returns the request context, defaulting to Background for
// a handlerCtx constructed without one (direct handler unit tests).
func (hc handlerCtx) ctxOrBackground() context.Context {
	if hc.ctx != nil {
		return hc.ctx
	}
	return context.Background()
}

// opOutcome is what a STAGE-4 handler reports back to the spine so the spine
// records ops_total EXACTLY once for the dispatched op (southface-01). The
// zero value is an allow; a handler that refused internally returns a deny
// outcome carrying the broker-resolved deny class.
//
// Two deny shapes exist because a handler-internal refusal reaches the metric
// counter by one of two routes:
//
//   - Through the mandateDeny hook (intent_denied, directory_not_empty,
//     not_downloadable, every denyEngine refusal): the hook already records the
//     deny in ops_total, so the handler returns outcomeDenyRecorded and the
//     spine records NOTHING further — neither the spurious allow nor a second
//     deny.
//   - Without the hook (a malformed op body, a malformed cursor, the
//     unimplemented stub): these write the wire error directly and never touch
//     the counter, so the handler returns outcomeDeny(class) and the SPINE
//     records the single deny entry from the returned class.
//
// Either way the spine emits one ops_total row whose outcome is never "allow"
// for a refused request, closing the spurious-second-allow accounting bug.
type opOutcome struct {
	// allowed is true only when the handler wrote a SUCCESS response. The spine
	// records ops_total{outcome=allow,deny_class=none} ONLY in that case.
	allowed bool
	// denyClass is the broker-resolved deny class the spine must record when the
	// refusal did NOT already record through the mandateDeny hook. Empty when
	// allowed, or when the deny was already recorded (outcomeDenyRecorded).
	denyClass string
}

// outcomeAllow reports a handler that wrote a success response; the spine
// records the single allow entry.
func outcomeAllow() opOutcome { return opOutcome{allowed: true} }

// outcomeDenyRecorded reports a handler-internal refusal that ALREADY recorded
// its deny in ops_total (it went through the mandateDeny hook). The spine
// records nothing further.
func outcomeDenyRecorded() opOutcome { return opOutcome{} }

// outcomeDeny reports a handler-internal refusal that did NOT record its deny
// (it wrote the wire error directly): the spine records the single deny entry
// from class.
func outcomeDeny(class string) opOutcome { return opOutcome{denyClass: class} }

// opHandler is the per-operation handler signature. The seven phase-9 ops bind
// real handlers; the other eleven stay unimplemented in this build. The
// returned opOutcome tells the spine whether — and how — to record ops_total
// for the dispatched op (southface-01).
type opHandler func(d *handlerDeps, hc handlerCtx) opOutcome

// unimplemented writes the REST unimplemented deny (501) with no x-deny-reason
// header. Every op the seven phase-9 handlers do not replace resolves to this —
// the registry is complete, those bodies are not. It writes the wire error
// directly (no mandateDeny hook), so it returns the deny class for the spine to
// record the single ops_total entry.
//
// PHASE-7(A3-deny): frozen @ canon-rev a030b7be914b: the body is the BoundedReason {reason_code,
// contract FORM ratified by #292 @ a030b7be914b; governing ADR remains status:proposed — freezes the wire FORM, not ADR acceptance
// message} REST shape (writeRESTDeny), not the Connect error frame; the HTTP
// 501 status is authoritative.
func unimplemented(_ *handlerDeps, hc handlerCtx) opOutcome {
	writeRESTDeny(hc.w, mapDeny(denyUnimplemented), "operation not implemented in this build")
	return outcomeDeny(denyUnimplemented)
}

// newHandlerRegistry returns a registry mapping every frozen southface.Op —
// all 16 unary ops and the two streaming ops (fileUpload, fileDownload) — to
// the unimplemented handler. Building from the closed op set guarantees full
// coverage; newDispatcherWithEngine then replaces the phase-9 ops and readFile
// (OPS-04, a unary op) with their real handlers. A registry that omitted an op
// would route it to a nil handler.
//
// fileUpload (OPS-05) and fileDownload (OPS-06) are dispatched OUT-OF-BAND:
// the REST router routes them to their dedicated entrypoints
// (serveUploadMultipart / serveDownloadOctetStream) before this registry is
// consulted, so their registry entries stay unimplemented and are never reached
// on the data-plane path. getFileMetadata/listFiles stay unimplemented
// (deferred).
func newHandlerRegistry() map[Op]opHandler {
	reg := make(map[Op]opHandler, len(knownOps))
	for op := range knownOps {
		reg[op] = unimplemented
	}
	return reg
}
