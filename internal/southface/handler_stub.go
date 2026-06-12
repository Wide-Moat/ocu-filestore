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
	ctx         context.Context
	w           http.ResponseWriter
	op          Op
	body        []byte
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

// opHandler is the per-operation handler signature. The seven phase-9 ops bind
// real handlers; the other eleven stay unimplemented in this build.
type opHandler func(d *handlerDeps, hc handlerCtx)

// unimplemented writes the Connect unimplemented error (501) with no
// x-deny-reason header. Every op the seven phase-9 handlers do not replace
// resolves to this — the registry is complete, those bodies are not.
func unimplemented(_ *handlerDeps, hc handlerCtx) {
	writeConnectError(hc.w, mapDeny(denyUnimplemented), "operation not implemented in this build")
}

// newHandlerRegistry returns a registry mapping every frozen southface.Op —
// all 16 unary ops and the two streaming ops (fileUpload, fileDownload) — to
// the unimplemented handler. Building from the closed op set guarantees full
// coverage; newDispatcherWithEngine then replaces the phase-9 ops and readFile
// (OPS-04, a unary op) with their real handlers. A registry that omitted an op
// would route it to a nil handler.
//
// fileUpload (OPS-05) is dispatched OUT-OF-BAND: the ServeHTTP streaming
// branch routes it to serveStreaming before the registry is consulted, so its
// registry entry stays unimplemented and is never reached on the streaming
// path. fileDownload/getFileMetadata/listFiles stay unimplemented (deferred).
func newHandlerRegistry() map[Op]opHandler {
	reg := make(map[Op]opHandler, len(knownOps))
	for op := range knownOps {
		reg[op] = unimplemented
	}
	return reg
}
