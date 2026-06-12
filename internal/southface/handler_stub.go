// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import "net/http"

// opHandler is the per-operation handler signature. Phase 9/10 implement the
// bodies; this build registers every op to the unimplemented handler.
type opHandler func(w http.ResponseWriter, r *http.Request)

// unimplemented writes the Connect unimplemented error (501) with no
// x-deny-reason header — every one of the 18 ops resolves to this in this
// build (the registry is complete, the bodies are not).
func unimplemented(w http.ResponseWriter, _ *http.Request) {
	writeConnectError(w, mapDeny(denyUnimplemented), "operation not implemented in this build")
}

// newHandlerRegistry returns a registry mapping every frozen southface.Op —
// all 16 unary ops and the two streaming ops (fileUpload, fileDownload) — to
// the unimplemented handler. A registry that omitted an op would route it to a
// nil handler; building from the closed op set guarantees full coverage.
func newHandlerRegistry() map[Op]opHandler {
	reg := make(map[Op]opHandler, len(knownOps))
	for op := range knownOps {
		reg[op] = unimplemented
	}
	return reg
}
