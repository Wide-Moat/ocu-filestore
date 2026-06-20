// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
)

// errSizeExceeded is the consumer-side mirror of ceilings.ErrSizeExceeded for
// the local whole-object pre-buffer check. checkDeclaredSize returns it; the
// upload handler maps it to the policy size deny (invalid_argument/size_exceeded),
// distinct from the transport message-too-large reject (resource_exhausted).
var errSizeExceeded = errors.New("southface: declared size exceeds whole-object ceiling")

// errStreamAborted is the hard-abort sentinel the multipart upload reassembler
// closes the engine pipe with when the inbound "file" part read fails BEFORE
// the closing multipart boundary — a truncated body or a mid-stream connection
// drop (the part read returns io.ErrUnexpectedEOF). It MUST be distinct from
// io.EOF: io.Copy inside the engine's WriteStream treats a pipe read returning
// io.EOF as a CLEAN end-of-stream and would commit the partial bytes
// (temp+rename), so passing the raw read error through io.EOF would commit a
// torn object. Closing the pipe with this non-EOF sentinel makes WriteStream
// fail and discard the temp, preserving the abort-discards-nothing invariant.
var errStreamAborted = errors.New("southface: inbound stream aborted before half-close")

// checkDeclaredSize is the named local mirror of the engine-side free function
// ceilings.CheckDeclaredSize(declared, ceiling int64) error. Its body is a
// single direct `>` comparison — NEVER a subtraction — so it is overflow-safe
// even when both operands approach math.MaxInt64 (a subtraction
// `declared-ceiling > 0` would overflow). The boundary is strict `>` (NOT
// `>=`): a declaration exactly at the ceiling is admitted. The consumer
// CeilingsSession seam does NOT expose this comparison (it is a free function
// on the real package, not a session method), so this is a local mirror, not a
// seam call — keeping the boundary semantics in ONE named place for the
// phase-11 seam swap. The fileUpload multipart handler runs it as the
// pre-assembly size reject before reading any object byte.
func checkDeclaredSize(declared, ceiling int64) error {
	if declared > ceiling {
		return errSizeExceeded
	}
	return nil
}

// statSizeContained resolves the object's current size for a whole-object
// download via engine.Stat, recovering a panicking engine into errInternalPanic.
// The download handler runs Stat on the MAIN handler goroutine BEFORE the
// HTTP-200 octet-stream header is committed, so without this guard a Stat panic
// would unwind to recoverDispatch and surface as a unary error AFTER the 200
// stream header was already on the wire — a status that can no longer change. A
// recovered panic returns a zero size and errInternalPanic, which the caller
// classifies through denyClassForEngineErr (-> denyInternal), the same path as
// any other unrecognised engine fault.
func statSizeContained(ctx context.Context, e Engine, scope, path string) (size int64, err error) {
	defer func() {
		if v := recover(); v != nil {
			size = 0
			err = errInternalPanic
		}
	}()
	fi, serr := e.Stat(ctx, scope, path)
	if serr != nil {
		return 0, serr
	}
	return fi.Size, nil
}
