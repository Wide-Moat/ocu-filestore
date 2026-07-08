// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"io/fs"
	"strings"
)

// EnsureDir idempotently makes every "/"-delimited level of the engine-relative
// subtree prefix dir, ROOT->LEAF, over the single-level engine MakeDir verb. It
// is the ONE home of the dir-marker convention both the south namespace spine
// (makeDirs, the make_parents branch) and the north Files-API create compose
// over (ADR-0029): the S3 engine's WriteStream refuses a write whose parent
// directory marker is absent (a *fs.PathError wrapping fs.ErrNotExist), so the
// join-subtree the create lands under must be materialised before the byte
// write. Unlike makeDirs' make_parents leaf, EnsureDir tolerates fs.ErrExist at
// EVERY level INCLUDING the leaf — the whole prefix is a precondition to
// converge on, not an object the caller asked to newly create, so a
// concurrent or prior creation of any level is success, not a caller-visible
// already_exists.
//
// An empty dir ("") is a no-op success: that is the static-path mode (no
// intent->subtree join is configured), where the object lands at the scope root
// whose parent — the root itself — always exists, so no marker is needed.
//
// The level count is capped at maxWalkDepth BEFORE any engine call (NFR-SEC-46),
// the same guard makeDirs applies: a caller must never drive a per-level
// engine-call loop of unbounded length or build a tree no later walk can
// traverse. Callers pass a PINNED deploy-map subtree constant (the create's
// CreateSubtree), NEVER a user-derived path, so EnsureDir never escapes the
// passed dir — it makes only the levels of dir, nothing above or beside it
// (NFR-SEC-73).
func EnsureDir(ctx context.Context, eng Engine, scope string, dir string) error {
	if dir == "" {
		return nil // static-path mode: the scope root is the parent, always present.
	}
	parts := strings.Split(dir, "/")
	if len(parts) > maxWalkDepth {
		return errInvalidPath
	}
	for i := range parts {
		if err := ctx.Err(); err != nil {
			return err // honour cancellation between levels
		}
		prefix := strings.Join(parts[:i+1], "/")
		err := eng.MakeDir(ctx, scope, prefix)
		if err == nil || errors.Is(err, fs.ErrExist) {
			continue // idempotent: this level now exists (we made it or it already did)
		}
		return err
	}
	return nil
}
