// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
)

// HandleStore is the south face's consumer port over the durable file_id
// index. The four ADR-0036 object verbs address that index rather than the
// engine's path namespace, so this face reads the same durable record the north
// face does — one object dialect over one store is the decision ADR-0036 rests
// on, and a second index would be the drift it exists to prevent.
//
// The methods and their semantics are handlestore.Store's own, deliberately not
// restated here: scope binding and the absent-equals-cross-scope ErrNotFound
// collapse are enforced BELOW this seam. A handler that re-implemented either
// would be a second place to weaken them, and the store is documented as the
// single file_id authority.
//
// It is narrower than handlestore.Store on purpose. Close is main's, Latched is
// the ops listener's, and EnsureObject is the north list's reconcile verb; a
// south handler must be unable to reach any of them.
type HandleStore interface {
	Get(ctx context.Context, fileID, attestedScope string) (handlestore.Record, error)
	List(ctx context.Context, in handlestore.ListInput) (handlestore.ListPage, error)
	Delete(ctx context.Context, fileID, attestedScope string) error
	// Put mints the durable handle createFile returns. It is the only mutating
	// method on this port: every other south write lands bytes in the guest
	// mount and mints nothing.
	Put(ctx context.Context, in handlestore.PutInput) (handlestore.Record, error)
}

// requireHandles answers the by-handle verbs when the deployment configured no
// durable store. It denies 503 rather than 501: the verb IS implemented and its
// body IS contract-pinned, so "not implemented" would misreport the build —
// what is missing is the backing resource, which is unavailability. ADR-0036
// makes the 501 set exactly the set with no frozen body, and a
// deployment-dependent 501 would destroy that identity.
//
// The north face already answers 503 when its store is unavailable; a store
// that was never configured is unavailable by configuration, and the same face
// of the same service gives the same answer.
func requireHandles(d *handlerDeps, hc handlerCtx) bool {
	if d.handles != nil {
		return true
	}
	hc.mandateDeny(denyBackendUnavailable, denyBackendUnavailable,
		"handle store not configured")
	return false
}
