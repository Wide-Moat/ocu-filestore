// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"context"
	"errors"
	"testing"

	"pgregory.net/rapid"
)

// TestPropGetResolvesIffScopeEqual asserts the resolver invariant over random
// (record-scope, attested-scope) pairs: Get resolves IFF the two scopes are
// byte-equal; otherwise it ALWAYS returns ErrNotFound — and the returned error
// for a cross-scope id is byte-identical to the error for an absent id (an
// attested scope can never learn that an id exists in a different scope).
func TestPropGetResolvesIffScopeEqual(t *testing.T) {
	scopes := []string{"", "fs-A", "fs-B", "fs-AA", "FS-A", "fs-a", "fs-A "}

	rapid.Check(t, func(rt *rapid.T) {
		_, s := newTestStore(t)

		recordScope := rapid.SampledFrom(scopes).Draw(rt, "record_scope")
		attestedScope := rapid.SampledFrom(scopes).Draw(rt, "attested_scope")

		rec, err := s.Put(context.Background(), samplePut(recordScope, "f"))
		if err != nil {
			rt.Fatalf("Put: %v", err)
		}

		got, getErr := s.Get(context.Background(), rec.FileID, attestedScope)
		// The unknown-id error under the SAME attested scope — the
		// indistinguishability reference.
		_, absentErr := s.Get(context.Background(), "never-minted-id", attestedScope)

		if recordScope == attestedScope && attestedScope != "" {
			// Byte-equal NON-EMPTY scope -> resolves to the exact record. An
			// empty attested scope authorizes nothing and falls through to the
			// ErrNotFound arm even when byte-equal (followup-2 defense-in-depth).
			if getErr != nil {
				rt.Fatalf("Get under byte-equal scope %q = %v, want the record", attestedScope, getErr)
			}
			if got != rec {
				rt.Fatalf("Get under byte-equal scope = %+v, want %+v", got, rec)
			}
			return
		}

		// Any non-equal scope -> ErrNotFound, zero record, and the error is
		// byte-identical to the absent-id error.
		if !errors.Is(getErr, ErrNotFound) {
			rt.Fatalf("Get(record_scope=%q, attested=%q) = %v, want ErrNotFound", recordScope, attestedScope, getErr)
		}
		if got != (Record{}) {
			rt.Fatalf("cross-scope Get leaked a non-zero Record: %+v", got)
		}
		if getErr.Error() != absentErr.Error() {
			rt.Fatalf("cross-scope and absent-id errors differ:\n cross=%q\n absent=%q (must be identical)", getErr.Error(), absentErr.Error())
		}
	})
}
