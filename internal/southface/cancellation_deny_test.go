// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"testing"
)

// TestCancellationDenyClass pins T2-5 (RES-03): context.Canceled and
// context.DeadlineExceeded must map to denyAborted (the aborted/canceled deny
// class) BEFORE any transient/throttle branch in both denyClassForEngineErr
// and denyClassForErr. This stops a client disconnect or deadline from
// polluting the audit chain as a generic error or being misclassified as a
// backend transient.
func TestCancellationDenyClass(t *testing.T) {
	t.Run("denyClassForEngineErr/ctx.Canceled", func(t *testing.T) {
		got := denyClassForEngineErr(context.Canceled)
		if got != denyAborted {
			t.Fatalf("denyClassForEngineErr(context.Canceled) = %q, want %q", got, denyAborted)
		}
	})

	t.Run("denyClassForEngineErr/ctx.DeadlineExceeded", func(t *testing.T) {
		got := denyClassForEngineErr(context.DeadlineExceeded)
		if got != denyAborted {
			t.Fatalf("denyClassForEngineErr(context.DeadlineExceeded) = %q, want %q", got, denyAborted)
		}
	})

	t.Run("denyClassForErr/ctx.Canceled", func(t *testing.T) {
		got := denyClassForErr(context.Canceled)
		if got != denyAborted {
			t.Fatalf("denyClassForErr(context.Canceled) = %q, want %q", got, denyAborted)
		}
	})

	t.Run("denyClassForErr/ctx.DeadlineExceeded", func(t *testing.T) {
		got := denyClassForErr(context.DeadlineExceeded)
		if got != denyAborted {
			t.Fatalf("denyClassForErr(context.DeadlineExceeded) = %q, want %q", got, denyAborted)
		}
	})

	t.Run("auditTruthForEngineErr/ctx.Canceled", func(t *testing.T) {
		got := auditTruthForEngineErr(context.Canceled)
		if got != denyAborted {
			t.Fatalf("auditTruthForEngineErr(context.Canceled) = %q, want %q", got, denyAborted)
		}
	})

	t.Run("auditTruthForEngineErr/ctx.DeadlineExceeded", func(t *testing.T) {
		got := auditTruthForEngineErr(context.DeadlineExceeded)
		if got != denyAborted {
			t.Fatalf("auditTruthForEngineErr(context.DeadlineExceeded) = %q, want %q", got, denyAborted)
		}
	})
}

// TestCancellationWireCode pins the wire code for the aborted deny class: the
// cancel/deadline verdict must yield the aborted Connect code (409), not the
// transient/throttle codes.
func TestCancellationWireCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ctx.Canceled/engineErr", context.Canceled},
		{"ctx.DeadlineExceeded/engineErr", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class := denyClassForEngineErr(tc.err)
			v := mapDeny(class)
			if v.WireCode != wireCodeAborted {
				t.Fatalf("wire code for %v = %q, want %q (aborted)", tc.err, v.WireCode, wireCodeAborted)
			}
		})
	}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ctx.Canceled/err", context.Canceled},
		{"ctx.DeadlineExceeded/err", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class := denyClassForErr(tc.err)
			v := mapDeny(class)
			if v.WireCode != wireCodeAborted {
				t.Fatalf("wire code for %v = %q, want %q (aborted)", tc.err, v.WireCode, wireCodeAborted)
			}
		})
	}
}

// TestCancellationClassifiedBeforeTransient verifies the ordering guarantee:
// a wrapped context.Canceled (e.g. from a timeout on an engine call) must
// still classify as denyAborted, not as denyBackendUnavailable or denyInternal.
// This pins that the cancellation branch is truly FIRST in the switch.
func TestCancellationClassifiedBeforeTransient(t *testing.T) {
	// Wrap context.Canceled in a generic error so it travels through
	// errors.Is wrapping — this is the realistic case where a network engine
	// wraps ctx errors.
	wrapped := &wrappedCtxErr{inner: context.Canceled}
	got := denyClassForEngineErr(wrapped)
	if got != denyAborted {
		t.Fatalf("denyClassForEngineErr(wrapped context.Canceled) = %q, want %q (must classify before transient/throttle)", got, denyAborted)
	}

	wrapped2 := &wrappedCtxErr{inner: context.DeadlineExceeded}
	got2 := denyClassForEngineErr(wrapped2)
	if got2 != denyAborted {
		t.Fatalf("denyClassForEngineErr(wrapped context.DeadlineExceeded) = %q, want %q (must classify before transient/throttle)", got2, denyAborted)
	}
}

// wrappedCtxErr is a trivial error wrapper that satisfies errors.Is via
// the standard Unwrap convention. It is the minimal stand-in for a
// context-cancellation error that has been wrapped by an intermediate layer
// (e.g. fmt.Errorf("op failed: %w", ctx.Err())).
type wrappedCtxErr struct{ inner error }

func (e *wrappedCtxErr) Error() string { return "wrapped: " + e.inner.Error() }
func (e *wrappedCtxErr) Unwrap() error { return e.inner }
