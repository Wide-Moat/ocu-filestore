// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"errors"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
)

// TestErrNotFoundCarriesNotFoundToken pins that ErrNotFound carries the
// denyclass.NotFound token in its message — the only resolution-failure the
// file_id path emits, and the token the audit record stamps.
func TestErrNotFoundCarriesNotFoundToken(t *testing.T) {
	if !strings.Contains(ErrNotFound.Error(), denyclass.NotFound) {
		t.Fatalf("ErrNotFound = %q, want it to carry the %q token", ErrNotFound.Error(), denyclass.NotFound)
	}
	if got := AuditReason(ErrNotFound); got != denyclass.NotFound {
		t.Fatalf("AuditReason(ErrNotFound) = %q, want %q", got, denyclass.NotFound)
	}
	// errors.Is must match through a wrapping (the disk store returns the
	// sentinel directly today, but callers may wrap it with context).
	wrapped := errors.Join(errors.New("read /files/x"), ErrNotFound)
	if !errors.Is(wrapped, ErrNotFound) {
		t.Fatal("errors.Is(wrapped, ErrNotFound) = false, want true")
	}
	if got := AuditReason(wrapped); got != denyclass.NotFound {
		t.Fatalf("AuditReason(wrapped ErrNotFound) = %q, want %q", got, denyclass.NotFound)
	}
}

// TestErrStoreUnavailableIsInternal pins the latched-store sentinel and its
// audit token: a store fault is a broker-internal state, not a client deny
// class.
func TestErrStoreUnavailableIsInternal(t *testing.T) {
	if got := AuditReason(ErrStoreUnavailable); got != denyclass.Internal {
		t.Fatalf("AuditReason(ErrStoreUnavailable) = %q, want %q", got, denyclass.Internal)
	}
}

// TestNoExportedErrorMapsToScopeMismatch is the structural guard: NONE of the
// package's exported error vars may carry the scope_mismatch token. scope_
// mismatch is reserved for the credscope axis; a file_id resolution failure
// that named it would leak that a probed handle exists in another scope. The
// table enumerates every exported sentinel — adding a new one without adding it
// here will not catch it, so this test is paired with the package's small,
// closed sentinel set (ErrNotFound, ErrStoreUnavailable).
func TestNoExportedErrorMapsToScopeMismatch(t *testing.T) {
	exported := []struct {
		name string
		err  error
	}{
		{"ErrNotFound", ErrNotFound},
		{"ErrStoreUnavailable", ErrStoreUnavailable},
	}
	for _, e := range exported {
		if strings.Contains(e.err.Error(), denyclass.ScopeMismatch) {
			t.Fatalf("%s = %q carries the reserved %q token; file_id failures must never name scope_mismatch", e.name, e.err.Error(), denyclass.ScopeMismatch)
		}
		if AuditReason(e.err) == denyclass.ScopeMismatch {
			t.Fatalf("AuditReason(%s) = scope_mismatch; reserved for the credscope axis", e.name)
		}
	}
}

// TestAuditReasonUnknownIsEmpty pins the fall-through: a foreign error yields
// the empty string so the caller falls back to its own classification.
func TestAuditReasonUnknownIsEmpty(t *testing.T) {
	if got := AuditReason(errors.New("some other error")); got != "" {
		t.Fatalf("AuditReason(foreign) = %q, want empty", got)
	}
	if got := AuditReason(nil); got != "" {
		t.Fatalf("AuditReason(nil) = %q, want empty", got)
	}
}
