// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package authz

import (
	"context"
	"errors"
	"testing"
)

// TestScopeMismatch pins AUTHZ-01 / NFR-SEC-43: a request whose Filesystem
// hint differs from the evidence Scope denies ErrScopeMismatch; the hint
// never widens scope.
func TestScopeMismatch(t *testing.T) {
	r := New(func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		return true, nil
	})
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentRead}}
	_, err := r.Resolve(context.Background(), ev, Request{Filesystem: "fs2", Intent: IntentRead})
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("Resolve: got %v, want ErrScopeMismatch", err)
	}
}

// TestUnknownEvidenceTypeDenies pins AUTHZ-01: a caller that is not
// CallerEvidence fails closed with ErrScopeMismatch.
func TestUnknownEvidenceTypeDenies(t *testing.T) {
	r := New(func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		return true, nil
	})
	_, err := r.Resolve(context.Background(), nil, Request{Filesystem: "fs1", Intent: IntentRead})
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("Resolve: got %v, want ErrScopeMismatch", err)
	}
}

// TestIntentDenied pins AUTHZ-01 / NFR-SEC-49: an intent absent from the
// caller's grant set denies ErrIntentDenied.
func TestIntentDenied(t *testing.T) {
	r := New(func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		return true, nil
	})
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentPreview}}
	_, err := r.Resolve(context.Background(), ev, Request{Filesystem: "fs1", Intent: IntentWrite})
	if !errors.Is(err, ErrIntentDenied) {
		t.Fatalf("Resolve: got %v, want ErrIntentDenied", err)
	}
}

// TestUnknownIntentDenied pins AUTHZ-01 / NFR-SEC-49: an off-enum intent
// value denies ErrIntentDenied; there is no default-allow branch.
func TestUnknownIntentDenied(t *testing.T) {
	r := New(func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		return true, nil
	})
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentRead}}
	_, err := r.Resolve(context.Background(), ev, Request{Filesystem: "fs1", Intent: Intent("delete")})
	if !errors.Is(err, ErrIntentDenied) {
		t.Fatalf("Resolve: got %v, want ErrIntentDenied", err)
	}
}

// TestNotDownloadable pins AUTHZ-02/03 / NFR-SEC-73: read with a false
// stored tag denies ErrNotDownloadable.
func TestNotDownloadable(t *testing.T) {
	r := New(func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		return false, nil
	})
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentRead}}
	_, err := r.Resolve(context.Background(), ev, Request{Filesystem: "fs1", Intent: IntentRead})
	if !errors.Is(err, ErrNotDownloadable) {
		t.Fatalf("Resolve: got %v, want ErrNotDownloadable", err)
	}
}

// TestWriteNotDownloadable pins AUTHZ-02 / NFR-SEC-73: a write grant never
// yields Downloadable=true.
func TestWriteNotDownloadable(t *testing.T) {
	r := New(func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		return true, nil
	})
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentWrite}}
	g, err := r.Resolve(context.Background(), ev, Request{Filesystem: "fs1", Intent: IntentWrite})
	if err != nil {
		t.Fatalf("Resolve: got %v, want nil", err)
	}
	if g.Downloadable {
		t.Fatal("write grant yielded Downloadable=true")
	}
}

// TestDownloadableFromTag pins AUTHZ-02 / NFR-SEC-73: read with a true
// stored tag yields Downloadable=true — the only allow that carries it.
func TestDownloadableFromTag(t *testing.T) {
	r := New(func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		return true, nil
	})
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentRead}}
	g, err := r.Resolve(context.Background(), ev, Request{Filesystem: "fs1", Intent: IntentRead})
	if err != nil {
		t.Fatalf("Resolve: got %v, want nil", err)
	}
	if !g.Downloadable {
		t.Fatal("read with stored tag true did not yield Downloadable=true")
	}
}
