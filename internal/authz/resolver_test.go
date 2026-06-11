// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package authz

import (
	"context"
	"errors"
	"testing"
)

// tagReturning is a StoredTagFunc that always reports the given disposition.
func tagReturning(dl bool, err error) StoredTagFunc {
	return func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		return dl, err
	}
}

// TestScopeMismatch pins AUTHZ-01 / NFR-SEC-43: a request whose Filesystem
// hint differs from the evidence Scope denies ErrScopeMismatch; the hint
// never widens scope.
func TestScopeMismatch(t *testing.T) {
	r := New(tagReturning(true, nil))
	for _, tc := range []struct {
		name     string
		evScope  FilesystemID
		reqScope FilesystemID
	}{
		{"empty request scope", "fs1", ""},
		{"different scope", "fs1", "fs2"},
		{"empty evidence scope, named request", "", "fs1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := CallerEvidence{Scope: tc.evScope, GrantedIntents: allIntents}
			_, err := r.Resolve(context.Background(), ev, Request{
				Filesystem: tc.reqScope,
				Path:       "a.txt",
				Intent:     IntentRead,
			})
			if !errors.Is(err, ErrScopeMismatch) {
				t.Fatalf("Resolve: got %v, want ErrScopeMismatch", err)
			}
		})
	}
}

// TestUnknownEvidenceTypeDenies pins AUTHZ-01: a caller that is not
// CallerEvidence fails closed with ErrScopeMismatch — the resolver never
// trusts an evidence type it cannot read.
func TestUnknownEvidenceTypeDenies(t *testing.T) {
	r := New(tagReturning(true, nil))
	for _, tc := range []struct {
		name   string
		caller any
	}{
		{"nil caller", nil},
		{"string caller", "fs1"},
		{"pointer to evidence", &CallerEvidence{Scope: "fs1", GrantedIntents: allIntents}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.Resolve(context.Background(), tc.caller, Request{
				Filesystem: "fs1",
				Path:       "a.txt",
				Intent:     IntentRead,
			})
			if !errors.Is(err, ErrScopeMismatch) {
				t.Fatalf("Resolve: got %v, want ErrScopeMismatch", err)
			}
		})
	}
}

// TestIntentDenied pins AUTHZ-01 / NFR-SEC-49: an intent absent from the
// caller's grant set denies ErrIntentDenied.
func TestIntentDenied(t *testing.T) {
	r := New(tagReturning(true, nil))
	for _, tc := range []struct {
		name   string
		grants []Intent
		intent Intent
	}{
		{"nil grant set", nil, IntentRead},
		{"empty grant set", []Intent{}, IntentWrite},
		{"preview-only caller requests write", []Intent{IntentPreview}, IntentWrite},
		{"preview-only caller requests read", []Intent{IntentPreview}, IntentRead},
		{"write-only caller requests read", []Intent{IntentWrite}, IntentRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := CallerEvidence{Scope: "fs1", GrantedIntents: tc.grants}
			_, err := r.Resolve(context.Background(), ev, Request{
				Filesystem: "fs1",
				Path:       "a.txt",
				Intent:     tc.intent,
			})
			if !errors.Is(err, ErrIntentDenied) {
				t.Fatalf("Resolve: got %v, want ErrIntentDenied", err)
			}
		})
	}
}

// TestUnknownIntentDenied pins AUTHZ-01 / NFR-SEC-49: an off-enum intent
// value denies ErrIntentDenied; there is no default-allow branch.
func TestUnknownIntentDenied(t *testing.T) {
	r := New(tagReturning(true, nil))
	// The off-enum intent is also placed in the grant set so the request
	// reaches the intent switch and exercises its default branch.
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{Intent("delete")}}
	_, err := r.Resolve(context.Background(), ev, Request{
		Filesystem: "fs1",
		Path:       "a.txt",
		Intent:     Intent("delete"),
	})
	if !errors.Is(err, ErrIntentDenied) {
		t.Fatalf("Resolve: got %v, want ErrIntentDenied", err)
	}
}

// TestNotDownloadable pins AUTHZ-02/03 / NFR-SEC-73: read with a false
// stored tag denies ErrNotDownloadable, and a tag lookup error denies the
// same way — fail-closed.
func TestNotDownloadable(t *testing.T) {
	for _, tc := range []struct {
		name string
		tag  StoredTagFunc
	}{
		{"stored tag false", tagReturning(false, nil)},
		{"tag lookup error", tagReturning(true, errors.New("lookup failed"))},
		{"tag lookup error with false tag", tagReturning(false, errors.New("lookup failed"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(tc.tag)
			ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentRead}}
			g, err := r.Resolve(context.Background(), ev, Request{
				Filesystem: "fs1",
				Path:       "a.txt",
				Intent:     IntentRead,
			})
			if !errors.Is(err, ErrNotDownloadable) {
				t.Fatalf("Resolve: got %v, want ErrNotDownloadable", err)
			}
			if g.Downloadable {
				t.Fatal("deny returned Downloadable=true")
			}
		})
	}
}

// TestWriteNotDownloadable pins AUTHZ-02 / NFR-SEC-73: a write grant never
// yields Downloadable=true, even with a permissive stored tag.
func TestWriteNotDownloadable(t *testing.T) {
	tagCalled := false
	r := New(func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		tagCalled = true
		return true, nil
	})
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentWrite}}
	g, err := r.Resolve(context.Background(), ev, Request{
		Filesystem: "fs1",
		Path:       "a.txt",
		Intent:     IntentWrite,
	})
	if err != nil {
		t.Fatalf("Resolve: got %v, want nil", err)
	}
	if g.Downloadable {
		t.Fatal("write grant yielded Downloadable=true")
	}
	if tagCalled {
		t.Fatal("StoredTagFunc called for write intent")
	}
}

// TestPreviewNotDownloadable pins AUTHZ-02 / NFR-SEC-73: preview resolves
// non-downloadable regardless of the stored tag, and the tag lookup is
// never consulted.
func TestPreviewNotDownloadable(t *testing.T) {
	tagCalled := false
	r := New(func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
		tagCalled = true
		return true, nil
	})
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentPreview}}
	g, err := r.Resolve(context.Background(), ev, Request{
		Filesystem: "fs1",
		Path:       "a.txt",
		Intent:     IntentPreview,
	})
	if err != nil {
		t.Fatalf("Resolve: got %v, want nil", err)
	}
	if g.Downloadable {
		t.Fatal("preview grant yielded Downloadable=true")
	}
	if tagCalled {
		t.Fatal("StoredTagFunc called for preview intent")
	}
}

// TestDownloadableFromTag pins AUTHZ-02 / NFR-SEC-73: read with a true
// stored tag yields Downloadable=true — the only allow that carries it,
// derived at read from broker-side state.
func TestDownloadableFromTag(t *testing.T) {
	r := New(tagReturning(true, nil))
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentRead}}
	g, err := r.Resolve(context.Background(), ev, Request{
		Filesystem: "fs1",
		Path:       "a.txt",
		Intent:     IntentRead,
	})
	if err != nil {
		t.Fatalf("Resolve: got %v, want nil", err)
	}
	if !g.Downloadable {
		t.Fatal("read with stored tag true did not yield Downloadable=true")
	}
}
