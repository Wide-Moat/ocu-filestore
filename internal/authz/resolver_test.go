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

// TestNewNilTagPanics pins fail-closed construction: wiring the resolver
// without a stored-tag lookup is surfaced as an immediate, named panic at
// New, never a latent nil-deref on the read path.
func TestNewNilTagPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("New(nil) did not panic")
		}
		msg, ok := r.(string)
		if !ok || msg != "authz: New requires a non-nil StoredTagFunc" {
			t.Fatalf("New(nil) panic: got %v, want named message", r)
		}
	}()
	New(nil)
}

// TestEmptyAttestedScopeDenies pins AUTHZ-01 / NFR-SEC-43 fail-closed: an
// empty host-attested Scope authorizes nothing, even when the request hint
// is equally empty and pure equality would otherwise hold.
func TestEmptyAttestedScopeDenies(t *testing.T) {
	r := New(tagReturning(true, nil))
	ev := CallerEvidence{Scope: "", GrantedIntents: allIntents}
	_, err := r.Resolve(context.Background(), ev, Request{
		Filesystem: "",
		Path:       "a.txt",
		Intent:     IntentRead,
	})
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("Resolve: got %v, want ErrScopeMismatch", err)
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
		{"read-only caller requests write", []Intent{IntentRead}, IntentWrite},
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

// TestNotDownloadable pins AUTHZ-02/03 / NFR-SEC-73, invariant 5. The two
// cases are deliberately DISTINCT and this distinction IS the invariant:
//
//   - A successful tag lookup reporting downloadable=false is NOT a deny. Per
//     invariant 5 the object is "readable in-session but yields no
//     egress-eligible artifact": the resolver ALLOWS the read and returns
//     Grant{Downloadable: false}, nil. The egress-artifact deny is the
//     consuming op's decision on the bit, not a resolver error. (This case was
//     previously pinned to ErrNotDownloadable — an over-deny that denied the
//     whole read; it is flipped here to match canon invariant 5, not to make a
//     test green: the southface read/download handlers already gate egress on
//     Grant.Downloadable and never relied on the resolver erroring.)
//   - A tag lookup ERROR stays fail-closed: the disposition could not be
//     resolved, so the read itself is denied ErrNotDownloadable.
func TestNotDownloadable(t *testing.T) {
	// Successful lookup, downloadable=false: read ALLOWED, artifact withheld.
	t.Run("stored tag false allows read with Downloadable=false", func(t *testing.T) {
		r := New(tagReturning(false, nil))
		ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentRead}}
		g, err := r.Resolve(context.Background(), ev, Request{
			Filesystem: "fs1",
			Path:       "a.txt",
			Intent:     IntentRead,
		})
		if err != nil {
			t.Fatalf("Resolve: got %v, want nil (read allowed in-session, invariant 5)", err)
		}
		if g.Downloadable {
			t.Fatal("read with a false stored tag yielded Downloadable=true; the egress artifact must be withheld")
		}
	})

	// Tag lookup error: fail-closed read deny (the disposition is unresolved).
	for _, tc := range []struct {
		name string
		tag  StoredTagFunc
	}{
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
				t.Fatalf("Resolve: got %v, want ErrNotDownloadable (fail-closed on unresolved disposition)", err)
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

// TestWriteGrantSubsumesRead pins the class-admission rule (ADR-0029 + the PoC
// outputs-rw contract): a write-only grant ADMITS read-class requests - an RW
// mount must stat, list, and read the subtree it writes, and the dispatch join
// confines those reads to the write subtree itself. The reverse direction
// (read grant requesting write) stays denied in TestIntentDenied - read carries
// no write lease (NFR-SEC-49).
func TestWriteGrantSubsumesRead(t *testing.T) {
	r := New(tagReturning(true, nil))
	ev := CallerEvidence{Scope: "fs1", GrantedIntents: []Intent{IntentWrite}}
	if _, err := r.Resolve(context.Background(), ev, Request{
		Filesystem: "fs1",
		Path:       "outputs/a.txt",
		Intent:     IntentRead,
	}); err != nil {
		t.Fatalf("a write-only grant must admit a read-class request, got %v", err)
	}
}
