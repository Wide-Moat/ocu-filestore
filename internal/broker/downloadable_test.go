// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/authz"
)

// TestPrefixDownloadablePolicyDefaultsFalse pins SEC-73: an object NOT under
// any configured downloadable prefix is non-downloadable (default false for
// any class above PUBLIC), and an empty prefix set makes everything
// non-downloadable (fail-closed deployment default).
func TestPrefixDownloadablePolicyDefaultsFalse(t *testing.T) {
	for _, prefixes := range [][]string{nil, {}, {"/pub"}} {
		tag := NewPrefixDownloadablePolicy(prefixes)
		if tag == nil {
			t.Fatalf("NewPrefixDownloadablePolicy(%v) returned nil; authz.New panics on nil", prefixes)
		}
		dl, err := tag(context.Background(), "fs1", "/private/secret.bin")
		if err != nil {
			t.Fatalf("tag(unconfigured): err %v, want nil", err)
		}
		if dl {
			t.Fatalf("tag(unconfigured, prefixes=%v): downloadable true, want false (default false)", prefixes)
		}
	}
}

// TestPrefixDownloadablePolicyMatchesPrefix pins that an object UNDER a
// configured prefix is downloadable, and a sibling path that merely shares a
// string-prefix-but-not-a-path-boundary is NOT (so "/pubX" does not match
// prefix "/pub").
func TestPrefixDownloadablePolicyMatchesPrefix(t *testing.T) {
	tag := NewPrefixDownloadablePolicy([]string{"/pub", "/share/out"})

	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/pub/report.pdf", true},
		{"/pub", true},
		{"/share/out/a/b.txt", true},
		{"/private/x", false},
		{"/pubX/y", false}, // string prefix but not a path-boundary match
		{"/share/outsider", false},
		{"/", false},
	} {
		dl, err := tag(context.Background(), "fs1", tc.path)
		if err != nil {
			t.Fatalf("tag(%q): err %v", tc.path, err)
		}
		if dl != tc.want {
			t.Fatalf("tag(%q): downloadable %v, want %v", tc.path, dl, tc.want)
		}
	}
}

// TestPrefixPolicyFeedsResolverReadDenyEgress pins SEC-73 end to end through
// the real resolver: a downloadable-prefixed object resolves to a grant with
// Downloadable=true on intent=read, while an unconfigured object is denied
// egress (ErrNotDownloadable) — readable in session, denied egress.
func TestPrefixPolicyFeedsResolverReadDenyEgress(t *testing.T) {
	tag := NewPrefixDownloadablePolicy([]string{"/pub"})
	res := authz.New(tag)
	ev := authz.CallerEvidence{Scope: "fs1", GrantedIntents: []authz.Intent{authz.IntentRead}}

	// Under the downloadable prefix: read grants egress.
	g, err := res.Resolve(context.Background(), ev, authz.Request{
		Filesystem: "fs1", Path: "/pub/report.pdf", Intent: authz.IntentRead,
	})
	if err != nil {
		t.Fatalf("read under /pub: err %v, want grant", err)
	}
	if !g.Downloadable {
		t.Fatalf("read under /pub: Downloadable false, want true")
	}

	// Outside any prefix: read is denied egress (fail-closed).
	_, err = res.Resolve(context.Background(), ev, authz.Request{
		Filesystem: "fs1", Path: "/private/secret.bin", Intent: authz.IntentRead,
	})
	if !errors.Is(err, authz.ErrNotDownloadable) {
		t.Fatalf("read outside prefix: got %v, want ErrNotDownloadable (deny egress)", err)
	}
}

// TestPreviewStaysNonDownloadable pins SEC-73: intent=preview is structurally
// non-downloadable regardless of the stored tag — even for an object under a
// configured downloadable prefix. The resolver enforces the preview rule; the
// tag func is never consulted for preview, so a spy tag proves it is not
// called.
func TestPreviewStaysNonDownloadable(t *testing.T) {
	called := false
	spy := func(ctx context.Context, fs authz.FilesystemID, path string) (bool, error) {
		called = true
		return true, nil // would grant if consulted
	}
	res := authz.New(spy)
	ev := authz.CallerEvidence{Scope: "fs1", GrantedIntents: []authz.Intent{authz.IntentPreview}}

	g, err := res.Resolve(context.Background(), ev, authz.Request{
		Filesystem: "fs1", Path: "/pub/report.pdf", Intent: authz.IntentPreview,
	})
	if err != nil {
		t.Fatalf("preview: err %v, want a non-downloadable grant", err)
	}
	if g.Downloadable {
		t.Fatalf("preview grant Downloadable true, want false (preview is structurally non-downloadable)")
	}
	if called {
		t.Fatalf("the stored-tag func was consulted for preview; it must not be (SEC-73)")
	}
}

// TestPrefixPolicyNormalizesConfiguredPrefixes pins the construction-time
// normalization: a whitespace-only or empty configured prefix is dropped (it
// never makes everything downloadable), a trailing slash is trimmed so "/pub/"
// and "/pub" behave identically, and a bare root "/" is kept as a sentinel that
// matches NOTHING on its own (a deployment that wants the whole scope egress-
// able configures explicit prefixes, never the bare root). These rows exercise
// the trailing-slash-trim and root-sentinel branches the earlier tests skip.
func TestPrefixPolicyNormalizesConfiguredPrefixes(t *testing.T) {
	// Whitespace-only and empty entries are dropped; "/pub/" trims to "/pub".
	tag := NewPrefixDownloadablePolicy([]string{"  ", "", "/pub/", "  /share/out/  "})
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/pub/report.pdf", true}, // trailing slash on the prefix was trimmed
		{"/pub", true},
		{"/share/out/a.txt", true}, // surrounding whitespace was trimmed
		{"/share/out", true},
		{"/private/x", false}, // the dropped empty/whitespace entries grant nothing
	} {
		dl, err := tag(context.Background(), "fs1", tc.path)
		if err != nil {
			t.Fatalf("tag(%q): err %v", tc.path, err)
		}
		if dl != tc.want {
			t.Fatalf("tag(%q): downloadable %v, want %v", tc.path, dl, tc.want)
		}
	}

	// A bare root "/" is kept verbatim (the trailing-slash trim is skipped for
	// it): it never expands to cover the whole tree on a path-boundary match —
	// "/anything" is NOT beneath it ("//"-joined prefix never matches), so a
	// deployment that wants the whole scope egress-able must configure explicit
	// prefixes, not the bare root.
	rootTag := NewPrefixDownloadablePolicy([]string{"/"})
	for _, path := range []string{"/anything", "/deep/nested/file.bin", "/pub/x"} {
		dl, err := rootTag(context.Background(), "fs1", path)
		if err != nil {
			t.Fatalf("rootTag(%q): err %v", path, err)
		}
		if dl {
			t.Fatalf("rootTag(%q): downloadable true, want false (bare root does not cover the tree)", path)
		}
	}
}

// TestPrefixPolicyFailClosedOnError pins that the policy returns (false, err)
// on an internal lookup failure so the resolver denies egress — fail-closed.
func TestPrefixPolicyFailClosedOnError(t *testing.T) {
	// A path that the policy cannot classify (e.g. an empty path) is treated
	// as non-downloadable, never silently downloadable.
	tag := NewPrefixDownloadablePolicy([]string{"/pub"})
	dl, err := tag(context.Background(), "fs1", "")
	if err != nil {
		// An error is acceptable (fail-closed), but it must not also report
		// downloadable true.
		if dl {
			t.Fatalf("error path reported downloadable true; must be false (fail-closed)")
		}
		return
	}
	if dl {
		t.Fatalf("empty path reported downloadable true, want false")
	}
}
