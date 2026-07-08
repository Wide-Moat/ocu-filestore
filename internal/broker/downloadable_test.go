// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker

import (
	"context"
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
		// Paths are engine-relative with no leading slash (ADR-0029 inv-5) — the
		// StoredTagFunc input the resolver delivers on both planes.
		{"pub/report.pdf", true},
		{"pub", true},
		{"share/out/a/b.txt", true},
		{"private/x", false},
		{"pubX/y", false}, // string prefix but not a path-boundary match
		{"share/outsider", false},
		{"", false},
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

// TestPrefixPolicyFeedsResolverReadEgressBit pins SEC-73 / invariant 5 end to
// end through the real resolver: the downloadable prefix policy resolves the
// EGRESS-ARTIFACT bit on intent=read without ever turning a non-downloadable
// object into a read deny. A prefixed object grants Downloadable=true; an
// unconfigured object is "readable in-session but yields no egress-eligible
// artifact" — the read is ALLOWED with Grant{Downloadable: false}, and the
// egress deny is the consuming op's decision on that bit, not a resolver error.
//
// This assertion was previously pinned to ErrNotDownloadable for the
// unconfigured path — an over-deny that refused the whole read. It is flipped
// here to match canon invariant 5 ("a non-downloadable object is readable
// in-session but yields no egress-eligible artifact"), not to make the test
// green: the policy func is unchanged (it still reports false for the
// unconfigured path); only the resolver's verdict for a clean false tag moved
// from deny to read-allowed-with-the-bit-withheld.
func TestPrefixPolicyFeedsResolverReadEgressBit(t *testing.T) {
	tag := NewPrefixDownloadablePolicy([]string{"/pub"})
	res := authz.New(tag)
	ev := authz.CallerEvidence{Scope: "fs1", GrantedIntents: []authz.Intent{authz.IntentRead}}

	// Under the downloadable prefix: read allowed, egress artifact grantable.
	// Paths are engine-relative with no leading slash (ADR-0029 inv-5).
	g, err := res.Resolve(context.Background(), ev, authz.Request{
		Filesystem: "fs1", Path: "pub/report.pdf", Intent: authz.IntentRead,
	})
	if err != nil {
		t.Fatalf("read under pub: err %v, want a grant", err)
	}
	if !g.Downloadable {
		t.Fatalf("read under pub: Downloadable false, want true")
	}

	// Outside any prefix: read is ALLOWED in-session, egress artifact withheld.
	g, err = res.Resolve(context.Background(), ev, authz.Request{
		Filesystem: "fs1", Path: "private/secret.bin", Intent: authz.IntentRead,
	})
	if err != nil {
		t.Fatalf("read outside prefix: got %v, want nil (readable in-session, invariant 5)", err)
	}
	if g.Downloadable {
		t.Fatalf("read outside prefix: Downloadable true, want false (egress artifact withheld)")
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
	// Whitespace-only and empty entries are dropped; a leading and/or trailing
	// slash on a configured prefix is tolerated and trimmed to the engine-relative
	// convention (ADR-0029 inv-5): "/pub/" and "  /share/out/  " normalise to
	// "pub" and "share/out". Query paths are engine-relative with no leading slash.
	tag := NewPrefixDownloadablePolicy([]string{"  ", "", "/pub/", "  /share/out/  "})
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"pub/report.pdf", true}, // leading + trailing slash on the prefix were trimmed
		{"pub", true},
		{"share/out/a.txt", true}, // surrounding whitespace was trimmed
		{"share/out", true},
		{"private/x", false}, // the dropped empty/whitespace entries grant nothing
	} {
		dl, err := tag(context.Background(), "fs1", tc.path)
		if err != nil {
			t.Fatalf("tag(%q): err %v", tc.path, err)
		}
		if dl != tc.want {
			t.Fatalf("tag(%q): downloadable %v, want %v", tc.path, dl, tc.want)
		}
	}

	// A bare root "/" stays the matches-nothing sentinel, DISTINCT from "*": a
	// deployment that wants the whole scope egress-able configures "*", never the
	// bare root. Under the engine-relative convention this holds two ways over —
	// "/" trims to "" and is dropped, AND even an empty prefix reaching
	// pathUnderPrefix would match nothing (HasPrefix(engine-relative-path, "/") is
	// false). This asserts the sentinel BEHAVIOUR, not the empty-drop mechanism;
	// the mechanism is defence-in-depth (see downloadable.go), so this leg passes
	// whether or not the drop is present — the load-bearing guarantee is the
	// no-leading-slash convention, covered by TestPrefixDownloadableCrossPlaneEngineRelative.
	rootTag := NewPrefixDownloadablePolicy([]string{"/"})
	for _, path := range []string{"anything", "deep/nested/file.bin", "pub/x"} {
		dl, err := rootTag(context.Background(), "fs1", path)
		if err != nil {
			t.Fatalf("rootTag(%q): err %v", path, err)
		}
		if dl {
			t.Fatalf("rootTag(%q): downloadable true, want false (bare root is a matches-nothing sentinel, not match-all)", path)
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

// TestPrefixPolicyMatchAllStar pins the explicit whole-scope token "*": every
// canonical in-scope path is downloadable, WITHOUT weakening the containment
// boundary (a traversal path is still refused) and WITHOUT the bare root "/"
// gaining any match (it stays the matches-nothing sentinel). This is the
// canon-ruled PUBLIC-class posture for a single-tenant trusted_operator output
// space (NFR-SEC-73): the agent's whole fs is downloadable because it writes
// outputs to be downloaded.
func TestPrefixPolicyMatchAllStar(t *testing.T) {
	star := NewPrefixDownloadablePolicy([]string{"*"})

	// Every canonical in-scope path — including a root-level file with no
	// sub-prefix (the fs-fleet outputs layout) — is downloadable under "*".
	for _, path := range []string{"/p.txt", "/deep/nested/output.docx", "/pub/x", "/outputs/report.pdf"} {
		dl, err := star(context.Background(), "fs1", path)
		if err != nil {
			t.Fatalf("star(%q): err %v", path, err)
		}
		if !dl {
			t.Fatalf("star(%q): downloadable false, want true (whole-scope token)", path)
		}
	}

	// Containment is preserved: "*" widens the in-scope surface, never the
	// boundary. A traversal-bearing path is still fail-closed to non-downloadable
	// (the bypass-01 guard runs before the match-all shortcut).
	for _, bad := range []string{"/../escape", "/a/../../etc/passwd", "/dir/./x"} {
		dl, err := star(context.Background(), "fs1", bad)
		if err != nil {
			t.Fatalf("star(%q): err %v", bad, err)
		}
		if dl {
			t.Fatalf("star(%q): downloadable true, want false — the whole-scope token must not grant a non-canonical/traversal path", bad)
		}
	}

	// Regression guard on the two-sided contract: WITHOUT the token, the same
	// root-level path is NOT downloadable (a plain "/pub" prefix does not cover
	// it), and a bare "/" is STILL the matches-nothing sentinel — "*" is the only
	// way to express whole-scope, never the bare root.
	noStar := NewPrefixDownloadablePolicy([]string{"/pub"})
	if dl, _ := noStar(context.Background(), "fs1", "/p.txt"); dl {
		t.Fatalf("without the token, /p.txt is downloadable; want false (only /pub covered)")
	}
	bareRoot := NewPrefixDownloadablePolicy([]string{"/"})
	if dl, _ := bareRoot(context.Background(), "fs1", "/p.txt"); dl {
		t.Fatalf("bare root '/' matched /p.txt; want false (bare root stays the matches-nothing sentinel, distinct from '*')")
	}
}

// TestPrefixDownloadableCrossPlaneEngineRelative pins the ADR-0029 inv-5
// stored-tag convention: the StoredTagFunc keys on the ENGINE-RELATIVE path with
// NO leading slash ("outputs/report.pdf"), one convention across the south and
// north planes. Before ADR-0029 the south plane passed the leading-slash form
// ("/outputs/report.pdf") while the north Files-API plane passed engine-relative
// ("outputs/report.pdf"), so a single configured prefix could never match both —
// the observed F9 pane 403. With the convention unified, a prefix configured as
// engine-relative "outputs" matches the engine-relative path both planes now
// present, and does NOT match the stale leading-slash form.
func TestPrefixDownloadableCrossPlaneEngineRelative(t *testing.T) {
	// The fleet-shipped downloadable prefix is engine-relative, no leading slash.
	tag := NewPrefixDownloadablePolicy([]string{"outputs"})

	// Both planes now present the engine-relative path — the join makes the
	// south path "outputs/uploads/x" and the north path "outputs/report.pdf",
	// both without a leading slash. The tag must grant on both.
	for _, p := range []string{"outputs/report.pdf", "outputs/uploads/x", "outputs"} {
		dl, err := tag(context.Background(), "fs1", p)
		if err != nil {
			t.Fatalf("tag(%q): err %v, want nil", p, err)
		}
		if !dl {
			t.Fatalf("tag(%q, prefix=outputs): downloadable false, want true (engine-relative convention)", p)
		}
	}

	// The stale LEADING-SLASH form must NOT match the engine-relative prefix —
	// this is the exact cross-plane mismatch ADR-0029 settles. A "/outputs/x"
	// path does not lie under the engine-relative "outputs" prefix on a path
	// boundary, so it is (correctly) non-downloadable; the fix is that the south
	// plane no longer PRESENTS this stale form to the tag.
	dl, err := tag(context.Background(), "fs1", "/outputs/report.pdf")
	if err != nil {
		t.Fatalf("tag(/outputs/report.pdf): err %v, want nil", err)
	}
	if dl {
		t.Fatalf("tag(/outputs/report.pdf, prefix=outputs): downloadable true; the leading-slash form must NOT match the engine-relative prefix")
	}

	// The read-only "uploads" subtree is NEVER downloadable under an outputs-only
	// prefix: a human upload landed under uploads/ is readable-in-session but not
	// egress-eligible (the exfil-bar, NFR-SEC-73).
	dl, err = tag(context.Background(), "fs1", "uploads/human-upload.bin")
	if err != nil {
		t.Fatalf("tag(uploads/...): err %v, want nil", err)
	}
	if dl {
		t.Fatalf("tag(uploads/human-upload.bin, prefix=outputs): downloadable true; the read-only subtree must not be egress-eligible")
	}
}
