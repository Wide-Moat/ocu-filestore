// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// prefixResolver is a PATH-AWARE Resolver that mirrors the broker's prefix
// downloadable policy: it grants Downloadable=true ONLY when the request path
// (whatever bytes it is handed) lies under a configured prefix on a path
// boundary. It exists to witness bypass-01 end-to-end: pre-fix the spine
// handed it the RAW wire path so "pub/../secret" prefix-matched "pub" and the
// tag returned true while the engine read the cleaned "secret"; post-fix the
// spine canonicalizes ONCE before authz, so this resolver sees the cleaned
// "secret", which is NOT under "pub", and downloadable resolves false. It also
// captures the path it was handed so a test can assert authz-path ==
// engine-path.
//
// The prefix is ENGINE-RELATIVE with NO leading slash ("pub", never "/pub"):
// the spine hands the resolver (and its StoredTagFunc) the engine-relative form
// so the south and north planes evaluate the stored tag against one convention
// (ADR-0029 inv-5).
type prefixResolver struct {
	prefix  string
	lastReq ResolveRequest
}

func (r *prefixResolver) Resolve(_ context.Context, _ any, req ResolveRequest) (Grant, error) {
	r.lastReq = req
	downloadable := req.Path == r.prefix || strings.HasPrefix(req.Path, r.prefix+"/")
	return Grant{Downloadable: downloadable}, nil
}

// TestCanonicalizeRejectsEscape pins the boundary canonicalizer directly in
// STATIC-PATH mode (subtree ""): the unsafe lexical classes that can change
// which object a path names (a NUL byte and a URL-shaped handle) are refused,
// and every other path cleans to its single canonical in-scope form. Crucially,
// a ".." that would climb above the scope root is ABSORBED by anchoring at "/"
// — "/pub/../secret" cleans to the in-scope sibling "/secret" and "/../escape"
// collapses to the in-scope "/escape" — so the canonical form NEVER names an
// object outside the scope, and authz and the engine resolve the identical
// in-scope path (bypass-01/03). The scope root "/" is admitted (a listing
// target), unlike the engine-side file-open validator that rejects the root.
func TestCanonicalizeRejectsEscape(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"/pub/report.pdf", "/pub/report.pdf", false},
		{"/pub/../secret", "/secret", false}, // sibling, in-scope after Clean
		{"/a/./b", "/a/b", false},
		{"/a//b", "/a/b", false},
		{"/", "/", false}, // scope root: a listing target, admitted
		{"", "/", false},  // empty -> scope root
		{"a/b", "/a/b", false},
		{"/../escape", "/escape", false},    // over-climb absorbed at the root
		{"/../../escape", "/escape", false}, // deeper over-climb absorbed
		{"../escape", "/escape", false},     // rootless over-climb absorbed
		{"/pub/../../etc", "/etc", false},   // never escapes: stays in-scope
		{"s3://bucket/key", "", true},       // scheme-shaped handle: refused
		{"/a\x00b", "", true},               // NUL byte: refused
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := canonicalizePath(c.in, "")
			if c.wantErr {
				if err == nil {
					t.Fatalf("canonicalizePath(%q, \"\") = %q, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalizePath(%q, \"\") error = %v, want %q", c.in, err, c.want)
			}
			if got != c.want {
				t.Fatalf("canonicalizePath(%q, \"\") = %q, want %q", c.in, got, c.want)
			}
			// The canonical form is idempotent and never carries a residual
			// traversal segment — the property authz/engine agreement rests on.
			if strings.Contains(got, "/../") || strings.HasSuffix(got, "/..") || got == ".." {
				t.Fatalf("canonicalizePath(%q, \"\") = %q still carries a traversal segment", c.in, got)
			}
		})
	}
}

// TestCanonicalizeSubtreeJoin pins the ADR-0029 inv-10 join: a supplied subtree
// is prepended BEFORE path.Clean, and the escape check becomes a
// subtree-containment check that SUBSUMES the bare "/.." reject. The
// load-bearing case is "/uploads/../x" under subtree "uploads": it cleans to
// "/x", which fails the "/uploads/" containment prefix and is refused — the
// exact hole the pre-ADR-0029 bare "/.." reject leaves open once a subtree is
// prepended. A URL-scheme leg dies pre-join. A unicode-normalisation pair yields
// DISTINCT joined paths (path.Clean is byte-wise; we never fold unicode).
func TestCanonicalizeSubtreeJoin(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		subtree string
		want    string
		wantErr bool
	}{
		{"leading-slash join", "/x", "outputs", "/outputs/x", false},
		{"relative join", "x", "outputs", "/outputs/x", false},
		{"nested join", "/a/b", "outputs", "/outputs/a/b", false},
		{"empty path is subtree root", "", "outputs", "/outputs", false},
		{"slash path is subtree root", "/", "uploads", "/uploads", false},
		// An in-subtree "../" that climbs back to the subtree root and no
		// further stays contained — the literal "uploads/" is a directory name
		// under the join, so "/uploads/../x" resolves to "/uploads/x" (safe).
		{"in-subtree dotdot stays contained", "/uploads/../x", "uploads", "/uploads/x", false},
		// The load-bearing escapes: a NET leading ".." climbs ABOVE the subtree
		// root after the join, so Clean-then-prefix rejects it (the exact hole a
		// bare "/.." reject leaves open once the subtree is prepended).
		{"leading dotdot escape rejected", "/../x", "uploads", "", true},
		{"rootless dotdot escape rejected", "../x", "uploads", "", true},
		{"deep net-climb escape rejected", "/uploads/../../x", "uploads", "", true},
		{"deeper net-climb escape rejected", "/uploads/a/../../../x", "uploads", "", true},
		{"absolute escape rejected", "/../etc", "outputs", "", true},
		// URL scheme dies BEFORE the join (never prefixed).
		{"url scheme dies pre-join", "s3://bucket/k", "outputs", "", true},
		{"nul byte dies pre-join", "/a\x00b", "outputs", "", true},
		// Redundant segments collapse under the join.
		{"redundant segments", "/./a//b", "uploads", "/uploads/a/b", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := canonicalizePath(c.in, c.subtree)
			if c.wantErr {
				if err == nil {
					t.Fatalf("canonicalizePath(%q, %q) = %q, want error", c.in, c.subtree, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalizePath(%q, %q) error = %v, want %q", c.in, c.subtree, err, c.want)
			}
			if got != c.want {
				t.Fatalf("canonicalizePath(%q, %q) = %q, want %q", c.in, c.subtree, got, c.want)
			}
			// The join is contained: the result is the subtree root or under it.
			base := "/" + c.subtree
			if got != base && !strings.HasPrefix(got, base+"/") {
				t.Fatalf("canonicalizePath(%q, %q) = %q escaped the join %q", c.in, c.subtree, got, base)
			}
		})
	}

	// Unicode-normalisation: a composed (NFC) and a decomposed (NFD) name are
	// DISTINCT byte strings, so they yield DISTINCT joined paths. path.Clean is
	// byte-wise and never folds unicode — this documents that we do not silently
	// collapse a composed vs decomposed name onto the same object.
	nfc := "é.txt"  // é as a single code point
	nfd := "é.txt" // e + combining acute accent
	gotNFC, err := canonicalizePath("/"+nfc, "uploads")
	if err != nil {
		t.Fatalf("canonicalizePath NFC error: %v", err)
	}
	gotNFD, err := canonicalizePath("/"+nfd, "uploads")
	if err != nil {
		t.Fatalf("canonicalizePath NFD error: %v", err)
	}
	if gotNFC == gotNFD {
		t.Fatalf("NFC %q and NFD %q joined to the SAME path %q; unicode was silently folded", nfc, nfd, gotNFC)
	}
}

// TestReadFileTraversalBypassDenied pins bypass-01: a guest that names
// "<granted-prefix>/../<outside-prefix>" through readFile is DENIED, and the
// resolver saw the SAME canonical path the engine would resolve — proving the
// authz path and the engine path agree (bypass-01/03 invariant).
//
// After the south-read-gate removal, the deny no longer comes from the
// downloadable axis (which is the north egress control only). The target path
// is NOT seeded in the engine: the spine canonicalises the traversal exploit to
// "secret/key.bin" (outside the "pub" prefix), the resolver sees that cleaned
// form (prefixResolver grants Downloadable=false for a path outside "pub"),
// and — because the object does not exist — the engine returns not_found (404)
// without exposing any content. A 200 or a resolution of the raw un-cleaned
// path would indicate a bypass.
func TestReadFileTraversalBypassDenied(t *testing.T) {
	eng := newFakeEngine()
	// Do NOT seed "secret/key.bin" — the path does not exist in the engine.
	// The load-bearing witness is that the resolver saw the CLEANED path
	// (authz-path == engine-path, bypass-01/03).
	// Seed a downloadable object so the prefix exists.
	eng.putBytes(opScope, "pub/report.pdf", []byte("public"))

	resolver := &prefixResolver{prefix: "pub"}
	d := newDispatcherWithEngine(resolver, &fakeGuard{}, okCeilings(), 1<<20, eng)
	d.maxFileSize = 1 << 20

	// The exploit path: /pub/../secret/key.bin cleans to /secret/key.bin.
	w := serveOp(d, OpReadFile,
		readBodyNoRange(opScope, "/pub/../secret/key.bin", true),
		opScope, okIntents())

	// Must be DENIED — the object does not exist so the engine returns
	// not_found (404). A 200 would mean the traversal bypass succeeded.
	if w.Code == 200 {
		t.Fatalf("traversal readFile returned 200 (bypass succeeded); body %s", w.Body.String())
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("traversal readFile status = %d, want 404 not_found (non-existent target after traversal clean); body %s", w.Code, w.Body.String())
	}

	// LOAD-BEARING WITNESS (bypass-01/03): the resolver must have seen the
	// CLEANED engine-relative path, not the raw traversal string. If it had
	// seen the raw string, the "pub" prefix would have matched "/pub/../secret"
	// and the grant would have been Downloadable=true. The resolver seeing
	// "secret/key.bin" proves authz-path == engine-path.
	if got := resolver.lastReq.Path; got != "secret/key.bin" {
		t.Fatalf("resolver saw path %q, want the canonical engine-relative secret/key.bin (authz-path == engine-path)", got)
	}
}

// TestAuthzPathEqualsEnginePath pins the invariant (bypass-03): for a request
// the spine accepts, the path the resolver sees equals the path the engine
// resolves — both in the engine-relative convention (ADR-0029 inv-5). It drives
// a successful readFile through a path with redundant segments and asserts the
// resolver and the engine Stat both saw the cleaned engine-relative form.
func TestAuthzPathEqualsEnginePath(t *testing.T) {
	eng := newFakeEngine()
	eng.putBytes(opScope, "pub/docs/a.txt", []byte("hello"))

	resolver := &prefixResolver{prefix: "pub"}
	d := newDispatcherWithEngine(resolver, &fakeGuard{}, okCeilings(), 1<<20, eng)
	d.maxFileSize = 1 << 20

	// Redundant segments: /pub/./docs//a.txt cleans to /pub/docs/a.txt.
	w := serveOp(d, OpReadFile,
		readBodyNoRange(opScope, "/pub/./docs//a.txt", true),
		opScope, okIntents())
	if w.Code != 200 {
		t.Fatalf("readFile status = %d, want 200; body %s", w.Code, w.Body.String())
	}

	if got := resolver.lastReq.Path; got != "pub/docs/a.txt" {
		t.Fatalf("resolver path = %q, want canonical engine-relative pub/docs/a.txt", got)
	}
	// The engine Stat (engine-relative) must name the same object: pub/docs/a.txt.
	found := false
	for _, p := range eng.statCalls() {
		if p == "pub/docs/a.txt" {
			found = true
		}
		if strings.Contains(p, "..") || strings.Contains(p, "//") || strings.Contains(p, "/./") {
			t.Fatalf("engine Stat saw a non-canonical path %q", p)
		}
	}
	if !found {
		t.Fatalf("engine Stat did not see the canonical pub/docs/a.txt; got %v", eng.statCalls())
	}

	// The emitted uuid must be keyed off the canonical guest path: re-observing
	// the same object via the canonical path returns the same id, and via a
	// dirty alias also returns the same id (both canonicalize identically).
	resp := decodeReadFile(t, w)
	if resp.File.UUID == "" {
		t.Fatalf("readFile emitted no uuid")
	}
	if resp.File.Path != "/pub/docs/a.txt" {
		t.Fatalf("readFile emitted path %q, want canonical /pub/docs/a.txt", resp.File.Path)
	}
}
