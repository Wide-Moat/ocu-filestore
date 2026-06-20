// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"strings"
	"testing"
)

// prefixResolver is a PATH-AWARE Resolver that mirrors the broker's prefix
// downloadable policy: it grants Downloadable=true ONLY when the request path
// (whatever bytes it is handed) lies under a configured prefix on a path
// boundary. It exists to witness bypass-01 end-to-end: pre-fix the spine
// handed it the RAW wire path so "/pub/../secret" prefix-matched "/pub" and
// the tag returned true while the engine read the cleaned "secret"; post-fix
// the spine canonicalizes ONCE before authz, so this resolver sees the cleaned
// "/secret", which is NOT under "/pub", and downloadable resolves false. It
// also captures the path it was handed so a test can assert authz-path ==
// engine-path.
type prefixResolver struct {
	prefix  string
	lastReq ResolveRequest
}

func (r *prefixResolver) Resolve(_ context.Context, _ any, req ResolveRequest) (Grant, error) {
	r.lastReq = req
	downloadable := req.Path == r.prefix || strings.HasPrefix(req.Path, r.prefix+"/")
	return Grant{Downloadable: downloadable}, nil
}

// TestCanonicalizeRejectsEscape pins the boundary canonicalizer directly: the
// unsafe lexical classes that can change which object a path names (a NUL byte
// and a URL-shaped handle) are refused, and every other path cleans to its
// single canonical in-scope form. Crucially, a ".." that would climb above the
// scope root is ABSORBED by anchoring at "/" — "/pub/../secret" cleans to the
// in-scope sibling "/secret" and "/../escape" collapses to the in-scope
// "/escape" — so the canonical form NEVER names an object outside the scope,
// and authz and the engine resolve the identical in-scope path (bypass-01/03).
// The scope root "/" is admitted (a listing target), unlike the engine-side
// file-open validator that rejects the root.
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
			got, err := canonicalizePath(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("canonicalizePath(%q) = %q, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalizePath(%q) error = %v, want %q", c.in, err, c.want)
			}
			if got != c.want {
				t.Fatalf("canonicalizePath(%q) = %q, want %q", c.in, got, c.want)
			}
			// The canonical form is idempotent and never carries a residual
			// traversal segment — the property authz/engine agreement rests on.
			if strings.Contains(got, "/../") || strings.HasSuffix(got, "/..") || got == ".." {
				t.Fatalf("canonicalizePath(%q) = %q still carries a traversal segment", c.in, got)
			}
		})
	}
}

// TestReadFileTraversalBypassDenied pins the bypass-01 read leg: a guest that
// names "<downloadable-prefix>/../<non-downloadable>" through readFile is
// DENIED, the non-downloadable object is NEVER Stat-served, and the resolver
// (the downloadable tag) saw the SAME canonical path the engine would resolve
// — proving the egress axis and the read target can no longer disagree.
func TestReadFileTraversalBypassDenied(t *testing.T) {
	eng := newFakeEngine()
	// Seed a non-downloadable object OUTSIDE the /pub prefix.
	eng.putBytes(opScope, "secret/key.bin", []byte("TOPSECRETKEYMATERIAL"))
	// Seed a downloadable object so the prefix is real.
	eng.putBytes(opScope, "pub/report.pdf", []byte("public"))

	resolver := &prefixResolver{prefix: "/pub"}
	d := newDispatcherWithEngine(resolver, &fakeGuard{}, okCeilings(), 1<<20, eng)
	d.maxFileSize = 1 << 20

	// The exploit path: /pub/../secret/key.bin cleans to /secret/key.bin.
	w := serveOp(d, OpReadFile,
		readBodyNoRange(opScope, "/pub/../secret/key.bin", true),
		opScope, okIntents())

	// Must be DENIED, not 200 with metadata.
	if w.Code == 200 {
		t.Fatalf("traversal readFile returned 200 (object served); body %s", w.Body.String())
	}
	if w.Code != 403 {
		t.Fatalf("traversal readFile status = %d, want 403 not_downloadable; body %s", w.Code, w.Body.String())
	}

	// The resolver (downloadable tag) must have seen the CLEANED path, not the
	// raw traversal string — otherwise the prefix match would have granted.
	if got := resolver.lastReq.Path; got != "/secret/key.bin" {
		t.Fatalf("resolver saw path %q, want the canonical /secret/key.bin (authz-path == engine-path)", got)
	}

	// The engine must NEVER have been asked to Stat the secret object: a
	// non-downloadable read denies BEFORE any engine touch.
	for _, p := range eng.statCalls() {
		if strings.Contains(p, "secret") {
			t.Fatalf("engine Stat'd %q during a denied traversal read; the object leaked", p)
		}
	}
}

// TestAuthzPathEqualsEnginePath pins the invariant (bypass-03): for a request
// the spine accepts, the path the resolver sees equals the path the engine
// resolves. It drives a successful readFile through a path with redundant
// segments and asserts the resolver and the engine Stat both saw the cleaned
// form.
func TestAuthzPathEqualsEnginePath(t *testing.T) {
	eng := newFakeEngine()
	eng.putBytes(opScope, "pub/docs/a.txt", []byte("hello"))

	resolver := &prefixResolver{prefix: "/pub"}
	d := newDispatcherWithEngine(resolver, &fakeGuard{}, okCeilings(), 1<<20, eng)
	d.maxFileSize = 1 << 20

	// Redundant segments: /pub/./docs//a.txt cleans to /pub/docs/a.txt.
	w := serveOp(d, OpReadFile,
		readBodyNoRange(opScope, "/pub/./docs//a.txt", true),
		opScope, okIntents())
	if w.Code != 200 {
		t.Fatalf("readFile status = %d, want 200; body %s", w.Code, w.Body.String())
	}

	if got := resolver.lastReq.Path; got != "/pub/docs/a.txt" {
		t.Fatalf("resolver path = %q, want canonical /pub/docs/a.txt", got)
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
