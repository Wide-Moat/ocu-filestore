// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/Wide-Moat/ocu-filestore/internal/authz"
)

// NewPrefixDownloadablePolicy returns the broker-side, operator-configured
// downloadable-tag source for the minimal trusted_operator single-tenant shelf
// (NFR-SEC-73). It is the StoredTagFunc authz.New requires — it is NEVER the
// wire downloadable flag and NEVER a write-time stamp; the tag is resolved
// broker-side at read from the deployment's configured prefix set.
//
// The returned func reports downloadable=true ONLY when the request path lies
// under a configured downloadable prefix (a path-boundary match: "/pub"
// matches "/pub" and "/pub/..." but not "/pubX"); everything else is false —
// default false for any class above PUBLIC (SEC-73). An empty prefix set makes
// every object non-downloadable, the fail-closed deployment default.
//
// It is fail-closed: it never reports downloadable=true for a path it cannot
// confidently match, so an unmatched path is readable-in-session-but-denied-
// egress. On intent=read the resolver maps a false tag to
// Grant{Downloadable: false}, nil (invariant 5: the read is allowed, the
// egress-eligible artifact withheld) — the egress-artifact deny is the
// consuming op's decision on Grant.Downloadable, NOT a resolver error. Only a
// non-nil error from this func denies the read fail-closed (ErrNotDownloadable).
// The resolver enforces the preview rule independently — intent=preview is
// structurally non-downloadable and never consults this func.
//
// The returned func is never nil (authz.New panics on nil — Pitfall 4).
// downloadableMatchAll is the explicit whole-scope downloadable token. It is
// DISTINCT from the bare root "/" (which stays a matches-nothing sentinel): a
// deployment marks its entire scope downloadable by CONSCIOUSLY passing "*", not
// by accidentally leaving a bare "/" in the prefix list. Canon-ruling (the
// contracts/storage gatekeeper, reading NFR-SEC-73): "*" expresses the
// PUBLIC-class posture the NFR provides for — for a single-tenant
// trusted_operator agent output space, the whole fs-fleet scope is downloadable
// by design (the agent writes outputs to be downloaded). It resolves ONLY the
// downloadable axis: scope (filesystem_id) and intent are still checked, and
// intent=preview stays structurally non-downloadable regardless of this token.
const downloadableMatchAll = "*"

func NewPrefixDownloadablePolicy(prefixes []string) authz.StoredTagFunc {
	// Normalize the configured prefixes once at construction.
	norm := make([]string, 0, len(prefixes))
	matchAll := false
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// "*" is the explicit whole-scope token — a conscious "this whole fs is
		// downloadable", separate from the matches-nothing bare root. It is not a
		// path prefix, so it never joins norm; it sets the match-all flag.
		if p == downloadableMatchAll {
			matchAll = true
			continue
		}
		// Drop a trailing slash so "/pub/" and "/pub" behave identically;
		// the root "/" is kept as a sentinel that matches nothing on its own
		// (a deployment marking the entire scope downloadable configures the
		// explicit prefixes it wants — "*" — not the bare root).
		if p != "/" {
			p = strings.TrimRight(p, "/")
		}
		norm = append(norm, p)
	}

	return func(_ context.Context, _ authz.FilesystemID, path string) (bool, error) {
		// An empty or rootless path cannot be matched to a configured prefix;
		// fail-closed to non-downloadable rather than guess.
		if path == "" {
			return false, nil
		}
		// Belt-and-suspenders (bypass-01): the egress gate decides on a
		// path-boundary PREFIX match, so it MUST never grant on a non-canonical
		// path. The wire boundary now canonicalizes once before authz, so a
		// dirty path should never reach here; if a future caller forgets, refuse
		// to grant rather than match a traversal segment against a prefix. A
		// path that still carries a ".." component or that does not equal its
		// own filepath.Clean form is fail-closed to non-downloadable — the
		// cleaned object it actually names may sit OUTSIDE the prefix. This guard
		// runs BEFORE the match-all shortcut, so "*" never grants a traversal
		// path (the whole-scope token widens the in-scope surface, never the
		// containment boundary).
		if filepath.Clean(path) != path || hasDotDotComponent(path) {
			return false, nil
		}
		// The explicit whole-scope token: every canonical in-scope path is
		// downloadable. Scope/intent/preview axes are enforced elsewhere and are
		// unaffected.
		if matchAll {
			return true, nil
		}
		for _, prefix := range norm {
			if pathUnderPrefix(path, prefix) {
				return true, nil
			}
		}
		return false, nil
	}
}

// hasDotDotComponent reports whether path carries a ".." as a whole
// "/"-delimited component (not merely as a substring of a legitimate name such
// as "..config"). It is the fail-closed companion to the filepath.Clean
// equality check: a path that is already clean cannot carry a ".." component,
// but the explicit test documents the egress-gate invariant in one place.
func hasDotDotComponent(path string) bool {
	for _, c := range strings.Split(path, "/") {
		if c == ".." {
			return true
		}
	}
	return false
}

// pathUnderPrefix reports whether path is the prefix itself or lies beneath it
// on a path boundary. It compares on "/"-delimited components so a configured
// prefix "/pub" matches "/pub" and "/pub/report.pdf" but not "/pubX/y".
func pathUnderPrefix(path, prefix string) bool {
	if path == prefix {
		return true
	}
	// Beneath the prefix: the prefix followed by a separator.
	return strings.HasPrefix(path, prefix+"/")
}
