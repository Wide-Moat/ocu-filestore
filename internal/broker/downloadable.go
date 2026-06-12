// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker

import (
	"context"
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
// egress (the resolver maps false -> ErrNotDownloadable on intent=read). The
// resolver enforces the preview rule independently — intent=preview is
// structurally non-downloadable and never consults this func.
//
// The returned func is never nil (authz.New panics on nil — Pitfall 4).
func NewPrefixDownloadablePolicy(prefixes []string) authz.StoredTagFunc {
	// Normalize the configured prefixes once at construction.
	norm := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Drop a trailing slash so "/pub/" and "/pub" behave identically;
		// the root "/" is kept as a sentinel that matches nothing on its own
		// (a deployment marking the entire scope downloadable configures the
		// explicit prefixes it wants, not the bare root).
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
		for _, prefix := range norm {
			if pathUnderPrefix(path, prefix) {
				return true, nil
			}
		}
		return false, nil
	}
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
