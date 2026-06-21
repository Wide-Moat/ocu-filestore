// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package authz

import (
	"context"
	"errors"
	"testing"

	"pgregory.net/rapid"
)

var allIntents = []Intent{IntentRead, IntentWrite, IntentPreview}

func arbitraryCallerEvidence(rt *rapid.T) CallerEvidence {
	return CallerEvidence{
		Scope: FilesystemID(rapid.String().Draw(rt, "ev_scope")),
		GrantedIntents: rapid.SliceOf(
			rapid.SampledFrom(allIntents),
		).Draw(rt, "grants"),
	}
}

// TestPropDenyByDefault asserts that allow implies an explicit grant match on
// every axis for arbitrary (evidence, request) pairs — including off-enum
// intent values — and that every deny carries exactly one of the three
// sentinels with Downloadable=false (AUTHZ-01, NFR-SEC-49).
//
// Invariant 5 / NFR-SEC-73 changes the deny model for the downloadable axis: a
// successful tag lookup reporting downloadable=false is NO LONGER a deny — the
// read is allowed in-session and the egress-eligible artifact is withheld
// (Grant{Downloadable: false}, nil). Only a tag-lookup ERROR denies
// ErrNotDownloadable, fail-closed. The generator therefore draws BOTH a random
// stored-tag bool AND an occasional lookup error, so:
//   - the false-tag read appears on the ALLOW side (asserted: the resolved bit
//     equals the drawn tag), keeping the new read-allowed semantics covered;
//   - the tag-ERROR read appears on the DENY side, keeping ErrNotDownloadable
//     a reachable, non-vacuous deny sentinel.
//
// This flip matches canon invariant 5, not merely a green test: it widens the
// allow set to include the readable-but-non-downloadable case the spec names.
func TestPropDenyByDefault(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		ev := arbitraryCallerEvidence(rt)

		// Mix enum intents with arbitrary strings so the off-enum default
		// deny branch is exercised, not just the three known values.
		intentGen := rapid.OneOf(
			rapid.SampledFrom(allIntents).AsAny(),
			rapid.String().AsAny(),
		)
		var intent Intent
		switch v := intentGen.Draw(rt, "intent").(type) {
		case Intent:
			intent = v
		case string:
			intent = Intent(v)
		}

		req := Request{
			Filesystem: FilesystemID(rapid.String().Draw(rt, "req_fs")),
			Path:       rapid.String().Draw(rt, "path"),
			Intent:     intent,
		}
		// The stored tag and an occasional lookup error are drawn together. A
		// lookup error is the ONLY way the downloadable axis denies now
		// (fail-closed); a clean lookup of either bool authorizes the read.
		storedTag := rapid.Bool().Draw(rt, "stored_tag")
		tagErrs := rapid.Bool().Draw(rt, "tag_lookup_errs")
		tag := func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
			if tagErrs {
				return storedTag, errors.New("lookup failed")
			}
			return storedTag, nil
		}

		g, err := New(tag).Resolve(context.Background(), ev, req)
		if err == nil {
			// The only condition under which allow is returned: explicit
			// positive match on the scope and intent axes.
			if ev.Scope == "" {
				rt.Fatal("allowed with empty attested scope")
			}
			if req.Filesystem != ev.Scope {
				rt.Fatal("allowed despite scope mismatch")
			}
			if !intentGranted(ev.GrantedIntents, req.Intent) {
				rt.Fatal("allowed despite intent not in grants")
			}
			// Invariant 5: on a cleanly-resolved read the granted downloadable
			// bit equals the stored tag (a false tag is a read-allowed grant
			// with the egress artifact withheld, never a deny). Write/preview
			// are structurally non-downloadable.
			if req.Intent == IntentRead && !tagErrs {
				if g.Downloadable != storedTag {
					rt.Fatalf("read allow: Downloadable=%v, want the stored tag %v", g.Downloadable, storedTag)
				}
			} else if g.Downloadable {
				rt.Fatal("write/preview allow yielded Downloadable=true")
			}
		} else {
			// Deny must carry exactly one of the three sentinels. The
			// ErrNotDownloadable deny is now reachable ONLY via a tag-lookup
			// error on intent=read (fail-closed) — never a clean false tag.
			if !errors.Is(err, ErrScopeMismatch) &&
				!errors.Is(err, ErrIntentDenied) &&
				!errors.Is(err, ErrNotDownloadable) {
				rt.Fatalf("unknown deny sentinel: %v", err)
			}
			if errors.Is(err, ErrNotDownloadable) {
				// The only path to this sentinel: a read whose tag lookup
				// errored. A clean false tag must NOT reach it (the read is
				// allowed in-session, invariant 5).
				if req.Intent != IntentRead || !tagErrs {
					rt.Fatalf("ErrNotDownloadable on a non-error path (intent=%q, tagErrs=%v): a clean false tag must allow the read", req.Intent, tagErrs)
				}
			}
			if g.Downloadable {
				rt.Fatal("deny returned Downloadable=true")
			}
		}
	})
}

// TestPropPreviewNotDownloadable asserts intent=preview never yields
// Downloadable=true regardless of how permissive the stored tag is
// (AUTHZ-02, NFR-SEC-73).
func TestPropPreviewNotDownloadable(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Non-empty scope: an empty attested scope denies on the scope axis
		// before the preview branch is ever reached (pinned elsewhere).
		scope := FilesystemID(rapid.StringN(1, -1, -1).Draw(rt, "scope"))
		ev := CallerEvidence{
			Scope:          scope,
			GrantedIntents: []Intent{IntentPreview},
		}
		req := Request{
			Filesystem: scope,
			Path:       rapid.String().Draw(rt, "path"),
			Intent:     IntentPreview,
		}
		// Even with stored tag = true, preview must be non-downloadable.
		tag := func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
			return true, nil
		}
		g, err := New(tag).Resolve(context.Background(), ev, req)
		if err != nil {
			rt.Fatalf("preview with matching scope and grant denied: %v", err)
		}
		if g.Downloadable {
			rt.Fatal("preview intent yielded Downloadable=true")
		}
	})
}

// TestPropScopeHintNoWiden asserts the request Filesystem hint never widens
// scope beyond the host-attested evidence Scope: any mismatch denies
// ErrScopeMismatch even with every intent granted and a permissive stored
// tag, and an empty attested scope denies unconditionally — equal-empty
// values never authorize (AUTHZ-01, NFR-SEC-43).
func TestPropScopeHintNoWiden(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Bias toward the empty attested scope so the equal-empty deny is
		// exercised every run batch, not left to chance.
		evidenceScope := FilesystemID(rapid.OneOf(
			rapid.Just(""),
			rapid.String(),
		).Draw(rt, "ev_scope"))
		requestScope := FilesystemID(rapid.String().Draw(rt, "req_scope"))
		if evidenceScope == requestScope && evidenceScope != "" {
			return // equal non-empty scopes are the allow case, not under test
		}

		ev := CallerEvidence{
			Scope:          evidenceScope,
			GrantedIntents: allIntents, // grant everything
		}
		req := Request{
			Filesystem: requestScope,
			Path:       rapid.String().Draw(rt, "path"),
			Intent:     rapid.SampledFrom(allIntents).Draw(rt, "intent"),
		}
		tag := func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
			return true, nil // permissive tag
		}
		_, err := New(tag).Resolve(context.Background(), ev, req)
		if !errors.Is(err, ErrScopeMismatch) {
			rt.Fatalf("scope mismatch not returned: %v", err)
		}
	})
}
