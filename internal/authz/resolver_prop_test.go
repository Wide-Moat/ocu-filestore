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

// TestPropDenyByDefault asserts that allow implies an explicit grant match
// on every axis for arbitrary (evidence, request) pairs — including
// off-enum intent values — and that every deny carries exactly one of the
// three sentinels with Downloadable=false (AUTHZ-01, NFR-SEC-49).
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
		tag := func(_ context.Context, _ FilesystemID, _ string) (bool, error) {
			return rapid.Bool().Draw(rt, "stored_tag"), nil
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
		} else {
			// Deny must carry exactly one of the three sentinels.
			if !errors.Is(err, ErrScopeMismatch) &&
				!errors.Is(err, ErrIntentDenied) &&
				!errors.Is(err, ErrNotDownloadable) {
				rt.Fatalf("unknown deny sentinel: %v", err)
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
