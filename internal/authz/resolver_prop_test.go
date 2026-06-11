// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package authz

import (
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
// on every axis for arbitrary (evidence, request) pairs, and that every
// deny carries exactly one of the three sentinels (AUTHZ-01, NFR-SEC-49).
func TestPropDenyByDefault(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = arbitraryCallerEvidence(rt)
		// Task 3 fills the resolver call and assertions.
	})
}

// TestPropPreviewNotDownloadable asserts intent=preview never yields
// Downloadable=true regardless of the stored tag (AUTHZ-02, NFR-SEC-73).
func TestPropPreviewNotDownloadable(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = FilesystemID(rapid.String().Draw(rt, "scope"))
		// Task 3 fills the resolver call and assertions.
	})
}

// TestPropScopeHintNoWiden asserts the request Filesystem hint never widens
// scope beyond the host-attested evidence Scope (AUTHZ-01, NFR-SEC-43).
func TestPropScopeHintNoWiden(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = FilesystemID(rapid.String().Draw(rt, "ev_scope"))
		// Task 3 fills the resolver call and assertions.
	})
}
