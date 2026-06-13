// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package admission

import (
	"errors"
	"testing"

	"pgregory.net/rapid"
)

// TestPropDenyByDefault asserts, for arbitrary string triples (covering valid
// enum values and off-enum garbage alike), that Admit returns nil if and only
// if the triple is in the explicit ok-set; every refusal carries the
// ErrAdmissionRefused sentinel (ADM-01, NFR-SEC-60).
func TestPropDenyByDefault(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Draw from arbitrary strings — covers valid enum values AND
		// invalid ones (wrong case, NUL bytes, surrogates, empty).
		profile := WorkloadTrustProfile(rapid.String().Draw(rt, "profile"))
		tenancy := Tenancy(rapid.String().Draw(rt, "tenancy"))
		credKind := CredentialKind(rapid.String().Draw(rt, "cred_kind"))

		err := Admit(profile, tenancy, credKind)

		_, inOKSet := credentialOKSet[admitKey{profile, tenancy, credKind}]
		if err == nil {
			if !inOKSet {
				rt.Fatalf("Admit(%q, %q, %q) returned nil but triple is not in ok-set",
					profile, tenancy, credKind)
			}
			return
		}
		if !errors.Is(err, ErrAdmissionRefused) {
			rt.Fatalf("Admit(%q, %q, %q) returned unexpected error: %v",
				profile, tenancy, credKind, err)
		}
		if inOKSet {
			rt.Fatalf("Admit(%q, %q, %q) refused but triple is in ok-set",
				profile, tenancy, credKind)
		}
	})
}
