// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package admission

import (
	"errors"
	"testing"
)

// TestAdmitExhaustiveTable iterates every (profile, tenancy, credential kind)
// cell — 3 x 2 x 2 = 12 — and asserts the admit/refuse outcome of each against
// a table that mirrors the ok-set, then asserts that exactly one cell admits
// the long-lived host-local credential (ADM-01, NFR-SEC-60).
func TestAdmitExhaustiveTable(t *testing.T) {
	allProfiles := []WorkloadTrustProfile{
		ProfileTrustedOperator,
		ProfileInternalWorkforce,
		ProfileUntrusted,
	}
	allTenancies := []Tenancy{TenancySingleTenant, TenancyMultiTenant}
	allCredKinds := []CredentialKind{CredHostLocalLongLived, CredSTSPerSession}

	// wantAdmit mirrors credentialOKSet — the test table IS the policy.
	wantAdmit := map[admitKey]bool{
		{ProfileTrustedOperator, TenancySingleTenant, CredHostLocalLongLived}: true,
		{ProfileTrustedOperator, TenancySingleTenant, CredSTSPerSession}:      true,
		{ProfileTrustedOperator, TenancyMultiTenant, CredSTSPerSession}:       true,
		{ProfileInternalWorkforce, TenancySingleTenant, CredSTSPerSession}:    true,
		{ProfileInternalWorkforce, TenancyMultiTenant, CredSTSPerSession}:     true,
		{ProfileUntrusted, TenancySingleTenant, CredSTSPerSession}:            true,
		{ProfileUntrusted, TenancyMultiTenant, CredSTSPerSession}:             true,
	}

	for _, p := range allProfiles {
		for _, tn := range allTenancies {
			for _, ck := range allCredKinds {
				key := admitKey{p, tn, ck}
				err := Admit(p, tn, ck)
				want := wantAdmit[key]
				if want && err != nil {
					t.Errorf("Admit(%q, %q, %q) = %v, want nil", p, tn, ck, err)
				}
				if !want && !errors.Is(err, ErrAdmissionRefused) {
					t.Errorf("Admit(%q, %q, %q) = %v, want ErrAdmissionRefused", p, tn, ck, err)
				}
			}
		}
	}

	// Exactly one admitted long-lived cell across all profile/tenancy cells —
	// the core NFR-SEC-60 claim.
	var longLivedAdmits int
	for _, p := range allProfiles {
		for _, tn := range allTenancies {
			if err := Admit(p, tn, CredHostLocalLongLived); err == nil {
				longLivedAdmits++
			}
		}
	}
	if longLivedAdmits != 1 {
		t.Errorf("long-lived admit cells = %d, want exactly 1 (NFR-SEC-60)", longLivedAdmits)
	}
}
