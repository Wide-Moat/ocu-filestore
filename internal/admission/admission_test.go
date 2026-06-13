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

// TestAdmitUnknownValues asserts that off-enum values on any axis — empty
// strings, wrong case, wrong separator, NUL bytes, arbitrary text — refuse
// with ErrAdmissionRefused; no default-admit path exists (NFR-SEC-60).
func TestAdmitUnknownValues(t *testing.T) {
	for _, tc := range []struct {
		name     string
		profile  WorkloadTrustProfile
		tenancy  Tenancy
		credKind CredentialKind
	}{
		{"all empty", "", "", ""},
		{"empty profile", "", TenancySingleTenant, CredHostLocalLongLived},
		{"empty tenancy", ProfileTrustedOperator, "", CredHostLocalLongLived},
		{"empty credential kind", ProfileTrustedOperator, TenancySingleTenant, ""},
		{"wrong-case profile", "TRUSTED_OPERATOR", TenancySingleTenant, CredHostLocalLongLived},
		{"wrong-separator profile", "trusted-operator", TenancySingleTenant, CredHostLocalLongLived},
		{"NUL profile", "\x00", TenancySingleTenant, CredHostLocalLongLived},
		{"NUL-suffixed profile", WorkloadTrustProfile(string(ProfileTrustedOperator) + "\x00"), TenancySingleTenant, CredHostLocalLongLived},
		{"arbitrary profile", "admin", TenancySingleTenant, CredHostLocalLongLived},
		{"arbitrary tenancy", ProfileTrustedOperator, "no_tenant", CredHostLocalLongLived},
		{"arbitrary credential kind", ProfileTrustedOperator, TenancySingleTenant, "root_credential"},
		{"wrong-case credential kind", ProfileTrustedOperator, TenancySingleTenant, "STS_PER_SESSION"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Admit(tc.profile, tc.tenancy, tc.credKind)
			if !errors.Is(err, ErrAdmissionRefused) {
				t.Fatalf("Admit(%q, %q, %q) = %v, want ErrAdmissionRefused", tc.profile, tc.tenancy, tc.credKind, err)
			}
		})
	}
}

// TestAdmitBrokerModeTable iterates every (profile, tenancy) cell — 3 x 2 = 6
// — and asserts a multiplexed broker is admitted only on trusted_operator +
// single_tenant; every other cell refuses with ErrTenancyRefused, and exactly
// one cell admits (NFR-SEC-76).
func TestAdmitBrokerModeTable(t *testing.T) {
	allProfiles := []WorkloadTrustProfile{
		ProfileTrustedOperator,
		ProfileInternalWorkforce,
		ProfileUntrusted,
	}
	allTenancies := []Tenancy{TenancySingleTenant, TenancyMultiTenant}

	var admits int
	for _, p := range allProfiles {
		for _, tn := range allTenancies {
			err := AdmitBrokerMode(p, tn)
			want := p == ProfileTrustedOperator && tn == TenancySingleTenant
			if want && err != nil {
				t.Errorf("AdmitBrokerMode(%q, %q) = %v, want nil", p, tn, err)
			}
			if !want && !errors.Is(err, ErrTenancyRefused) {
				t.Errorf("AdmitBrokerMode(%q, %q) = %v, want ErrTenancyRefused", p, tn, err)
			}
			if err == nil {
				admits++
			}
		}
	}
	if admits != 1 {
		t.Errorf("broker-mode admit cells = %d, want exactly 1 (NFR-SEC-76)", admits)
	}
}
