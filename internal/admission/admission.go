// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package admission is the broker's startup-time credential-admission policy:
// the NFR-SEC-60 decision table over (workload trust profile, tenancy,
// credential kind) and the NFR-SEC-76 multiplexed-broker tenancy clause. A
// long-lived host-local backend credential is admitted on exactly one cell —
// trusted_operator and single-tenant — while the stricter STS-per-session
// kind is admitted everywhere; a multiplexed broker is likewise admitted only
// on that same single cell. Every other combination, including unknown enum
// values, refuses with an errors.Is-matchable sentinel.
//
// The package is pure logic with no I/O. The daemon calls Admit and
// AdmitBrokerMode at startup with flag-derived values and refuses to serve
// on a non-nil return; it does not enforce continuously and holds no state.
package admission

import "errors"

// WorkloadTrustProfile is the deployment-wide workload trust axis the
// operator declares for the whole shelf.
type WorkloadTrustProfile string

const (
	// ProfileTrustedOperator is the solo-developer / single-operator profile.
	// It is the only profile admitted for a long-lived host-local backend
	// credential on the minimal shelf (NFR-SEC-60).
	ProfileTrustedOperator WorkloadTrustProfile = "trusted_operator"
	// ProfileInternalWorkforce covers vetted employees and partners driving
	// the agent. A long-lived backend credential is refused; STS-per-session
	// is mandatory (NFR-SEC-60).
	ProfileInternalWorkforce WorkloadTrustProfile = "internal_workforce"
	// ProfileUntrusted covers unknown actors and public endpoints. A
	// long-lived backend credential is refused (NFR-SEC-60).
	ProfileUntrusted WorkloadTrustProfile = "untrusted"
)

// Tenancy is the deployment tenancy axis.
type Tenancy string

const (
	// TenancySingleTenant is a deployment serving exactly one tenant.
	TenancySingleTenant Tenancy = "single_tenant"
	// TenancyMultiTenant is a deployment serving more than one tenant;
	// a long-lived backend credential is refused here regardless of
	// profile (NFR-SEC-60).
	TenancyMultiTenant Tenancy = "multi_tenant"
)

// CredentialKind is the backend-credential kind axis.
type CredentialKind string

const (
	// CredHostLocalLongLived is a long-lived static credential held by the
	// broker process. Admitted only on trusted_operator + single_tenant
	// (NFR-SEC-60).
	CredHostLocalLongLived CredentialKind = "host_local_long_lived"
	// CredSTSPerSession is a short-lived session-scoped credential. Always
	// admitted — it is the stricter kind mandated outside trusted_operator
	// (NFR-SEC-60).
	CredSTSPerSession CredentialKind = "sts_per_session"
)

// ErrAdmissionRefused is returned by Admit when the (profile, tenancy,
// credential kind) triple is rejected by the NFR-SEC-60 policy. Match it
// with errors.Is.
var ErrAdmissionRefused = errors.New("admission: credential kind refused for this profile and tenancy")

// ErrTenancyRefused is returned by AdmitBrokerMode when a multiplexed broker
// is requested for a configuration that requires per-tenant instantiation
// (NFR-SEC-76). Match it with errors.Is.
var ErrTenancyRefused = errors.New("admission: multiplexed broker refused for this profile and tenancy")

// admitKey is the (profile, tenancy, credential kind) triple used as the
// credential ok-set key.
type admitKey struct {
	Profile    WorkloadTrustProfile
	Tenancy    Tenancy
	Credential CredentialKind
}

// credentialOKSet is the explicit set of admitted (profile, tenancy,
// credential kind) triples. Every triple not in this set is refused —
// map-key absence is the only refusal mechanism, so there is no
// default-admit branch anywhere (ADM-01, NFR-SEC-60).
//
// sts_per_session is always admitted (it is the stricter kind); all six
// sts_per_session cells are enumerated explicitly so the exhaustive table
// test can iterate all 12 cells and find exactly these admitted.
var credentialOKSet = map[admitKey]struct{}{
	// Long-lived: exactly one admitted cell (NFR-SEC-60).
	{ProfileTrustedOperator, TenancySingleTenant, CredHostLocalLongLived}: {},
	// STS-per-session: admitted for all profiles and tenancies.
	{ProfileTrustedOperator, TenancySingleTenant, CredSTSPerSession}:   {},
	{ProfileTrustedOperator, TenancyMultiTenant, CredSTSPerSession}:    {},
	{ProfileInternalWorkforce, TenancySingleTenant, CredSTSPerSession}: {},
	{ProfileInternalWorkforce, TenancyMultiTenant, CredSTSPerSession}:  {},
	{ProfileUntrusted, TenancySingleTenant, CredSTSPerSession}:         {},
	{ProfileUntrusted, TenancyMultiTenant, CredSTSPerSession}:          {},
}

// Admit enforces the NFR-SEC-60 credential-admission policy. It returns nil
// only when the (profile, tenancy, credKind) triple is in the explicit
// ok-set; any other triple — including unknown string values — returns
// ErrAdmissionRefused. Inputs are compared by map-key identity only: no
// case-folding, no normalization, so any non-byte-identical value refuses
// uniformly.
//
// The daemon calls Admit at startup with flag-derived values and gates
// serving on a nil return.
func Admit(profile WorkloadTrustProfile, tenancy Tenancy, credKind CredentialKind) error {
	if _, ok := credentialOKSet[admitKey{profile, tenancy, credKind}]; ok {
		return nil
	}
	return ErrAdmissionRefused
}

// brokerModeKey is the (profile, tenancy) pair used as the broker-mode
// ok-set key.
type brokerModeKey struct {
	Profile WorkloadTrustProfile
	Tenancy Tenancy
}

// brokerModeOKSet is the explicit set of (profile, tenancy) pairs for which
// a multiplexed broker is admitted. It is kept separate from credentialOKSet
// because it answers a different policy question; its own exhaustive table
// test guards it against drift (NFR-SEC-76).
var brokerModeOKSet = map[brokerModeKey]struct{}{
	{ProfileTrustedOperator, TenancySingleTenant}: {},
}

// AdmitBrokerMode enforces the NFR-SEC-76 multiplexed-broker tenancy clause.
// It returns nil only when the deployment is single-tenant trusted_operator;
// any other configuration requires per-tenant broker instantiation and
// returns ErrTenancyRefused.
func AdmitBrokerMode(profile WorkloadTrustProfile, tenancy Tenancy) error {
	if _, ok := brokerModeOKSet[brokerModeKey{profile, tenancy}]; ok {
		return nil
	}
	return ErrTenancyRefused
}
