// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// PENDING-PHASE-7(A5-credscope): these tests pin the STRUCTURAL credential-scope
// flow (read bearer -> derive bound fsid -> compare to request fsid -> 403/401),
// which is testable now. The exact injected-credential SHAPE binds later via the
// CredentialScopeExtractor seam, so the tests drive a FAKE extractor and never
// depend on a real credential format, issuer, audience, or signature. No
// jwt/jwks dependency is exercised — by design, the scope check does not verify
// a signature. Flips to "frozen @ canon-rev <sha>" after #292 merges.

// fakeExtractor is a swappable CredentialScopeExtractor for the structural
// tests: it maps a bearer token to a pre-seeded scope, proving the seam is
// swappable without binding to any real credential shape.
type fakeExtractor struct {
	// byToken maps a verbatim bearer string to the scope it binds to. A token
	// absent from the map is rejected (the structural analogue of an
	// expired/foreign-authority credential).
	byToken map[string]CredentialScope
	// err, when non-nil, is returned for every Extract call (an
	// authority-rejected credential).
	err error
	// lastBearer records the most recent bearer Extract saw, so a test can
	// assert the scheme was stripped and the token passed verbatim.
	lastBearer string
}

func (e *fakeExtractor) Extract(bearer string) (CredentialScope, error) {
	e.lastBearer = bearer
	if e.err != nil {
		return CredentialScope{}, e.err
	}
	scope, ok := e.byToken[bearer]
	if !ok {
		return CredentialScope{}, errCredentialRejected
	}
	return scope, nil
}

// credScopeRequest builds a request carrying the given Authorization header
// value verbatim (empty omits the header entirely).
func credScopeRequest(authHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/filestore/fs/listDirectory", nil)
	r.Header.Del(authHeaderName)
	if authHeader != "" {
		r.Header.Set(authHeaderName, authHeader)
	}
	return r
}

// TestCredScopeMatchingFsidAllows asserts a request whose top-level
// filesystem_id matches the credential-bound scope is allowed, and the returned
// PeerScope is fully populated from the credential (scope, intents, uid/pid) —
// the SAME struct the dispatch spine reads and the SAME context helper stashes
// it under.
func TestCredScopeMatchingFsidAllows(t *testing.T) {
	const fsid = "tenant-eu-42"
	want := CredentialScope{
		FilesystemID:   fsid,
		GrantedIntents: []Intent{IntentRead, IntentWrite},
		UID:            1001,
		PID:            55,
	}
	ext := &fakeExtractor{byToken: map[string]CredentialScope{"real-credential": want}}

	r := credScopeRequest(bearerScheme + "real-credential")
	ps, v, ok := deriveCredScope(r, ext, fsid)
	if !ok {
		t.Fatalf("matching fsid denied: verdict=%+v", v)
	}
	if ps.FilesystemID != fsid {
		t.Errorf("PeerScope.FilesystemID = %q, want %q", ps.FilesystemID, fsid)
	}
	if !reflect.DeepEqual(ps.GrantedIntents, want.GrantedIntents) {
		t.Errorf("PeerScope.GrantedIntents = %v, want %v", ps.GrantedIntents, want.GrantedIntents)
	}
	if ps.UID != want.UID || ps.PID != want.PID {
		t.Errorf("PeerScope actor = (uid %d, pid %d), want (uid %d, pid %d)", ps.UID, ps.PID, want.UID, want.PID)
	}
	// The "Bearer " scheme must have been stripped before the extractor saw the
	// verbatim credential.
	if ext.lastBearer != "real-credential" {
		t.Errorf("extractor saw bearer %q, want the scheme-stripped credential", ext.lastBearer)
	}

	// The allow result stashes through the SAME context helper the dispatch
	// spine reads, proving credscope feeds the existing STAGE-0 contract.
	ctx := contextWithPeerScope(context.Background(), ps)
	got, present := peerScopeFromContext(ctx)
	if !present {
		t.Fatal("peerScopeFromContext returned ok=false after contextWithPeerScope")
	}
	if got.FilesystemID != fsid || !reflect.DeepEqual(got.GrantedIntents, want.GrantedIntents) {
		t.Errorf("round-tripped PeerScope = %+v, want fsid %q intents %v", got, fsid, want.GrantedIntents)
	}
}

// TestCredScopeForeignFsidDenies asserts a request whose top-level filesystem_id
// does NOT match the credential-bound scope is denied to the scope-mismatch
// class with a 403 / permission_denied wire verdict, and no PeerScope is
// returned. This is the route-layer mirror of the unix-transport STAGE-1b
// channel-scope cross-check.
func TestCredScopeForeignFsidDenies(t *testing.T) {
	const boundFsid = "tenant-eu-42"
	ext := &fakeExtractor{byToken: map[string]CredentialScope{
		"real-credential": {FilesystemID: boundFsid, GrantedIntents: []Intent{IntentRead}},
	}}

	r := credScopeRequest(bearerScheme + "real-credential")
	ps, v, ok := deriveCredScope(r, ext, "tenant-us-99")
	if ok {
		t.Fatalf("foreign fsid allowed: ps=%+v", ps)
	}
	if v.AuditReason != denyScopeMismatch {
		t.Errorf("audit reason = %q, want %q (scope_mismatch)", v.AuditReason, denyScopeMismatch)
	}
	if v.WireCode != wireCodePermissionDenied {
		t.Errorf("wire code = %q, want %q", v.WireCode, wireCodePermissionDenied)
	}
	if v.WireStatus != http.StatusForbidden {
		t.Errorf("wire status = %d, want 403", v.WireStatus)
	}
	if !reflect.DeepEqual(ps, PeerScope{}) {
		t.Errorf("a deny must return a zero PeerScope, got %+v", ps)
	}
}

// TestCredScopeMissingBearerUnauthenticated asserts that an absent, scheme-only,
// or empty-token Authorization header denies to the lease-expired /
// unauthenticated class with a 401 wire verdict — the broker cannot attribute
// the request to any scope, so it never reaches a handler.
func TestCredScopeMissingBearerUnauthenticated(t *testing.T) {
	// The extractor must never be consulted when the bearer is unusable.
	ext := &fakeExtractor{byToken: map[string]CredentialScope{
		"real-credential": {FilesystemID: "tenant-eu-42", GrantedIntents: []Intent{IntentRead}},
	}}

	cases := []struct {
		name       string
		authHeader string
	}{
		{"absent-header", ""},
		{"scheme-only-no-token", "Bearer"},
		{"scheme-and-space-no-token", "Bearer "},
		{"scheme-and-whitespace-token", "Bearer    "},
		{"wrong-scheme", "Basic real-credential"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ext.lastBearer = ""
			r := credScopeRequest(tc.authHeader)
			ps, v, ok := deriveCredScope(r, ext, "tenant-eu-42")
			if ok {
				t.Fatalf("missing/unusable bearer allowed: ps=%+v", ps)
			}
			if v.AuditReason != denyLeaseExpired {
				t.Errorf("audit reason = %q, want %q (lease_expired)", v.AuditReason, denyLeaseExpired)
			}
			if v.WireCode != wireCodeUnauthenticated {
				t.Errorf("wire code = %q, want %q", v.WireCode, wireCodeUnauthenticated)
			}
			if v.WireStatus != http.StatusUnauthorized {
				t.Errorf("wire status = %d, want 401", v.WireStatus)
			}
			if ext.lastBearer != "" {
				t.Errorf("extractor was consulted for an unusable bearer (saw %q)", ext.lastBearer)
			}
		})
	}
}

// TestCredScopeRejectedCredentialUnauthenticated asserts that a present, well-
// formed bearer the extractor cannot bind to a scope (an expired or
// authority-rejected credential) denies to the SAME unauthenticated 401 class as
// a missing bearer — the broker has no scope to enforce against.
func TestCredScopeRejectedCredentialUnauthenticated(t *testing.T) {
	t.Run("token-not-recognized", func(t *testing.T) {
		ext := &fakeExtractor{byToken: map[string]CredentialScope{}}
		r := credScopeRequest(bearerScheme + "unknown-credential")
		_, v, ok := deriveCredScope(r, ext, "tenant-eu-42")
		if ok {
			t.Fatal("unrecognized credential allowed")
		}
		if v.WireStatus != http.StatusUnauthorized || v.AuditReason != denyLeaseExpired {
			t.Errorf("verdict = %+v, want 401 / lease_expired", v)
		}
	})

	t.Run("extractor-error", func(t *testing.T) {
		ext := &fakeExtractor{err: errors.New("authority unreachable")}
		r := credScopeRequest(bearerScheme + "real-credential")
		_, v, ok := deriveCredScope(r, ext, "tenant-eu-42")
		if ok {
			t.Fatal("errored extraction allowed")
		}
		if v.WireStatus != http.StatusUnauthorized || v.AuditReason != denyLeaseExpired {
			t.Errorf("verdict = %+v, want 401 / lease_expired", v)
		}
	})

	t.Run("empty-bound-fsid-is-rejection", func(t *testing.T) {
		// A bound scope with an empty FilesystemID must never be treated as a
		// wildcard match; it is a rejection (401), even against an empty request
		// fsid.
		ext := newBearerScopeExtractor(func(string) (CredentialScope, error) {
			return CredentialScope{FilesystemID: "", GrantedIntents: []Intent{IntentRead}}, nil
		})
		r := credScopeRequest(bearerScheme + "real-credential")
		_, v, ok := deriveCredScope(r, ext, "")
		if ok {
			t.Fatal("empty-bound-fsid credential allowed (wildcard leak)")
		}
		if v.WireStatus != http.StatusUnauthorized || v.AuditReason != denyLeaseExpired {
			t.Errorf("verdict = %+v, want 401 / lease_expired", v)
		}
	})
}

// TestCredScopeExtractorSeamSwappable asserts the CredentialScopeExtractor seam
// is swappable: the default bearerScopeExtractor over an injected bind drives
// the SAME structural flow as a hand-rolled fake. Swapping the bind changes the
// derived scope without touching deriveCredScope — proving the exact extraction
// can bind later (PENDING-PHASE-7) while the flow is fixed now.
func TestCredScopeExtractorSeamSwappable(t *testing.T) {
	// Default extractor with a custom bind: a swapped-in production-shaped
	// extractor must work through deriveCredScope unchanged.
	bind := func(bearer string) (CredentialScope, error) {
		if bearer == "scope-a-credential" {
			return CredentialScope{FilesystemID: "scope-a", GrantedIntents: []Intent{IntentRead}}, nil
		}
		return CredentialScope{}, errCredentialRejected
	}
	ext := newBearerScopeExtractor(bind)

	r := credScopeRequest(bearerScheme + "scope-a-credential")
	ps, _, ok := deriveCredScope(r, ext, "scope-a")
	if !ok || ps.FilesystemID != "scope-a" {
		t.Fatalf("default extractor over a swapped bind failed: ps=%+v ok=%v", ps, ok)
	}

	// The interface is satisfied by both the default and the fake — both are
	// valid CredentialScopeExtractor values, the proof the seam is swappable.
	var _ CredentialScopeExtractor = ext
	var _ CredentialScopeExtractor = &fakeExtractor{}

	// A nil bind fails CLOSED: an unwired credential source rejects every
	// request rather than admitting an unscoped one.
	nilExt := newBearerScopeExtractor(nil)
	_, v, ok := deriveCredScope(credScopeRequest(bearerScheme+"anything"), nilExt, "scope-a")
	if ok {
		t.Fatal("nil-bind extractor admitted a request (must fail closed)")
	}
	if v.WireStatus != http.StatusUnauthorized {
		t.Errorf("nil-bind verdict = %d, want 401", v.WireStatus)
	}
}

// TestCredScopeNoJWKSDependency is a documentation guard: the credential-scope
// check derives a scope from the bearer WITHOUT verifying a signature. The
// extractor is consulted with the verbatim token and the flow never invokes a
// key-set lookup. A bind that simply echoes a bound scope — with no signature,
// issuer, audience, or alg check — produces a valid allow, proving the layer is
// JWKS-free by construction.
func TestCredScopeNoJWKSDependency(t *testing.T) {
	bind := func(bearer string) (CredentialScope, error) {
		// No signature verification, no issuer/audience/alg: the bound scope is
		// derived from the authority-injected credential directly.
		return CredentialScope{FilesystemID: "scope-x", GrantedIntents: []Intent{IntentRead}}, nil
	}
	ext := newBearerScopeExtractor(bind)
	ps, _, ok := deriveCredScope(credScopeRequest(bearerScheme+"opaque-injected-credential"), ext, "scope-x")
	if !ok || ps.FilesystemID != "scope-x" {
		t.Fatalf("JWKS-free allow path failed: ps=%+v ok=%v", ps, ok)
	}
}
