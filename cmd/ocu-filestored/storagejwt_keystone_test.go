// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// This file is the storage-credential-custody keystone: it proves the shipped
// filestore reads the weak Storage-JWT filesystem_id/intent claims WITHOUT
// verifying the signature (the live hole, ADR-0013/0019/0025 "impossible by
// construction" is UNENFORCED), then proves the JWKS-verifying extractor closes
// it: a forged/unsigned bearer is denied (401), a foreign filesystem_id is a
// scope deny, and a missing/expired signature is denied (401). It exercises the
// PRODUCTION credential-scope extractor the daemon wires (newCredentialScopeExtractor),
// never a test fake  -  the bind under test is exactly the shipped code path.

// keystoneVictimFSID is the scope a forged bearer names to steer the engine at a
// victim's prefix. It is NOT the daemon's configured -filesystem-id.
const keystoneVictimFSID = "victim-fsid"

// keystoneConfiguredFSID is the daemon's own -filesystem-id: the single scope the
// verified path is entitled to serve.
const keystoneConfiguredFSID = "own-fsid"

const keystoneIssuer = "https://control.ocu.test/storage"
const keystoneAudience = "ocu-filestore"

// forgeUnsignedBearer builds a JWT-SHAPED token with a valid header and a caller-
// chosen payload, signed with the "none" alg (an empty signature segment). No
// private key is involved: this is the exact shape an attacker forges to inject
// scope claims when the reader never verifies a signature.
func forgeUnsignedBearer(t *testing.T, fsid, intent string) string {
	t.Helper()
	header := map[string]any{"alg": "none", "typ": "JWT"}
	// The nested authz.intent mirrors the Control mint shape; the forged payload
	// also carries a top-level intent so the hole is proven against either read.
	payload := map[string]any{
		"iss":           keystoneIssuer,
		"aud":           keystoneAudience,
		"filesystem_id": fsid,
		"intent":        intent,
		"authz":         map[string]any{"intent": intent},
		"exp":           time.Now().Add(time.Hour).Unix(),
	}
	return b64seg(t, header) + "." + b64seg(t, payload) + "."
}

func b64seg(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal segment: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// keystoneSigner is an Ed25519 keypair plus the JWKS document that publishes its
// public half  -  the same {kty,crv,kid,use,alg,x} shape Control renders at
// -jwks-path and mounts read-only into filestore at -storage-jwks-path.
type keystoneSigner struct {
	priv ed25519.PrivateKey
	kid  string
	jwks []byte
}

func newKeystoneSigner(t *testing.T) keystoneSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kid := "keystone-kid-1"
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"kid": kid,
		"use": "sig",
		"alg": "EdDSA",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
	set := map[string]any{"keys": []any{jwk}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return keystoneSigner{priv: priv, kid: kid, jwks: raw}
}

// mint signs a well-formed Storage-JWT with the keystone signer's private key and
// kid, so a JWKS-verifying reader accepts it. exp is caller-chosen so the expired
// case is exercised with the SAME signing key (a valid signature, dead exp).
func (s keystoneSigner) mint(t *testing.T, fsid, intent string, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":           keystoneIssuer,
		"aud":           keystoneAudience,
		"filesystem_id": fsid,
		"intent":        intent,
		"authz":         map[string]any{"intent": intent},
		"exp":           exp.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = s.kid
	compact, err := tok.SignedString(s.priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return compact
}

// keystoneConfig builds the daemon config the extractor reads. verify toggles the
// new -verify-storage-jwt posture; jwks/issuer/audience feed the verifier.
func keystoneConfig(verify bool, jwks []byte) brokerConfig {
	return brokerConfig{
		filesystemID:       keystoneConfiguredFSID,
		grantedIntents:     []southface.Intent{southface.IntentRead, southface.IntentWrite},
		claimsBind:         true,
		verifyStorageJWT:   verify,
		storageJWKS:        jwks,
		storageJWTIssuer:   keystoneIssuer,
		storageJWTAudience: keystoneAudience,
	}
}

// TestStorageJWTKeystone_HoleLive is the RED probe: it proves TODAY's shipped
// claims-bind path (verify OFF) binds a forged UNSIGNED bearer's scope claims
// with NO signature check. A forged payload naming a victim filesystem_id is
// accepted verbatim  -  the attacker steers the credential-bound scope (and thus
// the engine prefix) to a scope it never proved title to. This test PASSES on the
// unfixed binary; after the fix the verified path (the other keystone) reds the
// same forged token.
func TestStorageJWTKeystone_HoleLive(t *testing.T) {
	ext := newCredentialScopeExtractor(keystoneConfig(false, nil))
	forged := forgeUnsignedBearer(t, keystoneVictimFSID, "write")

	scope, err := ext.Extract(forged)
	if err != nil {
		t.Fatalf("HOLE-LIVE probe: unfixed shipped path rejected a forged bearer (err=%v); "+
			"the hole is expected LIVE here  -  a signature check must NOT yet exist", err)
	}
	if scope.FilesystemID != keystoneVictimFSID {
		t.Fatalf("HOLE-LIVE probe: expected the forged victim fsid %q to be trusted verbatim, got %q",
			keystoneVictimFSID, scope.FilesystemID)
	}
	if len(scope.GrantedIntents) != 1 || scope.GrantedIntents[0] != southface.IntentWrite {
		t.Fatalf("HOLE-LIVE probe: expected the forged write intent trusted verbatim, got %v", scope.GrantedIntents)
	}
	t.Logf("HOLE LIVE: unsigned forged bearer accepted verbatim -> scope %q intents %v (no signature verified)",
		scope.FilesystemID, scope.GrantedIntents)
}

// TestStorageJWTKeystone_ForgedDenied is the GREEN probe: with verification ON, a
// forged UNSIGNED bearer (alg=none, no signature) is REJECTED  -  the extractor
// binds no scope, so the request is unauthenticated (401). This is the acceptance
// the fix must red.
func TestStorageJWTKeystone_ForgedDenied(t *testing.T) {
	signer := newKeystoneSigner(t)
	ext := newCredentialScopeExtractor(keystoneConfig(true, signer.jwks))
	forged := forgeUnsignedBearer(t, keystoneVictimFSID, "write")

	scope, err := ext.Extract(forged)
	if err == nil {
		t.Fatalf("GREEN probe FAILED: verified path accepted a forged unsigned bearer -> scope %q (the hole is still live)",
			scope.FilesystemID)
	}
	t.Logf("FIXED: forged unsigned bearer denied (err=%v)", err)
}

// TestStorageJWTKeystone_SignedAccepted proves the verified path still ADMITS a
// genuinely-signed token for the daemon's own configured scope: the fix denies
// forgeries WITHOUT breaking the legitimate credential.
func TestStorageJWTKeystone_SignedAccepted(t *testing.T) {
	signer := newKeystoneSigner(t)
	ext := newCredentialScopeExtractor(keystoneConfig(true, signer.jwks))
	good := signer.mint(t, keystoneConfiguredFSID, "write", time.Now().Add(time.Hour))

	scope, err := ext.Extract(good)
	if err != nil {
		t.Fatalf("verified path rejected a genuinely-signed bearer: %v", err)
	}
	if scope.FilesystemID != keystoneConfiguredFSID {
		t.Fatalf("verified scope = %q, want the signed fsid %q", scope.FilesystemID, keystoneConfiguredFSID)
	}
	if len(scope.GrantedIntents) != 1 || scope.GrantedIntents[0] != southface.IntentWrite {
		t.Fatalf("verified intents = %v, want [write] from the signed authz.intent claim", scope.GrantedIntents)
	}
}

// TestStorageJWTKeystone_ForeignFSIDEngineScope proves the engine independently
// confines a request to the daemon's provisioned scope: a verb naming a FOREIGN
// filesystem_id (even one a trusted signer named) is refused AT THE ENGINE with
// ErrForeignScope. The refusal originates in the engine's own scope guard, not
// only the body-vs-claim cross-check, so a token minted for another tenant cannot
// steer this engine's backend prefix. The confined engine wraps the SAME Engine
// interface the daemon composes at -filesystem-id.
func TestStorageJWTKeystone_ForeignFSIDEngineScope(t *testing.T) {
	inner := objectstore.NewLocalVolumeEngine(t.TempDir())
	eng, err := objectstore.NewScopeConfinedEngine(inner, objectstore.ScopeID(keystoneConfiguredFSID))
	if err != nil {
		t.Fatalf("build scope-confined engine: %v", err)
	}
	ctx := context.Background()

	// A verb for the engine's OWN provisioned scope is served.
	if err := eng.ProvisionScope(ctx, objectstore.ScopeID(keystoneConfiguredFSID)); err != nil {
		t.Fatalf("engine refused its own provisioned scope %q: %v", keystoneConfiguredFSID, err)
	}
	// A foreign scope is refused AT THE ENGINE with ErrForeignScope, on BOTH a
	// lifecycle verb and a data verb (the confinement is total, not per-verb).
	if err := eng.ProvisionScope(ctx, objectstore.ScopeID(keystoneVictimFSID)); !errors.Is(err, objectstore.ErrForeignScope) {
		t.Fatalf("ENGINE SCOPE HOLE: ProvisionScope(%q) = %v, want ErrForeignScope", keystoneVictimFSID, err)
	}
	if _, err := eng.List(ctx, objectstore.ScopeID(keystoneVictimFSID), "."); !errors.Is(err, objectstore.ErrForeignScope) {
		t.Fatalf("ENGINE SCOPE HOLE: List under %q = %v, want ErrForeignScope", keystoneVictimFSID, err)
	}
	t.Logf("engine confined foreign scope %q -> ErrForeignScope (403 at the engine)", keystoneVictimFSID)
}

// TestStorageJWTKeystone_ExpiredDenied proves an expired-but-validly-signed token
// is denied (401): the exp check fails the parse, so no scope is bound.
func TestStorageJWTKeystone_ExpiredDenied(t *testing.T) {
	signer := newKeystoneSigner(t)
	ext := newCredentialScopeExtractor(keystoneConfig(true, signer.jwks))
	expired := signer.mint(t, keystoneConfiguredFSID, "write", time.Now().Add(-time.Hour))

	if _, err := ext.Extract(expired); err == nil {
		t.Fatalf("verified path accepted an EXPIRED signed bearer (missing/expired must be 401)")
	}
}

// TestStorageJWTKeystone_AlgConfusionDenied proves alg-pinning: a token signed
// with an HMAC key whose bytes are the published Ed25519 public key (the classic
// RS/HS confusion analogue) is refused because the verifier pins the kid's
// registered alg and rejects any other method.
func TestStorageJWTKeystone_AlgConfusionDenied(t *testing.T) {
	signer := newKeystoneSigner(t)
	ext := newCredentialScopeExtractor(keystoneConfig(true, signer.jwks))

	pub := signer.priv.Public().(ed25519.PublicKey)
	claims := jwt.MapClaims{
		"iss":           keystoneIssuer,
		"aud":           keystoneAudience,
		"filesystem_id": keystoneConfiguredFSID,
		"authz":         map[string]any{"intent": "write"},
		"exp":           time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = signer.kid
	compact, err := tok.SignedString([]byte(pub))
	if err != nil {
		t.Fatalf("mint alg-confusion token: %v", err)
	}
	if _, err := ext.Extract(compact); err == nil {
		t.Fatalf("verified path accepted an alg-confused (HS256-over-EdDSA-pubkey) token")
	}
}
