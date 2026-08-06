// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const vtIssuer = "https://control.ocu.test/storage"
const vtAudience = "ocu-filestore"

// edSigner is an Ed25519 keypair plus the single-key JWKS document publishing its
// public half, matching Control's rendered artifact shape.
type edSigner struct {
	priv ed25519.PrivateKey
	kid  string
	jwks []byte
}

func newEdSigner(t *testing.T, kid string) edSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk := map[string]any{
		"kty": "OKP", "crv": "Ed25519", "kid": kid, "use": "sig", "alg": "EdDSA",
		"x": base64.RawURLEncoding.EncodeToString(pub),
	}
	raw, err := json.Marshal(map[string]any{"keys": []any{jwk}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return edSigner{priv: priv, kid: kid, jwks: raw}
}

func (s edSigner) mint(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = s.kid
	compact, err := tok.SignedString(s.priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return compact
}

func fixedNow(sec int64) func() time.Time {
	return func() time.Time { return time.Unix(sec, 0) }
}

func baseClaims(fsid, intent string, exp int64) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":           vtIssuer,
		"aud":           vtAudience,
		"filesystem_id": fsid,
		"authz":         map[string]any{"intent": intent},
		"exp":           exp,
	}
}

func TestStorageJWTVerifier_AcceptsSigned(t *testing.T) {
	s := newEdSigner(t, "k1")
	v, err := NewStorageJWTVerifier(s.jwks, vtIssuer, vtAudience, fixedNow(1000))
	if err != nil {
		t.Fatalf("NewStorageJWTVerifier: %v", err)
	}
	tok := s.mint(t, baseClaims("fs-a", "write", 2000))
	scope, err := v.VerifyScope(tok)
	if err != nil {
		t.Fatalf("VerifyScope rejected a valid token: %v", err)
	}
	if scope.FilesystemID != "fs-a" {
		t.Fatalf("FilesystemID = %q, want fs-a", scope.FilesystemID)
	}
	if len(scope.GrantedIntents) != 1 || scope.GrantedIntents[0] != IntentWrite {
		t.Fatalf("GrantedIntents = %v, want [write]", scope.GrantedIntents)
	}
}

func TestStorageJWTVerifier_RejectsUnsignedNone(t *testing.T) {
	s := newEdSigner(t, "k1")
	v, _ := NewStorageJWTVerifier(s.jwks, vtIssuer, vtAudience, fixedNow(1000))
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1","typ":"JWT"}`))
	pj, _ := json.Marshal(baseClaims("fs-a", "write", 2000))
	forged := hdr + "." + base64.RawURLEncoding.EncodeToString(pj) + "."
	if _, err := v.VerifyScope(forged); err == nil {
		t.Fatalf("VerifyScope accepted an alg=none token")
	}
}

func TestStorageJWTVerifier_RejectsWrongKID(t *testing.T) {
	s := newEdSigner(t, "k1")
	v, _ := NewStorageJWTVerifier(s.jwks, vtIssuer, vtAudience, fixedNow(1000))
	// Mint with a kid that is not published.
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, baseClaims("fs-a", "write", 2000))
	tok.Header["kid"] = "unknown-kid"
	compact, err := tok.SignedString(s.priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	if _, err := v.VerifyScope(compact); err == nil {
		t.Fatalf("VerifyScope accepted a token whose kid is not published")
	}
}

func TestStorageJWTVerifier_RejectsForeignSigner(t *testing.T) {
	published := newEdSigner(t, "k1")
	v, _ := NewStorageJWTVerifier(published.jwks, vtIssuer, vtAudience, fixedNow(1000))
	// A DIFFERENT private key under the SAME published kid: the signature can not verify.
	attacker := newEdSigner(t, "k1")
	tok := attacker.mint(t, baseClaims("fs-a", "write", 2000))
	if _, err := v.VerifyScope(tok); err == nil {
		t.Fatalf("VerifyScope accepted a token signed by an unpublished key")
	}
}

func TestStorageJWTVerifier_RejectsWrongIssuerAudience(t *testing.T) {
	s := newEdSigner(t, "k1")
	v, _ := NewStorageJWTVerifier(s.jwks, vtIssuer, vtAudience, fixedNow(1000))

	wrongIss := s.mint(t, jwt.MapClaims{"iss": "https://evil", "aud": vtAudience, "filesystem_id": "fs-a", "authz": map[string]any{"intent": "read"}, "exp": int64(2000)})
	if _, err := v.VerifyScope(wrongIss); err == nil {
		t.Fatalf("VerifyScope accepted a token with a foreign iss")
	}
	wrongAud := s.mint(t, jwt.MapClaims{"iss": vtIssuer, "aud": "someone-else", "filesystem_id": "fs-a", "authz": map[string]any{"intent": "read"}, "exp": int64(2000)})
	if _, err := v.VerifyScope(wrongAud); err == nil {
		t.Fatalf("VerifyScope accepted a token with a foreign aud")
	}
}

func TestStorageJWTVerifier_RejectsExpiredAndMissingExp(t *testing.T) {
	s := newEdSigner(t, "k1")
	v, _ := NewStorageJWTVerifier(s.jwks, vtIssuer, vtAudience, fixedNow(3000))
	expired := s.mint(t, baseClaims("fs-a", "write", 2000)) // exp 2000 < now 3000
	if _, err := v.VerifyScope(expired); err == nil {
		t.Fatalf("VerifyScope accepted an expired token")
	}
	noExp := s.mint(t, jwt.MapClaims{"iss": vtIssuer, "aud": vtAudience, "filesystem_id": "fs-a", "authz": map[string]any{"intent": "read"}})
	if _, err := v.VerifyScope(noExp); err == nil {
		t.Fatalf("VerifyScope accepted a token with no exp")
	}
}

func TestStorageJWTVerifier_RejectsEmptyFilesystemID(t *testing.T) {
	s := newEdSigner(t, "k1")
	v, _ := NewStorageJWTVerifier(s.jwks, vtIssuer, vtAudience, fixedNow(1000))
	tok := s.mint(t, baseClaims("", "write", 2000))
	if _, err := v.VerifyScope(tok); err == nil {
		t.Fatalf("VerifyScope accepted a verified token with an empty filesystem_id (must never wildcard)")
	}
}

func TestStorageJWTVerifier_FailClosedConstruction(t *testing.T) {
	s := newEdSigner(t, "k1")
	if _, err := NewStorageJWTVerifier([]byte(`{"keys":[]}`), vtIssuer, vtAudience, nil); err == nil {
		t.Fatalf("construction accepted an empty key set (must fail closed)")
	}
	if _, err := NewStorageJWTVerifier([]byte(`{bad json`), vtIssuer, vtAudience, nil); err == nil {
		t.Fatalf("construction accepted garbage JWKS")
	}
	if _, err := NewStorageJWTVerifier(s.jwks, "", vtAudience, nil); err == nil {
		t.Fatalf("construction accepted an empty issuer")
	}
	if _, err := NewStorageJWTVerifier(s.jwks, vtIssuer, "", nil); err == nil {
		t.Fatalf("construction accepted an empty audience")
	}
}

func TestStorageJWTVerifier_ES256Supported(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// SEC1 uncompressed point: 0x04 || X || Y, each coordinate a fixed-width
	// 32-octet half for P-256 — exactly the base64url payload the JWK wants.
	raw, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes: %v", err)
	}
	xb, yb := raw[1:33], raw[33:65]
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256", "kid": "ec1", "use": "sig", "alg": "ES256",
		"x": base64.RawURLEncoding.EncodeToString(xb),
		"y": base64.RawURLEncoding.EncodeToString(yb),
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	v, err := NewStorageJWTVerifier(jwks, vtIssuer, vtAudience, fixedNow(1000))
	if err != nil {
		t.Fatalf("NewStorageJWTVerifier(ES256): %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, baseClaims("fs-ec", "read", 2000))
	tok.Header["kid"] = "ec1"
	compact, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString ES256: %v", err)
	}
	scope, err := v.VerifyScope(compact)
	if err != nil {
		t.Fatalf("VerifyScope rejected a valid ES256 token: %v", err)
	}
	if scope.FilesystemID != "fs-ec" || len(scope.GrantedIntents) != 1 || scope.GrantedIntents[0] != IntentRead {
		t.Fatalf("ES256 scope = %+v, want fs-ec/read", scope)
	}
}

// TestStorageJWTVerifier_RejectsAlgConfusion pins the PER-KID alg check, which is
// the only thing standing between a published key and a token signed under a
// different algorithm. WithValidMethods admits BOTH EdDSA and ES256 for the
// verifier as a whole, so it cannot tell that THIS kid was published as EdDSA
// only: without the keyFunc's `alg != vk.alg` pin, an ES256-signed token naming
// an EdDSA kid reaches the signature check and is rejected only incidentally, by
// the key type mismatch inside golang-jwt.
//
// Non-vacuous: the two arms below assert the REASON, not just the refusal.
// keyFunc is called directly so the returned sentinel is observable —
// VerifyScope collapses every failure to errCredentialRejected, which is what
// let the deleted pin stay green across the whole suite. Deleting the pin makes
// both arms red.
func TestStorageJWTVerifier_RejectsAlgConfusion(t *testing.T) {
	ed := newEdSigner(t, "k1")
	v, err := NewStorageJWTVerifier(ed.jwks, vtIssuer, vtAudience, fixedNow(1000))
	if err != nil {
		t.Fatalf("NewStorageJWTVerifier: %v", err)
	}

	// An ES256 header naming the EdDSA-published kid: the alg the token declares
	// is not the alg the kid was published under.
	esToken := jwt.NewWithClaims(jwt.SigningMethodES256, baseClaims("fs-a", "write", 2000))
	esToken.Header["kid"] = ed.kid
	if _, err := v.keyFunc(esToken); !errors.Is(err, errAlgMismatch) {
		t.Fatalf("keyFunc(ES256 header on an EdDSA kid) error = %v, want errAlgMismatch", err)
	}

	// The same pin is what makes "none" unreachable at the key level, independent
	// of WithValidMethods: no published key is registered under alg "none".
	noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims("fs-a", "write", 2000))
	noneToken.Header["kid"] = ed.kid
	if _, err := v.keyFunc(noneToken); !errors.Is(err, errAlgMismatch) {
		t.Fatalf("keyFunc(alg=none on an EdDSA kid) error = %v, want errAlgMismatch", err)
	}

	// End to end, the same token is refused with the 401-mapped sentinel.
	esCompact := esToken.Raw
	if esCompact == "" {
		// Not yet serialized: sign with an unrelated P-256 key so the compact form
		// exists. The signature is irrelevant — the alg pin fires before it.
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		esCompact, err = esToken.SignedString(priv)
		if err != nil {
			t.Fatalf("SignedString ES256: %v", err)
		}
	}
	if _, err := v.VerifyScope(esCompact); !errors.Is(err, errCredentialRejected) {
		t.Fatalf("VerifyScope(alg-confused token) error = %v, want errCredentialRejected", err)
	}
}
