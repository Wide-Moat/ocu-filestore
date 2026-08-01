// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// StorageJWTVerifier closes the storage-credential-custody hole: it JWKS-verifies
// the weak Storage-JWT's signature before any filesystem_id/intent claim is
// trusted (ADR-0013/0019/0025). It holds ONLY the published public keys read from
// Control's rendered JWKS artifact (the same document Control writes at its
// -jwks-path); it holds no private material, mints nothing, and speaks no network
// protocol. The verification MIRRORS the Control-side stand-in verifier: kid
// match, per-kid alg pin (EdDSA/ES256, never "none"), signature, iss/aud, and a
// required exp against an injected clock.
//
// The bound scope comes ONLY from the VERIFIED claims: an unsigned or
// signature-invalid token binds no scope (errCredentialRejected -> 401), so a
// forged claim can no longer steer the engine prefix.
type StorageJWTVerifier struct {
	// keys maps a published key's kid to its reconstructed public key.
	keys map[string]verifierKey
	// issuer/audience are the iss/aud filestore requires; both must be non-empty
	// (the constructor rejects an empty value) so the verifier never accepts a
	// token whose iss/aud is unconstrained.
	issuer   string
	audience string
	// now supplies the instant exp is honored against; a nil now falls back to
	// the real wall clock. Tests inject a fixed clock so the expired case is
	// deterministic.
	now func() time.Time
}

// verifierKey is one published key: the reconstructed crypto public key plus the
// alg the JWK registered it under, so the keyFunc can PIN the token's header alg
// to the key's declared alg (reject alg-confusion and "none").
type verifierKey struct {
	pub publicKey
	alg string
}

// publicKey is the union of the public key types the verifier reconstructs from a
// JWK (ed25519.PublicKey or *ecdsa.PublicKey). It is an alias for any so the
// keyFunc can hand the concrete key to golang-jwt.
type publicKey = any

// storageJWK is one key in Control's rendered JWKS document. The member set
// mirrors the artifact Control writes: kty/crv/kid/use/alg and the unpadded
// base64url coordinates (y is EC-only).
type storageJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// storageJWKSet is the JWKS document shape ({"keys":[...]}) Control renders.
type storageJWKSet struct {
	Keys []storageJWK `json:"keys"`
}

// errEmptyStorageJWKS is the fail-closed construction error for an empty or
// key-less JWKS document: a verifier with no keys would reject every token, which
// would mask a misconfigured JWKS mount. Boot aborts rather than serve a verifier
// that can never admit a legitimate credential.
var errEmptyStorageJWKS = errors.New("southface: storage JWKS document has no keys")

// NewStorageJWTVerifier parses Control's rendered JWKS document and builds a
// verifier over its public keys. issuer/audience are the iss/aud filestore
// requires (both must be non-empty). now injects the exp clock; nil selects the
// wall clock. It is FAIL-CLOSED: an empty/garbage JWKS, a key-less set, an empty
// issuer/audience, or an unrenderable key is a construction error, so a
// misconfigured deployment aborts at boot rather than serving an
// always-reject or always-accept verifier.
func NewStorageJWTVerifier(jwksJSON []byte, issuer, audience string, now func() time.Time) (*StorageJWTVerifier, error) {
	if issuer == "" {
		return nil, fmt.Errorf("southface: storage JWT issuer is required")
	}
	if audience == "" {
		return nil, fmt.Errorf("southface: storage JWT audience is required")
	}
	var set storageJWKSet
	if err := json.Unmarshal(jwksJSON, &set); err != nil {
		return nil, fmt.Errorf("southface: parse storage JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errEmptyStorageJWKS
	}
	keys := make(map[string]verifierKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Kid == "" {
			return nil, fmt.Errorf("southface: storage JWKS key has no kid")
		}
		pub, alg, err := publicKeyFromStorageJWK(jwk)
		if err != nil {
			return nil, err
		}
		keys[jwk.Kid] = verifierKey{pub: pub, alg: alg}
	}
	return &StorageJWTVerifier{
		keys:     keys,
		issuer:   issuer,
		audience: audience,
		now:      now,
	}, nil
}

// errNoMatchingStorageKID is the internal sentinel the keyFunc returns when a
// token's kid names no published key (a forged kid, or a key rotated fully out).
var errNoMatchingStorageKID = errors.New("southface: no storage JWKS key for token kid")

// errAlgMismatch is the internal sentinel the keyFunc returns when a token's
// header alg is not the alg the matching kid was published under (alg-confusion,
// or a downgrade to "none").
var errAlgMismatch = errors.New("southface: token alg does not match the published key alg")

// VerifyScope verifies the weak Storage-JWT and binds the credential scope from
// the VERIFIED claims only. It parses with golang-jwt pinned to EdDSA/ES256,
// requires a matching kid + signature, honors iss/aud, and requires exp against
// the injected clock. On ANY parse/verify failure it returns errCredentialRejected
// (mapped to 401). On success it binds FilesystemID from the verified top-level
// filesystem_id claim (an empty value is a rejection, never a wildcard) and one
// GrantedIntent from the verified authz.intent claim via intentVocabulary.
func (v *StorageJWTVerifier) VerifyScope(bearer string) (CredentialScope, error) {
	timeFunc := time.Now
	if v.now != nil {
		timeFunc = v.now
	}
	parsed, err := jwt.Parse(
		bearer,
		v.keyFunc,
		jwt.WithValidMethods([]string{"EdDSA", "ES256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(timeFunc),
	)
	if err != nil {
		return CredentialScope{}, errCredentialRejected
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return CredentialScope{}, errCredentialRejected
	}
	fsid, _ := claims["filesystem_id"].(string)
	if fsid == "" {
		// A verified token that names no filesystem_id binds no scope: a rejection,
		// never a wildcard (component-04 invariant  -  an empty scope is a deny).
		return CredentialScope{}, errCredentialRejected
	}
	scope := CredentialScope{FilesystemID: fsid}
	if intent, ok := verifiedIntent(claims); ok {
		scope.GrantedIntents = []Intent{intent}
	}
	return scope, nil
}

// verifiedIntent reads the single intent grant from the VERIFIED claims. The
// Control mint carries the intent at authz.intent (nested); a deployment that
// mints a top-level intent is tolerated as a fallback. An unknown or absent token
// yields ok=false (no grant), which the resolver denies regardless of fsid.
func verifiedIntent(claims jwt.MapClaims) (Intent, bool) {
	if authz, ok := claims["authz"].(map[string]any); ok {
		if s, ok := authz["intent"].(string); ok {
			if intent, ok := intentVocabulary[s]; ok {
				return intent, true
			}
		}
	}
	if s, ok := claims["intent"].(string); ok {
		if intent, ok := intentVocabulary[s]; ok {
			return intent, true
		}
	}
	return "", false
}

// intentVocabulary maps the frozen wire intent tokens to the southface intent
// values, so the verifier binds the same read/write/preview vocabulary the
// daemon's -granted-intents ceiling parses.
var intentVocabulary = map[string]Intent{
	"read":    IntentRead,
	"write":   IntentWrite,
	"preview": IntentPreview,
}

// keyFunc selects the verification key for a parsed token from its kid header and
// PINS the token's header alg to the alg the matching kid was published under. A
// missing/unknown kid is errNoMatchingStorageKID; a header alg that disagrees
// with the published key's alg (alg-confusion, or "none") is errAlgMismatch.
// Both fail the parse closed  -  no partial key is ever returned.
func (v *StorageJWTVerifier) keyFunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, errNoMatchingStorageKID
	}
	vk, ok := v.keys[kid]
	if !ok {
		return nil, errNoMatchingStorageKID
	}
	alg, _ := token.Header["alg"].(string)
	if alg != vk.alg {
		return nil, errAlgMismatch
	}
	return vk.pub, nil
}

// publicKeyFromStorageJWK reconstructs the crypto public key from a published JWK
// and returns it with the alg the key is registered under. It mirrors the
// Control-side reconstruction: EdDSA/OKP-Ed25519 and ES256/EC-P-256, on-curve
// validated via crypto/ecdh so a forged coordinate can never reconstruct a key
// the parser would trust. An unsupported kty/crv is a hard error (fail-closed).
func publicKeyFromStorageJWK(jwk storageJWK) (publicKey, string, error) {
	switch {
	case jwk.Kty == "OKP" && jwk.Crv == "Ed25519" && jwk.Alg == "EdDSA":
		raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, "", fmt.Errorf("southface: decode OKP x: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("southface: OKP x is not an ed25519 public key")
		}
		return ed25519.PublicKey(raw), "EdDSA", nil
	case jwk.Kty == "EC" && jwk.Crv == "P-256" && jwk.Alg == "ES256":
		xRaw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, "", fmt.Errorf("southface: decode EC x: %w", err)
		}
		yRaw, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, "", fmt.Errorf("southface: decode EC y: %w", err)
		}
		pub, err := p256PublicKeyFromCoords(xRaw, yRaw)
		if err != nil {
			return nil, "", err
		}
		return pub, "ES256", nil
	default:
		return nil, "", fmt.Errorf("southface: unsupported storage JWK kty %q crv %q alg %q", jwk.Kty, jwk.Crv, jwk.Alg)
	}
}

// p256CoordLen is the octet length of a P-256 coordinate.
const p256CoordLen = 32

// p256PublicKeyFromCoords reconstructs and on-curve-validates a P-256 public key
// from raw x/y coordinates via the non-deprecated crypto/ecdh path (NewPublicKey
// rejects an off-curve point and the point at infinity), then builds the
// *ecdsa.PublicKey golang-jwt's ES256 method verifies against.
func p256PublicKeyFromCoords(x, y []byte) (publicKey, error) {
	if len(x) != p256CoordLen || len(y) != p256CoordLen {
		return nil, fmt.Errorf("southface: EC coordinate is not %d octets", p256CoordLen)
	}
	sec1 := make([]byte, 0, 1+2*p256CoordLen)
	sec1 = append(sec1, 0x04)
	sec1 = append(sec1, x...)
	sec1 = append(sec1, y...)
	if _, err := ecdh.P256().NewPublicKey(sec1); err != nil {
		return nil, fmt.Errorf("southface: EC point is not on P-256: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}
