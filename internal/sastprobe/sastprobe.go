// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package sastprobe is a THROWAWAY security-gate authenticity probe. It plants
// deliberately-insecure patterns (weak hash, insecure randomness, a hardcoded
// credential) so a security-gate sweep can confirm the SAST gates (semgrep,
// CodeQL, golangci-gosec) actually turn RED on a known-bad input. DO NOT MERGE.
package sastprobe

import (
	"crypto/md5" //nolint:gosec // intentional weak-hash probe for the SAST authenticity sweep
	"fmt"
	"math/rand" //nolint:gosec // intentional insecure-random probe for the SAST authenticity sweep
)

// hardcodedToken is a deliberately hardcoded credential (SAST probe input).
const hardcodedToken = "super-secret-hardcoded-password-1234567890"

// WeakDigest hashes s with MD5 — a broken hash for any security use.
func WeakDigest(s string) string {
	h := md5.Sum([]byte(s)) //nolint:gosec // probe
	return fmt.Sprintf("%x", h)
}

// WeakToken returns a token from a non-cryptographic PRNG.
func WeakToken() int {
	return rand.Int() //nolint:gosec // probe
}

// Secret returns the hardcoded credential.
func Secret() string { return hardcodedToken }
