// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ADR-0042 flips credential verification to ON by default. A verifier behind a
// default-off flag is a fail-open system wearing fail-closed code: the engine
// looks correct from the inside while a deployment that says nothing enforces
// nothing, which is how roadmap B1 happened.
//
// These pin the DEFAULT and the shape of the opt-out — properties of the
// configuration surface, not of the verifier, and unreachable from a test that
// only drives the verifier.

// minimalArgs is a config that satisfies every OTHER required flag, so a
// failure below is attributable to the credential posture and nothing else.
func minimalArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	root := shortDir(t)
	certFile, keyFile := testTLSCertPaths(t)
	return append([]string{
		"--engine-root", filepath.Join(root, "engine"),
		"--audit-sink", filepath.Join(root, "audit", "audit.jsonl"),
		"--filesystem-id", "fs1",
		"--broker-max-file-size", "1024",
		"--south-bind", freeLoopbackAddr(t),
		"--tls-cert", certFile,
		"--tls-key", keyFile,
	}, extra...)
}

// TestBootFailsWhenVerificationHasNoAnchor is the fail-closed consequence of the
// flip. With verification on by default and no JWKS supplied, the daemon refuses
// to start rather than starting unverified.
//
// This is also what proves the default: a build that quietly left verification
// off would START here, because every other required flag is present.
func TestBootFailsWhenVerificationHasNoAnchor(t *testing.T) {
	// run() blocks in serveUntilSignal once boot succeeds, so a regression here
	// HANGS rather than failing. Bound it: the assertion is that boot refuses, and
	// a daemon that got as far as serving has already answered the question.
	done := make(chan error, 1)
	go func() { done <- run(minimalArgs(t)) }()

	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon did not refuse within 10s — it reached serveUntilSignal, " +
			"so it booted with no credential anchor and verification is off or skipped")
	}
	if err == nil {
		t.Fatal("the daemon started with no credential anchor; verification is either " +
			"off by default or silently skipped, and a deployment that says nothing " +
			"would enforce nothing")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("the refusal does not name the credential posture: %v", err)
	}
}

// TestInsecureOptOutIsNamedForItsDanger pins the opt-out's SHAPE. ADR-0042
// requires the unverified posture to appear in the process argv as something a
// reader recognises: a boolean set to false reads as nothing to a drift gate, a
// reviewer, or a container inspection.
func TestInsecureOptOutIsNamedForItsDanger(t *testing.T) {
	// Bounded for the same reason as the boot test: with the opt-out accepted the
	// daemon SERVES, so a working flag blocks and a broken one returns an error.
	// A plain call would hang on success, which is the opposite of a useful test.
	done := make(chan error, 1)
	go func() { done <- run(minimalArgs(t, "--insecure-static-scope-bind")) }()

	select {
	case err := <-done:
		if err != nil && strings.Contains(err.Error(), "credential") {
			t.Fatalf("the insecure opt-out did not satisfy the credential posture: %v — "+
				"the flag reads as an escape hatch but leaves the daemon refusing", err)
		}
	case <-time.After(5 * time.Second):
		// Still serving: the opt-out was accepted, which is the property under test.
	}
}

// TestVerificationAndInsecureOptOutConflict refuses a config asking for both.
// Silently preferring one leaves an operator believing the other took effect,
// and which one they believe decides whether the deployment is safe.
func TestVerificationAndInsecureOptOutConflict(t *testing.T) {
	err := run(minimalArgs(t,
		"--credential-jwks-path", "/dev/null",
		"--credential-issuer", "https://issuer.example",
		"--credential-audience", "filestore",
		"--insecure-static-scope-bind",
	))
	if err == nil {
		t.Fatal("a config asking for verification AND the insecure bind was accepted; " +
			"an operator cannot tell which posture the deployment runs")
	}
	if !strings.Contains(err.Error(), "insecure") {
		t.Errorf("the refusal does not name the conflict: %v", err)
	}
}

// TestClaimsBindIsGone pins the removal. The seam bound scope from an UNVERIFIED
// bearer — the bearer chose its own scope — so ADR-0042 removes it rather than
// leaving a flag that reintroduces the hole when set.
func TestClaimsBindIsGone(t *testing.T) {
	err := run(minimalArgs(t, "--claims-bind"))
	if err == nil {
		t.Fatal("-claims-bind still parses; the unverified claims seam lets a bearer " +
			"choose its own scope")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") &&
		!strings.Contains(err.Error(), "claims-bind") {
		t.Errorf("the daemon failed for an unrelated reason: %v", err)
	}
}

// TestEachCredentialFlagIsSeparatelyRequired binds each companion flag to its
// own guard. The three checks run in sequence, so omitting one is caught by the
// NEXT one too — a test that supplies none proves only that some guard exists,
// and each could then be deleted while the suite stayed green.
//
// Each case here supplies the OTHER two, so only the named guard can refuse.
func TestEachCredentialFlagIsSeparatelyRequired(t *testing.T) {
	jwks := writeTestJWKS(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"jwks path", []string{"--credential-issuer", "iss", "--credential-audience", "aud"}, "credential-jwks-path"},
		{"issuer", []string{"--credential-jwks-path", jwks, "--credential-audience", "aud"}, "credential-issuer"},
		{"audience", []string{"--credential-jwks-path", jwks, "--credential-issuer", "iss"}, "credential-audience"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(minimalArgs(t, tc.args...))
			if err == nil {
				t.Fatalf("the daemon booted with %s missing", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("omitting %s was refused by a DIFFERENT guard (%v); this "+
					"assertion is not bound to the one it names", tc.want, err)
			}
		})
	}
}

// writeTestJWKS writes a minimal well-formed JWKS so a case can supply the path
// without the file itself becoming the reason for refusal.
func writeTestJWKS(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwks.json")
	const doc = `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","use":"sig","alg":"EdDSA","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write test jwks: %v", err)
	}
	return path
}
