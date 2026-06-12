// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/admission"
	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// shortDir returns a short-pathed temp directory (the platform unix-socket
// sun_path limit is below a typical t.TempDir() path).
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ocud")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// validBrokerConfig builds an admitted, fully-valid config rooted at temp
// dirs for the composition tests.
func validBrokerConfig(t *testing.T) brokerConfig {
	t.Helper()
	root := shortDir(t)
	return brokerConfig{
		engineRoot:     filepath.Join(root, "engine"),
		auditSink:      filepath.Join(root, "audit.jsonl"),
		socketDir:      filepath.Join(root, "sock"),
		filesystemID:   "fs-main-01",
		maxFileSize:    1 << 30,
		maxRequestByte: 4 << 20,
		grantedIntents: []southface.Intent{southface.IntentRead, southface.IntentWrite},
		dlPrefixes:     []string{"/pub"},
		profile:        admission.ProfileTrustedOperator,
		tenancy:        admission.TenancySingleTenant,
	}
}

// TestComposeAdmittedServesAndCloses pins WIRE-MAIN: the admitted triple
// composes the stack, provisions a session, and serves on a real socket; Close
// tears down cleanly (engine TeardownScope + registry/ceilings release).
func TestComposeAdmittedServesAndCloses(t *testing.T) {
	cfg := validBrokerConfig(t)
	srv, err := compose(cfg)
	if err != nil {
		t.Fatalf("compose(admitted): %v", err)
	}
	// Serve in the background; a clean Close returns nil from Serve.
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("Serve returned %v on clean shutdown, want nil", err)
	}
}

// TestComposeRefusedTripleBindsNoSocket pins SEC-60: a non-admitted
// profile/tenancy/credential triple returns the admission refusal and binds NO
// socket under -south-socket-dir.
func TestComposeRefusedTripleBindsNoSocket(t *testing.T) {
	cfg := validBrokerConfig(t)
	// multi-tenant + host-local-long-lived is NOT admitted (only
	// trusted_operator + single_tenant + host_local_long_lived is).
	cfg.tenancy = admission.TenancyMultiTenant

	_, err := compose(cfg)
	if !errors.Is(err, admission.ErrAdmissionRefused) && !errors.Is(err, admission.ErrTenancyRefused) {
		t.Fatalf("compose(refused triple): got %v, want an admission refusal", err)
	}
	// No socket file was minted under the socket dir.
	entries, _ := os.ReadDir(cfg.socketDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".sock" {
			t.Fatalf("a socket %q was bound on a refused triple; want none", e.Name())
		}
	}
}

// TestRunHelpIsNotAnError pins that -h/-help exits clean.
func TestRunHelpIsNotAnError(t *testing.T) {
	if err := run([]string{"-h"}); err != nil {
		t.Fatalf("run(-h): got %v, want nil", err)
	}
}

// TestRunRejectsUnknownFlag pins that an unknown flag is a parse error.
func TestRunRejectsUnknownFlag(t *testing.T) {
	if err := run([]string{"--no-such-flag"}); err == nil {
		t.Fatalf("run(unknown flag): got nil, want a parse error")
	}
}

// TestRunValidatesEngine pins that an unknown backend engine refuses with the
// typed sentinel, never a silent default.
func TestRunValidatesEngine(t *testing.T) {
	err := run([]string{"--engine", "gcs"})
	if !errors.Is(err, objectstore.ErrUnknownEngine) {
		t.Fatalf("run(--engine gcs): got %v, want ErrUnknownEngine", err)
	}
}

// TestRunMissingRequiredFlags pins WIRE-MAIN: each missing/invalid required
// flag returns a typed error (never a panic), and never reaches the serve
// path. The defaults leave -engine-root / -audit-sink / -filesystem-id empty
// and -broker-max-file-size 0, so the first missing required flag is named.
func TestRunMissingRequiredFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing_engine_root", []string{"--audit-sink", "/x", "--filesystem-id", "fs1", "--broker-max-file-size", "1024"}},
		{"missing_audit_sink", []string{"--engine-root", "/x", "--filesystem-id", "fs1", "--broker-max-file-size", "1024"}},
		{"missing_filesystem_id", []string{"--engine-root", "/x", "--audit-sink", "/y", "--broker-max-file-size", "1024"}},
		{"zero_broker_max_file_size", []string{"--engine-root", "/x", "--audit-sink", "/y", "--filesystem-id", "fs1", "--broker-max-file-size", "0"}},
		{"negative_broker_max_file_size", []string{"--engine-root", "/x", "--audit-sink", "/y", "--filesystem-id", "fs1", "--broker-max-file-size", "-1"}},
		{"all_defaults_missing_required", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.args)
			if !errors.Is(err, errMissingRequiredFlag) {
				t.Fatalf("run(%s): got %v, want errMissingRequiredFlag", tc.name, err)
			}
		})
	}
}

// TestRunValidatesProfileAndTenancy pins that unknown -profile / -tenancy
// values refuse with their typed sentinels before any serve path.
func TestRunValidatesProfileAndTenancy(t *testing.T) {
	if err := run([]string{"--profile", "root"}); !errors.Is(err, errBadProfile) {
		t.Fatalf("run(--profile root): got %v, want errBadProfile", err)
	}
	if err := run([]string{"--tenancy", "omni-tenant"}); !errors.Is(err, errBadTenancy) {
		t.Fatalf("run(--tenancy omni-tenant): got %v, want errBadTenancy", err)
	}
}

// TestRunRejectsUnknownIntent pins that a -granted-intents token outside
// read/write/preview refuses with the typed sentinel.
func TestRunRejectsUnknownIntent(t *testing.T) {
	args := []string{
		"--engine-root", "/x", "--audit-sink", "/y", "--filesystem-id", "fs1",
		"--broker-max-file-size", "1024", "--granted-intents", "read,delete",
	}
	if err := run(args); !errors.Is(err, errBadIntent) {
		t.Fatalf("run(bad intent): got %v, want errBadIntent", err)
	}
}

// TestTenancyHyphenToUnderscoreMap pins the load-bearing mapping: the
// Phase-8-frozen hyphenated flag values map to admission's underscored
// constants (single-tenant -> single_tenant). A direct admission call with the
// flag string would refuse — the map is not a passthrough.
func TestTenancyHyphenToUnderscoreMap(t *testing.T) {
	if got := tenancyAdmission["single-tenant"]; got != admission.TenancySingleTenant {
		t.Fatalf("single-tenant mapped to %q, want %q", got, admission.TenancySingleTenant)
	}
	if got := tenancyAdmission["multi-tenant"]; got != admission.TenancyMultiTenant {
		t.Fatalf("multi-tenant mapped to %q, want %q", got, admission.TenancyMultiTenant)
	}
	// The hyphenated flag value is NOT byte-identical to admission's constant.
	if string(admission.TenancySingleTenant) == "single-tenant" {
		t.Fatal("admission constant is hyphenated; the map would be a no-op (it must not be)")
	}
}
