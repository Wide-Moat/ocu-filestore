// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/admission"
	"github.com/Wide-Moat/ocu-filestore/internal/ceilings"
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
		engineKind:     objectstore.LocalVolume,
		engineRoot:     filepath.Join(root, "engine"),
		auditSink:      filepath.Join(root, "audit.jsonl"),
		socketDir:      filepath.Join(root, "sock"),
		filesystemID:   "fs-main-01",
		maxFileSize:    1 << 30,
		maxRequestByte: 4 << 20,
		opsPerSecond:   defaultOpsPerSecond,
		opsBurst:       defaultOpsBurst,
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

// TestComposeTinyOpsBucketServes pins the operator-tunable throttle floor:
// the smallest legal ops bucket (-ops-per-second 1 -ops-burst 1) is accepted
// and the daemon serves and closes cleanly — a tiny bucket throttles, it
// never refuses to start.
func TestComposeTinyOpsBucketServes(t *testing.T) {
	cfg := validBrokerConfig(t)
	cfg.opsPerSecond = 1
	cfg.opsBurst = 1
	srv, err := compose(cfg)
	if err != nil {
		t.Fatalf("compose(ops 1/1): %v", err)
	}
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

// TestComposeS3EngineRefusesPreBind pins T1-2: `-engine s3` returns the typed
// errS3EngineUnavailable sentinel from compose BEFORE admission and before any
// socket exists — never a silent local-volume fallback under the s3 name.
func TestComposeS3EngineRefusesPreBind(t *testing.T) {
	cfg := validBrokerConfig(t)
	cfg.engineKind = objectstore.S3

	_, err := compose(cfg)
	if !errors.Is(err, errS3EngineUnavailable) {
		t.Fatalf("compose(engine=s3): got %v, want errS3EngineUnavailable", err)
	}
	// The refusal happened pre-bind: no socket file under the socket dir.
	entries, _ := os.ReadDir(cfg.socketDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".sock" {
			t.Fatalf("a socket %q was bound for the refused s3 engine; want none", e.Name())
		}
	}
}

// TestRunS3EngineRefusesWithFullFlagSet pins the e2e-observable shape: a full,
// otherwise-valid required-flag set with -engine s3 passes flag validation and
// then refuses with errS3EngineUnavailable — proving the refusal comes from
// the engine gate, not from a missing flag.
func TestRunS3EngineRefusesWithFullFlagSet(t *testing.T) {
	root := shortDir(t)
	err := run([]string{
		"--engine", "s3",
		"--engine-root", filepath.Join(root, "engine"),
		"--audit-sink", filepath.Join(root, "audit.jsonl"),
		"--south-socket-dir", filepath.Join(root, "sock"),
		"--filesystem-id", "fs1",
		"--broker-max-file-size", "1",
	})
	if !errors.Is(err, errS3EngineUnavailable) {
		t.Fatalf("run(-engine s3, full flags): got %v, want errS3EngineUnavailable", err)
	}
}

// TestValidateStoresEngineKindS3LocalUnaffected pins that validate carries the
// parsed engine kind into brokerConfig (it was previously discarded) and that
// local-volume remains the composed default.
func TestValidateStoresEngineKindS3LocalUnaffected(t *testing.T) {
	cfg, err := validate("s3", "/x", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst)
	if err != nil {
		t.Fatalf("validate(engine=s3): %v", err)
	}
	if cfg.engineKind != objectstore.S3 {
		t.Fatalf("validate(engine=s3) stored kind %q, want %q", cfg.engineKind, objectstore.S3)
	}
	cfg, err = validate("local-volume", "/x", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst)
	if err != nil {
		t.Fatalf("validate(engine=local-volume): %v", err)
	}
	if cfg.engineKind != objectstore.LocalVolume {
		t.Fatalf("validate(engine=local-volume) stored kind %q, want %q", cfg.engineKind, objectstore.LocalVolume)
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
// flag — and each explicitly-bad optional ops ceiling — returns a typed error
// (never a panic), and never reaches the serve path: no socket is bound. The
// defaults leave -engine-root / -audit-sink / -filesystem-id empty and
// -broker-max-file-size 0, so the first missing required flag is named. The
// ops rows carry all required flags so only the bad ceiling can refuse:
// -ops-per-second must be > 0 and -ops-burst >= 1 (a sub-one burst would
// wedge the bucket).
func TestRunMissingRequiredFlags(t *testing.T) {
	required := []string{"--engine-root", "/x", "--audit-sink", "/y", "--filesystem-id", "fs1", "--broker-max-file-size", "1024"}
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
		{"zero_ops_per_second", append(append([]string{}, required...), "--ops-per-second", "0")},
		{"negative_ops_per_second", append(append([]string{}, required...), "--ops-per-second", "-5")},
		{"zero_ops_burst", append(append([]string{}, required...), "--ops-burst", "0")},
		{"fractional_ops_burst", append(append([]string{}, required...), "--ops-burst", "0.5")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sockDir := shortDir(t)
			err := run(append(append([]string{}, tc.args...), "--south-socket-dir", sockDir))
			if !errors.Is(err, errMissingRequiredFlag) {
				t.Fatalf("run(%s): got %v, want errMissingRequiredFlag", tc.name, err)
			}
			// The refusal happens before composition — no socket was bound.
			entries, _ := os.ReadDir(sockDir)
			for _, e := range entries {
				if filepath.Ext(e.Name()) == ".sock" {
					t.Fatalf("run(%s) bound socket %q despite the typed refusal; want none", tc.name, e.Name())
				}
			}
		})
	}
}

// TestValidateOpsCeilingPlumbing pins the operator-tunable throttle plumbing:
// the ops token-bucket values land in brokerConfig unchanged, and omitting
// the flags yields the shelf defaults (100 ops/s, 200-token burst) with no
// error from the rate path.
func TestValidateOpsCeilingPlumbing(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rate, brst float64
	}{
		{"defaults_flags_omitted", defaultOpsPerSecond, defaultOpsBurst},
		{"tiny_bucket_one_one", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := validate("local-volume", "/x", "/y", "/s", "fs1",
				"trusted_operator", "single-tenant", "read", "", 1024, 4096,
				tc.rate, tc.brst)
			if err != nil {
				t.Fatalf("validate(rate=%g burst=%g): %v", tc.rate, tc.brst, err)
			}
			if cfg.opsPerSecond != tc.rate || cfg.opsBurst != tc.brst {
				t.Fatalf("config carries ops %g/%g, want %g/%g",
					cfg.opsPerSecond, cfg.opsBurst, tc.rate, tc.brst)
			}
		})
	}
	// The defaults are the documented 100/200 shelf values.
	if defaultOpsPerSecond != 100.0 || defaultOpsBurst != 200.0 {
		t.Fatalf("flag defaults are %g/%g, want 100/200", defaultOpsPerSecond, defaultOpsBurst)
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

// nopServer is a no-op southface.Server for exercising teardownServer.Close
// in isolation.
type nopServer struct{}

func (nopServer) Serve() error { return nil }
func (nopServer) Close() error { return nil }

// deadlineRecordingEngine records whether the lifecycle context handed to
// TeardownScope carried a deadline. Only TeardownScope is implemented; the
// embedded nil Engine panics on any other verb — Close must touch exactly
// the one lifecycle verb.
type deadlineRecordingEngine struct {
	objectstore.Engine
	hadDeadline bool
	deadline    time.Time
}

func (e *deadlineRecordingEngine) TeardownScope(ctx context.Context, _ objectstore.ScopeID) error {
	e.deadline, e.hadDeadline = ctx.Deadline()
	return nil
}

// TestTeardownLifecycleCtxCarriesDeadline pins the W1 bounded-lifecycle
// contract: teardownServer.Close hands TeardownScope a context with a real
// deadline (bounded by teardownTimeout) — never a bare context.Background().
// A hung backend sweep can therefore never wedge shutdown indefinitely.
func TestTeardownLifecycleCtxCarriesDeadline(t *testing.T) {
	eng := &deadlineRecordingEngine{}
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         defaultOpsPerSecond,
		OpsBurst:             defaultOpsBurst,
		InFlightBytesCeiling: defaultInFlightBytes,
		FDCeiling:            defaultFDCeiling,
		Clock:                time.Now,
	})
	srv := &teardownServer{
		Server:  nopServer{},
		engine:  eng,
		ceiling: reg,
		scope:   objectstore.ScopeID("fs1"),
		fsid:    "fs1",
	}

	before := time.Now()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !eng.hadDeadline {
		t.Fatal("TeardownScope context carried no deadline; want a bounded lifecycle context")
	}
	if max := before.Add(teardownTimeout + time.Minute); eng.deadline.After(max) {
		t.Fatalf("teardown deadline %v exceeds the teardownTimeout bound (max %v)", eng.deadline, max)
	}
	if eng.deadline.Before(before) {
		t.Fatalf("teardown deadline %v is in the past", eng.deadline)
	}
}

// TestLifecycleTimeoutsBounded pins that both lifecycle bounds are finite,
// positive, and ordered (teardown sweeps a whole scope on a network engine,
// so its bound is the generous one).
func TestLifecycleTimeoutsBounded(t *testing.T) {
	if provisionTimeout <= 0 {
		t.Fatalf("provisionTimeout = %v; want > 0", provisionTimeout)
	}
	if teardownTimeout <= 0 {
		t.Fatalf("teardownTimeout = %v; want > 0", teardownTimeout)
	}
	if teardownTimeout < provisionTimeout {
		t.Fatalf("teardownTimeout %v < provisionTimeout %v; the scope sweep bound must be the generous one", teardownTimeout, provisionTimeout)
	}
}
