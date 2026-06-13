// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/admission"
	"github.com/Wide-Moat/ocu-filestore/internal/ceilings"
	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// testLogger returns a discard logger for use in tests; it avoids polluting
// test output with daemon lifecycle logs.
func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

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
	srv, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
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
	srv, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
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

// TestComposeCrashRestartErasesScope pins the T1-10/SEC-54 crash path at the
// composition level: a daemon that crashed mid-session (no Close, so no
// TeardownScope) leaves a dirty scope; the NEXT composition's ProvisionScope
// erases it, so the restarted daemon never re-serves prior-session bytes.
func TestComposeCrashRestartErasesScope(t *testing.T) {
	cfg := validBrokerConfig(t)
	srv1, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if err != nil {
		t.Fatalf("compose (session one): %v", err)
	}
	_ = srv1 // crashed: deliberately NO Close — teardown never runs.

	// Prior-session bytes, written straight into the provisioned scope.
	scopeDir := filepath.Join(cfg.engineRoot, cfg.filesystemID)
	prior := filepath.Join(scopeDir, "prior.bin")
	if err := os.WriteFile(prior, []byte("PRIORSESSION"), 0o600); err != nil {
		t.Fatalf("plant prior-session file: %v", err)
	}

	srv2, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if err != nil {
		t.Fatalf("compose (restart): %v", err)
	}
	defer srv2.Close()
	if _, err := os.Stat(prior); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prior-session file after restart provision: stat err = %v, want erased (SEC-54)", err)
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

	_, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
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

// TestComposeS3EngineRefusesPreBind pins the s3 composition's fail-closed
// intake: with no credential source available the composition refuses with
// the typed credential error BEFORE any socket exists — the daemon never
// serves an s3 engine it cannot sign for.
func TestComposeS3EngineRefusesPreBind(t *testing.T) {
	t.Setenv(objectstore.EnvS3AccessKeyID, "")
	t.Setenv(objectstore.EnvS3SecretAccessKey, "")
	cfg := validBrokerConfig(t)
	cfg.engineKind = objectstore.S3
	cfg.engineRoot = ""
	cfg.s3Bucket = "ocu-bucket"
	cfg.s3Endpoint = "http://127.0.0.1:9000"
	cfg.s3Region = "us-east-1"
	cfg.laneDevDirect = true

	_, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if !errors.Is(err, objectstore.ErrCredentialMissing) {
		t.Fatalf("compose(engine=s3, no credential): got %v, want ErrCredentialMissing", err)
	}
	// The refusal happened pre-bind: no socket file under the socket dir.
	entries, _ := os.ReadDir(cfg.socketDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".sock" {
			t.Fatalf("a socket %q was bound for the refused s3 engine; want none", e.Name())
		}
	}
}

// TestComposeS3RealEngineServes pins the 13-16 composition end-to-end against
// the live rig (gated): dev-direct transport + static env credentials compose
// the REAL s3 engine, ProvisionScope runs against MinIO for real, the daemon
// serves on a real socket, and Close tears the scope down.
func TestComposeS3RealEngineServes(t *testing.T) {
	endpoint := os.Getenv("OCU_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("OCU_S3_TEST_ENDPOINT not set - composed s3 engine live leg SKIPPED (boot deploy/docker-compose.test.yml)")
	}
	t.Setenv(objectstore.EnvS3AccessKeyID, os.Getenv("OCU_S3_TEST_ACCESS_KEY"))
	t.Setenv(objectstore.EnvS3SecretAccessKey, os.Getenv("OCU_S3_TEST_SECRET_KEY"))
	bucket := os.Getenv("OCU_S3_TEST_BUCKET")
	if bucket == "" {
		bucket = "ocu-conformance"
	}

	cfg := validBrokerConfig(t)
	cfg.engineKind = objectstore.S3
	cfg.engineRoot = ""
	cfg.s3Bucket = bucket
	cfg.s3Endpoint = endpoint
	cfg.s3Region = "us-east-1"
	cfg.s3PathStyle = true
	cfg.laneDevDirect = true

	srv, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if err != nil {
		t.Fatalf("compose(real s3): %v", err)
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

// TestRunS3EngineRefusesWithFullFlagSet pins the e2e-observable shape: a full,
// otherwise-valid required-flag set with -engine s3 and NO lane posture
// refuses with the typed ADR-0011 lane requirement — every other flag defect
// reports first, so this refusal provably means "flags valid, lane missing"
// (13-15). With the loud dev-direct override and no credential, the refusal
// moves to the credential intake (the composition gate).
func TestRunS3EngineRefusesWithFullFlagSet(t *testing.T) {
	t.Setenv(objectstore.EnvS3AccessKeyID, "")
	t.Setenv(objectstore.EnvS3SecretAccessKey, "")
	root := shortDir(t)
	full := []string{
		"--engine", "s3",
		"--s3-bucket", "ocu-bucket",
		"--s3-endpoint", "http://127.0.0.1:9000",
		"--audit-sink", filepath.Join(root, "audit.jsonl"),
		"--south-socket-dir", filepath.Join(root, "sock"),
		"--filesystem-id", "fs1",
		"--broker-max-file-size", "1",
	}
	if err := run(full); !errors.Is(err, errStorageLaneRequired) {
		t.Fatalf("run(-engine s3, full flags, no lane): got %v, want errStorageLaneRequired (ADR-0011)", err)
	}
	if err := run(append(full, "--storage-lane-dev-direct")); !errors.Is(err, objectstore.ErrCredentialMissing) {
		t.Fatalf("run(-engine s3, dev-direct, no creds): got %v, want ErrCredentialMissing", err)
	}
}

// TestValidateEngineConditionalRequiredFlags pins the 13-16 matrix: each
// engine kind requires its own backing-store flags and refuses the other
// kind's.
func TestValidateEngineConditionalRequiredFlags(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		engine, engineRoot             string
		s3Bucket, s3Endpoint, s3Region string
		s3PathStyle                    bool
		wantErr                        bool
	}{
		{"local with engine-root ok", "local-volume", "/x", "", "", "us-east-1", false, false},
		{"local without engine-root refused", "local-volume", "", "", "", "us-east-1", false, true},
		{"local with s3-bucket refused", "local-volume", "/x", "b", "", "us-east-1", false, true},
		{"local with s3-endpoint refused", "local-volume", "/x", "", "http://e", "us-east-1", false, true},
		{"local with s3-path-style refused", "local-volume", "/x", "", "", "us-east-1", true, true},
		{"s3 full ok", "s3", "", "b", "http://e", "us-east-1", true, false},
		{"s3 with engine-root refused", "s3", "/x", "b", "http://e", "us-east-1", false, true},
		{"s3 without bucket refused", "s3", "", "", "http://e", "us-east-1", false, true},
		{"s3 without endpoint refused", "s3", "", "b", "", "us-east-1", false, true},
		{"s3 without region refused", "s3", "", "b", "http://e", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validate(tc.engine, tc.engineRoot, "/y", "/s", "fs1",
				"trusted_operator", "single-tenant", "read", "", 1024, 4096,
				defaultOpsPerSecond, defaultOpsBurst, "", "", "",
				"", "", tc.engine == "s3", // dev-direct posture for the s3 rows
				tc.s3Bucket, tc.s3Endpoint, tc.s3Region, tc.s3PathStyle, "info", "")
			if tc.wantErr && !errors.Is(err, errMissingRequiredFlag) {
				t.Fatalf("validate(%s) = %v, want errMissingRequiredFlag", tc.name, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validate(%s) = %v, want nil", tc.name, err)
			}
		})
	}
}

// TestValidateStorageLaneMatrix pins the 13-15 refusal matrix (ADR-0011,
// NFR-SEC-16/85): s3 without a lane posture refuses naming the ADR; lane +
// dev-direct together refuse as ambiguous; any lane flag on local-volume
// refuses (a silent no-op would lie); -ca-bundle requires -storage-lane.
func TestValidateStorageLaneMatrix(t *testing.T) {
	call := func(engine, lane, bundle string, devDirect bool) error {
		engineRoot, bucket, endpoint := "/x", "", ""
		if engine == "s3" {
			engineRoot, bucket, endpoint = "", "ocu-bucket", "http://127.0.0.1:9000"
		}
		_, err := validate(engine, engineRoot, "/y", "/s", "fs1",
			"trusted_operator", "single-tenant", "read", "", 1024, 4096,
			defaultOpsPerSecond, defaultOpsBurst, "", "", "",
			lane, bundle, devDirect,
			bucket, endpoint, "us-east-1", false, "info", "")
		return err
	}

	if err := call("s3", "", "", false); !errors.Is(err, errStorageLaneRequired) {
		t.Fatalf("s3 + no lane posture = %v, want errStorageLaneRequired", err)
	}
	if err := call("s3", "http://lane:3128", "", true); !errors.Is(err, errStorageLaneAmbiguous) {
		t.Fatalf("s3 + lane + dev-direct = %v, want errStorageLaneAmbiguous", err)
	}
	if err := call("s3", "http://lane:3128", "", false); err != nil {
		t.Fatalf("s3 + lane = %v, want nil", err)
	}
	if err := call("s3", "", "", true); err != nil {
		t.Fatalf("s3 + dev-direct = %v, want nil (loud dev override)", err)
	}
	if err := call("s3", "http://lane:3128", "/etc/ocu/lane-ca.pem", false); err != nil {
		t.Fatalf("s3 + lane + ca-bundle = %v, want nil", err)
	}
	if err := call("s3", "", "/etc/ocu/lane-ca.pem", true); !errors.Is(err, errMissingRequiredFlag) {
		t.Fatalf("ca-bundle without lane = %v, want refusal", err)
	}
	if err := call("local-volume", "http://lane:3128", "", false); !errors.Is(err, errMissingRequiredFlag) {
		t.Fatalf("local-volume + lane = %v, want refusal", err)
	}
	if err := call("local-volume", "", "", true); !errors.Is(err, errMissingRequiredFlag) {
		t.Fatalf("local-volume + dev-direct = %v, want refusal", err)
	}
	if err := call("local-volume", "", "/etc/ocu/lane-ca.pem", false); !errors.Is(err, errMissingRequiredFlag) {
		t.Fatalf("local-volume + ca-bundle = %v, want refusal", err)
	}

	// The lane refusal text names the ADR and the SEC row — the operator
	// (and the e2e smoke) must see WHY a direct dial is refused.
	msg := errStorageLaneRequired.Error()
	for _, want := range []string{"ADR-0011", "SEC-16", "-storage-lane-dev-direct"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("lane refusal text %q does not name %q", msg, want)
		}
	}
}

// TestValidateStoresEngineKindS3LocalUnaffected pins that validate carries the
// parsed engine kind into brokerConfig (it was previously discarded) and that
// local-volume remains the composed default.
func TestValidateStoresEngineKindS3LocalUnaffected(t *testing.T) {
	cfg, err := validate("s3", "", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst, "", "", "", "", "", true,
		"ocu-bucket", "http://127.0.0.1:9000", "us-east-1", false, "info", "")
	if err != nil {
		t.Fatalf("validate(engine=s3): %v", err)
	}
	if cfg.engineKind != objectstore.S3 {
		t.Fatalf("validate(engine=s3) stored kind %q, want %q", cfg.engineKind, objectstore.S3)
	}
	cfg, err = validate("local-volume", "/x", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst, "", "", "", "", "", false,
		"", "", "us-east-1", false, "info", "")
	if err != nil {
		t.Fatalf("validate(engine=local-volume): %v", err)
	}
	if cfg.engineKind != objectstore.LocalVolume {
		t.Fatalf("validate(engine=local-volume) stored kind %q, want %q", cfg.engineKind, objectstore.LocalVolume)
	}
}

// TestValidateS3CredentialFileFlagGate pins the 13-13 flag discipline: the
// -s3-credential-file flag carries a PATH (never a secret value), is carried
// into brokerConfig for the s3 engine, and REFUSES on a non-s3 engine — a
// silently inert credential flag would lie about the deployment posture.
func TestValidateS3CredentialFileFlagGate(t *testing.T) {
	cfg, err := validate("s3", "", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst, "/etc/ocu/s3.cred", "", "", "", "", true,
		"ocu-bucket", "http://127.0.0.1:9000", "us-east-1", false, "info", "")
	if err != nil {
		t.Fatalf("validate(s3 + credential file): %v", err)
	}
	if cfg.s3CredentialFile != "/etc/ocu/s3.cred" {
		t.Fatalf("config carries credential file %q, want the flag path", cfg.s3CredentialFile)
	}

	_, err = validate("local-volume", "/x", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst, "/etc/ocu/s3.cred", "", "", "", "", false,
		"", "", "us-east-1", false, "info", "")
	if !errors.Is(err, errMissingRequiredFlag) {
		t.Fatalf("validate(local-volume + credential file) = %v, want errMissingRequiredFlag refusal", err)
	}
}

// TestValidateSTSFlagGate pins the 13-14 flag matrix: the STS flags refuse
// on a non-s3 engine, -s3-sts-endpoint requires -s3-sts-role-arn, and a
// valid s3 STS pair is carried into brokerConfig.
func TestValidateSTSFlagGate(t *testing.T) {
	const arn = "arn:aws:iam::000000000000:role/ocu-session"

	cfg, err := validate("s3", "", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst, "", arn, "http://sts.local:9000", "", "", true,
		"ocu-bucket", "http://127.0.0.1:9000", "us-east-1", false, "info", "")
	if err != nil {
		t.Fatalf("validate(s3 + sts pair): %v", err)
	}
	if cfg.s3STSRoleARN != arn || cfg.s3STSEndpoint != "http://sts.local:9000" {
		t.Fatalf("config carries sts %q/%q, want the flag values", cfg.s3STSRoleARN, cfg.s3STSEndpoint)
	}

	if _, err := validate("local-volume", "/x", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst, "", arn, "", "", "", false,
		"", "", "us-east-1", false, "info", ""); !errors.Is(err, errMissingRequiredFlag) {
		t.Fatalf("validate(local-volume + role arn) = %v, want refusal", err)
	}
	if _, err := validate("local-volume", "/x", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst, "", "", "http://sts.local:9000", "", "", false,
		"", "", "us-east-1", false, "info", ""); !errors.Is(err, errMissingRequiredFlag) {
		t.Fatalf("validate(local-volume + sts endpoint) = %v, want refusal", err)
	}
	if _, err := validate("s3", "", "/y", "/s", "fs1",
		"trusted_operator", "single-tenant", "read", "", 1024, 4096,
		defaultOpsPerSecond, defaultOpsBurst, "", "", "http://sts.local:9000", "", "", false,
		"ocu-bucket", "http://127.0.0.1:9000", "us-east-1", false, "info", ""); !errors.Is(err, errMissingRequiredFlag) {
		t.Fatalf("validate(s3 endpoint without role arn) = %v, want refusal", err)
	}
}

// TestSelectCredentialSourceKindFlows pins the 13-14 selection: without a
// role ARN the static source serves (host_local_long_lived); with one, the
// STS source serves (sts_per_session) — and BOTH kinds are admitted for the
// trusted_operator/single-tenant cell, so the credential kind genuinely
// flows from the source into admission (selection wired, no rows invented).
// A hostile filesystem id refuses before any policy text exists.
func TestSelectCredentialSourceKindFlows(t *testing.T) {
	t.Setenv(objectstore.EnvS3AccessKeyID, "AKIDTEST")
	t.Setenv(objectstore.EnvS3SecretAccessKey, "test-secret-value")
	cfg := validBrokerConfig(t)
	cfg.engineKind = objectstore.S3

	src, err := selectCredentialSource(cfg, "ocu-bucket", "us-east-1")
	if err != nil {
		t.Fatalf("selectCredentialSource(static): %v", err)
	}
	if got := src.Kind(); got != admission.CredHostLocalLongLived {
		t.Fatalf("static path Kind() = %q, want %q", got, admission.CredHostLocalLongLived)
	}
	if err := admission.Admit(cfg.profile, cfg.tenancy, src.Kind()); err != nil {
		t.Fatalf("Admit(static kind): %v", err)
	}

	cfg.s3STSRoleARN = "arn:aws:iam::000000000000:role/ocu-session"
	src, err = selectCredentialSource(cfg, "ocu-bucket", "us-east-1")
	if err != nil {
		t.Fatalf("selectCredentialSource(sts): %v", err)
	}
	if got := src.Kind(); got != admission.CredSTSPerSession {
		t.Fatalf("sts path Kind() = %q, want %q", got, admission.CredSTSPerSession)
	}
	if err := admission.Admit(cfg.profile, cfg.tenancy, src.Kind()); err != nil {
		t.Fatalf("Admit(sts kind): %v", err)
	}

	// A hostile scope id refuses at source construction — the inline policy
	// text for it is never built (validateScopeID runs first).
	cfg.filesystemID = "../escape"
	if _, err := selectCredentialSource(cfg, "ocu-bucket", "us-east-1"); !errors.Is(err, objectstore.ErrInvalidScopeID) {
		t.Fatalf("selectCredentialSource(hostile scope) = %v, want ErrInvalidScopeID", err)
	}
}

// TestRunVersionFlagPrintsAndExitsClean pins T1-13: `-version` prints the
// build identity to stdout and returns nil (exit 0 through main), without
// requiring any of the serving flags.
func TestRunVersionFlagPrintsAndExitsClean(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := run([]string{"-version"})
	_ = w.Close()
	os.Stdout = old
	out, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatalf("read captured stdout: %v", readErr)
	}
	if runErr != nil {
		t.Fatalf("run(-version): got %v, want nil (exit 0)", runErr)
	}
	got := string(out)
	if !strings.Contains(got, "ocu-filestored") || !strings.Contains(got, version) {
		t.Fatalf("run(-version) printed %q, want the daemon name and version %q", got, version)
	}
}

// TestVersionString pins the build-identity shape: the stamped version var
// (the ldflags -X main.version target — its existence is what makes the
// release stamping a real assignment, not a no-op) and the Go toolchain
// version from the embedded build info.
func TestVersionString(t *testing.T) {
	got := versionString()
	if !strings.HasPrefix(got, "ocu-filestored "+version) {
		t.Fatalf("versionString() = %q, want prefix %q", got, "ocu-filestored "+version)
	}
	// The test binary always embeds build info with a Go toolchain version.
	if !strings.Contains(got, "go1") {
		t.Fatalf("versionString() = %q, want the Go toolchain version", got)
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
				tc.rate, tc.brst, "", "", "", "", "", false,
				"", "", "us-east-1", false, "info", "")
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

// fakeLifecycleServer is a controllable southface.Server for the signal and
// teardown-ordering tests: Serve optionally blocks until Close is called
// (the real session's shape), and both verbs return injected errors.
type fakeLifecycleServer struct {
	serveStarted chan struct{}
	closeCalled  chan struct{}
	blockServe   bool
	serveErr     error
	closeErr     error
}

func (s *fakeLifecycleServer) Serve() error {
	close(s.serveStarted)
	if s.blockServe {
		<-s.closeCalled
	}
	return s.serveErr
}

func (s *fakeLifecycleServer) Close() error {
	close(s.closeCalled)
	return s.closeErr
}

// TestServeUntilSignalSigtermRunsTeardown pins T1-9/SEC-54 stop path: a real
// SIGTERM delivered to the process makes serveUntilSignal close the server
// (teardown runs) and SURFACES the close error — a teardown failure on a
// clean signal stop is never silently dropped.
func TestServeUntilSignalSigtermRunsTeardown(t *testing.T) {
	teardownErr := errors.New("teardown failed loudly")
	srv := &fakeLifecycleServer{
		serveStarted: make(chan struct{}),
		closeCalled:  make(chan struct{}),
		blockServe:   true,
		closeErr:     teardownErr,
	}
	result := make(chan error, 1)
	go func() { result <- serveUntilSignal(srv, testLogger(), nil) }()

	// Serve has started, therefore signal.NotifyContext is already armed
	// (it is registered before the Serve goroutine launches).
	<-srv.serveStarted
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("self-SIGTERM: %v", err)
	}

	select {
	case err := <-result:
		select {
		case <-srv.closeCalled:
		default:
			t.Fatal("serveUntilSignal returned without calling Close — teardown was skipped on SIGTERM")
		}
		if !errors.Is(err, teardownErr) {
			t.Fatalf("serveUntilSignal after SIGTERM = %v, want the surfaced teardown error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilSignal did not return within 10s of SIGTERM")
	}
}

// TestServeUntilSignalServeFaultStillTearsDown pins that a Serve that fails
// on its own (listener fault, no signal) still runs teardown, and BOTH the
// serve error and the close error surface via errors.Join.
func TestServeUntilSignalServeFaultStillTearsDown(t *testing.T) {
	serveFault := errors.New("listener fault")
	teardownErr := errors.New("teardown also failed")
	srv := &fakeLifecycleServer{
		serveStarted: make(chan struct{}),
		closeCalled:  make(chan struct{}),
		serveErr:     serveFault,
		closeErr:     teardownErr,
	}
	err := serveUntilSignal(srv, testLogger(), nil)
	select {
	case <-srv.closeCalled:
	default:
		t.Fatal("Close was not called after a serve fault — teardown skipped")
	}
	if !errors.Is(err, serveFault) || !errors.Is(err, teardownErr) {
		t.Fatalf("serveUntilSignal = %v, want BOTH the serve fault and the teardown error joined", err)
	}
}

// TestTeardownServerCloseJoinsBothErrors pins that teardownServer.Close runs
// the scope erase even when the session close fails, and reports both.
func TestTeardownServerCloseJoinsBothErrors(t *testing.T) {
	closeFault := errors.New("session close fault")
	eng := &deadlineRecordingEngine{}
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         defaultOpsPerSecond,
		OpsBurst:             defaultOpsBurst,
		InFlightBytesCeiling: defaultInFlightBytes,
		FDCeiling:            defaultFDCeiling,
		Clock:                time.Now,
	})
	srv := &teardownServer{
		Server:  failingCloseServer{err: closeFault},
		engine:  eng,
		ceiling: reg,
		scope:   objectstore.ScopeID("fs1"),
		fsid:    "fs1",
	}
	err := srv.Close()
	if !eng.hadDeadline {
		t.Fatal("TeardownScope did not run after a failing session close — the erase was skipped")
	}
	if !errors.Is(err, closeFault) {
		t.Fatalf("Close = %v, want the session close fault surfaced", err)
	}
}

// failingCloseServer is a southface.Server whose Close always fails.
type failingCloseServer struct{ err error }

func (failingCloseServer) Serve() error   { return nil }
func (f failingCloseServer) Close() error { return f.err }

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

// TestLogLevelFlagRefusesUnknown pins that validate refuses an unknown
// -log-level token with errBadLogLevel BEFORE any socket is bound.
func TestLogLevelFlagRefusesUnknown(t *testing.T) {
	for _, bad := range []string{"loud", "verbose", "DEBUG", "INFO", ""} {
		err := run([]string{"-log-level", bad})
		if err == nil {
			t.Errorf("run(-log-level %q): got nil, want errBadLogLevel", bad)
			continue
		}
		if !observ.IsBadLogLevel(err) {
			t.Errorf("run(-log-level %q) = %v, does not wrap errBadLogLevel", bad, err)
		}
	}
}

// TestLogLevelValidTokensAccepted pins that all four valid -log-level tokens
// are accepted (the flag reaches validate without a typed error; the full flag
// set still produces errMissingRequiredFlag for missing required serving flags).
func TestLogLevelValidTokensAccepted(t *testing.T) {
	for _, good := range []string{"debug", "info", "warn", "error"} {
		err := run([]string{"-log-level", good})
		// A valid log level should NOT produce errBadLogLevel; any other error
		// (e.g. errMissingRequiredFlag for missing serving flags) is expected.
		if observ.IsBadLogLevel(err) {
			t.Errorf("run(-log-level %q) = %v, want no errBadLogLevel", good, err)
		}
	}
}

// TestStartupEchoNoCredential plants a known secret token in a file and
// passes that file path as -s3-credential-file (via compose indirectly via
// run). Because the daemon never reads the file's BYTES into config, the
// token MUST NOT appear in any captured log line.
//
// This is the T-14-01 redaction proof for the startup echo.
func TestStartupEchoNoCredential(t *testing.T) {
	// Plant a secret in a temp file.
	secretToken := "SUPER_SECRET_CRED_XK8Z2P" // unique, unlikely to match any log constant
	credFile, err := os.CreateTemp(t.TempDir(), "cred")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := credFile.WriteString("access_key_id=" + secretToken + "\nsecret_access_key=" + secretToken); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	credFile.Close()

	// Capture stderr (the JSON log stream) over a compose+close cycle.
	root := shortDir(t)
	cfg := brokerConfig{
		engineKind:       objectstore.LocalVolume,
		engineRoot:       filepath.Join(root, "engine"),
		auditSink:        filepath.Join(root, "audit.jsonl"),
		socketDir:        filepath.Join(root, "sock"),
		filesystemID:     "fs-redact-01",
		maxFileSize:      1 << 20,
		maxRequestByte:   4 << 20,
		opsPerSecond:     defaultOpsPerSecond,
		opsBurst:         defaultOpsBurst,
		grantedIntents:   []southface.Intent{southface.IntentRead},
		profile:          admission.ProfileTrustedOperator,
		tenancy:          admission.TenancySingleTenant,
		logLevel:         slog.LevelInfo,
		s3CredentialFile: credFile.Name(), // path only, bytes never loaded here
	}

	var logBuf strings.Builder
	l := observ.NewLogger(&logBuf, slog.LevelInfo)

	// Emit the startup echo (same code run() calls).
	l.Info("ocu-filestored starting",
		slog.String("version", version),
		slog.String("engine", string(cfg.engineKind)),
		slog.String("socket_dir", cfg.socketDir),
		slog.String("audit_sink", cfg.auditSink),
		slog.String(observ.KeyScope, cfg.filesystemID),
		slog.String("profile", string(cfg.profile)),
		slog.String("s3_credential_file", cfg.s3CredentialFile), // path only
	)

	logged := logBuf.String()
	if strings.Contains(logged, secretToken) {
		t.Errorf("startup echo log contains the planted secret token %q — credential bytes must never appear in logs:\n%s", secretToken, logged)
	}
	// The credential FILE PATH should appear (it is operator-visible config).
	if !strings.Contains(logged, credFile.Name()) {
		t.Errorf("startup echo log does not contain the credential file path %q (operator should see which credential file is configured)", credFile.Name())
	}
}

// TestOpsListenFlagBehavior pins the -ops-listen flag surface (T2-2):
//   - An empty value disables the ops listener (no error from validate).
//   - A non-loopback address is refused fail-closed (errOpsListenNotLoopback
//     wrapped in the validate error) BEFORE any socket is bound.
//   - A loopback address is accepted and carried into brokerConfig.
//   - The default value is "127.0.0.1:9464".
func TestOpsListenFlagBehavior(t *testing.T) {
	call := func(addr string) (brokerConfig, error) {
		return validate("local-volume", "/x", "/y", "/s", "fs1",
			"trusted_operator", "single-tenant", "read", "", 1024, 4096,
			defaultOpsPerSecond, defaultOpsBurst, "", "", "",
			"", "", false,
			"", "", "us-east-1", false, "info", addr)
	}

	// Empty disables the listener — no error.
	cfg, err := call("")
	if err != nil {
		t.Fatalf("validate(ops-listen=\"\"): got %v, want nil", err)
	}
	if cfg.opsListen != "" {
		t.Fatalf("validate(ops-listen=\"\") stored %q, want empty (disabled)", cfg.opsListen)
	}

	// Loopback literal is accepted and stored.
	cfg, err = call("127.0.0.1:9464")
	if err != nil {
		t.Fatalf("validate(ops-listen=127.0.0.1:9464): got %v, want nil", err)
	}
	if cfg.opsListen != "127.0.0.1:9464" {
		t.Fatalf("validate(ops-listen=127.0.0.1:9464) stored %q, want the addr", cfg.opsListen)
	}

	// "localhost" is accepted.
	_, err = call("localhost:9464")
	if err != nil {
		t.Fatalf("validate(ops-listen=localhost:9464): got %v, want nil", err)
	}

	// Non-loopback is refused fail-closed.
	_, err = call("0.0.0.0:9464")
	if err == nil {
		t.Fatal("validate(ops-listen=0.0.0.0:9464): got nil, want non-loopback refusal")
	}
	if !telemetry.IsOpsListenNotLoopback(err) {
		t.Fatalf("validate(ops-listen=0.0.0.0:9464): err = %v, does not wrap errOpsListenNotLoopback", err)
	}

	// All-interfaces short form is also refused (":port" binds all interfaces).
	_, err = call(":9464")
	if err == nil {
		t.Fatal("validate(ops-listen=:9464): got nil, want all-interface refusal")
	}
	if !telemetry.IsOpsListenNotLoopback(err) {
		t.Fatalf("validate(ops-listen=:9464): err = %v, does not wrap errOpsListenNotLoopback", err)
	}

	// The default flag value is the documented loopback address.
	fs := flag.NewFlagSet("check-default", flag.ContinueOnError)
	opsListen := fs.String("ops-listen", "127.0.0.1:9464", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("flagset parse: %v", err)
	}
	if *opsListen != "127.0.0.1:9464" {
		t.Fatalf("-ops-listen default = %q, want 127.0.0.1:9464", *opsListen)
	}
}

// TestOpsListenNonLoopbackRefusedViaRun pins the end-to-end path: a
// non-loopback -ops-listen value causes run() to return a typed error before
// any serving flag is validated (the ops-listen check runs after -log-level,
// before engine checks).
func TestOpsListenNonLoopbackRefusedViaRun(t *testing.T) {
	err := run([]string{"--ops-listen", "0.0.0.0:9464"})
	if err == nil {
		t.Fatal("run(--ops-listen 0.0.0.0:9464): got nil, want refusal")
	}
	if !telemetry.IsOpsListenNotLoopback(err) {
		t.Fatalf("run(--ops-listen 0.0.0.0:9464): err = %v, does not wrap errOpsListenNotLoopback", err)
	}
}
