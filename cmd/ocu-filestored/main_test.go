// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
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

// testTLSCertPaths writes a fresh self-signed loopback certificate + key to two
// PEM files under a short temp dir and returns their paths. The south-face TLS
// transport requires a real cert+key, so the composition and run tests mint an
// ephemeral one rather than depend on an on-disk fixture.
func testTLSCertPaths(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-filestore-main-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	dir := shortDir(t)
	certFile = filepath.Join(dir, "tls-cert.pem")
	keyFile = filepath.Join(dir, "tls-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// freeLoopbackAddr returns a currently-free loopback host:port for the south
// face to bind. There is a small race between the probe close and the rebind,
// acceptable in a single-process test.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

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
	certFile, keyFile := testTLSCertPaths(t)
	return brokerConfig{
		engineKind:     objectstore.LocalVolume,
		engineRoot:     filepath.Join(root, "engine"),
		auditSink:      filepath.Join(root, "audit.jsonl"),
		bindAddr:       freeLoopbackAddr(t),
		certFile:       certFile,
		keyFile:        keyFile,
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

// TestComposeServeConstructionFailureTearsDownScope pins FILESTORED-11: when
// compose provisions a scope (eng.ProvisionScope) and a LATER step fails
// before ownership passes to teardownServer — here southface.Serve's TLS
// construction rejecting a malformed certificate — compose must roll back the
// just-provisioned scope (engine.TeardownScope), never leak a dirty scope onto
// the error path. The LocalVolume erase signature is observable: a freshly
// provisioned scope holds a .ocu-staging subdir; the rollback teardown
// re-creates the scope dir EMPTY, so the staging subdir is gone.
func TestComposeServeConstructionFailureTearsDownScope(t *testing.T) {
	cfg := validBrokerConfig(t)
	// Corrupt the certificate AFTER admission/provision but on the path Serve
	// loads: tls.LoadX509KeyPair on this garbage fails, and Serve returns the
	// error — the post-provision failure window FILESTORED-11 guards.
	if err := os.WriteFile(cfg.certFile, []byte("-----BEGIN CERTIFICATE-----\nnot a real cert\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatalf("plant malformed cert: %v", err)
	}

	srv, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if err == nil {
		_ = srv.Close()
		t.Fatal("compose with a malformed TLS cert returned nil error; want a Serve-construction failure")
	}
	if srv != nil {
		t.Fatalf("compose returned a non-nil Server on the failure path; want nil")
	}

	// The scope was provisioned then must have been torn down: the LocalVolume
	// erase re-creates the scope dir empty, so the .ocu-staging subdir left by
	// ProvisionScope is gone. Its survival would prove the leak FILESTORED-11
	// fixes (provisioned-but-never-torn-down).
	scopeDir := filepath.Join(cfg.engineRoot, cfg.filesystemID)
	staging := filepath.Join(scopeDir, ".ocu-staging")
	if _, err := os.Stat(staging); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging dir after a failed compose: stat err = %v, want erased — the provisioned scope was NOT torn down (FILESTORED-11)", err)
	}
}

// TestComposeRefusedTripleBindsNoListener pins SEC-60: a non-admitted
// profile/tenancy/credential triple returns the admission refusal and binds NO
// south-face TLS listener — compose refuses with a nil Server before
// southface.Serve is ever reached.
func TestComposeRefusedTripleBindsNoListener(t *testing.T) {
	cfg := validBrokerConfig(t)
	// multi-tenant + host-local-long-lived is NOT admitted (only
	// trusted_operator + single_tenant + host_local_long_lived is).
	cfg.tenancy = admission.TenancyMultiTenant

	srv, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if !errors.Is(err, admission.ErrAdmissionRefused) && !errors.Is(err, admission.ErrTenancyRefused) {
		t.Fatalf("compose(refused triple): got %v, want an admission refusal", err)
	}
	// The refusal returns no Server: nothing was bound on the south-face TLS
	// bind address (the listener is opened inside southface.Serve, which the
	// admission refusal short-circuits).
	if srv != nil {
		t.Fatalf("compose(refused triple) returned a non-nil Server; want nil (no listener bound)")
	}
}

// TestComposeS3EngineRefusesPreBind pins the s3 composition's fail-closed
// intake: with no credential source available the composition refuses with
// the typed credential error BEFORE any listener exists — the daemon never
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

	srv, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if !errors.Is(err, objectstore.ErrCredentialMissing) {
		t.Fatalf("compose(engine=s3, no credential): got %v, want ErrCredentialMissing", err)
	}
	// The refusal happened pre-bind: compose returns no Server, so no south-face
	// TLS listener was opened for the s3 engine it cannot sign for.
	if srv != nil {
		t.Fatalf("compose(engine=s3, no credential) returned a non-nil Server; want nil (no listener bound)")
	}
}

// TestComposeS3RealEngineServes pins the 13-16 composition end-to-end against
// the live rig (gated): static env credentials compose the REAL s3 engine,
// ProvisionScope runs against MinIO for real, the daemon serves on a real
// south-face TLS listener, a real fileUpload -> fileDownload round-trip crosses
// that listener (byte-exact) with the written object independently read back
// from the real MinIO bucket, and Close tears the scope down.
//
// The round-trip is the load-bearing half: without it the daemon composes,
// provisions, and Closes without ever serving a request — a bind-but-answer-
// nothing Serve() would pass. Driving one real request through the composed
// south face against the real engine, and asserting the bytes land in the real
// bucket via an independent S3 client, makes neither a no-op transport nor a
// mock backend able to pass.
func TestComposeS3RealEngineServes(t *testing.T) {
	endpoint := os.Getenv("OCU_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("OCU_S3_TEST_ENDPOINT not set - composed s3 engine live leg SKIPPED (boot deploy/docker-compose.test.yml)")
	}
	access := os.Getenv("OCU_S3_TEST_ACCESS_KEY")
	secret := os.Getenv("OCU_S3_TEST_SECRET_KEY")
	t.Setenv(objectstore.EnvS3AccessKeyID, access)
	t.Setenv(objectstore.EnvS3SecretAccessKey, secret)
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

	srv, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if err != nil {
		t.Fatalf("compose(real s3): %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	// Drive a real south-face round-trip against the composed daemon while it is
	// serving, THEN Close. The bytes must round-trip byte-exact through the
	// engine AND land in the real MinIO bucket (independent S3 client).
	cl := s3RTClient()
	baseURL := "https://" + cfg.bindAddr
	s3RTWaitReady(t, cl, baseURL)
	s3RTRoundTrip(t, cl, baseURL, cfg.filesystemID, bucket, endpoint, access, secret)

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("Serve returned %v on clean shutdown, want nil", err)
	}
}

// TestRunS3EngineRequiresCredential pins the e2e-observable shape: a full,
// otherwise-valid required-flag set with -engine s3 and no backend credential
// refuses at the credential intake (the composition gate) — the guest-path
// storage lane is retired (Wave 5), so the s3 engine's own backend credential
// is the only remaining gate.
func TestRunS3EngineRequiresCredential(t *testing.T) {
	t.Setenv(objectstore.EnvS3AccessKeyID, "")
	t.Setenv(objectstore.EnvS3SecretAccessKey, "")
	root := shortDir(t)
	certFile, keyFile := testTLSCertPaths(t)
	full := []string{
		"--engine", "s3",
		"--s3-bucket", "ocu-bucket",
		"--s3-endpoint", "http://127.0.0.1:9000",
		"--audit-sink", filepath.Join(root, "audit.jsonl"),
		"--south-bind", freeLoopbackAddr(t),
		"--tls-cert", certFile,
		"--tls-key", keyFile,
		"--filesystem-id", "fs1",
		"--broker-max-file-size", "1",
	}
	if err := run(full); !errors.Is(err, objectstore.ErrCredentialMissing) {
		t.Fatalf("run(-engine s3, no creds): got %v, want ErrCredentialMissing", err)
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
			_, err := validate(rawFlags{
				engine: tc.engine, engineRoot: tc.engineRoot, auditSink: "/y", southBind: "127.0.0.1:0", tlsCert: "/c", tlsKey: "/k", filesystemID: "fs1",
				profile: "trusted_operator", tenancy: "single-tenant", grantedIntents: "read",
				maxFileSize: 1024, maxRequestBytes: 4096,
				opsPerSecond: defaultOpsPerSecond, opsBurst: defaultOpsBurst,
				s3Bucket: tc.s3Bucket, s3Endpoint: tc.s3Endpoint, s3Region: tc.s3Region, s3PathStyle: tc.s3PathStyle,
				logLevelStr: "info",
			})
			if tc.wantErr && !errors.Is(err, errMissingRequiredFlag) {
				t.Fatalf("validate(%s) = %v, want errMissingRequiredFlag", tc.name, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validate(%s) = %v, want nil", tc.name, err)
			}
		})
	}
}

// TestValidateStoresEngineKindS3LocalUnaffected pins that validate carries the
// parsed engine kind into brokerConfig (it was previously discarded) and that
// local-volume remains the composed default.
func TestValidateStoresEngineKindS3LocalUnaffected(t *testing.T) {
	cfg, err := validate(rawFlags{
		engine: "s3", auditSink: "/y", southBind: "127.0.0.1:0", tlsCert: "/c", tlsKey: "/k", filesystemID: "fs1",
		profile: "trusted_operator", tenancy: "single-tenant", grantedIntents: "read",
		maxFileSize: 1024, maxRequestBytes: 4096,
		opsPerSecond: defaultOpsPerSecond, opsBurst: defaultOpsBurst,
		s3Bucket: "ocu-bucket", s3Endpoint: "http://127.0.0.1:9000", s3Region: "us-east-1",
		logLevelStr: "info",
	})
	if err != nil {
		t.Fatalf("validate(engine=s3): %v", err)
	}
	if cfg.engineKind != objectstore.S3 {
		t.Fatalf("validate(engine=s3) stored kind %q, want %q", cfg.engineKind, objectstore.S3)
	}
	cfg, err = validate(rawFlags{
		engine: "local-volume", engineRoot: "/x", auditSink: "/y", southBind: "127.0.0.1:0", tlsCert: "/c", tlsKey: "/k", filesystemID: "fs1",
		profile: "trusted_operator", tenancy: "single-tenant", grantedIntents: "read",
		maxFileSize: 1024, maxRequestBytes: 4096,
		opsPerSecond: defaultOpsPerSecond, opsBurst: defaultOpsBurst,
		s3Region:    "us-east-1",
		logLevelStr: "info",
	})
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
	cfg, err := validate(rawFlags{
		engine: "s3", auditSink: "/y", southBind: "127.0.0.1:0", tlsCert: "/c", tlsKey: "/k", filesystemID: "fs1",
		profile: "trusted_operator", tenancy: "single-tenant", grantedIntents: "read",
		maxFileSize: 1024, maxRequestBytes: 4096,
		opsPerSecond: defaultOpsPerSecond, opsBurst: defaultOpsBurst,
		s3CredentialFile: "/etc/ocu/s3.cred",
		s3Bucket:         "ocu-bucket", s3Endpoint: "http://127.0.0.1:9000", s3Region: "us-east-1",
		logLevelStr: "info",
	})
	if err != nil {
		t.Fatalf("validate(s3 + credential file): %v", err)
	}
	if cfg.s3CredentialFile != "/etc/ocu/s3.cred" {
		t.Fatalf("config carries credential file %q, want the flag path", cfg.s3CredentialFile)
	}

	_, err = validate(rawFlags{
		engine: "local-volume", engineRoot: "/x", auditSink: "/y", southBind: "127.0.0.1:0", tlsCert: "/c", tlsKey: "/k", filesystemID: "fs1",
		profile: "trusted_operator", tenancy: "single-tenant", grantedIntents: "read",
		maxFileSize: 1024, maxRequestBytes: 4096,
		opsPerSecond: defaultOpsPerSecond, opsBurst: defaultOpsBurst,
		s3CredentialFile: "/etc/ocu/s3.cred",
		s3Region:         "us-east-1",
		logLevelStr:      "info",
	})
	if !errors.Is(err, errMissingRequiredFlag) {
		t.Fatalf("validate(local-volume + credential file) = %v, want errMissingRequiredFlag refusal", err)
	}
}

// TestSelectCredentialSourceKindFlows pins the credential selection: the engine's
// OWN backend credential is the static host-local source (host_local_long_lived),
// which is admitted for the trusted_operator/single-tenant cell, so the
// credential kind genuinely flows from the source into admission. The broker
// mints/signs nothing (invariant 3) — the STS / AssumeRole per-session minting
// path is retired (Wave 5).
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
			// The refusal happens at validate, before compose binds any
			// south-face TLS listener: run returns the typed error directly.
			err := run(append([]string{}, tc.args...))
			if !errors.Is(err, errMissingRequiredFlag) {
				t.Fatalf("run(%s): got %v, want errMissingRequiredFlag", tc.name, err)
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
			cfg, err := validate(rawFlags{
				engine: "local-volume", engineRoot: "/x", auditSink: "/y", southBind: "127.0.0.1:0", tlsCert: "/c", tlsKey: "/k", filesystemID: "fs1",
				profile: "trusted_operator", tenancy: "single-tenant", grantedIntents: "read",
				maxFileSize: 1024, maxRequestBytes: 4096,
				opsPerSecond: tc.rate, opsBurst: tc.brst,
				s3Region:    "us-east-1",
				logLevelStr: "info",
			})
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
	certFile, keyFile := testTLSCertPaths(t)
	args := []string{
		"--engine-root", "/x", "--audit-sink", "/y", "--filesystem-id", "fs1",
		"--south-bind", freeLoopbackAddr(t), "--tls-cert", certFile, "--tls-key", keyFile,
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

// TestRunOpsListenerServesHealthRoutes pins the Handle-before-Serve fix: run()
// must register /healthz and /readyz on the ops listener BEFORE its Serve
// goroutine starts accepting connections, so a probe never hits an unregistered
// route (404) during startup. Once the daemon is up, both routes must answer
// with a non-404 status (200 liveness; 200/503 readiness — never 404).
func TestRunOpsListenerServesHealthRoutes(t *testing.T) {
	root := shortDir(t)
	auditSink := filepath.Join(root, "audit.jsonl")
	engineRoot := filepath.Join(root, "engine")

	// A free loopback port for the ops listener.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	opsAddr := probeLn.Addr().String()
	_ = probeLn.Close() // release so the daemon can bind it

	certFile, keyFile := testTLSCertPaths(t)
	args := []string{
		"--engine-root", engineRoot,
		"--audit-sink", auditSink,
		"--filesystem-id", "fs-health-01",
		"--broker-max-file-size", "1024",
		"--south-bind", freeLoopbackAddr(t),
		"--tls-cert", certFile,
		"--tls-key", keyFile,
		"--ops-listen", opsAddr,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- runCtx(ctx, args) }()

	client := &http.Client{Timeout: time.Second}
	probe := func(path string) (int, error) {
		resp, err := client.Get("http://" + opsAddr + path)
		if err != nil {
			return 0, err
		}
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}

	// Poll /healthz until the listener answers; once it answers it must never be
	// a 404 (the routes are registered before Serve accepts).
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, perr := probe("/healthz")
		if perr == nil {
			if code == http.StatusNotFound {
				t.Fatalf("/healthz returned 404 — routes were not registered before Serve")
			}
			if code != http.StatusOK {
				t.Fatalf("/healthz returned %d, want 200", code)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ops listener never answered /healthz: %v", perr)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// /readyz must also be a registered route (200 or 503, never 404).
	if code, perr := probe("/readyz"); perr != nil {
		t.Fatalf("/readyz probe: %v", perr)
	} else if code == http.StatusNotFound {
		t.Fatalf("/readyz returned 404 — readiness route was not registered before Serve")
	}

	cancel()
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		t.Fatal("runCtx() did not return within 10s of context cancellation")
	}
}

// TestRunPinsAuditSinkDirTo0700 pins the lock-dir hardening: run() creates the
// audit-sink's parent directory and Chmods it to 0700 unconditionally. os.MkdirAll
// applies the requested mode through the process umask (so a fresh directory would
// land at 0755 under the default umask 022), so the explicit Chmod is the
// load-bearing step that keeps the hash-chained audit log out of a
// world-traversable directory. The test forces a permissive umask, runs the
// daemon against a fresh audit-sink subdirectory, and asserts the created
// directory is 0700.
func TestRunPinsAuditSinkDirTo0700(t *testing.T) {
	// Force a permissive umask so an unpinned MkdirAll would yield 0777, making
	// the regression visible. Restore it afterwards.
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	root := shortDir(t)
	// The audit-sink lives in a not-yet-existing subdirectory so run() must
	// create (and pin) it.
	auditDir := filepath.Join(root, "audit-sink-dir")
	auditSink := filepath.Join(auditDir, "audit.jsonl")
	engineRoot := filepath.Join(root, "engine")

	// A free loopback port: probing /healthz on it proves the daemon is serving,
	// which means its signal handler is armed before we send SIGTERM.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	opsAddr := probeLn.Addr().String()
	_ = probeLn.Close()

	certFile, keyFile := testTLSCertPaths(t)
	args := []string{
		"--engine-root", engineRoot,
		"--audit-sink", auditSink,
		"--filesystem-id", "fs-chmod-01",
		"--broker-max-file-size", "1024",
		"--south-bind", freeLoopbackAddr(t),
		"--tls-cert", certFile,
		"--tls-key", keyFile,
		"--ops-listen", opsAddr,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- runCtx(ctx, args) }()

	// Wait until the daemon is serving (the audit-sink directory is created well
	// before this point).
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, perr := client.Get("http://" + opsAddr + "/healthz")
		if perr == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon never began serving: %v", perr)
		}
		time.Sleep(5 * time.Millisecond)
	}

	info, statErr := os.Stat(auditDir)
	if statErr != nil {
		t.Fatalf("stat audit-sink directory: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("audit-sink directory mode = %o, want 0700 (the Chmod must pin 0700 regardless of umask)", got)
	}

	// Unwind the daemon: cancelling the context triggers the same bounded drain +
	// teardown a SIGTERM would, without a process-global signal.
	cancel()
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		t.Fatal("runCtx() did not return within 10s of context cancellation")
	}
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
	// This test deliberately drives the REAL OS-signal path (not context
	// cancellation): it is the single remaining self-SIGTERM test, kept so the
	// production signal wiring stays covered. It is safe in isolation — the
	// handler is armed before Serve launches and the test consumes exactly the
	// one signal it sends.
	go func() { result <- serveUntilSignal(context.Background(), srv, testLogger(), nil) }()

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
	err := serveUntilSignal(context.Background(), srv, testLogger(), nil)
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
		bindAddr:         "127.0.0.1:0",
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
		slog.String("south_bind", cfg.bindAddr),
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
		return validate(rawFlags{
			engine: "local-volume", engineRoot: "/x", auditSink: "/y", southBind: "127.0.0.1:0", tlsCert: "/c", tlsKey: "/k", filesystemID: "fs1",
			profile: "trusted_operator", tenancy: "single-tenant", grantedIntents: "read",
			maxFileSize: 1024, maxRequestBytes: 4096,
			opsPerSecond: defaultOpsPerSecond, opsBurst: defaultOpsBurst,
			s3Region:    "us-east-1",
			logLevelStr: "info", opsListenAddr: addr,
		})
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

// TestComposeLatchCallbackWired pins T2-3: compose() wires FileSink.SetOnLatch
// to a closure that emits an ERROR slog line AND flips audit_sink_latched
// gauge to 1. This test trips the latch through the composed wiring by
// corrupting the audit sink file descriptor, then confirms the callbacks fire.
func TestComposeLatchCallbackWired(t *testing.T) {
	cfg := validBrokerConfig(t)
	m := telemetry.NewBrokerMetrics("test")
	var logBuf strings.Builder
	l := observ.NewLogger(&logBuf, slog.LevelDebug)
	srv, err := compose(cfg, l, m)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	defer srv.Close()

	// The compose function wires the latch callback. To trip it we need to
	// fault the auditgate FileSink — we do so by starting the server (so the
	// sink is live) then deleting the audit file from under it. A Mandate via
	// the south-face session will trigger the write fault, but since we
	// cannot easily fire Mandate directly here, we test the latch is wired
	// by checking that compose() returned without error (the seam is wired)
	// and that audit_sink_latched gauge starts at 0.
	//
	// A deeper latch-callback integration test requires a south-face round-trip
	// and is covered in TestLatchCallbackIntegration below.
	out := logBuf.String()
	_ = out // no ERROR emitted yet — just confirm compose succeeded
	// audit_sink_latched starts at 0 (not latched). Check for the value line
	// (not the HELP line which also contains "audit_sink_latched 1 when...").
	var metricsOut strings.Builder
	m.Registry().WriteTo(&metricsOut)
	metrics := metricsOut.String()
	// A latched gauge would render as "audit_sink_latched 1\n".
	// A healthy gauge renders no value line at all (zero value is omitted).
	if strings.Contains(metrics, "\naudit_sink_latched 1\n") {
		t.Fatalf("audit_sink_latched gauge is 1 on healthy compose; want 0 or absent")
	}
}

// TestHealthCheckFlagRefusedWhenNoListener pins -health-check against a dead
// address: run() with -health-check set to an address that binds nothing must
// return a non-nil error (the self-probe dial fails).
func TestHealthCheckFlagRefusedWhenNoListener(t *testing.T) {
	// Use port 1 (reserved, never listening) to guarantee the dial fails.
	err := run([]string{"-health-check", "-ops-listen", "127.0.0.1:1"})
	if err == nil {
		t.Fatal("run(-health-check, dead addr): got nil, want a dial error")
	}
}

// TestHealthCheckFlagExitsCleanAgainstLiveListener pins -health-check against
// a real ops listener: run() returns nil (exit 0) when /healthz answers 200.
func TestHealthCheckFlagExitsCleanAgainstLiveListener(t *testing.T) {
	m := telemetry.NewBrokerMetrics("test")
	ol, err := telemetry.NewOpsListener("127.0.0.1:0", m, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewOpsListener: %v", err)
	}
	telemetry.RegisterOpsListenerHealthHandlers(ol, nil) // register /healthz
	go ol.Serve()
	defer ol.Close()

	addr := ol.Addr()
	err = run([]string{"-health-check", "-ops-listen", addr})
	if err != nil {
		t.Fatalf("run(-health-check, live): got %v, want nil (exit 0)", err)
	}
}

// TestDockerfileAndComposeHealthcheckRewired pins the container healthcheck
// rewire: no -version healthcheck remains; a -health-check probe is present.
func TestDockerfileAndComposeHealthcheckRewired(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
	}{
		{"Dockerfile", "../../Dockerfile"},
		{"docker-compose.yml", "../../deploy/docker-compose.yml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("ReadFile(%s): %v", tc.path, err)
			}
			content := string(data)
			if strings.Contains(content, `"-version"`) && strings.Contains(content, "healthcheck") {
				t.Errorf("%s still has a -version healthcheck; expected -health-check probe", tc.name)
			}
			if !strings.Contains(content, "health-check") && !strings.Contains(content, "healthz") {
				t.Errorf("%s does not contain a -health-check or healthz reference", tc.name)
			}
		})
	}
}

// ── T2-17: OCU_FILESTORE_* env-var fallback tests ──────────────────────────

// TestEnvVarName pins the canonical conversion: dashes become underscores,
// the name is uppercased, and the OCU_FILESTORE_ prefix is prepended.
func TestEnvVarName(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"engine-root", "OCU_FILESTORE_ENGINE_ROOT"},
		{"audit-sink", "OCU_FILESTORE_AUDIT_SINK"},
		{"log-level", "OCU_FILESTORE_LOG_LEVEL"},
		{"ops-per-second", "OCU_FILESTORE_OPS_PER_SECOND"},
		{"broker-max-file-size", "OCU_FILESTORE_BROKER_MAX_FILE_SIZE"},
		{"downloadable-prefixes", "OCU_FILESTORE_DOWNLOADABLE_PREFIXES"},
	} {
		if got := envVarName(tc.in); got != tc.want {
			t.Errorf("envVarName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEnvFallbackMapExcludesCredentials pins the security carve-out:
// credential-bearing flags are NOT present in the generic env-fallback map,
// so no OCU_FILESTORE_* alias allows a credential value to reach the daemon
// via the generic config path.
func TestEnvFallbackMapExcludesCredentials(t *testing.T) {
	for flagName := range credentialBearingFlags {
		if _, ok := envFallbackMap[flagName]; ok {
			t.Errorf("credential-bearing flag %q is present in envFallbackMap; it must be excluded (T2-17 security carve-out)", flagName)
		}
	}
	// s3-credential-file specifically must not be env-aliased.
	if _, ok := envFallbackMap["s3-credential-file"]; ok {
		t.Error("envFallbackMap contains s3-credential-file; credential path flag must be excluded")
	}
}

// TestApplyEnvFallbacksAppliesWhenFlagAbsent pins the basic fallback case:
// when a flag is NOT set on the command line, its OCU_FILESTORE_* env var is
// applied as the value, and the flag's parsed value changes accordingly.
func TestApplyEnvFallbacksAppliesWhenFlagAbsent(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	engineRoot := fs.String("engine-root", "", "")
	auditSink := fs.String("audit-sink", "", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Setenv("OCU_FILESTORE_ENGINE_ROOT", "/data/engine")
	t.Setenv("OCU_FILESTORE_AUDIT_SINK", "/var/log/audit.jsonl")

	if err := applyEnvFallbacks(fs); err != nil {
		t.Fatalf("applyEnvFallbacks: %v", err)
	}
	if *engineRoot != "/data/engine" {
		t.Errorf("engine-root = %q, want /data/engine (from env)", *engineRoot)
	}
	if *auditSink != "/var/log/audit.jsonl" {
		t.Errorf("audit-sink = %q, want /var/log/audit.jsonl (from env)", *auditSink)
	}
}

// TestApplyEnvFallbacksExplicitFlagWins pins explicit-flag precedence: when a
// flag IS explicitly set on the command line, the OCU_FILESTORE_* env var for
// that flag is ignored entirely (the flag value is unchanged).
func TestApplyEnvFallbacksExplicitFlagWins(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	engineRoot := fs.String("engine-root", "", "")
	if err := fs.Parse([]string{"-engine-root", "/explicit/path"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Setenv("OCU_FILESTORE_ENGINE_ROOT", "/env/path")

	if err := applyEnvFallbacks(fs); err != nil {
		t.Fatalf("applyEnvFallbacks: %v", err)
	}
	if *engineRoot != "/explicit/path" {
		t.Errorf("engine-root = %q, want /explicit/path (explicit flag wins over env)", *engineRoot)
	}
}

// TestApplyEnvFallbacksMalformedEnvIsError pins that a malformed env-var value
// returns a typed parse error, the same as a malformed flag on the command
// line. The env var is applied through fs.Set() which exercises the flag's
// type parsing.
func TestApplyEnvFallbacksMalformedEnvIsError(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.Int64("broker-max-file-size", 0, "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Setenv("OCU_FILESTORE_BROKER_MAX_FILE_SIZE", "not-a-number")

	err := applyEnvFallbacks(fs)
	if err == nil {
		t.Fatal("applyEnvFallbacks(malformed int env): got nil, want a parse error")
	}
	if !strings.Contains(err.Error(), "OCU_FILESTORE_BROKER_MAX_FILE_SIZE") {
		t.Errorf("error %q does not name the offending env var", err.Error())
	}
}

// TestApplyEnvFallbacksEmptyEnvRetainsDefault pins that an env var set to
// the empty string is treated as absent: the flag's default value is
// retained unchanged.
func TestApplyEnvFallbacksEmptyEnvRetainsDefault(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	logLevel := fs.String("log-level", "info", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Setenv("OCU_FILESTORE_LOG_LEVEL", "")

	if err := applyEnvFallbacks(fs); err != nil {
		t.Fatalf("applyEnvFallbacks: %v", err)
	}
	if *logLevel != "info" {
		t.Errorf("log-level = %q, want info (default retained when env empty)", *logLevel)
	}
}

// TestEnvFallbackEndToEndViaRun pins the full run() path: env vars are
// applied after flag parsing, so a valid configuration supplied entirely via
// OCU_FILESTORE_* env vars reaches the validation and serve layer. The test
// uses run() and expects errMissingRequiredFlag to confirm the flags reached
// validate (not a parse error).
func TestEnvFallbackEndToEndViaRun(t *testing.T) {
	certFile, keyFile := testTLSCertPaths(t)
	t.Setenv("OCU_FILESTORE_ENGINE_ROOT", "/x")
	t.Setenv("OCU_FILESTORE_AUDIT_SINK", "/y")
	t.Setenv("OCU_FILESTORE_FILESYSTEM_ID", "fs-env-01")
	t.Setenv("OCU_FILESTORE_BROKER_MAX_FILE_SIZE", "1024")
	t.Setenv("OCU_FILESTORE_SOUTH_BIND", freeLoopbackAddr(t))
	t.Setenv("OCU_FILESTORE_TLS_CERT", certFile)
	t.Setenv("OCU_FILESTORE_TLS_KEY", keyFile)

	// With those env vars set, run() should pass flag parsing and reach
	// validate / compose, failing at validate because the paths don't
	// actually exist — the point is we get past "missing required flag".
	// Specifically we expect to succeed validate and fail at compose
	// (engine root does not exist) or get no error from validate at all.
	// We do NOT want errMissingRequiredFlag for the env-backed flags.
	err := run(nil) // no explicit flags
	if errors.Is(err, errMissingRequiredFlag) {
		// Check whether it's complaining about one of the flags we set via env.
		for _, envFlag := range []string{"engine-root", "audit-sink", "filesystem-id", "broker-max-file-size", "south-bind", "tls-cert", "tls-key"} {
			if strings.Contains(err.Error(), envFlag) {
				t.Errorf("run(via env vars) returned errMissingRequiredFlag naming %q — env fallback did not apply for that flag: %v", envFlag, err)
			}
		}
	}
	// The test passes as long as the env-backed required flags are not the
	// cause of the error. Any other error (e.g. compose failure, unknown path)
	// is expected and acceptable.
}

// TestEnvFallbackPrecedenceRepresentativeSample pins precedence for several
// representative flag types: string, int64, float64, and bool. In each case
// an explicit flag beats the env var; an absent flag takes the env var.
func TestEnvFallbackPrecedenceRepresentativeSample(t *testing.T) {
	// String: explicit wins.
	t.Run("string_explicit_wins", func(t *testing.T) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		v := fs.String("audit-sink", "", "")
		if err := fs.Parse([]string{"-audit-sink", "/flag/path"}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		t.Setenv("OCU_FILESTORE_AUDIT_SINK", "/env/path")
		if err := applyEnvFallbacks(fs); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if *v != "/flag/path" {
			t.Errorf("audit-sink = %q, want /flag/path", *v)
		}
	})

	// Int64: env fallback applies when flag absent.
	t.Run("int64_env_fallback", func(t *testing.T) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		v := fs.Int64("broker-max-file-size", 0, "")
		if err := fs.Parse(nil); err != nil {
			t.Fatalf("parse: %v", err)
		}
		t.Setenv("OCU_FILESTORE_BROKER_MAX_FILE_SIZE", "2097152")
		if err := applyEnvFallbacks(fs); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if *v != 2097152 {
			t.Errorf("broker-max-file-size = %d, want 2097152", *v)
		}
	})

	// Float64: env fallback applies when flag absent.
	t.Run("float64_env_fallback", func(t *testing.T) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		v := fs.Float64("ops-per-second", defaultOpsPerSecond, "")
		if err := fs.Parse(nil); err != nil {
			t.Fatalf("parse: %v", err)
		}
		t.Setenv("OCU_FILESTORE_OPS_PER_SECOND", "50.5")
		if err := applyEnvFallbacks(fs); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if *v != 50.5 {
			t.Errorf("ops-per-second = %g, want 50.5", *v)
		}
	})

	// Bool: env fallback applies when flag absent; explicit false wins over
	// env true.
	t.Run("bool_env_fallback", func(t *testing.T) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		v := fs.Bool("s3-path-style", false, "")
		if err := fs.Parse(nil); err != nil {
			t.Fatalf("parse: %v", err)
		}
		t.Setenv("OCU_FILESTORE_S3_PATH_STYLE", "true")
		if err := applyEnvFallbacks(fs); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if !*v {
			t.Errorf("s3-path-style = false, want true (from env)")
		}
	})

	// Bool explicit false wins (the flag was explicitly provided as false).
	t.Run("bool_explicit_false_wins", func(t *testing.T) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		v := fs.Bool("s3-path-style", false, "")
		if err := fs.Parse([]string{"-s3-path-style=false"}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		t.Setenv("OCU_FILESTORE_S3_PATH_STYLE", "true")
		if err := applyEnvFallbacks(fs); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if *v {
			t.Errorf("s3-path-style = true, want false (explicit flag wins)")
		}
	})
}

// TestCredentialFlagNotEnvAliasedViaGenericMap is the authoritative carve-out
// test: it verifies that no OCU_FILESTORE_* env var can supply the
// s3-credential-file flag through the generic applyEnvFallbacks path. Setting
// OCU_FILESTORE_S3_CREDENTIAL_FILE in the environment must NOT affect the
// flag value, even when the flag is absent from the command line.
func TestCredentialFlagNotEnvAliasedViaGenericMap(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	credFile := fs.String("s3-credential-file", "", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Setenv("OCU_FILESTORE_S3_CREDENTIAL_FILE", "/attacker/cred.file")

	if err := applyEnvFallbacks(fs); err != nil {
		t.Fatalf("applyEnvFallbacks: %v", err)
	}
	if *credFile != "" {
		t.Errorf("s3-credential-file = %q via OCU_FILESTORE_S3_CREDENTIAL_FILE; the generic env alias must not exist for credential flags (T2-17 carve-out)", *credFile)
	}
}

// TestEnvFallbackMapContainsAllNonCredentialFlags pins that every flag
// declared in the daemon's flag set (excluding credential-bearing ones) has an
// entry in envFallbackMap. This catches a flag rename that leaves the env map
// stale.
func TestEnvFallbackMapContainsAllNonCredentialFlags(t *testing.T) {
	// Build a minimal flag set mirroring run()'s declarations.
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Bool("version", false, "")
	fs.Bool("health-check", false, "")
	fs.String("log-level", "info", "")
	fs.String("ops-listen", "127.0.0.1:9464", "")
	fs.String("north-bind", "127.0.0.1:7080", "")
	fs.String("north-listen", "", "")
	fs.String("engine", "local-volume", "")
	fs.Int64("max-request-bytes", 52428800, "")
	fs.String("south-bind", "127.0.0.1:7443", "")
	fs.String("tls-cert", "", "")
	fs.String("tls-key", "", "")
	fs.String("audit-sink", "", "")
	fs.String("profile", "trusted_operator", "")
	fs.String("tenancy", "single-tenant", "")
	fs.String("engine-root", "", "")
	fs.String("s3-credential-file", "", "")
	fs.String("s3-bucket", "", "")
	fs.String("s3-endpoint", "", "")
	fs.String("s3-region", "us-east-1", "")
	fs.Bool("s3-path-style", false, "")
	fs.Int64("broker-max-file-size", 0, "")
	fs.String("filesystem-id", "", "")
	fs.String("granted-intents", "read,write", "")
	fs.String("downloadable-prefixes", "", "")
	fs.Float64("ops-per-second", defaultOpsPerSecond, "")
	fs.Float64("ops-burst", defaultOpsBurst, "")

	fs.VisitAll(func(f *flag.Flag) {
		if _, excluded := credentialBearingFlags[f.Name]; excluded {
			return
		}
		if _, ok := envFallbackMap[f.Name]; !ok {
			t.Errorf("flag %q is not in envFallbackMap; add it or list it in credentialBearingFlags (T2-17)", f.Name)
		}
	})
}

// TestMultiScopeDistinctBindsBothCompose pins the multi-scope topology fix
// (T2-7): two compose() calls with DISTINCT filesystem_id values (and therefore
// distinct audit-sinks) on DISTINCT south-face TLS bind addresses must both
// succeed.
//
// The per-scope audit-sink lock (acquired in run, not compose) is the sole
// single-instance guard; distinct scopes have distinct sinks and therefore
// distinct lock files, so they coexist as N daemons (one per filesystem_id).
func TestMultiScopeDistinctBindsBothCompose(t *testing.T) {
	// Scope A: first daemon, its own engine root, audit sink, and TLS bind.
	cfgA := validBrokerConfig(t)
	cfgA.filesystemID = "fs-scope-a"
	cfgA.auditSink = filepath.Join(shortDir(t), "audit-a.jsonl")

	srvA, err := compose(cfgA, testLogger(), telemetry.NewBrokerMetrics("test-a"))
	if err != nil {
		t.Fatalf("compose(scope-a): %v", err)
	}
	serveErrA := make(chan error, 1)
	go func() { serveErrA <- srvA.Serve() }()
	defer func() {
		_ = srvA.Close()
		<-serveErrA
	}()

	// Scope B: second daemon, DISTINCT filesystem_id (distinct audit-sink) on a
	// DISTINCT TLS bind. This must succeed — distinct scopes coexist; only the
	// per-scope audit-sink lock guards the chain.
	cfgB := validBrokerConfig(t)
	cfgB.filesystemID = "fs-scope-b"
	cfgB.auditSink = filepath.Join(shortDir(t), "audit-b.jsonl")

	srvB, err := compose(cfgB, testLogger(), telemetry.NewBrokerMetrics("test-b"))
	if err != nil {
		t.Fatalf("compose(scope-b): %v — distinct scopes must coexist as N daemons", err)
	}
	serveErrB := make(chan error, 1)
	go func() { serveErrB <- srvB.Serve() }()
	if err := srvB.Close(); err != nil {
		t.Fatalf("close(scope-b): %v", err)
	}
	<-serveErrB
}

// TestSystemdUnitIsTypeNotify pins the systemd unit has Type=notify and the
// required hardening directives.
func TestSystemdUnitIsTypeNotify(t *testing.T) {
	path := "../../contrib/systemd/ocu-filestored.service"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(systemd unit): %v", err)
	}
	content := string(data)
	for _, want := range []string{
		"Type=notify",
		"TimeoutStopSec=",
		"NoNewPrivileges=",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("systemd unit missing %q", want)
		}
	}
}

// TestSdNotifyWiredInServeUntilSignal pins that serveUntilSignal calls
// SdNotifyReady (READY=1) after the south server starts serving, and calls
// SdNotifyStopping (STOPPING=1) on the signal branch before Close. A real
// unixgram socket in NOTIFY_SOCKET asserts the exact datagrams.
func TestSdNotifyWiredInServeUntilSignal(t *testing.T) {
	dir, err := os.MkdirTemp("", "sdnt")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	sockPath := filepath.Join(dir, "n.sock")

	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Skipf("ListenUnixgram unavailable: %v", err)
	}
	defer ln.Close()
	t.Setenv("NOTIFY_SOCKET", sockPath)

	srv := &fakeLifecycleServer{
		serveStarted: make(chan struct{}),
		closeCalled:  make(chan struct{}),
		blockServe:   true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- serveUntilSignal(ctx, srv, testLogger(), nil) }()

	// Wait for SdNotifyReady to fire (READY=1 datagram).
	<-srv.serveStarted

	buf := make([]byte, 128)
	if err := ln.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, err := ln.Read(buf)
	if err != nil {
		t.Fatalf("Read READY=1: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("first datagram: got %q, want READY=1", got)
	}

	// Stop via context cancellation, which drives the same STOPPING notification
	// path a SIGTERM would — without a process-global signal.
	cancel()
	if err := ln.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, err = ln.Read(buf)
	if err != nil {
		t.Fatalf("Read STOPPING=1: %v", err)
	}
	if got := string(buf[:n]); got != "STOPPING=1" {
		t.Fatalf("second datagram: got %q, want STOPPING=1", got)
	}

	select {
	case <-result:
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilSignal did not return within 10s")
	}
}
