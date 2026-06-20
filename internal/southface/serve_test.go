// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// serveFakeResolver is a minimal Resolver that always grants. The Serve
// lifecycle tests never drive a request through it; they only need a non-nil
// seam so the wiring guard passes.
type serveFakeResolver struct{}

func (serveFakeResolver) Resolve(context.Context, any, ResolveRequest) (Grant, error) {
	return Grant{}, nil
}

// serveFakeGuard always mandates successfully.
type serveFakeGuard struct{}

func (serveFakeGuard) Mandate(context.Context, any) error { return nil }

// serveFakeEngine is a do-nothing engine; the Serve lifecycle tests register
// it only so the dispatcher wires the handler registry.
type serveFakeEngine struct{}

func (serveFakeEngine) List(context.Context, string, string) ([]FileInfo, error) {
	return nil, nil
}
func (serveFakeEngine) Stat(context.Context, string, string) (FileInfo, error) {
	return FileInfo{}, nil
}
func (serveFakeEngine) MakeDir(context.Context, string, string) error                { return nil }
func (serveFakeEngine) MoveDir(context.Context, string, string, string, bool) error  { return nil }
func (serveFakeEngine) RemoveDir(context.Context, string, string) error              { return nil }
func (serveFakeEngine) CopyFile(context.Context, string, string, string, bool) error { return nil }
func (serveFakeEngine) MoveFile(context.Context, string, string, string, bool) error { return nil }
func (serveFakeEngine) RemoveFile(context.Context, string, string) error             { return nil }
func (serveFakeEngine) ReadRange(context.Context, string, string, int64, int64, io.Writer) error {
	return nil
}
func (serveFakeEngine) WriteStream(context.Context, string, string, io.Reader, bool) error {
	return nil
}

// serveFakeExtractor binds every presented bearer to a fixed scope. The
// lifecycle tests only need a non-nil credential-scope source so the wiring
// guard passes; they do not drive a real request through it.
func serveFakeExtractor() CredentialScopeExtractor {
	return NewCredentialScopeExtractor(func(bearer string) (CredentialScope, error) {
		if bearer == "" {
			return CredentialScope{}, nil
		}
		return CredentialScope{FilesystemID: "fs-serve-01", GrantedIntents: []Intent{IntentRead, IntentWrite}}, nil
	})
}

// serveTestCert writes a fresh self-signed loopback certificate + key to two
// PEM files under the test temp dir and returns their paths plus a cert pool
// trusting the certificate.
func serveTestCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-filestore-serve-test"},
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
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: no certificate parsed")
	}
	return certFile, keyFile, pool
}

// freeLoopbackAddr returns a currently-free loopback host:port. There is a
// small race between the probe close and the server rebind, acceptable in a
// single-process test.
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

func serveValidConfig(t *testing.T) Config {
	t.Helper()
	certFile, keyFile, _ := serveTestCert(t)
	return Config{
		Resolver:          serveFakeResolver{},
		Guard:             serveFakeGuard{},
		Ceilings:          ceilingsRegistryStub(),
		Engine:            serveFakeEngine{},
		CredExtractor:     serveFakeExtractor(),
		BindAddr:          freeLoopbackAddr(t),
		CertFile:          certFile,
		KeyFile:           keyFile,
		SizeCeiling:       4 << 20,
		BrokerMaxFileSize: 1 << 30,
	}
}

// ceilingsRegistryStub returns a non-enforcing CeilingsRegistry for the Serve
// lifecycle tests. A nil-safe in-package fake keeps the test independent of
// the broker adapter package.
func ceilingsRegistryStub() CeilingsRegistry { return serveFakeCeilings{} }

type serveFakeCeilings struct{}

func (serveFakeCeilings) Session(string) CeilingsSession { return serveFakeSession{} }
func (serveFakeCeilings) Release(string)                 {}

type serveFakeSession struct{}

func (serveFakeSession) TryConsumeOp() error      { return nil }
func (serveFakeSession) AcquireBytes(int64) error { return nil }
func (serveFakeSession) ReleaseBytes(int64)       {}
func (serveFakeSession) TryAcquireFD() error      { return nil }
func (serveFakeSession) ReleaseFD()               {}

// TestServeRejectsUnsetBrokerMaxFileSize pins SEC-46/78: a non-positive
// BrokerMaxFileSize is a wiring fault that returns a typed error, never a
// silent default.
func TestServeRejectsUnsetBrokerMaxFileSize(t *testing.T) {
	for _, bad := range []int64{0, -1} {
		cfg := serveValidConfig(t)
		cfg.BrokerMaxFileSize = bad
		if _, err := Serve(cfg); !errors.Is(err, ErrBrokerMaxFileSizeUnset) {
			t.Fatalf("Serve(BrokerMaxFileSize=%d): got %v, want ErrBrokerMaxFileSizeUnset", bad, err)
		}
	}
}

// TestServeRejectsNilSeams pins the fail-loud wiring guard: a nil
// Resolver/Guard/Engine/Ceilings/CredExtractor returns ErrSeamMissing, never a
// latent nil-deref on the serve path.
func TestServeRejectsNilSeams(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"nil_resolver", func(c *Config) { c.Resolver = nil }},
		{"nil_guard", func(c *Config) { c.Guard = nil }},
		{"nil_engine", func(c *Config) { c.Engine = nil }},
		{"nil_ceilings", func(c *Config) { c.Ceilings = nil }},
		{"nil_credextractor", func(c *Config) { c.CredExtractor = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := serveValidConfig(t)
			tc.mutate(&cfg)
			if _, err := Serve(cfg); !errors.Is(err, ErrSeamMissing) {
				t.Fatalf("Serve(%s): got %v, want ErrSeamMissing", tc.name, err)
			}
		})
	}
}

// TestServeRejectsMissingTLSMaterial pins that a missing bind address or an
// unreadable cert/key refuses startup with a typed TLS-config error rather than
// binding a half-configured listener.
func TestServeRejectsMissingTLSMaterial(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty_bind", func(c *Config) { c.BindAddr = "" }},
		{"empty_cert", func(c *Config) { c.CertFile = "" }},
		{"empty_key", func(c *Config) { c.KeyFile = "" }},
		{"missing_cert_file", func(c *Config) { c.CertFile = filepath.Join(t.TempDir(), "nope.pem") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := serveValidConfig(t)
			tc.mutate(&cfg)
			if _, err := Serve(cfg); !errors.Is(err, errTLSConfig) {
				t.Fatalf("Serve(%s): got %v, want errTLSConfig", tc.name, err)
			}
		})
	}
}

// TestServeSetsMaxFileSizeFromConfig pins finding #2: the returned server's
// dispatcher carries maxFileSize == cfg.BrokerMaxFileSize, NOT sizeCeiling.
// This is the only place the unexported field is set from a flag value.
func TestServeSetsMaxFileSizeFromConfig(t *testing.T) {
	cfg := serveValidConfig(t)
	cfg.SizeCeiling = 4 << 20
	cfg.BrokerMaxFileSize = 123_456_789
	srv, err := Serve(cfg)
	if err != nil {
		t.Fatalf("Serve: unexpected error %v", err)
	}
	defer srv.Close()
	ts, ok := srv.(*tlsServer)
	if !ok {
		t.Fatalf("Serve returned %T, want *tlsServer", srv)
	}
	router, ok := ts.srv.Handler.(*restRouter)
	if !ok {
		t.Fatalf("server handler is %T, want *restRouter", ts.srv.Handler)
	}
	d := router.dispatcher
	if d.maxFileSize != cfg.BrokerMaxFileSize {
		t.Fatalf("maxFileSize = %d, want %d (BrokerMaxFileSize, not sizeCeiling)", d.maxFileSize, cfg.BrokerMaxFileSize)
	}
	if d.maxFileSize == d.sizeCeiling {
		t.Fatalf("maxFileSize must be distinct from sizeCeiling; both are %d", d.maxFileSize)
	}
	if d.credExtractor == nil {
		t.Fatal("Serve did not wire the credential-scope extractor onto the dispatcher")
	}
}

// TestServeServesAndCloses pins the lifecycle: the returned Server serves over
// TLS HTTP/2 and answers a request, and Close shuts it down cleanly.
func TestServeServesAndCloses(t *testing.T) {
	certFile, keyFile, pool := serveTestCert(t)
	addr := freeLoopbackAddr(t)
	cfg := Config{
		Resolver:          serveFakeResolver{},
		Guard:             serveFakeGuard{},
		Ceilings:          ceilingsRegistryStub(),
		Engine:            serveFakeEngine{},
		CredExtractor:     serveFakeExtractor(),
		BindAddr:          addr,
		CertFile:          certFile,
		KeyFile:           keyFile,
		SizeCeiling:       4 << 20,
		BrokerMaxFileSize: 1 << 30,
	}
	srv, err := Serve(cfg)
	if err != nil {
		t.Fatalf("Serve: unexpected error %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		Timeout:   3 * time.Second,
	}
	// The server rebinds the just-freed port in its goroutine; retry the dial
	// briefly so the test does not race the bind.
	probe := "https://" + addr + "/v1/filestore/fs/readFile"
	deadline := time.Now().Add(3 * time.Second)
	var reached bool
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, probe, nil)
		resp, derr := client.Do(req)
		if derr == nil {
			resp.Body.Close()
			reached = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reached {
		t.Fatal("TLS south-face server did not become reachable")
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("Serve returned %v, want nil on clean shutdown", err)
	}
}
