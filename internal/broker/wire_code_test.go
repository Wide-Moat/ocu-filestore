// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker

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
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/authz"
	"github.com/Wide-Moat/ocu-filestore/internal/ceilings"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// TestGuardAdapterRemapsAuditUnavailable pins the FC-01 remap in isolation:
// the real auditgate.ErrAuditUnavailable (bare and wrapped) crosses the
// adapter as the southface mirror the spine's denyClassForErr classifies to
// unavailable/503; a non-sentinel error passes through (denyInternal).
func TestGuardAdapterRemapsAuditUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   error
		want bool // expect the southface mirror
	}{
		{"bare_sentinel", auditgate.ErrAuditUnavailable, true},
		{"wrapped_sentinel", fmt.Errorf("ctx: %w", auditgate.ErrAuditUnavailable), true},
		{"non_sentinel_passthrough", errors.New("boom"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := NewGuard(stubGuard{err: tc.in}).Mandate(context.Background(), struct{}{})
			if got := errors.Is(err, southface.ErrAuditUnavailable); got != tc.want {
				t.Fatalf("errors.Is(err, southface.ErrAuditUnavailable) = %v, want %v (err %v)", got, tc.want, err)
			}
			if err == nil {
				t.Fatal("a guard error was dropped to nil")
			}
		})
	}
}

// TestCeilingsAdapterRemapsSentinels pins the FC-02 remap against the REAL
// limiter package: each exhausted ceiling crosses the adapter as the
// southface mirror (throttle/bytes/fd), so the spine classifies it to
// resource_exhausted/429 instead of internal/500.
func TestCeilingsAdapterRemapsSentinels(t *testing.T) {
	fixed := time.Unix(0, 0)
	// OpsPerSecond:1, OpsBurst:1 satisfies the fail-loud contract.
	// The clock is frozen so no tokens refill between calls. We drain the
	// single burst token with the first TryConsumeOp call; every subsequent
	// call then returns ErrThrottleExceeded deterministically — no wall-time
	// dependency, no flake.
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         1,
		OpsBurst:             1,
		InFlightBytesCeiling: 4,
		FDCeiling:            0, // zero is valid (>= 0); TryAcquireFD fails immediately
		Clock:                func() time.Time { return fixed },
	})
	sess := NewCeilings(reg).Session("fs-exhausted")

	// Drain the single burst token so the bucket is now empty.
	if err := sess.TryConsumeOp(); err != nil {
		t.Fatalf("pre-drain TryConsumeOp: got %v, want nil", err)
	}

	// Bucket is empty — the next op must remap to the southface sentinel.
	if err := sess.TryConsumeOp(); !errors.Is(err, southface.ErrThrottleExceeded) {
		t.Fatalf("TryConsumeOp: got %v, want the southface.ErrThrottleExceeded mirror", err)
	}
	if err := sess.AcquireBytes(8); !errors.Is(err, southface.ErrBytesExceeded) {
		t.Fatalf("AcquireBytes(over): got %v, want the southface.ErrBytesExceeded mirror", err)
	}
	if err := sess.TryAcquireFD(); !errors.Is(err, southface.ErrFDExceeded) {
		t.Fatalf("TryAcquireFD: got %v, want the southface.ErrFDExceeded mirror", err)
	}
	// Positive control: an in-ceiling acquire stays nil and the release pair
	// passes through to the real gauge.
	if err := sess.AcquireBytes(2); err != nil {
		t.Fatalf("AcquireBytes(in-ceiling): got %v, want nil", err)
	}
	sess.ReleaseBytes(2)
}

// downGuard is an auditgate.Guard whose every Mandate fails with the REAL
// auditgate sentinel — the faulted-FileSink stand-in (the real sink returns
// exactly this on any durable-write failure).
type downGuard struct{}

func (downGuard) Mandate(context.Context, any) error { return auditgate.ErrAuditUnavailable }

// testTLSCert writes a fresh self-signed loopback certificate + key to two PEM
// files under the test temp dir and returns their paths along with a cert pool
// trusting the certificate. It lets the live end-to-end tests drive the REAL
// TLS HTTP/2 south face the way a guest dials it (guest -> edge -> service over
// HTTPS) without depending on any on-disk fixture.
func testTLSCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ocu-filestore-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
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
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: no certificate parsed")
	}
	return certFile, keyFile, pool
}

// serveSouthface stands up a REAL south-face TLS HTTP/2 server with the REAL
// broker adapters bound (resolver over authz, the given guard and ceilings
// registry, the engine adapter over the stub engine) and returns a client that
// dials it over HTTPS. The credential-scope extractor binds every presented
// bearer to the "fs-wire" scope (the edge-injected-credential model: the
// service receives the real credential on Authorization: Bearer and never
// JWKS-verifies it). The returned base URL is the service_url the client posts
// to.
func serveSouthface(t *testing.T, guard auditgate.Guard, reg *ceilings.Registry) (*http.Client, string) {
	t.Helper()
	resolver := authz.New(func(context.Context, authz.FilesystemID, string) (bool, error) {
		return true, nil
	})
	certFile, keyFile, pool := testTLSCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // free the port; the server rebinds it (a small race window, acceptable in tests)

	extractor := southface.NewCredentialScopeExtractor(func(bearer string) (southface.CredentialScope, error) {
		if bearer == "" {
			return southface.CredentialScope{}, nil
		}
		return southface.CredentialScope{
			FilesystemID:   "fs-wire",
			GrantedIntents: []southface.Intent{southface.IntentRead, southface.IntentWrite},
		}, nil
	})

	srv, err := southface.Serve(southface.Config{
		Resolver:          NewResolver(resolver),
		Guard:             NewGuard(guard),
		Ceilings:          NewCeilings(reg),
		Engine:            NewEngine(stubEngine{}),
		CredExtractor:     extractor,
		BindAddr:          addr,
		CertFile:          certFile,
		KeyFile:           keyFile,
		SizeCeiling:       1 << 20,
		BrokerMaxFileSize: 1 << 20,
	})
	if err != nil {
		t.Fatalf("southface.Serve: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		Timeout: 5 * time.Second,
	}
	// The TLS server rebinds the just-freed port; retry the first dial briefly
	// so the test does not race the goroutine's ServeTLS bind.
	waitForServer(t, client, "https://"+addr+"/v1/filestore/fs/readFile")
	return client, "https://" + addr
}

// waitForServer blocks until the TLS server answers (any HTTP response) or a
// short deadline elapses, so the live tests do not race the Serve goroutine's
// bind.
func waitForServer(t *testing.T, client *http.Client, probeURL string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, probeURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("TLS south-face server did not become reachable")
}

// postReadFile sends a unary readFile through the live TLS service. The route is
// the REST surface (POST <service_url>/v1/filestore/fs/<op>, application/json,
// Authorization: Bearer) the unary transport speaks end-to-end.
func postReadFile(t *testing.T, client *http.Client, baseURL string) *http.Response {
	t.Helper()
	body := `{"filesystem_id":"fs-wire","path":"/x","authorization_metadata":{"intent":"read","downloadable":false}}`
	req, err := http.NewRequest(http.MethodPost,
		baseURL+"/v1/filestore/fs/readFile", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-edge-injected-credential")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

// TestUnaryAuditDownIs503 pins FC-01 end-to-end: a faulted audit gate behind
// the REAL guard adapter denies a unary op with unavailable/503 — not the
// pre-fix internal/500 — so unary and streaming agree on the audit-down
// wire class.
func TestUnaryAuditDownIs503(t *testing.T) {
	client, baseURL := serveSouthface(t, downGuard{}, ceilings.NewNopRegistry())
	resp := postReadFile(t, client, baseURL)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("audit-down unary status = %d, want 503", resp.StatusCode)
	}
	if h := resp.Header.Get("x-deny-reason"); h != "" {
		t.Fatalf("x-deny-reason = %q on audit-down, want none", h)
	}
}

// TestUnaryThrottleIs429 pins FC-02 end-to-end: an exhausted REAL ops/s
// bucket behind the REAL ceilings adapter denies a unary op with
// resource_exhausted/429 — not the pre-fix internal/500 — so client backoff
// works.
func TestUnaryThrottleIs429(t *testing.T) {
	fixed := time.Unix(0, 0)
	// OpsPerSecond:1, OpsBurst:1 satisfies the fail-loud contract. The clock
	// is frozen so no tokens refill. The dispatch path keys its session on the
	// filesystem ID ("fs-wire" from the Entry in serveSouthface). We pre-drain
	// that session's single burst token here, before the HTTP request, so the
	// live request finds an empty bucket and returns 429 deterministically.
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         1,
		OpsBurst:             1,
		InFlightBytesCeiling: 1 << 20,
		FDCeiling:            8,
		Clock:                func() time.Time { return fixed },
	})
	// Pre-drain: the dispatch path will look up session key "fs-wire"
	// (= Entry.FilesystemID set in serveSouthface). Draining it here, before
	// the request is sent, guarantees the bucket is empty when the handler
	// calls TryConsumeOp — no timing dependency, no flake.
	if err := reg.Session(ceilings.SessionKey("fs-wire")).TryConsumeOp(); err != nil {
		t.Fatalf("pre-drain TryConsumeOp: got %v, want nil", err)
	}
	client, baseURL := serveSouthface(t, stubGuard{}, reg)
	resp := postReadFile(t, client, baseURL)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("throttled unary status = %d, want 429", resp.StatusCode)
	}
	if h := resp.Header.Get("x-deny-reason"); h != "" {
		t.Fatalf("x-deny-reason = %q on a throttle, want none", h)
	}
}
