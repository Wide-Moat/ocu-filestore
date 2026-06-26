// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package northface

import (
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

// testCertPaths writes a fresh self-signed loopback certificate + key to two PEM
// files under the test temp dir and returns their paths. Mount B requires a real
// cert+key (it loads the same paths the south face does), so the test mints an
// ephemeral one.
func testCertPaths(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-filestore-mountb-test"},
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

// freeLoopbackAddr returns a currently-free loopback host:port for Mount B to
// bind. The small race between probe-close and rebind is acceptable in a
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

// TestNewMountBBadCertErrors pins the fail-loud construction gate: a missing or
// unreadable cert/key path refuses with errMountConfig rather than binding a
// half-configured listener.
func TestNewMountBBadCertErrors(t *testing.T) {
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	t.Run("missing cert file", func(t *testing.T) {
		_, err := NewMountB("127.0.0.1:0", "/no/such/cert.pem", "/no/such/key.pem", h, nil)
		if !errors.Is(err, errMountConfig) {
			t.Fatalf("err = %v, want errMountConfig", err)
		}
	})

	t.Run("empty bind", func(t *testing.T) {
		cert, key := testCertPaths(t)
		_, err := NewMountB("", cert, key, h, nil)
		if !errors.Is(err, errMountConfig) {
			t.Fatalf("err = %v, want errMountConfig", err)
		}
	})

	t.Run("nil handler", func(t *testing.T) {
		cert, key := testCertPaths(t)
		_, err := NewMountB("127.0.0.1:0", cert, key, nil, nil)
		if !errors.Is(err, errMountConfig) {
			t.Fatalf("err = %v, want errMountConfig", err)
		}
	})
}

// TestMountBServeCloseRoundTrip pins the listener lifecycle and that a GET
// reaches the INJECTED handler over TLS: Mount B binds, a TLS client GETs a
// sentinel path, the injected handler answers, and Close shuts it down cleanly.
func TestMountBServeCloseRoundTrip(t *testing.T) {
	cert, key := testCertPaths(t)
	addr := freeLoopbackAddr(t)

	reached := make(chan string, 1)
	injected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- r.URL.Path
		w.WriteHeader(http.StatusTeapot) // a distinctive status proving THIS handler answered
		_, _ = io.WriteString(w, "from-injected-handler")
	})

	mb, err := NewMountB(addr, cert, key, injected, nil)
	if err != nil {
		t.Fatalf("NewMountB: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- mb.Serve() }()
	t.Cleanup(func() {
		_ = mb.Close()
		<-serveErr
	})

	// Wait for the listener to accept, then GET over TLS (skip-verify: the cert
	// is an ephemeral self-signed loopback cert).
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // ephemeral self-signed test cert
		Timeout:   3 * time.Second,
	}
	var resp *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err = client.Get("https://" + addr + "/v1/files/probe")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Mount B never became reachable: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want 418 (the injected handler's distinctive status)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "from-injected-handler" {
		t.Fatalf("body = %q, want from-injected-handler", body)
	}
	select {
	case got := <-reached:
		if got != "/v1/files/probe" {
			t.Fatalf("injected handler saw path %q, want /v1/files/probe", got)
		}
	default:
		t.Fatal("injected handler was never reached")
	}
}

// TestMountBCloseIsClean pins that Close on a served Mount B collapses
// http.ErrServerClosed to a nil Serve return (a clean shutdown is not an error).
func TestMountBCloseIsClean(t *testing.T) {
	cert, key := testCertPaths(t)
	addr := freeLoopbackAddr(t)
	mb, err := NewMountB(addr, cert, key, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil)
	if err != nil {
		t.Fatalf("NewMountB: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- mb.Serve() }()
	time.Sleep(50 * time.Millisecond)
	if cerr := mb.Close(); cerr != nil {
		t.Fatalf("Close = %v, want nil", cerr)
	}
	if serr := <-serveErr; serr != nil {
		t.Fatalf("Serve returned %v after a clean Close, want nil", serr)
	}
}
