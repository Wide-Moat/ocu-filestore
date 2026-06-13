// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// laneTransport unwraps the built client's *http.Transport.
func laneTransport(t *testing.T, c *http.Client) *http.Transport {
	t.Helper()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport is %T, want *http.Transport", c.Transport)
	}
	return tr
}

// TestLane_FixedProxy pins ADR-0011's transit rule at the transport: for
// ARBITRARY target URLs the transport resolves its proxy to the lane —
// always, unconditionally.
func TestLane_FixedProxy(t *testing.T) {
	c, err := NewLaneTransport("http://lane.internal:3128", "")
	if err != nil {
		t.Fatalf("NewLaneTransport: %v", err)
	}
	tr := laneTransport(t, c)
	for _, target := range []string{
		"https://bucket.s3.example/key",
		"http://127.0.0.1:9000/ocu-conformance/k",
		"https://anything.else.invalid/x?y=z",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		got, err := tr.Proxy(req)
		if err != nil {
			t.Fatalf("Proxy(%q): %v", target, err)
		}
		if got == nil || got.String() != "http://lane.internal:3128" {
			t.Fatalf("Proxy(%q) = %v, want the fixed lane URL", target, got)
		}
	}
}

// TestLane_EnvProxyIgnored pins NFR-SEC-85's no-fallback rule: the proxy
// environment variables can neither redirect the lane transport nor punch
// through the dev-direct transport. http.ProxyFromEnvironment does not
// exist on this path by construction; this test would catch a regression
// that reintroduces it.
func TestLane_EnvProxyIgnored(t *testing.T) {
	for _, v := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"} {
		t.Setenv(v, "http://evil-proxy.invalid:9")
	}

	c, err := NewLaneTransport("http://lane.internal:3128", "")
	if err != nil {
		t.Fatalf("NewLaneTransport: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://bucket.s3.example/key", nil)
	got, err := laneTransport(t, c).Proxy(req)
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if got == nil || got.Host != "lane.internal:3128" {
		t.Fatalf("Proxy under hostile env = %v, want the fixed lane", got)
	}

	// Dev-direct: no proxy AT ALL, even with the env set.
	d, err := NewDevDirectTransport("")
	if err != nil {
		t.Fatalf("NewDevDirectTransport: %v", err)
	}
	if p := laneTransport(t, d).Proxy; p != nil {
		t.Fatal("dev-direct transport has a proxy function; want none (and never the environment)")
	}
}

// TestLane_StrictTLS pins the fail-closed TLS posture: InsecureSkipVerify
// is false on the built transport (asserted through reflection so a field
// rename in a future Go version breaks this test loudly), TLS 1.2 is the
// floor, and the handshake/dial timeouts are bounded.
func TestLane_StrictTLS(t *testing.T) {
	for name, build := range map[string]func() (*http.Client, error){
		"lane":       func() (*http.Client, error) { return NewLaneTransport("https://lane.internal:3128", "") },
		"dev-direct": func() (*http.Client, error) { return NewDevDirectTransport("") },
	} {
		t.Run(name, func(t *testing.T) {
			c, err := build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			tr := laneTransport(t, c)
			if tr.TLSClientConfig == nil {
				t.Fatal("TLSClientConfig is nil; want an explicit strict config")
			}
			field := reflect.ValueOf(tr.TLSClientConfig).Elem().FieldByName("InsecureSkipVerify")
			if !field.IsValid() {
				t.Fatal("tls.Config has no InsecureSkipVerify field; re-pin the strict-TLS assertion")
			}
			if field.Bool() {
				t.Fatal("InsecureSkipVerify is set; the strict-TLS posture is broken")
			}
			if tr.TLSClientConfig.MinVersion < 0x0303 { // TLS 1.2
				t.Fatalf("TLS MinVersion = %x, want >= TLS 1.2", tr.TLSClientConfig.MinVersion)
			}
			if tr.TLSHandshakeTimeout <= 0 || tr.TLSHandshakeTimeout > time.Minute {
				t.Fatalf("TLSHandshakeTimeout = %v, want bounded (0, 1m]", tr.TLSHandshakeTimeout)
			}
			if tr.DialContext == nil {
				t.Fatal("DialContext is nil; want a bounded dialer")
			}
		})
	}
}

// writeTestCA writes a self-signed CA certificate PEM and returns its path.
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-lane-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "lane-ca.pem")
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestLane_CABundle pins the bundle intake: a valid PEM bundle loads into a
// CLONED system pool (RootCAs set); a missing or garbled bundle REFUSES
// startup — never a silent fallback to system roots alone.
func TestLane_CABundle(t *testing.T) {
	t.Run("valid bundle loads", func(t *testing.T) {
		c, err := NewLaneTransport("https://lane.internal:3128", writeTestCA(t))
		if err != nil {
			t.Fatalf("NewLaneTransport(ca bundle): %v", err)
		}
		if laneTransport(t, c).TLSClientConfig.RootCAs == nil {
			t.Fatal("RootCAs is nil after a valid bundle load")
		}
	})
	t.Run("missing bundle refuses", func(t *testing.T) {
		_, err := NewLaneTransport("https://lane.internal:3128", filepath.Join(t.TempDir(), "absent.pem"))
		if !errors.Is(err, ErrLaneConfig) {
			t.Fatalf("missing bundle = %v, want ErrLaneConfig", err)
		}
	})
	t.Run("garbled bundle refuses", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "garbage.pem")
		if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := NewLaneTransport("https://lane.internal:3128", path)
		if !errors.Is(err, ErrLaneConfig) {
			t.Fatalf("garbled bundle = %v, want ErrLaneConfig", err)
		}
	})
}

// TestLane_URLRefusals pins the lane-URL gate: empty, scheme-less,
// non-http(s), and unparseable URLs refuse typed.
func TestLane_URLRefusals(t *testing.T) {
	for _, bad := range []string{"", "lane.internal:3128", "ftp://lane:21", "://x", "http://"} {
		if _, err := NewLaneTransport(bad, ""); !errors.Is(err, ErrLaneConfig) {
			t.Fatalf("NewLaneTransport(%q) = %v, want ErrLaneConfig", bad, err)
		}
	}
}
