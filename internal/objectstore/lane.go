// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Storage-lane transport (T1-8, ADR-0011): a network engine's backend leg
// transits the storage-dedicated egress lane — the lane proxy is FIXED at
// construction. http.ProxyFromEnvironment is never consulted: an
// HTTPS_PROXY/HTTP_PROXY/NO_PROXY environment variable can neither redirect
// the backend leg nor bypass the lane (NFR-SEC-16, NFR-SEC-85). TLS is
// strict fail-closed: no InsecureSkipVerify path exists in this repo; an
// inspecting lane proxy's CA arrives only via an explicit PEM bundle that
// APPENDS to a cloned system pool — a missing or garbled bundle refuses
// startup, never silently falls back.

// Bounded transport timeouts: a wedged lane or backend can never hang a
// dial or handshake indefinitely. Verb-level deadlines stay with the
// caller's ctx.
const (
	laneDialTimeout         = 10 * time.Second
	laneTLSHandshakeTimeout = 10 * time.Second
	laneIdleConnTimeout     = 90 * time.Second
	laneExpectContinue      = 1 * time.Second
)

// ErrLaneConfig refuses a misconfigured storage-lane transport (bad lane
// URL, unreadable or unparseable CA bundle). Match it with errors.Is.
var ErrLaneConfig = errors.New("objectstore: storage-lane transport misconfigured")

// NewLaneTransport builds the s3 client's HTTP client with the storage
// lane as a FIXED proxy: every backend request transits laneURL
// (ADR-0011); the process environment's proxy variables are ignored by
// construction. caBundlePath optionally appends an inspecting lane proxy's
// CA to a CLONE of the system pool (the system roots stay trusted; nothing
// is replaced); empty means the system pool alone.
func NewLaneTransport(laneURL, caBundlePath string) (*http.Client, error) {
	if laneURL == "" {
		return nil, fmt.Errorf("%w: lane URL is required", ErrLaneConfig)
	}
	u, err := url.Parse(laneURL)
	if err != nil {
		return nil, fmt.Errorf("%w: lane URL %q: %v", ErrLaneConfig, laneURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%w: lane URL %q must be http(s)://host[:port]", ErrLaneConfig, laneURL)
	}
	return buildLaneClient(u, caBundlePath)
}

// NewDevDirectTransport builds the LOUD dev-rig client: the same strict-TLS
// bounded transport with NO proxy — a direct backend dial. It exists for
// development rigs only and violates the ADR-0011 deployment posture; the
// daemon's flag surface forces the operator to say -storage-lane-dev-direct
// explicitly to get here.
func NewDevDirectTransport(caBundlePath string) (*http.Client, error) {
	return buildLaneClient(nil, caBundlePath)
}

// buildLaneClient is the shared tail: fixed-proxy (or no-proxy) transport,
// strict TLS, bounded timeouts.
func buildLaneClient(proxy *url.URL, caBundlePath string) (*http.Client, error) {
	// Strict TLS, fail-closed. InsecureSkipVerify is never set — not here,
	// not anywhere in this repo (the lane test pins the built transport;
	// the SAST gate watches the tree).
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if caBundlePath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("%w: system cert pool: %v", ErrLaneConfig, err)
		}
		pem, err := os.ReadFile(caBundlePath)
		if err != nil {
			return nil, fmt.Errorf("%w: ca bundle: %v", ErrLaneConfig, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: ca bundle %q holds no parseable PEM certificate", ErrLaneConfig, caBundlePath)
		}
		tlsCfg.RootCAs = pool
	}

	tr := &http.Transport{
		// The decision point: a fixed lane proxy, or nil for the loud
		// dev-direct rig. NEVER http.ProxyFromEnvironment.
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   laneDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   laneTLSHandshakeTimeout,
		IdleConnTimeout:       laneIdleConnTimeout,
		ExpectContinueTimeout: laneExpectContinue,
		ForceAttemptHTTP2:     true,
	}
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	return &http.Client{Transport: tr}, nil
}
