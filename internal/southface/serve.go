// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"errors"
	"log/slog"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// ErrBrokerMaxFileSizeUnset — the whole-object upload ceiling
// (BrokerMaxFileSizeBytes) was not configured with a positive value. SEC-46/78
// requires a positive whole-object ceiling: a zero or negative value is a
// wiring fault that fails loud at construction, never a silent default. Match
// it with errors.Is.
var ErrBrokerMaxFileSizeUnset = errors.New("southface: broker max file size must be a positive whole-object ceiling")

// ErrSeamMissing — a required consumer seam (Resolver, Guard, Engine,
// CeilingsRegistry) or the credential-scope extractor was nil. The composition
// layer must bind every seam before serving; a nil seam is a wiring fault that
// fails loud at construction rather than a latent nil-deref on the serve path.
// Match it with errors.Is.
var ErrSeamMissing = errors.New("southface: a required seam is nil")

// Config is the frozen call site for the one exported south-face constructor.
// The composition layer fills it with the broker-side adapters, the
// flag-derived ceilings, and the TLS bind/cert/key; Serve validates it and
// wires the existing locked dispatch spine behind the REST router and the TLS
// HTTP/2 server. The field set is API: it freezes here.
//
// PENDING-PHASE-7(A1-route, A5-credscope): the transport is REST over the
// edge-injected-credential HTTPS the guest dials (guest -> edge -> service). The
// service receives ONLY the edge-injected real credential on Authorization:
// Bearer; CredExtractor derives the credential-bound filesystem scope from it.
// The retired unix-socket session fields (per-socket registry/entry/dir,
// peer-cred checker, host uid, peer accept/drop counters) are gone with the
// peer-cred transport. Component-04 mints/signs nothing (invariant 3).
type Config struct {
	// Resolver is the three-axis authorization seam (consumer view of authz).
	Resolver Resolver
	// Guard is the fail-closed audit seam (consumer view of auditgate).
	Guard Guard
	// Ceilings is the per-session limiter registry (consumer view of
	// ceilings).
	Ceilings CeilingsRegistry
	// Engine is the storage backend seam (consumer view of objectstore).
	Engine Engine
	// CredExtractor is the A5 credential-scope source: it derives the
	// credential-bound filesystem scope from the edge-injected Authorization:
	// Bearer the service receives on every admitted request. It is the
	// transport-neutral successor to the unix peer-cred checker; a nil value is
	// a wiring fault (an unwired credential source would fail closed on every
	// request, so it is refused loud at construction).
	CredExtractor CredentialScopeExtractor
	// BindAddr is the host:port the TLS south-face server binds (the service_url
	// the guest dials outbound through the Egress edge).
	BindAddr string
	// CertFile and KeyFile are the PEM paths for the service's own server
	// certificate. They are loaded at construction; a defect refuses startup.
	CertFile string
	KeyFile  string
	// SizeCeiling is the per-RPC-message body ceiling (NFR-SEC-78), applied
	// pre-buffer on the Content-Length and as the MaxBytesReader backstop.
	SizeCeiling int64
	// BrokerMaxFileSize is the whole-object upload ceiling (NFR-SEC-46):
	// fileUpload rejects a declared_size_bytes above it before reading any
	// chunk. It MUST be positive and is DISTINCT from SizeCeiling. This is the
	// only value that reaches the dispatcher's unexported maxFileSize field.
	BrokerMaxFileSize int64
	// Logger is the structured logger for the session. A nil value is
	// treated as a discard-all logger so existing callers and tests that
	// construct Config by literal need not supply one.
	Logger *slog.Logger
	// BrokerMetrics is the telemetry metric set for ops_total and stage-latency
	// histograms. A nil value leaves the dispatcher instrumentation as no-ops so
	// existing tests that do not supply metrics compile and pass unchanged.
	BrokerMetrics *telemetry.BrokerMetrics
}

// Serve is the sole exported south-face constructor. It validates the wiring
// (a positive whole-object ceiling and non-nil seams, fail-loud), builds the
// existing unexported dispatcher over the injected seams, sets its
// whole-object upload ceiling from cfg.BrokerMaxFileSize (the ONLY place the
// unexported maxFileSize field is set from a flag, finding #2), wires the
// credential-scope source, wraps the dispatcher in the REST router, and returns
// the TLS HTTP/2 Server. The LOCKED STAGE 0->4 dispatch pipeline is wired here,
// never re-litigated.
func Serve(cfg Config) (Server, error) {
	if cfg.BrokerMaxFileSize <= 0 {
		return nil, ErrBrokerMaxFileSizeUnset
	}
	if cfg.Resolver == nil || cfg.Guard == nil || cfg.Engine == nil ||
		cfg.Ceilings == nil || cfg.CredExtractor == nil {
		return nil, ErrSeamMissing
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	d := newDispatcherWithEngine(cfg.Resolver, cfg.Guard, cfg.Ceilings, cfg.SizeCeiling, cfg.Engine)
	// Finding #2: the whole-object upload ceiling is the control plane's
	// BrokerMaxFileSizeBytes, distinct from the per-message SizeCeiling. This
	// is the one place a flag value reaches the unexported maxFileSize field.
	d.maxFileSize = cfg.BrokerMaxFileSize
	d.logger = logger
	d.brokerMetrics = cfg.BrokerMetrics
	// The credential-scope source: STAGE 0 of every op derives the
	// host-attested PeerScope from the edge-injected Authorization: Bearer.
	d.credExtractor = cfg.CredExtractor

	router := newRESTRouter(d)

	srv, err := newTLSServer(cfg.BindAddr, cfg.CertFile, cfg.KeyFile, router, logger)
	if err != nil {
		return nil, err
	}
	return srv, nil
}
