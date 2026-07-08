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

// ErrInvalidSubtree — a deployment-supplied subtree override was empty after
// trimming or carried a ".." component (ADR-0029). A deployment may override the
// intent->subtree join target but can never disable the join by setting it empty
// or point it out of the scope tree; either is a wiring fault that fails loud at
// construction. Match it with errors.Is.
var ErrInvalidSubtree = errors.New("southface: subtree override must be a non-empty engine-relative path with no traversal segment")

// ErrSubtreeDisabled refuses an empty (disabled) intent->subtree join map at
// Serve construction. The join is mandatory (ADR-0029 Decision bullet 2: "never
// bypass it") — an empty map would coincide the write and downloadable axes on a
// flat namespace and reopen the NFR-SEC-73 split. The composition layer defaults
// to DefaultSubtreeMap(); a disabled map reaching the engine is a wiring fault.
// Match it with errors.Is.
var ErrSubtreeDisabled = errors.New("southface: the intent->subtree join map is disabled (empty); the join is mandatory (ADR-0029), a deployment defaults to the pinned map and can only override it, never bypass it")

// Config is the frozen call site for the one exported south-face constructor.
// The composition layer fills it with the broker-side adapters, the
// flag-derived ceilings, and the TLS bind/cert/key; Serve validates it and
// wires the existing locked dispatch spine behind the REST router and the TLS
// HTTP/2 server. The field set is API: it freezes here.
//
// PHASE-7(A1-route): frozen @ canon-rev a030b7be914b: the transport is REST over
// the edge-injected-credential HTTPS the guest dials (guest -> edge -> service).
// contract FORM ratified by #292 @ a030b7be914b; governing ADR remains status:proposed — freezes the wire FORM, not ADR acceptance
// PENDING-PHASE-7(A5-credscope): the
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
	// Subtrees is the intent->subtree join map (ADR-0029 inv-10). A zero-value
	// (disabled) map runs canonicalizePath in static-path mode — the pre-ADR-0029
	// behaviour — so a deployment that supplies no subtree overrides keeps the flat
	// static-path layout. A populated map (DefaultSubtreeMap or a NewSubtreeMap
	// override) engine-joins every file-op path under the intent's subtree before
	// the invariant-1 traversal check.
	Subtrees SubtreeMap
	// GrantedIntents is the static -granted-intents ceiling (ADR-0029 Decision
	// bullet 5): the intents the deployment serves. The dispatcher intersects the
	// credential's claim with this ceiling to derive the effective grant set the
	// authz spine reads. The ceiling never grants — it only narrows the claim. A
	// nil value leaves the claim unnarrowed (the pre-ADR-0029 behaviour).
	GrantedIntents []Intent
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
	// The intent->subtree join is mandatory (ADR-0029 Decision bullet 2: "never
	// bypass it"). An empty map would run canonicalizePath in static-path mode and
	// coincide the write and downloadable axes on one flat namespace, reopening the
	// NFR-SEC-73 split. A disabled map at engine boot is a wiring fault, refused
	// loud — the composition layer defaults to DefaultSubtreeMap() and only an
	// override (all three intents) is a legitimate populated map.
	if !cfg.Subtrees.enabled() {
		return nil, ErrSubtreeDisabled
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
	// The ADR-0029 join map and -granted-intents ceiling. A disabled (zero-value)
	// map keeps canonicalizePath in static-path mode; a nil ceiling leaves the
	// credential claim unnarrowed — both preserve the pre-ADR-0029 behaviour when
	// the composition layer supplies neither.
	d.subtrees = cfg.Subtrees
	d.grantedIntentsCeiling = cfg.GrantedIntents

	router := newRESTRouter(d)

	srv, err := newTLSServer(cfg.BindAddr, cfg.CertFile, cfg.KeyFile, router, logger)
	if err != nil {
		return nil, err
	}
	return srv, nil
}
