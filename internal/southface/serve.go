// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"errors"
	"log/slog"
	"net"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// ErrBrokerMaxFileSizeUnset — the whole-object upload ceiling
// (BrokerMaxFileSizeBytes) was not configured with a positive value. SEC-46/78
// requires a positive whole-object ceiling: a zero or negative value is a
// wiring fault that fails loud at construction, never a silent default. Match
// it with errors.Is.
var ErrBrokerMaxFileSizeUnset = errors.New("southface: broker max file size must be a positive whole-object ceiling")

// ErrSeamMissing — a required consumer seam (Resolver, Guard, Engine,
// CeilingsRegistry), the session registry, or the peer checker was nil. The
// composition layer must bind every seam before serving; a nil seam is a
// wiring fault that fails loud at construction rather than a latent nil-deref
// on the serve path. Match it with errors.Is.
var ErrSeamMissing = errors.New("southface: a required seam is nil")

// PeerChecker is the exported alias of the package's peer-credential
// extractor seam: it reads the kernel-attested uid/pid of an accepted
// connection so the accept gate can drop a non-host peer before any byte is
// read (NFR-SEC-76). The composition layer obtains the host-peer checker from
// HostPeerChecker; it never reimplements the gate.
type PeerChecker = func(net.Conn) (uint32, int32, error)

// HostPeerChecker returns the package's real, build-tagged peer-credential
// extractor (extractPeerCred): SO_PEERCRED on Linux, the loud-skip stub on
// darwin. The composition layer wires this into Config.CheckPeer so the
// SEC-76 accept gate uses the genuine kernel-attested credentials — it is
// never reimplemented outside this package.
func HostPeerChecker() PeerChecker { return extractPeerCred }

// Config is the frozen call site for the one exported south-face constructor.
// The composition layer fills it with the broker-side adapters and the
// flag-derived ceilings/session entry; Serve validates it and wires the
// existing locked dispatch spine. The field set is API: it freezes here.
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
	// Registry is the socket-path -> scope binding map; Serve provisions the
	// session's binding into it and Close releases it.
	Registry *SessionRegistry
	// Entry is the channel-bound scope identity for this session's socket.
	Entry SessionEntry
	// Dir is the host-owned 0700 directory the per-session socket is minted
	// under.
	Dir string
	// SizeCeiling is the per-RPC-message body ceiling (NFR-SEC-78), applied
	// pre-buffer on the Content-Length and as the MaxBytesReader backstop.
	SizeCeiling int64
	// BrokerMaxFileSize is the whole-object upload ceiling (NFR-SEC-46):
	// fileUpload rejects a declared_size_bytes above it before reading any
	// chunk. It MUST be positive and is DISTINCT from SizeCeiling. This is the
	// only value that reaches the dispatcher's unexported maxFileSize field.
	BrokerMaxFileSize int64
	// CheckPeer is the accept-gate peer-credential extractor; the composition
	// layer supplies HostPeerChecker().
	CheckPeer PeerChecker
	// HostUID is the broker's own uid; the accept gate drops any peer whose
	// uid does not match (NFR-SEC-76).
	HostUID uint32
	// Logger is the structured logger for the session. A nil value is
	// treated as a discard-all logger so existing callers and tests that
	// construct Config by literal need not supply one.
	Logger *slog.Logger
	// OnPeerAccepted is an optional callback invoked when a connection is
	// admitted through the SEC-76 accept gate (uid matches the host uid). A nil
	// value is a no-op. The composition layer supplies a telemetry counter
	// increment here so southface does not import telemetry directly.
	OnPeerAccepted func()
	// OnPeerDropped is an optional callback invoked when a connection is
	// rejected at the SEC-76 accept gate (uid mismatch or peercred error). A nil
	// value is a no-op. The composition layer supplies a telemetry counter
	// increment here alongside the plan-01 logger-based onPeerDrop callback.
	OnPeerDropped func()
	// BrokerMetrics is the telemetry metric set for ops_total, stage-latency
	// histograms, and (via OnPeerAccepted/OnPeerDropped) peer counters. A nil
	// value leaves the dispatcher instrumentation as no-ops so existing tests
	// that do not supply metrics compile and pass unchanged.
	BrokerMetrics *telemetry.BrokerMetrics
}

// Serve is the sole exported south-face constructor. It validates the wiring
// (a positive whole-object ceiling and non-nil seams, fail-loud), builds the
// existing unexported dispatcher over the injected seams, sets its
// whole-object upload ceiling from cfg.BrokerMaxFileSize (the ONLY place the
// unexported maxFileSize field is set from a flag, finding #2), provisions the
// session binding, and returns the per-session Server. The LOCKED STAGE 0->4
// dispatch pipeline is wired here, never re-litigated.
func Serve(cfg Config) (Server, error) {
	if cfg.BrokerMaxFileSize <= 0 {
		return nil, ErrBrokerMaxFileSizeUnset
	}
	if cfg.Resolver == nil || cfg.Guard == nil || cfg.Engine == nil ||
		cfg.Ceilings == nil || cfg.Registry == nil || cfg.CheckPeer == nil {
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

	s, err := provisionSession(cfg.Dir, cfg.Entry, cfg.Registry, d, cfg.CheckPeer, cfg.HostUID, logger, cfg.OnPeerAccepted, cfg.OnPeerDropped)
	if err != nil {
		return nil, err
	}
	return s, nil
}
