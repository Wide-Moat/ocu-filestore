// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry

// This file declares the concrete broker metric set. Op names and deny-class
// names are mirrored here as string constants — telemetry is a leaf package
// that does NOT import internal/southface. The sync rule: whenever
// internal/southface/southface.go or internal/southface/deny.go adds or
// renames an Op or deny-class constant, the mirror slices below MUST be
// updated to match. TestClosedLabelAllOpsAccepted in metrics_test.go pins
// the ops mirror by calling KnownOps().

// knownOps is the closed set of southface Op names used as label values in
// ops_total{op,...}. Mirrored from internal/southface/southface.go.
// Sync rule: update this list any time a new Op const is added to southface.
var knownOps = []string{
	"listDirectory",
	"makeDirectory",
	"moveDirectory",
	"removeDirectory",
	"createFile",
	"readFile",
	"readMetadata",
	"getFileMetadata",
	"listFiles",
	"copyFile",
	"moveFile",
	"removeFile",
	"fileUpload",
	"fileDownload",
	"importFiles",
	"importZip",
	"migrateFilesystem",
	"removeFilesystem",
}

// knownDenyClasses is the closed set of deny-class audit-reason values used as
// label values in ops_total{deny_class,...}. Mirrored from
// internal/southface/deny.go. "none" is the sentinel used for allow outcomes.
var knownDenyClasses = []string{
	"none",
	"scope_mismatch",
	"intent_mismatch",
	"not_found",
	"audit_down",
	"unimplemented",
	"internal",
	"throttle_exceeded",
	"size_exceeded",
	"fd_exceeded",
	"bytes_exceeded",
	"route_op_mismatch",
}

// knownOutcomes is the closed set of outcome label values in ops_total.
var knownOutcomes = []string{"allow", "deny"}

// knownStages is the closed set of dispatch stage labels for the
// stage_latency_seconds histogram.
var knownStages = []string{"audit_mandate", "engine", "authz"}

// stageLatencyBuckets are the histogram upper-bound boundaries (seconds):
// 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s, 10s.
var stageLatencyBuckets = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0}

// KnownOps returns the closed set of southface op names recognised by the
// telemetry label enum. Tests use this to assert the mirror is non-empty and
// to exercise every value against the counter without triggering a panic.
func KnownOps() []string {
	cp := make([]string, len(knownOps))
	copy(cp, knownOps)
	return cp
}

// BrokerMetrics is the concrete metric set for the ocu-filestore broker daemon.
// Obtain it via NewBrokerMetrics; do not construct directly.
type BrokerMetrics struct {
	reg              *Registry
	opsTotal         *Counter
	stageLatency     *Histogram
	peerAccepted     *Counter
	peerDropped      *Counter
	inFlightBytes    *Gauge
	fdInUse          *Gauge
	opsTokens        *Gauge
	auditSinkLatched *Gauge
}

// NewBrokerMetrics creates and registers the full broker metric set.
// version is emitted in build_info{version=...} — it should be the value of
// the daemon's main.version var.
func NewBrokerMetrics(version string) *BrokerMetrics {
	reg := NewRegistry()

	opsTotal := reg.NewCounter("ops_total",
		"Total file operations dispatched, by op, outcome, and deny class.",
		LabelSet{
			"op":         knownOps,
			"outcome":    knownOutcomes,
			"deny_class": knownDenyClasses,
		},
	)

	stageLatency := reg.NewHistogram("stage_latency_seconds",
		"Latency of the three locked dispatch stages.",
		stageLatencyBuckets,
		LabelSet{"stage": knownStages},
	)

	peerAccepted := reg.NewCounter("peer_accepted_total",
		"Connections admitted through the SEC-76 peer-cred accept gate.",
		LabelSet{},
	)

	peerDropped := reg.NewCounter("peer_dropped_total",
		"Connections rejected at the SEC-76 peer-cred accept gate.",
		LabelSet{},
	)

	// Ceilings gauges are unlabeled: this single-tenant trusted_operator shelf
	// serves one session at a time; labeling by filesystem-id would be an
	// unbounded cardinality risk (PII-ish uuid). Gauges are updated by the
	// calling code via SetCeilings.
	inFlightBytes := reg.NewGauge("ceilings_in_flight_bytes",
		"Current in-flight bytes for the active session.",
		LabelSet{},
	)
	fdInUse := reg.NewGauge("ceilings_fd_in_use",
		"Current open file descriptor count for the active session.",
		LabelSet{},
	)
	opsTokens := reg.NewGauge("ceilings_ops_tokens",
		"Current token-bucket level (ops/s tokens available) for the active session.",
		LabelSet{},
	)

	// audit_sink_latched is a binary gauge: 0 when the FileSink is healthy,
	// 1 after the fail-closed audit latch trips (SEC-79 made observable via
	// scraping; T-14-10). The composition layer flips it via SetAuditSinkLatched.
	auditSinkLatched := reg.NewGauge("audit_sink_latched",
		"1 when the fail-closed audit sink has permanently latched (broker serving 100% denies); 0 when healthy.",
		LabelSet{},
	)

	reg.NewBuildInfo(version)

	return &BrokerMetrics{
		reg:              reg,
		opsTotal:         opsTotal,
		stageLatency:     stageLatency,
		peerAccepted:     peerAccepted,
		peerDropped:      peerDropped,
		inFlightBytes:    inFlightBytes,
		fdInUse:          fdInUse,
		opsTokens:        opsTokens,
		auditSinkLatched: auditSinkLatched,
	}
}

// Registry returns the underlying *Registry for use by the ops listener's
// WriteTo handler.
func (m *BrokerMetrics) Registry() *Registry {
	return m.reg
}

// RecordOp increments ops_total for the given op/outcome/deny_class triple.
// deny_class must be "none" for allow outcomes.
// Panics if any label value is not in the closed enum — that is a wiring bug.
func (m *BrokerMetrics) RecordOp(op, outcome, denyClass string) {
	m.opsTotal.Inc(Labels{"op": op, "outcome": outcome, "deny_class": denyClass})
}

// ObserveStage records one stage latency observation in seconds.
// stage must be one of "audit_mandate", "engine", "authz".
func (m *BrokerMetrics) ObserveStage(stage string, seconds float64) {
	m.stageLatency.Observe(Labels{"stage": stage}, seconds)
}

// PeerAccepted increments the peer_accepted_total counter.
func (m *BrokerMetrics) PeerAccepted() {
	m.peerAccepted.Inc(Labels{})
}

// PeerDropped increments the peer_dropped_total counter.
func (m *BrokerMetrics) PeerDropped() {
	m.peerDropped.Inc(Labels{})
}

// SetCeilings updates the ceilings gauges from a snapshot of the active
// session's limiters. inFlightBytes and fdInUse are integer counts; opsTokens
// is the float token-bucket level.
func (m *BrokerMetrics) SetCeilings(inFlightBytes float64, fdInUse float64, opsTokens float64) {
	m.inFlightBytes.Set(Labels{}, inFlightBytes)
	m.fdInUse.Set(Labels{}, fdInUse)
	m.opsTokens.Set(Labels{}, opsTokens)
}

// SetAuditSinkLatched sets the audit_sink_latched gauge. The composition layer
// calls this with 1 when the FileSink on-latch callback fires (SEC-79 made
// observable; T-14-10). A value of 0 indicates a healthy sink.
func (m *BrokerMetrics) SetAuditSinkLatched(v float64) {
	m.auditSinkLatched.Set(Labels{}, v)
}
