// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry

import "github.com/Wide-Moat/ocu-filestore/internal/denyclass"

// This file declares the concrete broker metric set. Op names are mirrored
// here as string constants — telemetry is a leaf package that does NOT import
// internal/southface (which would create an import cycle, since southface
// imports telemetry). The op-name sync rule: whenever
// internal/southface/southface.go adds or renames an Op constant, the knownOps
// slice below MUST be updated to match; TestClosedLabelAllOpsAccepted pins it.
//
// The deny_class label enum is NOT mirrored: it is derived directly from the
// shared, zero-dependency internal/denyclass package — the SINGLE source of
// truth that southface's deny table also consumes. There is no second list to
// drift.

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
// label values in ops_total{deny_class,...}. It is derived — not mirrored —
// from the shared internal/denyclass vocabulary, so every value southface can
// emit as a refusal's AuditReason is a valid label and the set can never drift.
// denyclass.All() includes the "none" sentinel used for allow outcomes.
var knownDenyClasses = denyclass.All()

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
	reg                *Registry
	opsTotal           *Counter
	stageLatency       *Histogram
	inFlightBytes      *Gauge
	fdInUse            *Gauge
	opsTokens          *Gauge
	auditSinkLatched   *Gauge
	handleStoreLatched *Gauge
	auditFanOutDropped *Gauge
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

	// audit_fanout_dropped_total counts committed events the downstream
	// collector refused. It is NOT an audit failure: the local chain holds
	// every one of them, and the file plane was never stalled or denied
	// (NFR-SEC-79 durable-first, fail-open). A non-zero value means the
	// customer's collector is behind the authoritative local record by exactly
	// that many events — the "counted and reconciled, never silently lost"
	// half of the same NFR. It is a gauge mirroring the sink's own monotonic
	// counter, so a daemon restart re-reads from the sink rather than double
	// counting.
	auditFanOutDropped := reg.NewGauge("audit_fanout_dropped_total",
		"Committed audit events the downstream collector refused; the local durable record holds all of them.",
		LabelSet{},
	)

	// handle_store_latched is a binary gauge: 0 when the durable file_id handle
	// store is healthy, 1 after its fail-closed write/sync latch trips (ADR-0023).
	// The composition layer flips it via SetHandleStoreLatched from the store's
	// on-latch callback.
	handleStoreLatched := reg.NewGauge("handle_store_latched",
		"1 when the durable file_id handle store has permanently latched on a write/sync fault; 0 when healthy.",
		LabelSet{},
	)

	reg.NewBuildInfo(version)

	return &BrokerMetrics{
		reg:                reg,
		opsTotal:           opsTotal,
		stageLatency:       stageLatency,
		inFlightBytes:      inFlightBytes,
		fdInUse:            fdInUse,
		opsTokens:          opsTokens,
		auditSinkLatched:   auditSinkLatched,
		handleStoreLatched: handleStoreLatched,
		auditFanOutDropped: auditFanOutDropped,
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

// SetHandleStoreLatched sets the handle_store_latched gauge. The composition
// layer calls this with 1 when the DiskStore on-latch callback fires (ADR-0023).
// A value of 0 indicates a healthy store.
func (m *BrokerMetrics) SetHandleStoreLatched(v float64) {
	m.handleStoreLatched.Set(Labels{}, v)
}

// SetAuditFanOutDropped publishes the audit sink's dropped-fan-out count. The
// composition layer mirrors FileSink.DroppedFanOut() here, so the operator sees
// how far the downstream collector trails the authoritative local record
// (NFR-SEC-79). Zero is the healthy reading and is exposed as a real series,
// not an absent one.
func (m *BrokerMetrics) SetAuditFanOutDropped(v float64) {
	m.auditFanOutDropped.Set(Labels{}, v)
}

// BeforeScrape registers a hook run immediately before each exposition render.
// It exists for values the daemon owns elsewhere and does not push on every
// change — the audit sink's drop counter is incremented on a fan-out goroutine
// that holds no reference to the metric set, so sampling it at scrape keeps the
// series current without a background ticker whose period would decide the
// staleness. A nil fn clears the hook; a second call replaces the first.
func (m *BrokerMetrics) BeforeScrape(fn func()) {
	m.reg.SetBeforeCollect(fn)
}
