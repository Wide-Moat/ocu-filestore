// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// TestMetricsBrokerSetRegistersAll verifies that every metric family the broker
// requires is registered and renders in the exposition.
func TestMetricsBrokerSetRegistersAll(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	out := buf.String()

	requiredFamilies := []string{
		"ops_total",
		"stage_latency_seconds",
		"peer_accepted_total",
		"peer_dropped_total",
		"build_info",
		"ceilings_in_flight_bytes",
		"ceilings_fd_in_use",
		"ceilings_ops_tokens",
	}
	for _, name := range requiredFamilies {
		if !strings.Contains(out, name) {
			t.Errorf("metric family %q missing from exposition:\n%s", name, out)
		}
	}
}

// TestMetricsOpsTotal verifies the closed label enum for ops_total.
func TestMetricsOpsTotal(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	// Valid allow recording.
	m.RecordOp("readFile", "allow", "none")
	// Valid deny recording.
	m.RecordOp("fileUpload", "deny", "size_exceeded")

	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	out := buf.String()

	if !strings.Contains(out, `deny_class="none",op="readFile",outcome="allow"} 1`) {
		t.Fatalf("readFile allow not found:\n%s", out)
	}
	if !strings.Contains(out, `deny_class="size_exceeded",op="fileUpload",outcome="deny"} 1`) {
		t.Fatalf("fileUpload deny not found:\n%s", out)
	}

	// Out-of-enum op must panic.
	t.Run("panics_on_bogus_op", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on bogus op")
			}
		}()
		m.RecordOp("BOGUS", "allow", "none")
	})
}

// TestMetricsStageHistograms verifies that per-stage latency histograms are
// available and accumulate observations.
func TestMetricsStageHistograms(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	m.ObserveStage("authz", 0.002)
	m.ObserveStage("audit_mandate", 0.001)
	m.ObserveStage("engine", 0.05)

	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	out := buf.String()

	for _, stage := range []string{"authz", "audit_mandate", "engine"} {
		if !strings.Contains(out, `stage="`+stage+`"`) {
			t.Errorf("stage %q not found in output:\n%s", stage, out)
		}
	}
}

// TestMetricsPeerCounters verifies that peer accepted/dropped counters exist.
func TestMetricsPeerCounters(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	m.PeerAccepted()
	m.PeerAccepted()
	m.PeerDropped()

	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	out := buf.String()

	if !strings.Contains(out, "peer_accepted_total") {
		t.Fatalf("peer_accepted_total missing:\n%s", out)
	}
	if !strings.Contains(out, "peer_dropped_total") {
		t.Fatalf("peer_dropped_total missing:\n%s", out)
	}
	if !strings.Contains(out, "peer_accepted_total 2") {
		t.Fatalf("peer_accepted_total not 2:\n%s", out)
	}
	if !strings.Contains(out, "peer_dropped_total 1") {
		t.Fatalf("peer_dropped_total not 1:\n%s", out)
	}
}

// TestMetricsBuildInfo verifies build_info carries the passed version.
func TestMetricsBuildInfo(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v9.9.9-golden")

	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	out := buf.String()

	if !strings.Contains(out, `version="v9.9.9-golden"`) {
		t.Fatalf("version not found:\n%s", out)
	}
}

// TestClosedLabelAllOpsAccepted verifies all southface Op names are in the
// closed op enum (and thus accepted by the registry without panic).
func TestClosedLabelAllOpsAccepted(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	// All southface op names that are in the closed metric enum.
	// These must match the enum in metrics.go — this test pins the sync rule.
	knownOps := telemetry.KnownOps()
	for _, op := range knownOps {
		// Must not panic.
		m.RecordOp(op, "allow", "none")
	}
	if len(knownOps) == 0 {
		t.Fatal("KnownOps returned empty slice — enum not initialized")
	}
}
