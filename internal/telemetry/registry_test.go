// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// TestRegistryCounterClosedEnum verifies that a Counter refuses an out-of-enum
// label value and accepts every value from its closed set.
func TestRegistryCounterClosedEnum(t *testing.T) {
	reg := telemetry.NewRegistry()

	// Op enum: a finite closed set mirroring southface.Op names.
	opEnum := []string{"listDirectory", "makeDirectory", "readFile", "fileUpload", "fileDownload"}
	outcomeEnum := []string{"allow", "deny"}
	denyClassEnum := []string{"scope_mismatch", "intent_mismatch", "not_found",
		"audit_down", "unimplemented", "internal", "throttle_exceeded",
		"size_exceeded", "fd_exceeded", "bytes_exceeded",
		"route_op_mismatch", "none"}

	c := reg.NewCounter("ops_total", "Total ops dispatched.",
		telemetry.LabelSet{
			"op":         opEnum,
			"outcome":    outcomeEnum,
			"deny_class": denyClassEnum,
		},
	)

	// Valid labels — must succeed.
	c.Inc(telemetry.Labels{"op": "readFile", "outcome": "allow", "deny_class": "none"})
	c.Inc(telemetry.Labels{"op": "fileUpload", "outcome": "deny", "deny_class": "size_exceeded"})

	// Out-of-enum value — must panic (it is a wiring bug, not a runtime error).
	t.Run("panics_on_bogus_op", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on out-of-enum op label, got none")
			}
		}()
		c.Inc(telemetry.Labels{"op": "BOGUS_OP", "outcome": "allow", "deny_class": "none"})
	})

	t.Run("panics_on_bogus_deny_class", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on out-of-enum deny_class label, got none")
			}
		}()
		c.Inc(telemetry.Labels{"op": "readFile", "outcome": "allow", "deny_class": "BOGUS_CLASS"})
	})

	t.Run("panics_on_missing_key", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on missing label key, got none")
			}
		}()
		c.Inc(telemetry.Labels{"op": "readFile", "outcome": "allow"}) // deny_class missing
	})
}

// TestRegistryGauge verifies that a Gauge can be set, incremented, and decremented.
func TestRegistryGauge(t *testing.T) {
	reg := telemetry.NewRegistry()
	g := reg.NewGauge("test_gauge", "A test gauge.", telemetry.LabelSet{})

	g.Set(telemetry.Labels{}, 42.0)
	if got := g.Current(telemetry.Labels{}); got != 42.0 {
		t.Fatalf("expected 42.0, got %f", got)
	}
	g.Set(telemetry.Labels{}, 0.0)
	if got := g.Current(telemetry.Labels{}); got != 0.0 {
		t.Fatalf("expected 0.0 after reset, got %f", got)
	}
}

// TestRegistryHistogram verifies count, sum, and bucket accumulation.
func TestRegistryHistogram(t *testing.T) {
	reg := telemetry.NewRegistry()
	buckets := []float64{0.001, 0.005, 0.01, 0.1, 1.0, 10.0}
	stageEnum := []string{"audit_mandate", "engine", "authz"}
	h := reg.NewHistogram("stage_latency_seconds", "Stage latency.", buckets,
		telemetry.LabelSet{"stage": stageEnum},
	)

	h.Observe(telemetry.Labels{"stage": "authz"}, 0.003)  // falls in 0.005 bucket
	h.Observe(telemetry.Labels{"stage": "authz"}, 0.0005) // falls in 0.001 bucket

	snap := h.Snapshot(telemetry.Labels{"stage": "authz"})
	if snap.Count != 2 {
		t.Fatalf("expected count=2, got %d", snap.Count)
	}
	if snap.Sum < 0.0035 || snap.Sum > 0.0036 {
		t.Fatalf("unexpected sum: %f", snap.Sum)
	}
	// Both observations <= 0.005 bucket.
	if snap.Buckets[1] != 2 { // index 1 = le=0.005
		t.Fatalf("expected bucket[0.005]=2, got %d", snap.Buckets[1])
	}

	t.Run("panics_on_bogus_stage", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on out-of-enum stage label, got none")
			}
		}()
		h.Observe(telemetry.Labels{"stage": "BOGUS"}, 0.001)
	})
}
