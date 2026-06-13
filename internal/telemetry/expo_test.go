// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// TestExpoCounterGolden verifies the exact Prometheus text-format 0.0.4 output
// for a counter with labels.
func TestExpoCounterGolden(t *testing.T) {
	reg := telemetry.NewRegistry()
	opEnum := []string{"readFile", "listDirectory"}
	outcomeEnum := []string{"allow", "deny"}
	denyClassEnum := []string{"none", "scope_mismatch"}

	c := reg.NewCounter("ops_total", "Total ops dispatched.",
		telemetry.LabelSet{
			"op":         opEnum,
			"outcome":    outcomeEnum,
			"deny_class": denyClassEnum,
		},
	)
	c.Inc(telemetry.Labels{"op": "readFile", "outcome": "allow", "deny_class": "none"})
	c.Inc(telemetry.Labels{"op": "readFile", "outcome": "allow", "deny_class": "none"})
	c.Inc(telemetry.Labels{"op": "listDirectory", "outcome": "deny", "deny_class": "scope_mismatch"})

	var buf bytes.Buffer
	reg.WriteTo(&buf)
	out := buf.String()

	// Must have HELP and TYPE lines.
	if !strings.Contains(out, "# HELP ops_total Total ops dispatched.") {
		t.Fatalf("missing HELP line in:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE ops_total counter") {
		t.Fatalf("missing TYPE line in:\n%s", out)
	}
	// Sample lines must be present.
	if !strings.Contains(out, `ops_total{`) {
		t.Fatalf("missing sample lines in:\n%s", out)
	}
	// The two-increment counter must show 2.
	if !strings.Contains(out, `deny_class="none",op="readFile",outcome="allow"} 2`) {
		t.Fatalf("counter value 2 not found:\n%s", out)
	}
	// The single-increment counter must show 1.
	if !strings.Contains(out, `deny_class="scope_mismatch",op="listDirectory",outcome="deny"} 1`) {
		t.Fatalf("counter value 1 not found:\n%s", out)
	}
}

// TestExpoLabelEscaping verifies that label values containing quotes/backslashes
// are properly escaped in the exposition output.
func TestExpoLabelEscaping(t *testing.T) {
	reg := telemetry.NewRegistry()
	// Use an unlabeled gauge so we control the label set; inject a fabricated
	// metric with special chars via a dedicated build_info-style API.
	_ = reg.NewGauge("escape_test", "Test gauge.", telemetry.LabelSet{})

	// We test escaping via the exposition renderer itself by directly checking
	// the escapeLabel function behavior (indirectly through expo output).
	// The closed-enum discipline means real label values are clean, but the
	// renderer must still escape defensively.
	//
	// We construct a metric family name+labels that would produce special chars
	// if unescaped. Since the registry only accepts registered enums, test the
	// escaping logic through build_info where we supply the version string.
	bi := reg.NewBuildInfo("test\nversion\\a\"b")
	_ = bi

	var buf bytes.Buffer
	reg.WriteTo(&buf)
	out := buf.String()

	// The version value must be escaped: \n -> \n, \" -> \", \\ -> \\
	if strings.Contains(out, "test\nversion") {
		t.Fatal("newline must be escaped but found literal newline in label value")
	}
	if !strings.Contains(out, `test\nversion\\a\"b`) {
		t.Fatalf("escaped value not found in:\n%s", out)
	}
}

// TestExpoHistogramGolden verifies Prometheus histogram output format.
func TestExpoHistogramGolden(t *testing.T) {
	reg := telemetry.NewRegistry()
	buckets := []float64{0.001, 0.01, 0.1, 1.0}
	stageEnum := []string{"authz", "audit_mandate", "engine"}
	h := reg.NewHistogram("stage_latency_seconds", "Stage latency.",
		buckets, telemetry.LabelSet{"stage": stageEnum},
	)
	h.Observe(telemetry.Labels{"stage": "authz"}, 0.005) // bucket 0.01

	var buf bytes.Buffer
	reg.WriteTo(&buf)
	out := buf.String()

	if !strings.Contains(out, "# HELP stage_latency_seconds Stage latency.") {
		t.Fatalf("missing HELP:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE stage_latency_seconds histogram") {
		t.Fatalf("missing TYPE:\n%s", out)
	}
	if !strings.Contains(out, `stage_latency_seconds_bucket{le="0.001",stage="authz"} 0`) {
		t.Fatalf("bucket 0.001 missing or wrong:\n%s", out)
	}
	if !strings.Contains(out, `stage_latency_seconds_bucket{le="0.01",stage="authz"} 1`) {
		t.Fatalf("bucket 0.01 missing or wrong:\n%s", out)
	}
	// The remaining bounds above the observation are cumulative and must stay
	// at 1 (one observation total) — not re-summed past the count.
	if !strings.Contains(out, `stage_latency_seconds_bucket{le="0.1",stage="authz"} 1`) {
		t.Fatalf("bucket 0.1 must be cumulative 1, not re-summed:\n%s", out)
	}
	if !strings.Contains(out, `stage_latency_seconds_bucket{le="1",stage="authz"} 1`) {
		t.Fatalf("bucket 1 must be cumulative 1, not re-summed:\n%s", out)
	}
	if !strings.Contains(out, `stage_latency_seconds_bucket{le="+Inf",stage="authz"} 1`) {
		t.Fatalf("+Inf bucket missing:\n%s", out)
	}
	if !strings.Contains(out, `stage_latency_seconds_count{stage="authz"} 1`) {
		t.Fatalf("_count missing:\n%s", out)
	}
	if !strings.Contains(out, `stage_latency_seconds_sum{stage="authz"}`) {
		t.Fatalf("_sum missing:\n%s", out)
	}
}

// TestExpoBuildInfo verifies build_info gauge format.
func TestExpoBuildInfo(t *testing.T) {
	reg := telemetry.NewRegistry()
	reg.NewBuildInfo("v1.2.3-test")

	var buf bytes.Buffer
	reg.WriteTo(&buf)
	out := buf.String()

	if !strings.Contains(out, "# HELP build_info") {
		t.Fatalf("missing build_info HELP:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE build_info gauge") {
		t.Fatalf("missing build_info TYPE:\n%s", out)
	}
	if !strings.Contains(out, `build_info{version="v1.2.3-test"} 1`) {
		t.Fatalf("build_info sample missing:\n%s", out)
	}
}
