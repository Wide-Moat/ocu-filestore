// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// renderRegistry scrapes a registry to its Prometheus text exposition, the same
// path production uses. Tests assert through this rather than through any
// read-back accessor so they exercise the real exposition code.
func renderRegistry(t *testing.T, reg *telemetry.Registry) string {
	t.Helper()
	var buf bytes.Buffer
	n, err := reg.WriteTo(&buf)
	if err != nil {
		t.Fatalf("Registry.WriteTo: %v", err)
	}
	if int(n) != buf.Len() {
		t.Fatalf("WriteTo reported n=%d but wrote %d bytes", n, buf.Len())
	}
	return buf.String()
}

// errAfterWriter writes ok up to limit bytes, then fails every Write. It is
// used to prove WriteTo honours io.WriterTo's error contract.
type errAfterWriter struct {
	limit   int
	written int
	failErr error
}

func (e *errAfterWriter) Write(p []byte) (int, error) {
	if e.written >= e.limit {
		return 0, e.failErr
	}
	n := len(p)
	if e.written+n > e.limit {
		n = e.limit - e.written
	}
	e.written += n
	if n < len(p) {
		return n, e.failErr
	}
	return n, nil
}

// TestWriteToPropagatesWriteError verifies that a mid-render write failure is
// returned by WriteTo (not swallowed as success) and that the byte count
// reflects only what was actually written (telemetry-05).
func TestWriteToPropagatesWriteError(t *testing.T) {
	reg := telemetry.NewRegistry()
	c := reg.NewCounter("test_counter", "A test counter.", telemetry.LabelSet{})
	c.Inc(telemetry.Labels{})

	sentinel := errors.New("sink closed")
	w := &errAfterWriter{limit: 10, failErr: sentinel}
	n, err := reg.WriteTo(w)
	if !errors.Is(err, sentinel) {
		t.Fatalf("WriteTo err = %v, want %v", err, sentinel)
	}
	if n != 10 {
		t.Fatalf("WriteTo n = %d, want 10 (bytes actually written before the failure)", n)
	}
}

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

// TestRegistryGauge verifies that a Gauge's value is reflected in the exposition
// and that a later Set replaces (not accumulates) the prior value.
func TestRegistryGauge(t *testing.T) {
	reg := telemetry.NewRegistry()
	g := reg.NewGauge("test_gauge", "A test gauge.", telemetry.LabelSet{})

	g.Set(telemetry.Labels{}, 42.0)
	if out := renderRegistry(t, reg); !strings.Contains(out, "test_gauge 42\n") {
		t.Fatalf("expected gauge value 42 in exposition, got:\n%s", out)
	}
	g.Set(telemetry.Labels{}, 0.0)
	if out := renderRegistry(t, reg); !strings.Contains(out, "test_gauge 0\n") {
		t.Fatalf("expected gauge value 0 after reset in exposition, got:\n%s", out)
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

	out := renderRegistry(t, reg)
	// Count and sum surface in the exposition.
	if !strings.Contains(out, `stage_latency_seconds_count{stage="authz"} 2`) {
		t.Fatalf("expected count=2 in exposition, got:\n%s", out)
	}
	if !strings.Contains(out, `stage_latency_seconds_sum{stage="authz"} 0.0035`) {
		t.Fatalf("expected sum=0.0035 in exposition, got:\n%s", out)
	}
	// Both observations <= 0.005, so the cumulative le=0.005 bucket is 2.
	if !strings.Contains(out, `stage_latency_seconds_bucket{le="0.005",stage="authz"} 2`) {
		t.Fatalf("expected le=0.005 bucket=2 in exposition, got:\n%s", out)
	}
	// One observation <= 0.001, so that cumulative bucket is 1.
	if !strings.Contains(out, `stage_latency_seconds_bucket{le="0.001",stage="authz"} 1`) {
		t.Fatalf("expected le=0.001 bucket=1 in exposition, got:\n%s", out)
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
