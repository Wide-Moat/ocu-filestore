// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// exposition renders the registry the way the ops listener serves it.
func exposition(t *testing.T, m *telemetry.BrokerMetrics) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := m.Registry().WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return buf.String()
}

// TestAuditFanOutDroppedIsExposed pins the operator-visible half of NFR-SEC-79:
// a dropped fan-out must be "counted and reconciled, never silently lost". A
// counter the daemon holds but never exposes is indistinguishable from silent
// loss to everyone outside the process, so the metric family has to reach the
// exposition.
func TestAuditFanOutDroppedIsExposed(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")
	out := exposition(t, m)
	if !strings.Contains(out, "audit_fanout_dropped_total") {
		t.Fatalf("audit_fanout_dropped_total missing from exposition:\n%s", out)
	}
}

// TestAuditFanOutDroppedTracksTheSinkCounter pins the VALUE, not just the
// family name. A registered-but-never-updated counter would satisfy the
// exposure test above while reporting zero drops during an outage — the exact
// silent loss the NFR forbids.
func TestAuditFanOutDroppedTracksTheSinkCounter(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	m.SetAuditFanOutDropped(3)
	out := exposition(t, m)
	if !strings.Contains(out, "audit_fanout_dropped_total 3") {
		t.Fatalf("audit_fanout_dropped_total did not report 3:\n%s", out)
	}

	// The sink's counter is monotonic and authoritative; the gauge mirrors
	// whatever it currently reads rather than accumulating its own total.
	m.SetAuditFanOutDropped(5)
	out = exposition(t, m)
	if !strings.Contains(out, "audit_fanout_dropped_total 5") {
		t.Fatalf("audit_fanout_dropped_total did not follow the sink to 5:\n%s", out)
	}
}

// TestAuditFanOutDroppedExposesARealZero is the positive control. An operator
// alerts on this series with `> 0`, and an unlabeled gauge emits no series at
// all until something writes it — so a metric that only appeared once drops
// began would make that alert rule silently vacuous. The daemon primes the
// value at boot for exactly this reason; here the priming write stands in for
// that call.
func TestAuditFanOutDroppedExposesARealZero(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")
	m.SetAuditFanOutDropped(0)
	out := exposition(t, m)
	if !strings.Contains(out, "audit_fanout_dropped_total 0") {
		t.Fatalf("a zero drop count is not a visible series:\n%s", out)
	}
}

// TestBeforeScrapeSamplesAtRenderTime pins the sampling seam. The sink
// increments its counter on a fan-out goroutine holding no reference to the
// metric set, so without a scrape-time read the exposition would serve whatever
// value was last pushed — a drop count that stops moving is worse than one that
// is absent, because it reads as healthy.
func TestBeforeScrapeSamplesAtRenderTime(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	// Stands in for FileSink.DroppedFanOut(): a value that changes behind the
	// metric set's back between scrapes.
	current := 0
	m.BeforeScrape(func() { m.SetAuditFanOutDropped(float64(current)) })

	if out := exposition(t, m); !strings.Contains(out, "audit_fanout_dropped_total 0") {
		t.Fatalf("first scrape did not sample 0:\n%s", out)
	}
	current = 7
	if out := exposition(t, m); !strings.Contains(out, "audit_fanout_dropped_total 7") {
		t.Fatalf("second scrape did not pick up the sink's new value:\n%s", out)
	}
}
