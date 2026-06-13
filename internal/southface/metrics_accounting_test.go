// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// opsTotalRe matches one ops_total exposition sample line, capturing its
// outcome label and its integer counter value. Labels are emitted in
// alphabetical order (deny_class, op, outcome) by the registry, so the outcome
// label is always last before the closing brace.
var opsTotalRe = regexp.MustCompile(`ops_total\{[^}]*outcome="([^"]+)"\} (\d+)`)

// opsTotals scrapes the registry and returns the sum of ops_total counter
// values per outcome ("allow"/"deny"), counting ONLY non-zero samples. The
// exposition format emits a line for every label combination in the closed
// enum (most are zero); summing the values gives the true count of recorded
// ops regardless of how many zero-valued combinations the enum spans.
func opsTotals(t *testing.T, m *telemetry.BrokerMetrics) map[string]int {
	t.Helper()
	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	got := map[string]int{}
	for _, line := range strings.Split(buf.String(), "\n") {
		sub := opsTotalRe.FindStringSubmatch(line)
		if sub == nil {
			continue
		}
		v, err := strconv.Atoi(sub[2])
		if err != nil {
			t.Fatalf("ops_total value not an int in %q: %v", line, err)
		}
		got[sub[1]] += v
	}
	return got
}

// opsTotalFor returns the counter value for one exact {op, outcome, deny_class}
// triple (0 if the line is absent or zero).
func opsTotalFor(t *testing.T, m *telemetry.BrokerMetrics, op, outcome, denyClass string) int {
	t.Helper()
	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	want := `ops_total{deny_class="` + denyClass + `",op="` + op + `",outcome="` + outcome + `"} `
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, want) {
			v, err := strconv.Atoi(strings.TrimPrefix(line, want))
			if err != nil {
				t.Fatalf("ops_total value not an int in %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

// stageObservations returns the stage_latency_seconds histogram observation
// count for a given stage label (0 if absent).
func stageObservations(t *testing.T, m *telemetry.BrokerMetrics, stage string) int {
	t.Helper()
	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	want := `stage_latency_seconds_count{stage="` + stage + `"} `
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, want) {
			v, err := strconv.Atoi(strings.TrimPrefix(line, want))
			if err != nil {
				t.Fatalf("stage count not an int in %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

// TestHandlerInternalDenyRecordsExactlyOneDeny pins southface-01: a STAGE-4
// handler that refuses INTERNALLY books EXACTLY ONE ops_total entry whose
// outcome is "deny" — never the spurious allow+deny pair the unconditional
// recordAllow used to produce. Both internal-deny shapes are covered: a
// mandateDeny refusal (intent_denied) and a direct-write refusal (a malformed
// op body).
func TestHandlerInternalDenyRecordsExactlyOneDeny(t *testing.T) {
	t.Run("intent_denied via mandateDeny books one deny, zero allow", func(t *testing.T) {
		eng := newFakeEngine()
		m := telemetry.NewBrokerMetrics("v0.0.0-test")
		// Resolver allows (default), so the spine clears STAGE 2-3; the handler's
		// defense-in-depth write gate refuses because the channel grant lacks
		// IntentWrite. The wire intent still equals the route's required intent
		// (write) so the spine's STAGE-2 binding passes.
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
		d.brokerMetrics = m

		w := serveOp(d, OpRemoveFile,
			mutationOpBody(OpRemoveFile, boundScope, IntentWrite),
			boundScope, []Intent{IntentRead}) // NO write grant on the channel

		// Wire verdict is a 403 intent_denied.
		if w.Code != 403 {
			t.Fatalf("status = %d, want 403 (intent_denied); body %s", w.Code, w.Body.String())
		}
		totals := opsTotals(t, m)
		if totals["allow"] != 0 {
			t.Fatalf("ops_total allow = %d, want 0 (a refused request must not book an allow)", totals["allow"])
		}
		if totals["deny"] != 1 {
			t.Fatalf("ops_total deny = %d, want exactly 1", totals["deny"])
		}
		if got := opsTotalFor(t, m, "removeFile", "deny", denyIntentDenied); got != 1 {
			t.Fatalf("ops_total{op=removeFile,outcome=deny,deny_class=intent_denied} = %d, want 1", got)
		}
	})

	t.Run("malformed body via direct write books one deny, zero allow", func(t *testing.T) {
		eng := newFakeEngine()
		m := telemetry.NewBrokerMetrics("v0.0.0-test")
		d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)
		d.brokerMetrics = m

		// A well-formed ENVELOPE (so the spine clears STAGE 0-3 and books no
		// deny) but a body that fails the op-level strict decode (an unknown
		// field) — handleReadFile's decodeOp writes the wire error directly and
		// returns outcomeDeny(malformed); the SPINE books the single deny.
		body := `{"filesystem_id":"` + boundScope + `","path":"/p","bogus_field":1,"authorization_metadata":{"intent":"read","downloadable":false}}`
		w := serveOp(d, OpReadFile, body, boundScope, []Intent{IntentRead})

		if w.Code != 400 {
			t.Fatalf("status = %d, want 400 (malformed body); body %s", w.Code, w.Body.String())
		}
		totals := opsTotals(t, m)
		if totals["allow"] != 0 {
			t.Fatalf("ops_total allow = %d, want 0", totals["allow"])
		}
		if totals["deny"] != 1 {
			t.Fatalf("ops_total deny = %d, want exactly 1", totals["deny"])
		}
		if got := opsTotalFor(t, m, "readFile", "deny", denyMalformed); got != 1 {
			t.Fatalf("ops_total{op=readFile,outcome=deny,deny_class=malformed_envelope} = %d, want 1", got)
		}
	})

	t.Run("successful handler books one allow, zero deny", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(boundScope, "p", 4)
		m := telemetry.NewBrokerMetrics("v0.0.0-test")
		d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)
		d.brokerMetrics = m

		w := serveOp(d, OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead})
		if w.Code != 200 {
			t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
		}
		totals := opsTotals(t, m)
		if totals["allow"] != 1 {
			t.Fatalf("ops_total allow = %d, want exactly 1", totals["allow"])
		}
		if totals["deny"] != 0 {
			t.Fatalf("ops_total deny = %d, want 0 on the success path", totals["deny"])
		}
	})
}
