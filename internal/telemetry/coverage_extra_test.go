// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// TestRegisterOpsListenerHealthHandlers verifies the composition entry point
// wires /healthz and /readyz onto a live OpsListener's mux. It builds a real
// loopback listener, registers the health routes via the composition seam, then
// dials both endpoints over the real socket and asserts the responses match the
// liveness/readiness contract.
func TestRegisterOpsListenerHealthHandlers(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")
	l, err := telemetry.NewOpsListener("127.0.0.1:0", m, discardLogger())
	if err != nil {
		t.Fatalf("NewOpsListener: %v", err)
	}
	defer l.Close()

	// One passing probe and one failing probe: /healthz must stay 200 (pure
	// liveness, independent of probe state) and /readyz must report 503 naming
	// only the failing probe.
	probes := []telemetry.ReadyProbe{
		{Name: "audit_latch", Check: alwaysOK},
		{Name: "engine_root", Check: alwaysFail("scope dir removed")},
	}
	telemetry.RegisterOpsListenerHealthHandlers(l, probes)

	go l.Serve()
	addr := l.Addr()

	// /healthz: liveness, 200 even though a readiness probe fails.
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// /readyz: 503 because engine_root fails, body names engine_root only.
	resp, err = http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz: got %d, want 503", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bs := string(body)
	if !strings.Contains(bs, "engine_root") {
		t.Fatalf("/readyz body %q does not name the failing probe", bs)
	}
	if strings.Contains(bs, "audit_latch") {
		t.Fatalf("/readyz body %q names a passing probe", bs)
	}
	// T-14-09: names only — the probe's error text must never leak.
	if strings.Contains(bs, "scope dir removed") {
		t.Fatalf("/readyz body %q leaks the probe error message (T-14-09)", bs)
	}
}

// TestSetCeilingsScrape verifies SetCeilings writes the three ceilings gauges
// and that the values appear verbatim in the Prometheus exposition.
func TestSetCeilingsScrape(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	m.SetCeilings(4096, 7, 12.5)

	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	out := buf.String()

	// Unlabeled gauges render as "name value" (no label braces).
	for _, want := range []string{
		"ceilings_in_flight_bytes 4096",
		"ceilings_fd_in_use 7",
		"ceilings_ops_tokens 12.5",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("exposition missing %q:\n%s", want, out)
		}
	}

	// A second call overwrites (gauges are set, not added).
	m.SetCeilings(0, 0, 0)
	buf.Reset()
	m.Registry().WriteTo(&buf)
	out = buf.String()
	for _, want := range []string{
		"ceilings_in_flight_bytes 0",
		"ceilings_fd_in_use 0",
		"ceilings_ops_tokens 0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("after reset, exposition missing %q:\n%s", want, out)
		}
	}
}

// TestSetAuditSinkLatchedScrape verifies the binary audit_sink_latched gauge
// flips between 0 (healthy) and 1 (latched) and is visible in the exposition
// (SEC-79 made observable; T-14-10).
func TestSetAuditSinkLatchedScrape(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	// Trip the latch: the gauge cell only materialises once Set is called, so
	// SetAuditSinkLatched(1) is what makes the latched state observable.
	m.SetAuditSinkLatched(1)
	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	if !strings.Contains(buf.String(), "audit_sink_latched 1") {
		t.Fatalf("audit_sink_latched not 1 after latch:\n%s", buf.String())
	}

	// Reset to healthy.
	m.SetAuditSinkLatched(0)
	buf.Reset()
	m.Registry().WriteTo(&buf)
	if !strings.Contains(buf.String(), "audit_sink_latched 0") {
		t.Fatalf("audit_sink_latched not 0 after reset:\n%s", buf.String())
	}
}

// TestValidateOpsListenAddr exercises the bind-free address validator: empty
// disables the listener (nil), loopback forms pass, non-loopback and
// unparseable forms are refused with the errOpsListenNotLoopback sentinel.
func TestValidateOpsListenAddr(t *testing.T) {
	t.Run("empty_disables", func(t *testing.T) {
		if err := telemetry.ValidateOpsListenAddr(""); err != nil {
			t.Fatalf("empty addr: want nil, got %v", err)
		}
	})

	loopback := []string{"127.0.0.1:9464", "[::1]:9464", "localhost:9464", "127.0.0.5:0"}
	for _, addr := range loopback {
		t.Run("ok_"+addr, func(t *testing.T) {
			if err := telemetry.ValidateOpsListenAddr(addr); err != nil {
				t.Fatalf("ValidateOpsListenAddr(%q): want nil, got %v", addr, err)
			}
		})
	}

	refused := []string{
		"0.0.0.0:9464",
		":9464", // host="" binds all interfaces -> refused
		"10.0.0.1:9464",
		"192.168.1.1:0",
		"8.8.8.8:53",
	}
	for _, addr := range refused {
		t.Run("refuse_"+addr, func(t *testing.T) {
			err := telemetry.ValidateOpsListenAddr(addr)
			if err == nil {
				t.Fatalf("ValidateOpsListenAddr(%q): want error, got nil", addr)
			}
			if !telemetry.IsOpsListenNotLoopback(err) {
				t.Fatalf("ValidateOpsListenAddr(%q): want IsOpsListenNotLoopback, got %v", addr, err)
			}
		})
	}

	// Unparseable host:port (missing the port colon) is a parse error wrapped
	// as a refusal — validation must fail closed.
	t.Run("refuse_unparseable", func(t *testing.T) {
		err := telemetry.ValidateOpsListenAddr("not-a-host-port")
		if err == nil {
			t.Fatal("ValidateOpsListenAddr(unparseable): want error, got nil")
		}
		if !telemetry.IsOpsListenNotLoopback(err) {
			t.Fatalf("ValidateOpsListenAddr(unparseable): want IsOpsListenNotLoopback, got %v", err)
		}
	})
}

// TestValidateOpsListenAddrMatchesNewOpsListener pins that the bind-free
// validator agrees with NewOpsListener's own admission decision: every addr the
// validator refuses, the constructor refuses too, and vice-versa for the
// loopback forms.
func TestValidateOpsListenAddrMatchesNewOpsListener(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	// Refused by both.
	for _, addr := range []string{"0.0.0.0:0", "10.0.0.1:0", ":0"} {
		if telemetry.ValidateOpsListenAddr(addr) == nil {
			t.Fatalf("validator accepted %q that the constructor refuses", addr)
		}
		if _, err := telemetry.NewOpsListener(addr, m, discardLogger()); err == nil {
			t.Fatalf("constructor accepted %q that the validator refuses", addr)
		}
	}

	// Accepted by both (port 0 -> ephemeral, so the bind succeeds).
	for _, addr := range []string{"127.0.0.1:0", "localhost:0"} {
		if err := telemetry.ValidateOpsListenAddr(addr); err != nil {
			t.Fatalf("validator refused loopback %q: %v", addr, err)
		}
		l, err := telemetry.NewOpsListener(addr, m, discardLogger())
		if err != nil {
			t.Fatalf("constructor refused loopback %q: %v", addr, err)
		}
		l.Close()
	}
}

// TestCounterAdd verifies Counter.Add increments a cell by n, that repeated Add
// calls accumulate, and that an out-of-enum label value panics (a wiring bug).
func TestCounterAdd(t *testing.T) {
	reg := telemetry.NewRegistry()
	c := reg.NewCounter("unlabeled_add_total", "Unlabeled counter under test.",
		telemetry.LabelSet{},
	)

	c.Add(telemetry.Labels{}, 3)
	c.Add(telemetry.Labels{}, 4)

	var buf bytes.Buffer
	reg.WriteTo(&buf)
	if !strings.Contains(buf.String(), "unlabeled_add_total 7") {
		t.Fatalf("expected unlabeled_add_total 7 after Add(3)+Add(4):\n%s", buf.String())
	}

	t.Run("labeled_add", func(t *testing.T) {
		lc := reg.NewCounter("ops_total", "ops.",
			telemetry.LabelSet{"outcome": {"allow", "deny"}},
		)
		lc.Add(telemetry.Labels{"outcome": "deny"}, 5)
		lc.Add(telemetry.Labels{"outcome": "allow"}, 2)
		var b bytes.Buffer
		reg.WriteTo(&b)
		out := b.String()
		if !strings.Contains(out, `ops_total{outcome="deny"} 5`) {
			t.Fatalf("expected ops_total deny 5:\n%s", out)
		}
		if !strings.Contains(out, `ops_total{outcome="allow"} 2`) {
			t.Fatalf("expected ops_total allow 2:\n%s", out)
		}
	})

	t.Run("panics_on_bogus_label", func(t *testing.T) {
		bc := reg.NewCounter("bogus_total", "bogus.",
			telemetry.LabelSet{"outcome": {"allow", "deny"}},
		)
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on out-of-enum label value in Add")
			}
		}()
		bc.Add(telemetry.Labels{"outcome": "MAYBE"}, 1)
	})
}

// TestIsLoopbackAddrViaValidator drives the isLoopbackAddr branches through the
// exported ValidateOpsListenAddr surface: IPv4 loopback, IPv6 ::1, the
// "localhost" alias, a non-loopback hostname that resolves off-loopback, and an
// invalid/unresolvable host. These rows cover the hostname-resolution and
// literal-IP arms that the existing suite left untested.
func TestIsLoopbackAddrViaValidator(t *testing.T) {
	cases := []struct {
		name      string
		addr      string
		wantRefus bool // true => expect errOpsListenNotLoopback
	}{
		{"ipv4_loopback", "127.0.0.1:0", false},
		{"ipv4_loopback_high", "127.255.255.254:0", false},
		{"ipv6_loopback", "[::1]:0", false},
		{"localhost_alias", "localhost:0", false},
		{"empty_host_all_ifaces", ":0", true},
		{"private_ipv4", "192.168.0.1:0", true},
		{"public_ipv4", "1.1.1.1:0", true},
		// An unresolvable hostname returns ok=false (not an error) from
		// isLoopbackAddr, so ValidateOpsListenAddr refuses it as non-loopback.
		{"unresolvable_host", "this-host-does-not-exist.invalid:0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := telemetry.ValidateOpsListenAddr(tc.addr)
			if tc.wantRefus {
				if err == nil {
					t.Fatalf("addr %q: want refusal, got nil", tc.addr)
				}
				if !telemetry.IsOpsListenNotLoopback(err) {
					t.Fatalf("addr %q: want IsOpsListenNotLoopback, got %v", tc.addr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("addr %q: want accepted, got %v", tc.addr, err)
			}
		})
	}
}

// TestOpsListenerServeShutdown drives the full Serve/Close lifecycle over a real
// loopback socket: bind, serve in a goroutine, scrape /metrics, then Close and
// confirm the listener stops accepting. This exercises the Serve happy path and
// the ErrServerClosed-swallow branch on graceful shutdown.
func TestOpsListenerServeShutdown(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	l, err := telemetry.NewOpsListener("127.0.0.1:0", m, discardLogger())
	if err != nil {
		t.Fatalf("NewOpsListener: %v", err)
	}

	served := make(chan struct{})
	go func() {
		l.Serve() // returns when Close is called; ErrServerClosed is swallowed.
		close(served)
	}()

	addr := l.Addr()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics while serving: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Serve must return after Close (the goroutine closes `served`).
	<-served

	// After shutdown the endpoint must no longer be reachable.
	if _, err := http.Get("http://" + addr + "/metrics"); err == nil {
		t.Fatal("expected dial failure after Close, got a response")
	}
}
