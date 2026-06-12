// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/authz"
	"github.com/Wide-Moat/ocu-filestore/internal/ceilings"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// TestGuardAdapterRemapsAuditUnavailable pins the FC-01 remap in isolation:
// the real auditgate.ErrAuditUnavailable (bare and wrapped) crosses the
// adapter as the southface mirror the spine's denyClassForErr classifies to
// unavailable/503; a non-sentinel error passes through (denyInternal).
func TestGuardAdapterRemapsAuditUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   error
		want bool // expect the southface mirror
	}{
		{"bare_sentinel", auditgate.ErrAuditUnavailable, true},
		{"wrapped_sentinel", fmt.Errorf("ctx: %w", auditgate.ErrAuditUnavailable), true},
		{"non_sentinel_passthrough", errors.New("boom"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := NewGuard(stubGuard{err: tc.in}).Mandate(context.Background(), struct{}{})
			if got := errors.Is(err, southface.ErrAuditUnavailable); got != tc.want {
				t.Fatalf("errors.Is(err, southface.ErrAuditUnavailable) = %v, want %v (err %v)", got, tc.want, err)
			}
			if err == nil {
				t.Fatal("a guard error was dropped to nil")
			}
		})
	}
}

// TestCeilingsAdapterRemapsSentinels pins the FC-02 remap against the REAL
// limiter package: each exhausted ceiling crosses the adapter as the
// southface mirror (throttle/bytes/fd), so the spine classifies it to
// resource_exhausted/429 instead of internal/500.
func TestCeilingsAdapterRemapsSentinels(t *testing.T) {
	fixed := time.Unix(0, 0)
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         0,
		OpsBurst:             0, // bucket starts and stays empty
		InFlightBytesCeiling: 4,
		FDCeiling:            0,
		Clock:                func() time.Time { return fixed },
	})
	sess := NewCeilings(reg).Session("fs-exhausted")

	if err := sess.TryConsumeOp(); !errors.Is(err, southface.ErrThrottleExceeded) {
		t.Fatalf("TryConsumeOp: got %v, want the southface.ErrThrottleExceeded mirror", err)
	}
	if err := sess.AcquireBytes(8); !errors.Is(err, southface.ErrBytesExceeded) {
		t.Fatalf("AcquireBytes(over): got %v, want the southface.ErrBytesExceeded mirror", err)
	}
	if err := sess.TryAcquireFD(); !errors.Is(err, southface.ErrFDExceeded) {
		t.Fatalf("TryAcquireFD: got %v, want the southface.ErrFDExceeded mirror", err)
	}
	// Positive control: an in-ceiling acquire stays nil and the release pair
	// passes through to the real gauge.
	if err := sess.AcquireBytes(2); err != nil {
		t.Fatalf("AcquireBytes(in-ceiling): got %v, want nil", err)
	}
	sess.ReleaseBytes(2)
}

// downGuard is an auditgate.Guard whose every Mandate fails with the REAL
// auditgate sentinel — the faulted-FileSink stand-in (the real sink returns
// exactly this on any durable-write failure).
type downGuard struct{}

func (downGuard) Mandate(context.Context, any) error { return auditgate.ErrAuditUnavailable }

// serveSouthface stands up a REAL south-face session over a unix socket with
// the REAL broker adapters bound (resolver over authz, the given guard and
// ceilings registry, the engine adapter over the stub engine) and returns a
// client. The peer checker admits the test process.
func serveSouthface(t *testing.T, guard auditgate.Guard, reg *ceilings.Registry) *http.Client {
	t.Helper()
	dir := shortDir(t)
	resolver := authz.New(func(context.Context, authz.FilesystemID, string) (bool, error) {
		return true, nil
	})
	srv, err := southface.Serve(southface.Config{
		Resolver:          NewResolver(resolver),
		Guard:             NewGuard(guard),
		Ceilings:          NewCeilings(reg),
		Engine:            NewEngine(stubEngine{}),
		Registry:          southface.NewSessionRegistry(),
		Entry:             southface.SessionEntry{FilesystemID: "fs-wire", GrantedIntents: []southface.Intent{southface.IntentRead, southface.IntentWrite}},
		Dir:               dir,
		SizeCeiling:       1 << 20,
		BrokerMaxFileSize: 1 << 20,
		CheckPeer:         func(net.Conn) (uint32, int32, error) { return 7, 1, nil },
		HostUID:           7,
	})
	if err != nil {
		t.Fatalf("southface.Serve: %v", err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })

	socketPath := dir + "/fs-wire.sock"
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}
}

// postReadFile sends a unary readFile through the live session socket.
func postReadFile(t *testing.T, client *http.Client) *http.Response {
	t.Helper()
	body := `{"filesystem_id":"fs-wire","path":"/x","authorization_metadata":{"intent":"read","downloadable":false}}`
	req, err := http.NewRequest(http.MethodPost,
		"http://session/ocu.filestore.v1alpha.FilesystemService/readFile", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

// TestUnaryAuditDownIs503 pins FC-01 end-to-end: a faulted audit gate behind
// the REAL guard adapter denies a unary op with unavailable/503 — not the
// pre-fix internal/500 — so unary and streaming agree on the audit-down
// wire class.
func TestUnaryAuditDownIs503(t *testing.T) {
	client := serveSouthface(t, downGuard{}, ceilings.NewNopRegistry())
	resp := postReadFile(t, client)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("audit-down unary status = %d, want 503", resp.StatusCode)
	}
	if h := resp.Header.Get("x-deny-reason"); h != "" {
		t.Fatalf("x-deny-reason = %q on audit-down, want none", h)
	}
}

// TestUnaryThrottleIs429 pins FC-02 end-to-end: an exhausted REAL ops/s
// bucket behind the REAL ceilings adapter denies a unary op with
// resource_exhausted/429 — not the pre-fix internal/500 — so client backoff
// works.
func TestUnaryThrottleIs429(t *testing.T) {
	fixed := time.Unix(0, 0)
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         0,
		OpsBurst:             0,
		InFlightBytesCeiling: 1 << 20,
		FDCeiling:            8,
		Clock:                func() time.Time { return fixed },
	})
	client := serveSouthface(t, stubGuard{}, reg)
	resp := postReadFile(t, client)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("throttled unary status = %d, want 429", resp.StatusCode)
	}
	if h := resp.Header.Get("x-deny-reason"); h != "" {
		t.Fatalf("x-deny-reason = %q on a throttle, want none", h)
	}
}
