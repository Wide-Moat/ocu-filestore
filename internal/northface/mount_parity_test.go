// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package northface

import (
	"crypto/tls"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// tlsGet dials addr over TLS (skip-verify for the ephemeral self-signed loopback
// cert) and returns the response, retrying until the listener accepts.
func tlsGet(t *testing.T, addr, path string) *http.Response {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // ephemeral self-signed test cert
		Timeout:   3 * time.Second,
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := client.Get("https://" + addr + path)
		if err == nil {
			return resp
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener %s never reachable: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMountBServesOnlyInjectedHandler pins that EVERY path on the north listener
// reaches the SAME injected handler — Mount B does not graft any other routes
// (no south spine, no implicit mux). A sentinel handler counts every hit and
// answers a distinctive status regardless of path.
func TestMountBServesOnlyInjectedHandler(t *testing.T) {
	cert, key := testCertPaths(t)
	addr := freeLoopbackAddr(t)

	var hits int64
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusTeapot)
	})
	mb, err := NewMountB(addr, cert, key, sentinel, nil)
	if err != nil {
		t.Fatalf("NewMountB: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- mb.Serve() }()
	t.Cleanup(func() { _ = mb.Close(); <-serveErr })

	// Hit a variety of paths — Files-API routes AND paths a south spine would
	// own (e.g. a south op path). ALL must reach the one injected handler.
	for _, p := range []string{
		"/v1/files",
		"/v1/files/abc",
		"/v1/files/abc/content",
		"/readFile",           // a south-style op path: must NOT be specially routed
		"/storage.v1.Storage", // a Connect-style south path
		"/anything/else",
	} {
		resp := tlsGet(t, addr, p)
		if resp.StatusCode != http.StatusTeapot {
			t.Fatalf("path %q -> %d, want 418 (the sole injected handler); Mount B grafted an extra route", p, resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if got := atomic.LoadInt64(&hits); got != 6 {
		t.Fatalf("injected handler hit %d times, want 6 (every path reached it)", got)
	}
}

// TestMountBDistinctBindFromSouth pins that a north listener and a (stand-in)
// south listener on DISTINCT binds are independent: a request to the north bind
// reaches ONLY the north handler, never the south one. The two handlers answer
// distinctive statuses so a cross-routing would be visible.
func TestMountBDistinctBindFromSouth(t *testing.T) {
	cert, key := testCertPaths(t)
	northAddr := freeLoopbackAddr(t)
	southAddr := freeLoopbackAddr(t)
	if northAddr == southAddr {
		t.Fatal("north and south binds collided; the test needs distinct binds")
	}

	northHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // 418 = north
	})
	// A stand-in south listener (a plain Mount B with a DIFFERENT handler) on its
	// own bind — it represents the south spine's separate listener.
	southHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 403 = south (would be visible if cross-routed)
	})

	northMB, err := NewMountB(northAddr, cert, key, northHandler, nil)
	if err != nil {
		t.Fatalf("north NewMountB: %v", err)
	}
	southMB, err := NewMountB(southAddr, cert, key, southHandler, nil)
	if err != nil {
		t.Fatalf("south NewMountB: %v", err)
	}
	nErr, sErr := make(chan error, 1), make(chan error, 1)
	go func() { nErr <- northMB.Serve() }()
	go func() { sErr <- southMB.Serve() }()
	t.Cleanup(func() {
		_ = northMB.Close()
		_ = southMB.Close()
		<-nErr
		<-sErr
	})

	// A request to the NORTH bind reaches the NORTH handler (418), never the
	// south handler (403). The distinct binds are the physical trust boundary.
	resp := tlsGet(t, northAddr, "/v1/files")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("north bind -> %d, want 418 (north handler only); a 403 would mean the south plane was reachable from the north listener", resp.StatusCode)
	}
}
