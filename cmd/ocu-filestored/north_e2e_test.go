// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// fencedScopeHeaderName mirrors the FENCED host-attested scope header the north
// Files-API ScopeSource placeholder reads (internal/filesapi). It is duplicated
// here as a wire literal because the production constant is unexported; the e2e
// must present the same header the daemon's wired ScopeSource consumes.
const fencedScopeHeaderName = "X-OCU-Filesystem-Id"

// composeWithNorth builds an admitted config with a durable handle store and a
// dedicated north bind, composes the stack, and starts serving. It returns the
// live teardownServer, the north bind address, and the live DiskStore so the
// test can Put a record and then GET it back over the north TLS listener.
func composeWithNorth(t *testing.T) (*teardownServer, string, *handlestore.DiskStore) {
	t.Helper()
	cfg := validBrokerConfig(t)
	cfg.filesystemID = "fs-e2e-01"
	cfg.handleStore = filepath.Join(shortDir(t), "handles.jsonl")
	cfg.northBind = freeLoopbackAddr(t)

	srv, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if err != nil {
		t.Fatalf("compose with north: %v", err)
	}
	ts, ok := srv.(*teardownServer)
	if !ok {
		t.Fatalf("compose returned %T, want *teardownServer", srv)
	}
	if ts.handleStore == nil {
		t.Fatal("teardownServer.handleStore is nil; the durable store was not wired")
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()
	t.Cleanup(func() { _ = srv.Close(); <-serveErr })

	return ts, cfg.northBind, ts.handleStore
}

// TestNorthEndToEndPutThenGet pins the compose-level wiring: with --handle-store
// set, a record Put into the REAL DiskStore is resolvable as a FileObject over
// the REAL north TLS listener (real engine + real audit sink, no mocks). This is
// the end-to-end proof that Mount B serves the filesapi handler against the live
// durable store.
func TestNorthEndToEndPutThenGet(t *testing.T) {
	_, northAddr, store := composeWithNorth(t)

	// Put a record into the live durable store (the store mints the file_id and
	// stamps CreatedAt). It is bound to the attested scope the e2e presents.
	rec, err := store.Put(context.Background(), handlestore.PutInput{
		Scope:     "fs-e2e-01",
		ObjectRef: "obj/report.pdf",
		Filename:  "report.pdf",
		Mime:      "application/pdf",
		Size:      2048,
	})
	if err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // ephemeral self-signed test cert
		Timeout:   3 * time.Second,
	}

	// GET the metadata over the north TLS listener, presenting the host-attested
	// scope. Retry until the listener accepts.
	var resp *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, "https://"+northAddr+"/v1/files/"+rec.FileID, nil)
		req.Header.Set(fencedScopeHeaderName, "fs-e2e-01")
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("north listener never reachable: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("north GET status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var fo struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Filename string `json:"filename"`
		MimeType string `json:"mime_type"`
		Size     int64  `json:"size_bytes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fo); err != nil {
		t.Fatalf("decode FileObject: %v", err)
	}
	if fo.ID != rec.FileID || fo.Type != "file" || fo.Filename != "report.pdf" || fo.MimeType != "application/pdf" || fo.Size != 2048 {
		t.Fatalf("FileObject = %+v, mismatch with the Put record %+v", fo, rec)
	}
}

// TestNorthEndToEndCrossScopeIs404 pins the keystone over the wire: presenting a
// DIFFERENT host-attested scope than the record's scope yields a 404 (the record
// exists but in another scope — indistinguishable from absent).
func TestNorthEndToEndCrossScopeIs404(t *testing.T) {
	_, northAddr, store := composeWithNorth(t)
	rec, err := store.Put(context.Background(), handlestore.PutInput{
		Scope: "fs-e2e-01", ObjectRef: "obj/x", Filename: "x", Size: 1,
	})
	if err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // ephemeral self-signed test cert
		Timeout:   3 * time.Second,
	}
	var resp *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, "https://"+northAddr+"/v1/files/"+rec.FileID, nil)
		req.Header.Set(fencedScopeHeaderName, "fs-OTHER-scope") // wrong scope
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("north listener never reachable: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-scope GET status = %d, want 404 (keystone)", resp.StatusCode)
	}
	if resp.Header.Get("x-deny-reason") != "" {
		t.Fatal("cross-scope 404 carries x-deny-reason; the keystone must be header-less")
	}
}

// TestNorthUnsetNoNorthListener pins that with --handle-store UNSET no north
// listener is constructed: the composed server is a dualServer with a nil north,
// so it serves south-only and nothing binds the north plane.
func TestNorthUnsetNoNorthListener(t *testing.T) {
	cfg := validBrokerConfig(t) // no handleStore
	srv, err := compose(cfg, testLogger(), telemetry.NewBrokerMetrics("test"))
	if err != nil {
		t.Fatalf("compose without handle store: %v", err)
	}
	defer func() { _ = srv.Close() }()

	ts, ok := srv.(*teardownServer)
	if !ok {
		t.Fatalf("compose returned %T, want *teardownServer", srv)
	}
	ds, ok := ts.Server.(*dualServer)
	if !ok {
		t.Fatalf("teardownServer wraps %T, want *dualServer", ts.Server)
	}
	if ds.north != nil {
		t.Fatal("north listener constructed despite an unset --handle-store; want nil north (south-only)")
	}
}
