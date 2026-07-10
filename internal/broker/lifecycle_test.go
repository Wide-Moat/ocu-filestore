// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
)

// TestE2EEraseBeforeReuse pins SEC-54 at the broker-lifecycle level: a byte
// written under a scope is unreadable after TeardownScope + re-provision of the
// same filesystem_id. Teardown is a lifecycle action with no south-face RPC, so
// this exercises the wiring's lifecycle path (the same ProvisionScope /
// TeardownScope calls main makes through the real engine, NOT the consumer
// seam) rather than the wire. The objectstore package has its own engine-level
// erase test; this adds the broker-lifecycle path.
func TestE2EEraseBeforeReuse(t *testing.T) {
	root, err := os.MkdirTemp("", "erase")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	eng := objectstore.NewLocalVolumeEngine(root)
	ctx := context.Background()
	scope := objectstore.ScopeID("fs-erase-01")
	const path = "secret.bin"

	// Session A: provision, write a byte.
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope A: %v", err)
	}
	payload := []byte("TOPSECRET")
	if _, err := eng.WriteStream(ctx, scope, path, bytes.NewReader(payload), false); err != nil {
		t.Fatalf("WriteStream A: %v", err)
	}
	// Confirm it is readable in session A.
	var buf bytes.Buffer
	if err := eng.ReadRange(ctx, scope, path, 0, int64(len(payload)), &buf); err != nil {
		t.Fatalf("ReadRange A (should succeed): %v", err)
	}
	if !bytes.Equal(buf.Bytes(), payload) {
		t.Fatalf("ReadRange A returned %q, want %q", buf.Bytes(), payload)
	}

	// Teardown + re-provision the SAME fsid — erase-before-reuse (SEC-54).
	if err := eng.TeardownScope(ctx, scope); err != nil {
		t.Fatalf("TeardownScope: %v", err)
	}
	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope B (re-grant): %v", err)
	}

	// Session B: the prior path must be not_found — the bytes did not survive.
	var after bytes.Buffer
	err = eng.ReadRange(ctx, scope, path, 0, int64(len(payload)), &after)
	if err == nil {
		t.Fatalf("ReadRange B read %q after teardown; want not_found (SEC-54)", after.Bytes())
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadRange B error = %v, want fs.ErrNotExist (not merely an error)", err)
	}
}

// TestE2EEraseThroughEngineAdapter pins that the broker engine adapter (the
// consumer-seam view main wires) reports the post-teardown read as not_found
// through the same path the dispatch handlers take — the adapter passes the
// stdlib not-exist sentinel through verbatim so denyClassForEngineErr degrades
// it to not_found.
func TestE2EEraseThroughEngineAdapter(t *testing.T) {
	root, err := os.MkdirTemp("", "erase2")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	realEng := objectstore.NewLocalVolumeEngine(root)
	ctx := context.Background()
	scope := "fs-erase-02"
	sid := objectstore.ScopeID(scope)
	const path = "kept.bin"

	if err := realEng.ProvisionScope(ctx, sid); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}
	adapter := NewEngine(realEng)
	digest, err := adapter.WriteStream(ctx, scope, path, strings.NewReader("DATA"), false)
	if err != nil {
		t.Fatalf("adapter.WriteStream: %v", err)
	}
	// The adapter threads the real local engine's single-pass content digest (D6)
	// through unchanged - assert it equals the precomputed hex SHA-256 of "DATA"
	// (a live-engine leg, not a stub echo).
	sum := sha256.Sum256([]byte("DATA"))
	if want := hex.EncodeToString(sum[:]); digest != want {
		t.Fatalf("adapter.WriteStream digest = %q, want the content sha256 %q", digest, want)
	}
	if err := realEng.TeardownScope(ctx, sid); err != nil {
		t.Fatalf("TeardownScope: %v", err)
	}
	if err := realEng.ProvisionScope(ctx, sid); err != nil {
		t.Fatalf("re-ProvisionScope: %v", err)
	}

	var buf bytes.Buffer
	err = adapter.ReadRange(ctx, scope, path, 0, 4, &buf)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("adapter.ReadRange after teardown: got %v, want fs.ErrNotExist (verbatim pass-through)", err)
	}
}
