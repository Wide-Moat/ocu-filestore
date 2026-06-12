// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// TestSessionRegistryLifecycle pins provision/lookup/release: a provisioned
// path looks up its bound entry, an unprovisioned path reports ok=false, a
// released path is gone, and a duplicate provision refuses with the typed
// sentinel (a wiring mistake fails loud, never silently rebinds).
func TestSessionRegistryLifecycle(t *testing.T) {
	r := NewSessionRegistry()
	entry := SessionEntry{
		FilesystemID:   "fs-golden-01",
		GrantedIntents: []Intent{IntentRead, IntentWrite},
	}

	if _, ok := r.Lookup("/tmp/none.sock"); ok {
		t.Fatalf("Lookup(unprovisioned) = ok, want !ok")
	}
	if err := r.Provision("/tmp/a.sock", entry); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	got, ok := r.Lookup("/tmp/a.sock")
	if !ok {
		t.Fatalf("Lookup(provisioned) = !ok, want ok")
	}
	if got.FilesystemID != entry.FilesystemID || len(got.GrantedIntents) != 2 {
		t.Fatalf("Lookup = %+v, want %+v", got, entry)
	}
	if err := r.Provision("/tmp/a.sock", entry); !errors.Is(err, ErrSessionExists) {
		t.Fatalf("duplicate Provision: got %v, want ErrSessionExists", err)
	}
	r.Release("/tmp/a.sock")
	if _, ok := r.Lookup("/tmp/a.sock"); ok {
		t.Fatalf("Lookup(released) = ok, want !ok")
	}
	// Re-provision after release rebinds cleanly.
	if err := r.Provision("/tmp/a.sock", entry); err != nil {
		t.Fatalf("re-Provision after Release: %v", err)
	}
}

// TestSessionRegistryConcurrent exercises concurrent Provision/Lookup/Release
// under -race: distinct goroutines on distinct paths plus readers on a shared
// path must be race-clean.
func TestSessionRegistryConcurrent(t *testing.T) {
	r := NewSessionRegistry()
	shared := "/tmp/shared.sock"
	if err := r.Provision(shared, SessionEntry{FilesystemID: "fs-shared"}); err != nil {
		t.Fatalf("Provision shared: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/tmp/s-%d.sock", i)
			if err := r.Provision(path, SessionEntry{FilesystemID: fmt.Sprintf("fs-%d", i)}); err != nil {
				t.Errorf("Provision(%s): %v", path, err)
				return
			}
			if _, ok := r.Lookup(shared); !ok {
				t.Errorf("Lookup(shared) lost during concurrency")
			}
			if _, ok := r.Lookup(path); !ok {
				t.Errorf("Lookup(%s) = !ok after Provision", path)
			}
			r.Release(path)
		}(i)
	}
	wg.Wait()
	if _, ok := r.Lookup(shared); !ok {
		t.Fatalf("shared entry gone after concurrent churn")
	}
}
