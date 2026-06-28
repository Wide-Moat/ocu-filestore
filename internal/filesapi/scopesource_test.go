// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// TestFencedScopeSourcePresentHeader pins the placeholder ScopeSource happy
// path: a present host-attested filesystem_id header yields a PeerScope bound to
// it with the read intent grant and zero UID/PID (no kernel peer on the F9 host
// leg).
func TestFencedScopeSourcePresentHeader(t *testing.T) {
	src := NewFencedScopeSource()
	r := httptest.NewRequest(http.MethodGet, "/v1/files/abc", nil)
	r.Header.Set(fencedScopeHeader, "fs-alpha")

	ps, ok := src.Scope(r)
	if !ok {
		t.Fatal("present header -> ok=false, want ok=true")
	}
	if ps.FilesystemID != "fs-alpha" {
		t.Fatalf("FilesystemID = %q, want fs-alpha", ps.FilesystemID)
	}
	if len(ps.GrantedIntents) != 1 || ps.GrantedIntents[0] != southface.IntentRead {
		t.Fatalf("GrantedIntents = %v, want [read]", ps.GrantedIntents)
	}
	if ps.UID != 0 || ps.PID != 0 {
		t.Fatalf("UID/PID = %d/%d, want 0/0 (no kernel peer on the F9 host leg)", ps.UID, ps.PID)
	}
}

// TestFencedScopeSourceAbsentHeaderFailsClosed pins the fail-closed path: an
// absent (or empty) host-attested scope field is ok=false — a request without a
// resolvable attested scope is refused before any store lookup.
func TestFencedScopeSourceAbsentHeaderFailsClosed(t *testing.T) {
	src := NewFencedScopeSource()

	t.Run("absent", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v1/files/abc", nil)
		if _, ok := src.Scope(r); ok {
			t.Fatal("absent header -> ok=true, want ok=false (fail-closed)")
		}
	})

	t.Run("empty", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v1/files/abc", nil)
		r.Header.Set(fencedScopeHeader, "")
		if _, ok := src.Scope(r); ok {
			t.Fatal("empty header -> ok=true, want ok=false (fail-closed)")
		}
	})
}
