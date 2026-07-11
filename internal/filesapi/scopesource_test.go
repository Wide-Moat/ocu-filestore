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

// TestValidateScopeShape is the north shape-guard keystone (ADR-0030 north
// face, open question #348). It pins that the north choke point accepts a
// shape-legal filesystem_id ("<base>" or "<base>-<16hex>" and any other single,
// clean path element) and REFUSES one whose bytes could change which directory a
// baseDir join resolves to: a path separator, a NUL, "." / "..", or a non-clean
// form. This mirrors the engine's scope-id shape rules at the north edge so a
// malformed scope is refused BEFORE the store, not deep in the engine.
//
// It is a cooperative SHAPE + TRAVERSAL guard, NOT a per-chat authorization
// point: the caller supplies the whole filesystem_id, so this check enforces
// only that the value is a legal single path element. Per-chat isolation lives
// on the credential/south path (a different plane), not here.
func TestValidateScopeShape(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
		ok   bool
	}{
		{"plain base", "fs-fleet", true},
		{"base with 16hex chat suffix", "fs-fleet-abcdef0123456789", true},
		{"other clean element", "fs-alpha", true},
		{"empty", "", false},
		{"dot", ".", false},
		{"dotdot", "..", false},
		{"forward slash traversal", "fs-fleet-abc/123", false},
		{"parent escape", "fs-fleet-../etc", false},
		{"back slash", "fs-fleet\\etc", false},
		{"nul byte", "fs-fleet\x00etc", false},
		{"embedded slash", "a/b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateScopeShape(tc.id)
			if tc.ok && err != nil {
				t.Fatalf("validateScopeShape(%q) = %v, want nil (shape-legal)", tc.id, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("validateScopeShape(%q) = nil, want a shape refusal", tc.id)
			}
		})
	}
}

// TestFencedScopeSourceTraversalIdFailsClosed pins that the header source itself
// refuses a traversal-shaped filesystem_id (ok=false), so the route's existing
// fail-closed path (503, no scope-distinction leak) refuses it at the edge. This
// is the source-level leg of the north shape guard.
func TestFencedScopeSourceTraversalIdFailsClosed(t *testing.T) {
	src := NewFencedScopeSource()
	for _, id := range []string{"fs-fleet-abc/123", "fs-fleet-../etc", "fs-fleet\\etc"} {
		t.Run(id, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/files/abc", nil)
			r.Header.Set(fencedScopeHeader, id)
			if _, ok := src.Scope(r); ok {
				t.Fatalf("traversal-shaped scope %q -> ok=true, want ok=false (shape guard fail-closed)", id)
			}
		})
	}
}
