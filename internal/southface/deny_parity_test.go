// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
)

// TestSouthDenyMatchesDenywire is the cross-package parity guard: the south
// face delegates its deny mapping and REST deny writer to the shared
// internal/denywire package, and this test proves the south-visible behaviour
// is byte-identical to denywire for EVERY deny class plus the degraded
// scope_mismatch -> not_found case. It is the drift guard that lets the south
// shims delegate safely — if a future edit to either side diverges, this fails.
//
// The independent anchor lives in denywire_test.go (a hand-written golden table
// NOT derived from any mapping function); this test pins south == denywire, and
// that test pins denywire == the anchor. The two together close the loop:
// south's wire form cannot drift from the hand-written truth in either
// direction.
func TestSouthDenyMatchesDenywire(t *testing.T) {
	for _, class := range denyclass.DenyClasses() {
		class := class
		t.Run(class, func(t *testing.T) {
			// Verdict-level parity: every field of south mapDeny equals denywire.
			south := mapDeny(class)
			shared := denywire.MapDeny(class)
			if south.AuditReason != shared.AuditReason ||
				south.WireCode != shared.WireCode ||
				south.WireStatus != shared.WireStatus ||
				south.WireHeader != shared.WireHeader {
				t.Fatalf("mapDeny(%q) south=%+v denywire=%+v", class, south, shared)
			}

			// The denyTable row (south's own copy, kept for the telemetry drift
			// guard) must agree with the shared mapping too — this reads the row
			// fields so south's table can never silently diverge from denywire.
			row := denyTable[class]
			if row.wireCode != shared.WireCode || row.header != shared.WireHeader {
				t.Fatalf("denyTable[%q] = %+v, denywire = code %q header %v",
					class, row, shared.WireCode, shared.WireHeader)
			}

			// Writer-level parity: the bytes south writes equal the bytes denywire
			// writes (status, headers, body) for the same verdict and message.
			ws := httptest.NewRecorder()
			writeRESTDeny(ws, south, "diagnostic message")
			wd := httptest.NewRecorder()
			denywire.WriteRESTDeny(wd, shared, "diagnostic message")

			if ws.Code != wd.Code {
				t.Fatalf("status: south=%d denywire=%d", ws.Code, wd.Code)
			}
			if ws.Body.String() != wd.Body.String() {
				t.Fatalf("body: south=%q denywire=%q", ws.Body.String(), wd.Body.String())
			}
			if ws.Header().Get(denyReasonHeader) != wd.Header().Get(denywire.DenyReasonHeader) {
				t.Fatalf("x-deny-reason: south=%q denywire=%q",
					ws.Header().Get(denyReasonHeader), wd.Header().Get(denywire.DenyReasonHeader))
			}
			if ws.Header().Get("Content-Type") != wd.Header().Get("Content-Type") {
				t.Fatalf("Content-Type: south=%q denywire=%q",
					ws.Header().Get("Content-Type"), wd.Header().Get("Content-Type"))
			}
		})
	}
}

// TestSouthDenyDegradedMatchesDenywire pins the anti-enumeration degrade
// (scope_mismatch audited truth, not_found wire class) through both faces: the
// audit reason stays scope_mismatch, the wire degrades to header-less 404, and
// south's writeRESTDeny output equals denywire's. This is the load-bearing
// keystone case the north Files-API plane relies on (a cross-scope file_id must
// be byte-identical to an unknown one).
func TestSouthDenyDegradedMatchesDenywire(t *testing.T) {
	south := mapDenyDegraded(denyScopeMismatch, denyNotFound)
	shared := denywire.MapDenyDegraded(denyclass.ScopeMismatch, denyclass.NotFound)

	if south.AuditReason != denyScopeMismatch {
		t.Fatalf("south degraded AuditReason = %q, want scope_mismatch", south.AuditReason)
	}
	if south.WireStatus != 404 || south.WireHeader {
		t.Fatalf("south degraded wire = status %d header %v, want 404/false", south.WireStatus, south.WireHeader)
	}

	ws := httptest.NewRecorder()
	writeRESTDeny(ws, south, "object not found")
	wd := httptest.NewRecorder()
	denywire.WriteRESTDeny(wd, shared, "object not found")

	if ws.Code != wd.Code || ws.Body.String() != wd.Body.String() {
		t.Fatalf("degraded parity: south=(%d,%q) denywire=(%d,%q)",
			ws.Code, ws.Body.String(), wd.Code, wd.Body.String())
	}
	if ws.Header().Get(denyReasonHeader) != "" || wd.Header().Get(denywire.DenyReasonHeader) != "" {
		t.Fatalf("degraded 404 must be header-less: south=%q denywire=%q",
			ws.Header().Get(denyReasonHeader), wd.Header().Get(denywire.DenyReasonHeader))
	}
}
