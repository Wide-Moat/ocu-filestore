// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package denywire

import (
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
)

// goldenVerdict is the INDEPENDENT anchor for one deny class: the wire code,
// HTTP status, and header gating a refusal of that class MUST carry. It is hand
// written here, NOT derived from denyTable, so it is a genuine second source —
// a drift between the table and this anchor is a real failure, not a tautology.
type goldenVerdict struct {
	wireCode   string
	status     int
	wireHeader bool
}

// golden is the hand-written expected mapping for EVERY denyclass token. The
// first four authorization verdicts carry the x-deny-reason header; everything
// else is header-less. The status column is keyed independently of
// StatusForWireCode (the values are typed out, not computed).
var golden = map[string]goldenVerdict{
	denyclass.ScopeMismatch:      {"permission_denied", 403, true},
	denyclass.IntentDenied:       {"permission_denied", 403, true},
	denyclass.NotDownloadable:    {"permission_denied", 403, true},
	denyclass.LeaseExpired:       {"unauthenticated", 401, true},
	denyclass.SizeExceeded:       {"invalid_argument", 400, false},
	denyclass.Malformed:          {"invalid_argument", 400, false},
	denyclass.DirNotEmpty:        {"invalid_argument", 400, false},
	denyclass.NotFound:           {"not_found", 404, false},
	denyclass.Throttle:           {"resource_exhausted", 429, false},
	denyclass.AuditDown:          {"unavailable", 503, false},
	denyclass.BackendUnavailable: {"unavailable", 503, false},
	denyclass.AlreadyExists:      {"already_exists", 409, false},
	denyclass.Aborted:            {"aborted", 409, false},
	denyclass.Unimplemented:      {"unimplemented", 501, false},
	denyclass.Internal:           {"internal", 500, false},
}

// TestDenyVerdictGoldenTable pins MapDeny against the independent golden anchor
// for every denyclass token: the anchor's key set MUST equal the shared
// vocabulary (no class unmapped, no extra), and each MapDeny verdict MUST match
// the hand-written wire code, status, and header gating. A drift in either the
// table or this anchor fails loudly.
func TestDenyVerdictGoldenTable(t *testing.T) {
	classes := denyclass.DenyClasses()

	// The golden anchor must cover exactly the shared vocabulary.
	gotKeys := make([]string, 0, len(golden))
	for k := range golden {
		gotKeys = append(gotKeys, k)
	}
	wantKeys := append([]string(nil), classes...)
	sort.Strings(gotKeys)
	sort.Strings(wantKeys)
	if len(gotKeys) != len(wantKeys) {
		t.Fatalf("golden anchor covers %d classes, shared vocabulary has %d\n got: %v\nwant: %v",
			len(gotKeys), len(wantKeys), gotKeys, wantKeys)
	}
	for i := range wantKeys {
		if gotKeys[i] != wantKeys[i] {
			t.Fatalf("golden anchor drift at %d: have %q want %q", i, gotKeys[i], wantKeys[i])
		}
	}

	for _, class := range classes {
		class := class
		want := golden[class]
		t.Run(class, func(t *testing.T) {
			v := MapDeny(class)
			if v.AuditReason != class {
				t.Errorf("AuditReason = %q, want %q", v.AuditReason, class)
			}
			if v.WireCode != want.wireCode {
				t.Errorf("WireCode = %q, want %q", v.WireCode, want.wireCode)
			}
			if v.WireStatus != want.status {
				t.Errorf("WireStatus = %d, want %d", v.WireStatus, want.status)
			}
			if v.WireHeader != want.wireHeader {
				t.Errorf("WireHeader = %v, want %v", v.WireHeader, want.wireHeader)
			}
		})
	}
}

// TestMapDenyUnknownFailsClosed pins the unknown-class fallback: a token not in
// the table maps to internal/500, no header, AuditReason carrying the unknown
// token verbatim (so the audit record still names what was refused).
func TestMapDenyUnknownFailsClosed(t *testing.T) {
	v := MapDeny("not_a_real_class")
	if v.WireCode != WireCodeInternal || v.WireStatus != 500 || v.WireHeader {
		t.Fatalf("unknown class verdict = %+v, want internal/500/no-header", v)
	}
	if v.AuditReason != "not_a_real_class" {
		t.Fatalf("AuditReason = %q, want the unknown token verbatim", v.AuditReason)
	}
}

// TestMapDenyDegradedSplitsTruthFromWire pins the degrade: the audit reason is
// the TRUTH while the wire code/status/header come from the wire class. The
// canonical degrade is scope_mismatch (truth) -> not_found (wire), which keeps
// the truth out of the header.
func TestMapDenyDegradedSplitsTruthFromWire(t *testing.T) {
	v := MapDenyDegraded(denyclass.ScopeMismatch, denyclass.NotFound)
	if v.AuditReason != denyclass.ScopeMismatch {
		t.Errorf("AuditReason = %q, want scope_mismatch (truth)", v.AuditReason)
	}
	if v.WireCode != WireCodeNotFound || v.WireStatus != 404 {
		t.Errorf("wire = %q/%d, want not_found/404", v.WireCode, v.WireStatus)
	}
	if v.WireHeader {
		t.Error("degraded not_found verdict must be header-less (no truth leak)")
	}
}

// TestWriteRESTDenyShape pins the REST deny writer: the authoritative status,
// the {reason_code, message} JSON body, the Content-Type, the message clamp,
// and the x-deny-reason header present iff WireHeader.
func TestWriteRESTDenyShape(t *testing.T) {
	reasonRE := regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

	for _, class := range denyclass.DenyClasses() {
		want := golden[class]
		t.Run(class, func(t *testing.T) {
			v := MapDeny(class)
			w := httptest.NewRecorder()
			WriteRESTDeny(w, v, "diagnostic message")

			if w.Code != want.status {
				t.Fatalf("status = %d, want %d", w.Code, want.status)
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			hdr := w.Header().Get(DenyReasonHeader)
			if want.wireHeader {
				if hdr != class {
					t.Fatalf("x-deny-reason = %q, want %q", hdr, class)
				}
			} else if hdr != "" {
				t.Fatalf("x-deny-reason = %q, want absent for header-less verdict", hdr)
			}

			var body boundedReason
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if !reasonRE.MatchString(body.ReasonCode) {
				t.Fatalf("reason_code %q is not pattern-valid", body.ReasonCode)
			}
			if body.ReasonCode != strings.ToUpper(want.wireCode) {
				t.Fatalf("reason_code = %q, want %q", body.ReasonCode, strings.ToUpper(want.wireCode))
			}
			if body.Message != "diagnostic message" {
				t.Fatalf("message = %q, want the diagnostic verbatim", body.Message)
			}
		})
	}
}

// TestWriteRESTDenyClampsMessage pins the 256-byte message clamp: an oversize
// diagnostic is truncated to exactly BoundedReasonMessageMax bytes on the wire.
func TestWriteRESTDenyClampsMessage(t *testing.T) {
	long := strings.Repeat("x", BoundedReasonMessageMax+50)
	w := httptest.NewRecorder()
	WriteRESTDeny(w, MapDeny(denyclass.Internal), long)

	var body boundedReason
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Message) != BoundedReasonMessageMax {
		t.Fatalf("clamped message len = %d, want %d", len(body.Message), BoundedReasonMessageMax)
	}
	if body.Message != long[:BoundedReasonMessageMax] {
		t.Fatal("clamped message is not the leading BoundedReasonMessageMax bytes")
	}
}

// TestBoundedReasonHelper pins the exported clamp helper directly: a short
// message passes through, a long one is truncated.
func TestBoundedReasonHelper(t *testing.T) {
	if got := BoundedReason("short"); got != "short" {
		t.Fatalf("BoundedReason(short) = %q, want short", got)
	}
	long := strings.Repeat("y", BoundedReasonMessageMax+1)
	if got := BoundedReason(long); len(got) != BoundedReasonMessageMax {
		t.Fatalf("BoundedReason(long) len = %d, want %d", len(got), BoundedReasonMessageMax)
	}
}
