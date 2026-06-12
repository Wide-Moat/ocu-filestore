// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// goldenUnaryBody is the GOLDEN-FIXTURES representative unary request body
// (triplet fs-golden-01 / golden dir). Both broker and guest pin identical
// bytes; the broker decodes it parsed-equal.
const goldenUnaryBody = `{"filesystem_id":"fs-golden-01","path":"/golden-dir","authorization_metadata":{"intent":"read","downloadable":false}}`

// TestGoldenUnaryDecode pins that the golden representative unary request
// decodes to the exact spine view: scope fs-golden-01, path /golden-dir,
// intent read — with the exact route and version header the guest sends.
func TestGoldenUnaryDecode(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, servicePrefix+"listDirectory", strings.NewReader(goldenUnaryBody))
	r.ContentLength = int64(len(goldenUnaryBody))
	op, err := parseRoute(r.Method, r.URL.Path)
	if err != nil || op != OpListDirectory {
		t.Fatalf("parseRoute: op %q err %v, want listDirectory/nil", op, err)
	}

	w := httptest.NewRecorder()
	var env unaryEnvelope
	if err := decodeUnaryEnvelope(w, r, 1<<20, &env); err != nil {
		t.Fatalf("decodeUnaryEnvelope: %v", err)
	}
	want := unaryEnvelope{
		FilesystemID:          "fs-golden-01",
		Path:                  "/golden-dir",
		AuthorizationMetadata: authorizationMetadata{Intent: IntentRead, Downloadable: false},
	}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("decoded envelope = %+v, want %+v", env, want)
	}
}

// TestGoldenErrorBodyShape pins the GOLDEN-FIXTURES error body shape: a
// non-2xx response carries application/json {code, message}; x-deny-reason
// appears ONLY on permission_denied and unauthenticated verdicts.
func TestGoldenErrorBodyShape(t *testing.T) {
	for _, tc := range []struct {
		name       string
		verdict    DenyVerdict
		wantHeader bool
	}{
		{"permission_denied carries header", mapDeny(denyScopeMismatch), true},
		{"unauthenticated carries header", mapDeny(denyLeaseExpired), true},
		{"not_found carries no header", mapDeny(denyNotFound), false},
		{"resource_exhausted carries no header", mapDeny(denyThrottle), false},
		{"unavailable carries no header", mapDeny(denyAuditDown), false},
		{"unimplemented carries no header", mapDeny(denyUnimplemented), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeConnectError(w, tc.verdict, "msg")

			if ct := w.Header().Get("Content-Type"); ct != contentTypeJSON {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			if w.Code != tc.verdict.WireStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.verdict.WireStatus)
			}
			var ce connectError
			if err := json.Unmarshal(w.Body.Bytes(), &ce); err != nil {
				t.Fatalf("body not {code,message} JSON: %v", err)
			}
			if ce.Code != tc.verdict.WireCode || ce.Message != "msg" {
				t.Fatalf("body = %+v, want code=%q message=msg", ce, tc.verdict.WireCode)
			}
			gotHeader := w.Header().Get("x-deny-reason") != ""
			if gotHeader != tc.wantHeader {
				t.Fatalf("x-deny-reason present=%v, want %v", gotHeader, tc.wantHeader)
			}
			if tc.wantHeader && w.Header().Get("x-deny-reason") != tc.verdict.AuditReason {
				t.Fatalf("x-deny-reason = %q, want %q", w.Header().Get("x-deny-reason"), tc.verdict.AuditReason)
			}
		})
	}
}
