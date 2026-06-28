// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
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
	r := httptest.NewRequest(http.MethodPost, restBase+"listDirectory", strings.NewReader(goldenUnaryBody))
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

// The non-2xx REST deny body shape (a BoundedReason {reason_code, message}
// diagnostic, with x-deny-reason gated to permission_denied / unauthenticated)
// is pinned by restdeny_test.go's TestRESTDeny — the Connect {code, message}
// body it superseded is retired.
