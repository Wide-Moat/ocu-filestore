// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzEnvelope asserts SEC-51: decodeUnaryEnvelope never panics on arbitrary
// input and always yields either a clean decode or one of the structured
// envelope sentinels — never an unclassified error and never a crash.
func FuzzEnvelope(f *testing.F) {
	const ceiling = 1 << 16
	f.Add(`{"filesystem_id":"fs1","path":"/p","authorization_metadata":{"intent":"read","downloadable":false}}`)
	f.Add(`{"filesystem_id":"fs1","bogus":1}`)
	f.Add(`{"filesystem_id":"a"}{"filesystem_id":"b"}`)
	f.Add(``)
	f.Add(`42`)
	f.Add(`{`)
	f.Add(strings.Repeat("A", 1<<17))

	f.Fuzz(func(t *testing.T, body string) {
		r := httptest.NewRequest(http.MethodPost, restBase+"listDirectory", strings.NewReader(body))
		r.ContentLength = int64(len(body))
		w := httptest.NewRecorder()
		var env unaryEnvelope
		err := decodeUnaryEnvelope(w, r, ceiling, &env)
		if err == nil {
			return
		}
		if !errors.Is(err, errMalformedEnvelope) && !errors.Is(err, errDeclaredSizeExceeded) {
			t.Fatalf("decodeUnaryEnvelope: unclassified error %v for body %q", err, body)
		}
	})
}
