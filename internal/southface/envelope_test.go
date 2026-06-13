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

// TestRouteParse pins the route table: a known op routes; a non-POST method
// to a valid route is errBadMethod (405 out of band); an unknown route or a
// path outside the service prefix is errUnknownRoute.
func TestRouteParse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		method  string
		path    string
		wantOp  Op
		wantErr error
	}{
		{"known unary op", http.MethodPost, servicePrefix + "listDirectory", OpListDirectory, nil},
		{"known streaming op", http.MethodPost, servicePrefix + "fileUpload", OpFileUpload, nil},
		{"non-POST to valid route", http.MethodGet, servicePrefix + "listDirectory", "", errBadMethod},
		{"unknown op on prefix", http.MethodPost, servicePrefix + "noSuchOp", "", errUnknownRoute},
		{"path outside prefix", http.MethodPost, "/other/listDirectory", "", errUnknownRoute},
		{"bare prefix", http.MethodPost, servicePrefix, "", errUnknownRoute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, err := parseRoute(tc.method, tc.path)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("parseRoute: got err %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRoute: got err %v, want nil", err)
			}
			if op != tc.wantOp {
				t.Fatalf("parseRoute: got op %q, want %q", op, tc.wantOp)
			}
		})
	}
}

// TestVersionHeader pins D1: the Connect-Protocol-Version header is REQUIRED
// and must be "1"; absent or wrong is errBadVersion.
func TestVersionHeader(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		set     bool
		wantErr bool
	}{
		{"value 1", "1", true, false},
		{"absent", "", false, true},
		{"wrong value", "2", true, true},
		{"empty value", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, servicePrefix+"listDirectory", nil)
			r.Header.Del(connectProtocolVersionHeader)
			if tc.set {
				r.Header.Set(connectProtocolVersionHeader, tc.value)
			}
			err := checkVersion(r)
			if tc.wantErr != (err != nil) {
				t.Fatalf("checkVersion: got %v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, errBadVersion) {
				t.Fatalf("checkVersion: got %v, want errBadVersion", err)
			}
		})
	}
}

// TestContentType pins the application/json requirement, tolerating a charset
// parameter.
func TestContentType(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"plain json", "application/json", false},
		{"json with charset", "application/json; charset=utf-8", false},
		{"text plain", "text/plain", true},
		{"absent", "", true},
		{"connect json", "application/connect+json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, servicePrefix+"listDirectory", nil)
			r.Header.Del("Content-Type")
			if tc.value != "" {
				r.Header.Set("Content-Type", tc.value)
			}
			err := checkContentType(r)
			if tc.wantErr != (err != nil) {
				t.Fatalf("checkContentType(%q): got %v, wantErr=%v", tc.value, err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, errBadContentType) {
				t.Fatalf("checkContentType: got %v, want errBadContentType", err)
			}
		})
	}
}

// TestEnvelopeStrictDecode pins SEC-51: an unknown top-level field, a trailing
// second JSON value, and a non-object body each fail errMalformedEnvelope; a
// representative valid body decodes clean.
func TestEnvelopeStrictDecode(t *testing.T) {
	const ceiling = 1 << 20
	for _, tc := range []struct {
		name    string
		body    string
		wantErr error
	}{
		{"valid", `{"filesystem_id":"fs1","path":"/p","authorization_metadata":{"intent":"read","downloadable":false}}`, nil},
		{"unknown top field", `{"filesystem_id":"fs1","bogus":true}`, errMalformedEnvelope},
		{"trailing value", `{"filesystem_id":"fs1"}{"filesystem_id":"fs2"}`, errMalformedEnvelope},
		{"not an object", `42`, errMalformedEnvelope},
		{"truncated", `{"filesystem_id":`, errMalformedEnvelope},
		{"empty", ``, errMalformedEnvelope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, servicePrefix+"listDirectory", strings.NewReader(tc.body))
			r.ContentLength = int64(len(tc.body))
			w := httptest.NewRecorder()
			var env unaryEnvelope
			err := decodeUnaryEnvelope(w, r, ceiling, &env)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("decodeUnaryEnvelope: got %v, want nil", err)
				}
				if env.FilesystemID != "fs1" {
					t.Fatalf("decoded filesystem_id = %q, want fs1", env.FilesystemID)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("decodeUnaryEnvelope: got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestEnvelopeOversize pins SEC-78: a Content-Length above the ceiling is
// rejected before any body byte is read; an absent Content-Length falls back
// to the MaxBytesReader backstop, which catches an over-ceiling stream as a
// size deny without panicking.
func TestEnvelopeOversize(t *testing.T) {
	const ceiling = 64

	t.Run("content-length over ceiling, no body read", func(t *testing.T) {
		body := strings.Repeat("A", 4096)
		cr := &countingReader{r: strings.NewReader(body)}
		r := httptest.NewRequest(http.MethodPost, servicePrefix+"listDirectory", cr)
		r.ContentLength = int64(len(body))
		w := httptest.NewRecorder()
		var env unaryEnvelope
		if err := decodeUnaryEnvelope(w, r, ceiling, &env); !errors.Is(err, errDeclaredSizeExceeded) {
			t.Fatalf("decodeUnaryEnvelope: got %v, want errDeclaredSizeExceeded", err)
		}
		if cr.n != 0 {
			t.Fatalf("read %d bytes from an over-CL body, want 0 (SEC-78)", cr.n)
		}
	})

	t.Run("absent content-length, backstop catches oversize", func(t *testing.T) {
		body := `{"filesystem_id":"` + strings.Repeat("x", 4096) + `"}`
		r := httptest.NewRequest(http.MethodPost, servicePrefix+"listDirectory", strings.NewReader(body))
		r.ContentLength = -1 // absent
		w := httptest.NewRecorder()
		var env unaryEnvelope
		if err := decodeUnaryEnvelope(w, r, ceiling, &env); !errors.Is(err, errDeclaredSizeExceeded) {
			t.Fatalf("decodeUnaryEnvelope: got %v, want errDeclaredSizeExceeded via backstop", err)
		}
	})
}

// countingReader counts the bytes read from it so the oversize test can prove
// a pre-buffer reject reads zero body bytes.
type countingReader struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
