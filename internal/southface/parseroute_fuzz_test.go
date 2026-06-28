// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"net/http"
	"testing"
)

// FuzzParseRoute asserts SEC-51 on the pure route parser: parseRoute never
// panics on an arbitrary (method, path) pair and its result is TOTAL — it is
// EITHER a known routable Op (a member of the frozen knownOps enum) with a nil
// error, OR an empty Op with a non-nil structured route error. It is never a
// bogus/empty Op with a nil error (a silent accept of an unroutable request) and
// never a non-empty Op outside the frozen enum (an invented route). A parser
// must refuse cleanly, never crash and never half-accept.
func FuzzParseRoute(f *testing.F) {
	// Seed corpus: valid routes, wrong method, unknown op, path traversal, empty,
	// huge path, NUL bytes, and a prefix-but-not-member path.
	f.Add(http.MethodPost, restBase+"fileUpload")     // valid streamed op
	f.Add(http.MethodPost, restBase+"listDirectory")  // valid unary op
	f.Add(http.MethodGet, restBase+"fileUpload")      // wrong method -> errBadMethod
	f.Add(http.MethodPut, restBase+"createFile")      // wrong method -> errBadMethod
	f.Add(http.MethodPost, restBase+"unknownOp")      // unknown op -> errUnknownRoute
	f.Add(http.MethodPost, restBase+"fileDelete")     // enum member but NOT routable
	f.Add(http.MethodPost, restBase+"../../etc/pwd")  // traversal in the op segment
	f.Add(http.MethodPost, "/v1/filestore/fs")        // prefix-but-not-under-base
	f.Add(http.MethodPost, "/")                       // root, outside base
	f.Add(http.MethodPost, "")                        // empty path
	f.Add("", "")                                     // empty method and path
	f.Add(http.MethodPost, restBase)                  // base exactly -> empty op segment
	f.Add(http.MethodPost, restBase+"fileUpload/sub") // trailing extra segment
	f.Add(http.MethodPost, restBase+"file\x00Upload") // NUL byte in the op
	f.Add("PO\x00ST", restBase+"fileUpload")          // NUL byte in the method
	f.Add(http.MethodPost, restBase+hugeSegment())    // huge op segment

	f.Fuzz(func(t *testing.T, method, path string) {
		op, err := parseRoute(method, path)

		if err != nil {
			// REFUSE: a non-nil error MUST carry an empty Op (never a half-result
			// that names a route while also erroring).
			if op != "" {
				t.Fatalf("parseRoute(%q,%q) returned a non-empty Op %q alongside error %v; a refusal must name no route",
					method, path, op, err)
			}
			return
		}

		// ACCEPT: a nil error MUST name a member of the frozen routable enum. An
		// empty Op (or any Op outside knownOps) with a nil error is a silent
		// accept of an unroutable request — the exact bypass SEC-51 forbids.
		if op == "" {
			t.Fatalf("parseRoute(%q,%q) accepted with an EMPTY Op and nil error (silent accept)", method, path)
		}
		if _, ok := knownOps[op]; !ok {
			t.Fatalf("parseRoute(%q,%q) accepted Op %q which is NOT in the frozen knownOps enum (invented route)",
				method, path, op)
		}
		// An accepted route is POST by contract; parseRoute must never accept any
		// other method.
		if method != http.MethodPost {
			t.Fatalf("parseRoute(%q,%q) accepted a non-POST method as Op %q", method, path, op)
		}
	})
}

// hugeSegment returns a multi-kilobyte path segment so the seed corpus exercises
// the parser against an oversized op name (no length ceiling lives in the parser
// itself — an oversized name simply misses knownOps and is refused).
func hugeSegment() string {
	const n = 8192
	b := make([]byte, n)
	for i := range b {
		b[i] = 'A'
	}
	return string(b)
}
