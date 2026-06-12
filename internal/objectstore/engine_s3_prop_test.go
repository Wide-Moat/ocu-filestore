// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
	"pgregory.net/rapid"
)

// TestS3_KeyValidator_Prop is the section-8 containment property over the
// sole join site: for ARBITRARY scope and path inputs (the default rapid
// string tables include NUL, separators, dots, control characters, and
// non-NFC sequences), any key objectKey accepts:
//
//   - carries the exact "<scope>/" prefix and never escapes it (no ".."
//     segment, no absolute form, no empty segment that a backend would
//     collapse),
//   - contains no control (Cc) or format (Cf) character and is valid UTF-8
//     in NFC form,
//   - never exceeds the backend's 1024-byte key limit.
//
// Rejection is always acceptable; the property binds only accepted keys —
// acceptance is the security event on a flat keyspace.
func TestS3_KeyValidator_Prop(t *testing.T) {
	e := &s3Engine{bucket: "b"}
	rapid.Check(t, func(rt *rapid.T) {
		scope := ScopeID(rapid.String().Draw(rt, "scope"))
		p := rapid.String().Draw(rt, "path")

		key, err := e.objectKey(scope, p)
		if err != nil {
			return // rejection is always acceptable
		}

		prefix := string(scope) + "/"
		if !strings.HasPrefix(key, prefix) {
			rt.Fatalf("accepted key %q lacks scope prefix %q (scope=%q path=%q)", key, prefix, scope, p)
		}
		rest := strings.TrimPrefix(key, prefix)
		if rest == "" {
			rt.Fatalf("accepted key %q names the scope root itself (path=%q)", key, p)
		}
		for _, seg := range strings.Split(rest, "/") {
			if seg == "" || seg == "." || seg == ".." {
				rt.Fatalf("accepted key %q carries unsafe segment %q (path=%q)", key, seg, p)
			}
		}
		if len(key) > s3MaxKeyBytes {
			rt.Fatalf("accepted key is %d bytes, over the %d-byte cap (path=%q)", len(key), s3MaxKeyBytes, p)
		}
		if !utf8.ValidString(key) {
			rt.Fatalf("accepted key %q is not valid UTF-8 (path=%q)", key, p)
		}
		for _, r := range rest {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				rt.Fatalf("accepted key %q carries control/format rune %U (path=%q)", key, r, p)
			}
		}
		if !norm.NFC.IsNormalString(rest) {
			rt.Fatalf("accepted key %q is not NFC (path=%q)", key, p)
		}
	})
}

// TestS3_KeyValidator_PrefixBoundary_Prop pins the flat-keyspace boundary
// subtlety: an accepted key for scope "fs1" must never be a prefix-match
// trap for a SIBLING scope (e.g. scope "fs1" never yields a key under
// "fs10/"). The "/" terminator in every prefix comparison is what makes
// "fs1" and "fs10" disjoint; this property proves the validator never
// constructs a key that crosses that boundary.
func TestS3_KeyValidator_PrefixBoundary_Prop(t *testing.T) {
	e := &s3Engine{bucket: "b"}
	rapid.Check(t, func(rt *rapid.T) {
		p := rapid.String().Draw(rt, "path")
		key, err := e.objectKey("fs1", p)
		if err != nil {
			return
		}
		if !strings.HasPrefix(key, "fs1/") {
			rt.Fatalf("key %q outside fs1/ (path=%q)", key, p)
		}
		if strings.HasPrefix(key, "fs10/") {
			rt.Fatalf("key %q crossed into sibling scope fs10/ (path=%q)", key, p)
		}
	})
}
