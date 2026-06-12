// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/base64"
	"errors"
)

// cursorV1 is the version prefix byte stamped on every minted cursor. A
// version byte keeps phase-9 cursors distinguishable from any future cursor
// shape (phase 10) so a stale token decodes to a clean rejection rather than a
// silent mis-walk.
const cursorV1 byte = 1

// errMalformedCursor names a cursor token that is not a base64url-decodable,
// non-empty, correctly-versioned token the broker minted. The broker only
// ever decodes cursors it minted (the token is opaque to callers); a
// malformed token is a client fault.
var errMalformedCursor = errors.New("southface: malformed cursor")

// encodeCursor mints an opaque keyset cursor encoding the last-emitted full
// relative path. The wire form is base64url(version-byte || raw-relpath-bytes)
// with no padding; the broker emits exactly the bytes it will later decode, so
// the round-trip is byte-identical. An empty afterRelPath still mints a
// non-empty token (the version byte alone), distinct from the empty
// last-page cursor.
func encodeCursor(afterRelPath string) string {
	buf := make([]byte, 0, 1+len(afterRelPath))
	buf = append(buf, cursorV1)
	buf = append(buf, afterRelPath...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// decodeCursor reverses encodeCursor. An empty token is the genuine
// first-page / no-cursor case and returns ("", nil). A token that is not
// base64url-decodable, decodes to zero bytes, or carries the wrong version
// byte returns errMalformedCursor. Otherwise the bytes after the version
// prefix are the resume-after relative path (which may itself be empty).
func decodeCursor(tok string) (string, error) {
	if tok == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(b) == 0 || b[0] != cursorV1 {
		return "", errMalformedCursor
	}
	return string(b[1:]), nil
}
