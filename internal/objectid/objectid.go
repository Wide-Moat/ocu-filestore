// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package objectid mints broker-held object handles: a 32-char lowercase hex
// string from 16 bytes of crypto/rand. It is a zero-dependency leaf package so
// that every component that needs a fresh, collision-resistant, non-guessable
// handle (the session-scoped south-face object-id store and the durable
// Files-API handle store) consumes ONE definition rather than a per-package
// copy. The shape reuses the spine's correlation-id convention — no uuid
// dependency, zero new packages (CLAUDE.md minimal shelf).
package objectid

import (
	"crypto/rand"
	"encoding/hex"
)

// New returns a 32-char lowercase hex object handle from 16 bytes of
// crypto/rand. A failing kernel CSPRNG is unrecoverable — fail loud (panic),
// the same contract the south-face mint relied on before this lift: a broker
// that cannot draw randomness must not mint a guessable or colliding handle.
func New() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("objectid: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
