// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package objectstore is the broker's single backend client — the only
// component in the deployment that speaks the backend protocol and signs
// backend requests (NFR-SEC-25). The backend engine is a pluggable adapter
// (architecture repo ADR-0010): a local-volume engine (the solo reference,
// a host filesystem permission, no network leg) and an S3 engine, both
// present from day one.
//
// A network engine's backend leg transits the storage-dedicated egress lane
// (ADR-0011); a direct backend dial bypassing it is refused (NFR-SEC-16).
// Path resolution happens here, inside the host-attested filesystem_id
// prefix: traversal, symlink, absolute-path, and URL-shaped handles are
// rejected before any backend call (NFR-SEC-25). The credential never
// leaves this package.
package objectstore

import (
	"errors"
	"fmt"
)

// EngineKind names a backend engine.
type EngineKind string

const (
	// LocalVolume exercises a host filesystem permission, not a network
	// credential; it opens no network leg, so the egress-transit rule does
	// not apply to it.
	LocalVolume EngineKind = "local-volume"
	// S3 is the network engine; its leg transits the storage lane.
	S3 EngineKind = "s3"
)

// ErrUnknownEngine is the sentinel ParseEngine wraps when the configured
// engine name is not a known kind. Never a silent default. Match it with
// errors.Is.
var ErrUnknownEngine = errors.New("objectstore: unknown backend engine")

// ErrNotImplemented is the scaffold sentinel: no engine has an
// implementation in this build. Match it with errors.Is.
var ErrNotImplemented = errors.New("objectstore: not implemented in this build")

// ParseEngine maps a deployment-config string to an EngineKind, wrapping
// ErrUnknownEngine and listing the valid kinds on an unknown value.
func ParseEngine(s string) (EngineKind, error) {
	switch EngineKind(s) {
	case LocalVolume, S3:
		return EngineKind(s), nil
	default:
		return "", fmt.Errorf("%w %q (valid: %s, %s)", ErrUnknownEngine, s, LocalVolume, S3)
	}
}

// Engine is the pluggable backend seam. The implementation PR fixes the
// operation set against the contract's verb mapping; the scaffold pins only
// the identity and the rule that every byte path goes through one Engine
// value held by one client.
type Engine interface {
	// Kind names the engine.
	Kind() EngineKind
}
