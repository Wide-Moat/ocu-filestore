// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package authz is the three-axis authorization resolver both broker faces
// call: scope (filesystem_id) × intent (read/write/preview) × downloadable,
// re-derived per request, deny-by-default, keyed on the authenticated caller
// (NFR-SEC-49). The downloadable axis is resolved at READ on both faces,
// never stamped at write (NFR-SEC-73); intent=preview is read-only and
// non-downloadable regardless of stored tag.
//
// The resolver answers policy only. Path resolution inside the prefix
// (traversal/symlink rejection, NFR-SEC-25) and backend signing belong to
// the object-store client; the caller's host-attested identity is
// established by the face that terminates the connection, never by a
// caller-supplied claim (NFR-SEC-43).
package authz

import (
	"context"
	"errors"
)

// FilesystemID is the per-session logical scope — the isolation unit, not a
// crypto boundary. Canonical across the three storage contracts.
type FilesystemID string

// Intent is the storage-intent axis (NFR-SEC-49).
type Intent string

const (
	IntentRead    Intent = "read"
	IntentWrite   Intent = "write"
	IntentPreview Intent = "preview"
)

// ErrScopeMismatch — the request names a filesystem scope the caller's
// host-attested identity does not hold. Match it with errors.Is.
var ErrScopeMismatch = errors.New("authz: filesystem scope mismatch")

// ErrIntentDenied — the caller's grant does not include the requested
// intent (a preview-authorized caller cannot invoke download/write,
// NFR-SEC-49). Match it with errors.Is.
var ErrIntentDenied = errors.New("authz: intent denied for caller")

// ErrNotDownloadable — the object is readable in-session but yields no
// egress-eligible artifact; the byte path out is refused (NFR-SEC-73).
// Match it with errors.Is.
var ErrNotDownloadable = errors.New("authz: object not downloadable")

// Request is one authorization question: may this caller act on this path
// in this scope with this intent.
type Request struct {
	Filesystem FilesystemID
	// Path is relative to the filesystem scope; the resolver never sees an
	// absolute or backend-shaped handle (those are rejected earlier).
	Path   string
	Intent Intent
}

// Grant is an allow decision. Downloadable carries the read-time
// disposition; it is only meaningful for read-shaped intents.
type Grant struct {
	Downloadable bool
}

// Resolver answers the three-axis question per request, deny-by-default.
// caller is the face-established, host-attested principal — its concrete
// type belongs to the face packages; the resolver treats it as opaque
// evidence, never trusting any id inside the Request over it.
type Resolver interface {
	Resolve(ctx context.Context, caller any, req Request) (Grant, error)
}
