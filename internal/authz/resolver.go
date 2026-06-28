// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package authz

import (
	"context"
)

// CallerEvidence is the face-established, host-attested identity presented
// to the resolver. Both faces construct it after their respective
// accept-time checks; the resolver trusts it without further verification.
// It is a value type — the face cannot mutate evidence after passing it.
type CallerEvidence struct {
	// Scope is the host-attested filesystem_id for this caller's session.
	// The resolver compares Request.Filesystem against this value; the
	// request value is a hint, never the identity (NFR-SEC-43).
	Scope FilesystemID
	// GrantedIntents is the exhaustive set of intents this caller may
	// request. An intent absent from this slice is denied regardless of
	// any other field (NFR-SEC-49).
	GrantedIntents []Intent
}

// StoredTagFunc returns the broker-side stored downloadable tag for the
// named object in the named scope. It is called only on read-shaped requests
// after scope and intent are cleared; the resolver never calls it for write
// or preview intents (NFR-SEC-73).
//
// A non-nil error is treated as a deny (fail-closed).
type StoredTagFunc func(ctx context.Context, fs FilesystemID, path string) (downloadable bool, err error)

type policyResolver struct {
	tag StoredTagFunc
}

// New returns a Resolver backed by the given stored-tag lookup function.
// tag must be non-nil — New panics otherwise, surfacing a wiring mistake at
// construction instead of a latent nil-deref on the read path. The tag is
// called only for IntentRead after scope and intent checks pass (NFR-SEC-73).
func New(tag StoredTagFunc) Resolver {
	if tag == nil {
		panic("authz: New requires a non-nil StoredTagFunc")
	}
	return &policyResolver{tag: tag}
}

// Resolve answers the three-axis question as a flat, ordered, deny-by-default
// sequence: every allow is preceded by an explicit positive match on each
// axis; there is no default-allow branch (NFR-SEC-49).
func (r *policyResolver) Resolve(ctx context.Context, caller any, req Request) (Grant, error) {
	ev, ok := caller.(CallerEvidence)
	if !ok {
		// Unknown evidence type — deny; never trust what we cannot read.
		return Grant{}, ErrScopeMismatch
	}

	// Axis 1: scope. An empty host-attested Scope authorizes nothing — it is
	// a face bug, never a grant; denying here keeps equal-empty values from
	// satisfying the equality check below (fail-closed).
	if ev.Scope == "" {
		return Grant{}, ErrScopeMismatch
	}
	// The request hint is never authoritative (NFR-SEC-43).
	if req.Filesystem != ev.Scope {
		return Grant{}, ErrScopeMismatch
	}

	// Axis 2: intent must be in the caller's explicit grant set (NFR-SEC-49).
	if !intentGranted(ev.GrantedIntents, req.Intent) {
		return Grant{}, ErrIntentDenied
	}

	// Axis 3: downloadable resolved at read (NFR-SEC-73, invariant 5). The
	// downloadable bit is an EGRESS-ARTIFACT disposition, not a read gate: a
	// non-downloadable object is "readable in-session but yields no
	// egress-eligible artifact" — the read axis still clears, and the egress
	// decision (deny the byte-path-out, withhold a presigned URL) belongs to
	// the consuming op, which reads Grant.Downloadable. The resolver therefore
	// never turns a successful "not downloadable" verdict into a read deny;
	// only the tag-lookup ERROR stays fail-closed. Preview is structurally
	// non-downloadable regardless of stored tag.
	switch req.Intent {
	case IntentRead:
		dl, err := r.tag(ctx, req.Filesystem, req.Path)
		if err != nil {
			// Tag lookup failure denies — fail-closed. The disposition could
			// not be resolved, so we cannot safely allow the read at all.
			return Grant{}, ErrNotDownloadable
		}
		if !dl {
			// Read allowed, egress-eligible artifact withheld (invariant 5):
			// the object is readable in-session; the false bit feeds the
			// consuming op's egress-artifact decision, not a read deny.
			return Grant{Downloadable: false}, nil
		}
		// Read allowed and egress-eligible: this is the only line in this
		// package that grants the downloadable bit.
		return Grant{Downloadable: true}, nil
	case IntentWrite:
		// Write grants never carry the downloadable bit (NFR-SEC-73).
		return Grant{Downloadable: false}, nil
	case IntentPreview:
		// Preview is read-only and non-downloadable regardless of the
		// stored tag; the tag lookup is never consulted (NFR-SEC-73).
		return Grant{Downloadable: false}, nil
	default:
		// Unknown intent — deny; never a default-allow.
		return Grant{}, ErrIntentDenied
	}
}

// intentGranted reports whether intent is present in the caller's explicit
// grant set. A nil or empty set grants nothing — deny-by-default is the
// natural empty-set result.
func intentGranted(grants []Intent, intent Intent) bool {
	for _, g := range grants {
		if g == intent {
			return true
		}
	}
	return false
}
