// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package broker is the composition layer: it binds the six internal seam
// packages (authz, auditgate, ceilings, objectstore) to the southface
// CONSUMER interfaces, which import none of them. Each adapter is a thin
// per-call type narrowing — the real seams are structurally compatible but
// not assignable (authz takes a named FilesystemID, ceilings a named
// SessionKey, objectstore a named ScopeID), so a bare assignment will not
// compile and the var _ southface.X proofs below pin the binding at build
// time.
//
// The adapters preserve the spine's security invariants and never weaken
// them: the resolver re-derives authorization per request from the channel
// scope and never reintroduces a body-derived scope (NFR-SEC-43/49); the
// guard fails closed (NFR-SEC-79); the engine's path-validation errors pass
// through verbatim so the spine's load-bearing classification ordering holds
// (NFR-SEC-25). The downloadable tag source is broker-side and operator
// configured (NFR-SEC-73) — see downloadable.go.
package broker

import (
	"context"
	"errors"
	"io"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/authz"
	"github.com/Wide-Moat/ocu-filestore/internal/ceilings"
	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// --- Resolver adapter (southface.Resolver <- authz) -----------------------

// resolverAdapter narrows the southface plain-string request/evidence shapes
// to the authz named types per call and remaps the authz deny sentinels onto
// the southface mirrors the deny mapper classifies (Option A). The caller
// evidence is built by the spine from the CHANNEL scope; this adapter never
// reads identity from the request body (NFR-SEC-43/49).
type resolverAdapter struct{ r authz.Resolver }

var _ southface.Resolver = (*resolverAdapter)(nil)

// NewResolver wraps an authz.Resolver as a southface.Resolver.
func NewResolver(r authz.Resolver) southface.Resolver { return resolverAdapter{r: r} }

func (a resolverAdapter) Resolve(ctx context.Context, caller any, req southface.ResolveRequest) (southface.Grant, error) {
	// The spine passes its own southface.CallerEvidence (plain string Scope);
	// convert it to the authz named type. An unreadable evidence type is a
	// wiring fault — deny (the authz resolver would do the same).
	sev, ok := caller.(southface.CallerEvidence)
	if !ok {
		return southface.Grant{}, southface.ErrScopeMismatch
	}
	aev := authz.CallerEvidence{
		Scope:          authz.FilesystemID(sev.Scope),
		GrantedIntents: toAuthzIntents(sev.GrantedIntents),
	}
	g, err := a.r.Resolve(ctx, aev, authz.Request{
		Filesystem: authz.FilesystemID(req.Filesystem),
		Path:       req.Path,
		Intent:     authz.Intent(req.Intent),
	})
	if err != nil {
		return southface.Grant{}, mapResolverErr(err)
	}
	return southface.Grant{Downloadable: g.Downloadable}, nil
}

// toAuthzIntents converts the southface intent slice to the authz intent
// slice; the underlying string values are identical (the wire vocabulary).
func toAuthzIntents(in []southface.Intent) []authz.Intent {
	out := make([]authz.Intent, len(in))
	for i, v := range in {
		out[i] = authz.Intent(v)
	}
	return out
}

// mapResolverErr remaps the real authz deny sentinels onto the southface
// mirrors the spine's denyClassForErr matches with errors.Is (Option A). A
// non-sentinel error passes through unchanged and falls to denyInternal.
func mapResolverErr(err error) error {
	switch {
	case errors.Is(err, authz.ErrScopeMismatch):
		return southface.ErrScopeMismatch
	case errors.Is(err, authz.ErrIntentDenied):
		return southface.ErrIntentDenied
	case errors.Is(err, authz.ErrNotDownloadable):
		return southface.ErrNotDownloadable
	default:
		return err
	}
}

// --- Guard adapter (southface.Guard <- auditgate) -------------------------

// guardAdapter wraps an auditgate.Guard (e.g. *auditgate.FileSink) as a
// southface.Guard. The spine already maps its event to the concrete
// auditgate.FileActivityEvent before calling Mandate (W1.2), so the adapter
// forwards the event unchanged; the real sink type-asserts it and fails
// closed on any durable-write failure (NFR-SEC-79).
type guardAdapter struct{ g auditgate.Guard }

var _ southface.Guard = (*guardAdapter)(nil)

// NewGuard wraps an auditgate.Guard as a southface.Guard.
func NewGuard(g auditgate.Guard) southface.Guard { return guardAdapter{g: g} }

func (a guardAdapter) Mandate(ctx context.Context, event any) error {
	return a.g.Mandate(ctx, event)
}

// --- Ceilings adapter (southface.CeilingsRegistry <- ceilings) ------------

// ceilingsAdapter narrows the string session key to the named
// ceilings.SessionKey and returns *ceilings.Session as a
// southface.CeilingsSession (which it already satisfies structurally).
type ceilingsAdapter struct{ r *ceilings.Registry }

var _ southface.CeilingsRegistry = (*ceilingsAdapter)(nil)

// NewCeilings wraps a *ceilings.Registry as a southface.CeilingsRegistry.
func NewCeilings(r *ceilings.Registry) southface.CeilingsRegistry { return ceilingsAdapter{r: r} }

func (a ceilingsAdapter) Session(key string) southface.CeilingsSession {
	return a.r.Session(ceilings.SessionKey(key))
}

func (a ceilingsAdapter) Release(key string) { a.r.Release(ceilings.SessionKey(key)) }

// --- Engine adapter (southface.Engine <- objectstore) ---------------------

// engineAdapter narrows the string scope to the named objectstore.ScopeID per
// call over the 10 data verbs the southface consumer seam declares. It does
// NOT wrap Kind/ProvisionScope/TeardownScope — those lifecycle verbs are
// called by main on the real engine directly (scope provision and
// erase-before-reuse, NFR-SEC-54), not through the consumer seam.
//
// Engine errors pass through with a narrow remap: only the objectstore typed
// sentinels (ErrAlreadyExists, ErrInvalidPath) are translated to the
// southface mirrors; the stdlib fs.ErrExist/fs.ErrNotExist and the
// *fs.PathError/*os.LinkError escapes pass through VERBATIM so the spine's
// denyClassForEngineErr keeps matching them with its load-bearing ordering
// (NFR-SEC-25, Pitfall 3).
type engineAdapter struct{ e objectstore.Engine }

var _ southface.Engine = (*engineAdapter)(nil)

// NewEngine wraps an objectstore.Engine as a southface.Engine over the 10
// data verbs.
func NewEngine(e objectstore.Engine) southface.Engine { return engineAdapter{e: e} }

func (a engineAdapter) List(ctx context.Context, scope, path string) ([]southface.FileInfo, error) {
	infos, err := a.e.List(ctx, objectstore.ScopeID(scope), path)
	if err != nil {
		return nil, mapEngineErr(err)
	}
	out := make([]southface.FileInfo, len(infos))
	for i, fi := range infos {
		out[i] = toSouthfaceFileInfo(fi)
	}
	return out, nil
}

func (a engineAdapter) Stat(ctx context.Context, scope, path string) (southface.FileInfo, error) {
	fi, err := a.e.Stat(ctx, objectstore.ScopeID(scope), path)
	if err != nil {
		return southface.FileInfo{}, mapEngineErr(err)
	}
	return toSouthfaceFileInfo(fi), nil
}

func (a engineAdapter) MakeDir(ctx context.Context, scope, path string) error {
	return mapEngineErr(a.e.MakeDir(ctx, objectstore.ScopeID(scope), path))
}

func (a engineAdapter) MoveDir(ctx context.Context, scope, src, dst string, overwrite bool) error {
	return mapEngineErr(a.e.MoveDir(ctx, objectstore.ScopeID(scope), src, dst, overwrite))
}

func (a engineAdapter) RemoveDir(ctx context.Context, scope, path string) error {
	return mapEngineErr(a.e.RemoveDir(ctx, objectstore.ScopeID(scope), path))
}

func (a engineAdapter) CopyFile(ctx context.Context, scope, src, dst string, overwrite bool) error {
	return mapEngineErr(a.e.CopyFile(ctx, objectstore.ScopeID(scope), src, dst, overwrite))
}

func (a engineAdapter) MoveFile(ctx context.Context, scope, src, dst string, overwrite bool) error {
	return mapEngineErr(a.e.MoveFile(ctx, objectstore.ScopeID(scope), src, dst, overwrite))
}

func (a engineAdapter) RemoveFile(ctx context.Context, scope, path string) error {
	return mapEngineErr(a.e.RemoveFile(ctx, objectstore.ScopeID(scope), path))
}

func (a engineAdapter) ReadRange(ctx context.Context, scope, path string, offset, length int64, w io.Writer) error {
	return mapEngineErr(a.e.ReadRange(ctx, objectstore.ScopeID(scope), path, offset, length, w))
}

func (a engineAdapter) WriteStream(ctx context.Context, scope, path string, r io.Reader, overwrite bool) error {
	return mapEngineErr(a.e.WriteStream(ctx, objectstore.ScopeID(scope), path, r, overwrite))
}

func toSouthfaceFileInfo(fi objectstore.FileInfo) southface.FileInfo {
	return southface.FileInfo{
		Name:    fi.Name,
		Size:    fi.Size,
		ModTime: fi.ModTime,
		IsDir:   fi.IsDir,
	}
}

// mapEngineErr remaps the objectstore TYPED sentinels onto the southface
// engine mirrors the spine's denyClassForEngineErr matches with errors.Is
// (Option A). The stdlib fs.ErrExist/fs.ErrNotExist and the
// *fs.PathError/*os.LinkError escapes are NOT remapped — they pass through
// verbatim so the spine still classifies them, preserving the load-bearing
// already-exists/not-exist-before-escape ordering (Pitfall 3). A nil error
// passes through nil.
func mapEngineErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, objectstore.ErrAlreadyExists):
		return southface.ErrAlreadyExists
	case errors.Is(err, objectstore.ErrInvalidPath):
		return southface.ErrInvalidPath
	default:
		return err
	}
}
