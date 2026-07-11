// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// ErrForeignScope is the engine-side scope-confinement sentinel: a verb named a
// scope other than the one this engine was provisioned to serve. It is the
// engine's OWN authority over the backend prefix (GA Wave 1, ADR-0013/0029
// "the engine  -  the same point that enforces filesystem_id scope"): even if an
// upstream credential path were bypassed, the engine independently refuses to
// key any object under a scope it holds no title to. Match it with errors.Is.
var ErrForeignScope = errors.New("objectstore: request scope is not the engine's provisioned scope")

// scopeConfinedEngine wraps an Engine and confines EVERY data and lifecycle verb
// to the single provisioned scope the deployment granted (the daemon's
// -filesystem-id). A verb whose scope argument is not the allowed scope is
// refused with ErrForeignScope BEFORE the inner engine runs, so a forged or
// mis-wired scope can never steer the backend prefix to another tenant. This is
// defense-in-depth on top of the credential-scope extractor: the extractor binds
// the scope from the VERIFIED claim, and this guard independently pins the engine
// to the one scope it was provisioned for.
type scopeConfinedEngine struct {
	inner   Engine
	allowed ScopeID
}

var _ Engine = (*scopeConfinedEngine)(nil)

// NewScopeConfinedEngine wraps inner so every verb is confined to allowed. A verb
// naming any other scope is ErrForeignScope. The allowed scope must pass the same
// shape guard the inner engine applies, so a malformed provisioned scope is a
// hard construction error rather than a guard that silently admits everything.
func NewScopeConfinedEngine(inner Engine, allowed ScopeID) (Engine, error) {
	if inner == nil {
		return nil, errors.New("objectstore: scope-confined engine requires an inner engine")
	}
	if err := validateScopeID(allowed); err != nil {
		return nil, fmt.Errorf("objectstore: scope-confined engine allowed scope: %w", err)
	}
	return &scopeConfinedEngine{inner: inner, allowed: allowed}, nil
}

// guard is the SOLE confinement site: it refuses any scope that is not the
// engine's provisioned scope. Every verb calls it before delegating.
func (e *scopeConfinedEngine) guard(scope ScopeID) error {
	if scope != e.allowed {
		return fmt.Errorf("%w: %q (provisioned %q)", ErrForeignScope, scope, e.allowed)
	}
	return nil
}

func (e *scopeConfinedEngine) Kind() EngineKind { return e.inner.Kind() }

func (e *scopeConfinedEngine) ProvisionScope(ctx context.Context, scope ScopeID) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.ProvisionScope(ctx, scope)
}

func (e *scopeConfinedEngine) TeardownScope(ctx context.Context, scope ScopeID) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.TeardownScope(ctx, scope)
}

func (e *scopeConfinedEngine) List(ctx context.Context, scope ScopeID, path string) ([]FileInfo, error) {
	if err := e.guard(scope); err != nil {
		return nil, err
	}
	return e.inner.List(ctx, scope, path)
}

func (e *scopeConfinedEngine) Stat(ctx context.Context, scope ScopeID, path string) (FileInfo, error) {
	if err := e.guard(scope); err != nil {
		return FileInfo{}, err
	}
	return e.inner.Stat(ctx, scope, path)
}

func (e *scopeConfinedEngine) MakeDir(ctx context.Context, scope ScopeID, path string) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.MakeDir(ctx, scope, path)
}

func (e *scopeConfinedEngine) MoveDir(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.MoveDir(ctx, scope, src, dst, overwrite)
}

func (e *scopeConfinedEngine) RemoveDir(ctx context.Context, scope ScopeID, path string) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.RemoveDir(ctx, scope, path)
}

func (e *scopeConfinedEngine) CopyFile(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.CopyFile(ctx, scope, src, dst, overwrite)
}

func (e *scopeConfinedEngine) MoveFile(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.MoveFile(ctx, scope, src, dst, overwrite)
}

func (e *scopeConfinedEngine) RemoveFile(ctx context.Context, scope ScopeID, path string) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.RemoveFile(ctx, scope, path)
}

func (e *scopeConfinedEngine) ReadRange(ctx context.Context, scope ScopeID, path string, offset, length int64, w io.Writer) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.ReadRange(ctx, scope, path, offset, length, w)
}

func (e *scopeConfinedEngine) WriteStream(ctx context.Context, scope ScopeID, path string, r io.Reader, overwrite bool) error {
	if err := e.guard(scope); err != nil {
		return err
	}
	return e.inner.WriteStream(ctx, scope, path, r, overwrite)
}
