// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"io"
	"regexp"
	"sync"
)

// lazyProvisionEngine is a DAEMON-LAYER decorator over an Engine that lazily
// scaffolds a derived scope's storage markers on the first data verb per
// scope. It exists to close the D5 write-first fault: per-chat isolation
// (ADR-0030) derives a fresh scope "<base>-<hex16>" per chat, and only the
// boot/base scope has its uploads/ and outputs/ markers seeded at startup. A
// fresh derived scope has no markers, so an agent-writes-first flow (the
// primary two-mount direction) faults on the absent marker. This decorator
// scaffolds those markers once, on first access, using the SAME provisioning
// verbs the boot path uses.
//
// Fail-closed is preserved: scaffolding runs ONLY for a scope whose name is a
// legitimately-derived scope of THIS deployment's base (the bootBase itself,
// or "<bootBase>-<16 lowercase-hex>"). A scope that is neither is NOT
// scaffolded - it delegates straight to the wrapped engine, which refuses it
// exactly as it does today. The decorator never widens what the engine
// accepts; it only ensures a legitimately-derived scope has its markers before
// the wrapped verb runs.
//
// The engine interface and both concrete engines (local-volume, s3) are
// UNCHANGED. This is a wrapper applied once at compose so both the north
// filesapi Engine and the south southface Engine share it, killing the
// uploads-first/writes-first asymmetry.
type lazyProvisionEngine struct {
	Engine
	// shapeRe matches a legitimately-derived scope of this deployment's base:
	// the bootBase followed by "-" and exactly 16 lowercase-hex digits.
	shapeRe *regexp.Regexp
	// bootBase is the deployment's base scope; the base itself is also a
	// legal (un-suffixed) scope.
	bootBase string
	// scaffold seeds a scope's markers idempotently (ProvisionScope + the
	// marker MakeDir loop). It is the SAME helper the boot path calls, bound
	// to the wrapped engine and the boot marker list by the compose site.
	scaffold func(ctx context.Context, scope ScopeID) error
	// state tracks per-scope scaffold progress. Only SUCCESS is memoized: a
	// failed attempt (a transient backend refusal such as a storage-full 5xx
	// mapped to ErrTransient, or a canceled caller context) fails THAT
	// caller's verb and leaves the scope un-scaffolded, so the next touch
	// retries. Memoizing a failure would wedge the scope until process
	// restart while the backend condition it names is recoverable. The
	// per-scope mutex serializes attempts, so concurrent first-touches
	// converge on a single scaffold call and a retry can never stampede: at
	// most one attempt is in flight per scope, and attempts are paced by the
	// data-verb rate.
	mu    sync.Mutex
	state map[ScopeID]*scaffoldState
}

// scaffoldState is one scope's scaffold progress: attempt serializes
// attempts, done latches on the first success.
type scaffoldState struct {
	attempt sync.Mutex
	done    bool
}

// NewLazyProvisionEngine wraps eng so the FIRST data verb per UNSEEN,
// legitimately-derived scope lazily scaffolds that scope's markers via
// scaffold before the wrapped verb runs. bootBase is the deployment's base
// scope; a scope is derived-legal iff it equals bootBase or matches
// "^<bootBase>-[0-9a-f]{16}$". A scope that is not derived-legal is passed
// straight through (fail-closed: the wrapped engine refuses it as today).
func NewLazyProvisionEngine(eng Engine, bootBase string, scaffold func(ctx context.Context, scope ScopeID) error) Engine {
	return &lazyProvisionEngine{
		Engine:   eng,
		shapeRe:  regexp.MustCompile("^" + regexp.QuoteMeta(bootBase) + "-[0-9a-f]{16}$"),
		bootBase: bootBase,
		scaffold: scaffold,
		state:    make(map[ScopeID]*scaffoldState),
	}
}

// derivedLegal reports whether scope is a legitimately-derived scope of this
// deployment's base: the base itself, or "<bootBase>-<16 lowercase-hex>". A
// random attacker scope is NOT derived-legal, so it is never auto-provisioned.
func (e *lazyProvisionEngine) derivedLegal(scope ScopeID) bool {
	s := string(scope)
	return s == e.bootBase || e.shapeRe.MatchString(s)
}

// ensureScaffold scaffolds a derived-legal scope's markers, memoizing SUCCESS
// only. It is a no-op for a scope that is not derived-legal (fail-closed: the
// caller then delegates to the wrapped engine, which refuses the scope as
// today). Under concurrent first-touches the per-scope mutex serializes
// attempts: the winner scaffolds, the waiters observe its success without a
// second call. A failed attempt is returned to its caller and NOT recorded,
// so the next touch retries — a transient backend refusal or a canceled
// caller context never poisons the scope until restart.
func (e *lazyProvisionEngine) ensureScaffold(ctx context.Context, scope ScopeID) error {
	if !e.derivedLegal(scope) {
		return nil
	}
	e.mu.Lock()
	st, ok := e.state[scope]
	if !ok {
		st = new(scaffoldState)
		e.state[scope] = st
	}
	e.mu.Unlock()

	st.attempt.Lock()
	defer st.attempt.Unlock()
	if st.done {
		return nil
	}
	if err := e.scaffold(ctx, scope); err != nil {
		return err
	}
	st.done = true
	return nil
}

// The data verbs each ensure the scope is scaffolded (for a derived-legal
// scope) before delegating to the embedded Engine. The lifecycle verbs
// (ProvisionScope, TeardownScope) are NOT wrapped: they carry their own
// scaffold/erase semantics and delegate straight through the embedded Engine.

func (e *lazyProvisionEngine) List(ctx context.Context, scope ScopeID, path string) ([]FileInfo, error) {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return nil, err
	}
	return e.Engine.List(ctx, scope, path)
}

func (e *lazyProvisionEngine) Stat(ctx context.Context, scope ScopeID, path string) (FileInfo, error) {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return FileInfo{}, err
	}
	return e.Engine.Stat(ctx, scope, path)
}

func (e *lazyProvisionEngine) MakeDir(ctx context.Context, scope ScopeID, path string) error {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return err
	}
	return e.Engine.MakeDir(ctx, scope, path)
}

func (e *lazyProvisionEngine) MoveDir(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return err
	}
	return e.Engine.MoveDir(ctx, scope, src, dst, overwrite)
}

func (e *lazyProvisionEngine) RemoveDir(ctx context.Context, scope ScopeID, path string) error {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return err
	}
	return e.Engine.RemoveDir(ctx, scope, path)
}

func (e *lazyProvisionEngine) CopyFile(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return err
	}
	return e.Engine.CopyFile(ctx, scope, src, dst, overwrite)
}

func (e *lazyProvisionEngine) MoveFile(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return err
	}
	return e.Engine.MoveFile(ctx, scope, src, dst, overwrite)
}

func (e *lazyProvisionEngine) RemoveFile(ctx context.Context, scope ScopeID, path string) error {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return err
	}
	return e.Engine.RemoveFile(ctx, scope, path)
}

func (e *lazyProvisionEngine) ReadRange(ctx context.Context, scope ScopeID, path string, offset, length int64, w io.Writer) error {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return err
	}
	return e.Engine.ReadRange(ctx, scope, path, offset, length, w)
}

func (e *lazyProvisionEngine) WriteStream(ctx context.Context, scope ScopeID, path string, r io.Reader, overwrite bool) (string, error) {
	if err := e.ensureScaffold(ctx, scope); err != nil {
		return "", err
	}
	return e.Engine.WriteStream(ctx, scope, path, r, overwrite)
}
