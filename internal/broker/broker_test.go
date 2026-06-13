// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/authz"
	"github.com/Wide-Moat/ocu-filestore/internal/ceilings"
	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// --- compile-time interface proofs (WIRE-ADAPT) ---------------------------
// The four var _ southface.X = (*adapter)(nil) assertions live in broker.go
// and fail the build if an adapter drifts from its consumer interface. These
// constructors exercise the exported wrappers so the proofs are also covered.

func TestAdaptersSatisfyConsumerInterfaces(t *testing.T) {
	var _ southface.Resolver = NewResolver(stubAuthzResolver{})
	var _ southface.Guard = NewGuard(stubGuard{})
	var _ southface.CeilingsRegistry = NewCeilings(ceilings.NewNopRegistry())
	var _ southface.Engine = NewEngine(stubEngine{})
}

// --- resolver sentinel round-trip table (WIRE-SENTINEL) -------------------

// stubAuthzResolver returns a configured error so the adapter's remap is
// exercised in isolation from the real policy resolver.
type stubAuthzResolver struct{ err error }

func (s stubAuthzResolver) Resolve(context.Context, any, authz.Request) (authz.Grant, error) {
	return authz.Grant{Downloadable: true}, s.err
}

// TestResolverAdapterRemapsSentinels feeds each real authz sentinel through
// the resolver adapter and asserts the southface mirror is returned (so the
// spine's denyClassForErr classifies it). A non-sentinel error passes through
// and a wrapped sentinel still remaps — the non-vacuity counters.
func TestResolverAdapterRemapsSentinels(t *testing.T) {
	caller := southface.CallerEvidence{Scope: "fs1", GrantedIntents: []southface.Intent{southface.IntentRead}}
	req := southface.ResolveRequest{Filesystem: "fs1", Path: "/x", Intent: southface.IntentRead}

	for _, tc := range []struct {
		name string
		in   error
		want error // nil = expect pass-through (not a southface mirror)
	}{
		{"scope_mismatch", authz.ErrScopeMismatch, southface.ErrScopeMismatch},
		{"intent_denied", authz.ErrIntentDenied, southface.ErrIntentDenied},
		{"not_downloadable", authz.ErrNotDownloadable, southface.ErrNotDownloadable},
		{"wrapped_scope_mismatch", fmt.Errorf("ctx: %w", authz.ErrScopeMismatch), southface.ErrScopeMismatch},
		{"non_sentinel_passthrough", errors.New("boom"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewResolver(stubAuthzResolver{err: tc.in})
			_, err := a.Resolve(context.Background(), caller, req)
			if tc.want == nil {
				// Non-vacuity: an unknown error is NOT remapped to a mirror;
				// it passes through so the spine falls to denyInternal.
				if errors.Is(err, southface.ErrScopeMismatch) ||
					errors.Is(err, southface.ErrIntentDenied) ||
					errors.Is(err, southface.ErrNotDownloadable) {
					t.Fatalf("non-sentinel error %v was remapped to a mirror (got %v)", tc.in, err)
				}
				if err == nil {
					t.Fatalf("non-sentinel error dropped to nil")
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Resolve remap: got %v, want errors.Is(%v)", err, tc.want)
			}
		})
	}
}

// TestResolverAdapterRejectsForeignEvidence pins that the adapter denies an
// evidence type it cannot read (scope_mismatch), never trusting an unknown
// caller shape (NFR-SEC-43).
func TestResolverAdapterRejectsForeignEvidence(t *testing.T) {
	a := NewResolver(stubAuthzResolver{})
	_, err := a.Resolve(context.Background(), "not-evidence", southface.ResolveRequest{})
	if !errors.Is(err, southface.ErrScopeMismatch) {
		t.Fatalf("foreign evidence: got %v, want ErrScopeMismatch", err)
	}
}

// TestResolverAdapterDoesNotDeriveScopeFromBody pins SEC-49/43: the adapter
// builds caller evidence from the channel scope and the request hint
// separately and never substitutes the body scope for the caller scope. With
// the real resolver, a request scope that disagrees with the caller scope
// denies scope_mismatch.
func TestResolverAdapterDoesNotDeriveScopeFromBody(t *testing.T) {
	a := NewResolver(authz.New(func(context.Context, authz.FilesystemID, string) (bool, error) {
		return true, nil
	}))
	caller := southface.CallerEvidence{Scope: "fs-real", GrantedIntents: []southface.Intent{southface.IntentRead}}
	// Body claims a different scope than the channel-bound caller scope.
	req := southface.ResolveRequest{Filesystem: "fs-attacker", Path: "/x", Intent: southface.IntentRead}
	if _, err := a.Resolve(context.Background(), caller, req); !errors.Is(err, southface.ErrScopeMismatch) {
		t.Fatalf("cross-scope request: got %v, want ErrScopeMismatch (body scope must not be authoritative)", err)
	}
}

// --- guard adapter --------------------------------------------------------

type stubGuard struct{ err error }

func (s stubGuard) Mandate(context.Context, any) error { return s.err }

// TestGuardAdapterForwardsMandate pins that the guard adapter forwards the
// event unchanged and propagates the fail-closed error (NFR-SEC-79). The
// real audit-down sentinel crosses as the SOUTHFACE mirror (FC-01) so the
// spine's deny mapper classifies it to unavailable/503.
func TestGuardAdapterForwardsMandate(t *testing.T) {
	if err := NewGuard(stubGuard{}).Mandate(context.Background(), struct{}{}); err != nil {
		t.Fatalf("Mandate(ok): got %v, want nil", err)
	}
	err := NewGuard(stubGuard{err: auditgate.ErrAuditUnavailable}).Mandate(context.Background(), struct{}{})
	if !errors.Is(err, southface.ErrAuditUnavailable) {
		t.Fatalf("Mandate(down): got %v, want the southface.ErrAuditUnavailable mirror (FC-01 remap)", err)
	}
}

// TestGuardAdapterDeliversToRealFileSink pins Pitfall 1 end-to-end through the
// adapter: a mapped FileActivityEvent is durably written; a foreign event is
// refused fail-closed.
func TestGuardAdapterDeliversToRealFileSink(t *testing.T) {
	dir := shortDir(t)
	sink, err := auditgate.NewFileSink(dir + "/audit.jsonl")
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	g := NewGuard(sink)
	ev := auditgate.FileActivityEvent{ClassUID: 1001, CategoryUID: 1, ActivityID: auditgate.ActivityRead}
	if err := g.Mandate(context.Background(), ev); err != nil {
		t.Fatalf("Mandate(FileActivityEvent): got %v, want nil", err)
	}
	if err := g.Mandate(context.Background(), struct{}{}); err == nil {
		t.Fatalf("Mandate(foreign): got nil, want a fail-closed refusal")
	}
}

// --- ceilings adapter -----------------------------------------------------

// TestCeilingsAdapterNarrowsKey pins the string->SessionKey narrowing and
// that the returned *ceilings.Session satisfies CeilingsSession.
func TestCeilingsAdapterNarrowsKey(t *testing.T) {
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         1000,
		OpsBurst:             1000,
		InFlightBytesCeiling: 1 << 30,
		FDCeiling:            64,
		Clock:                time.Now,
	})
	a := NewCeilings(reg)
	sess := a.Session("fs-key")
	if err := sess.TryConsumeOp(); err != nil {
		t.Fatalf("TryConsumeOp on a fresh session: got %v, want nil", err)
	}
	a.Release("fs-key") // must not panic on a known or unknown key
	a.Release("never-seen")
}

// --- engine sentinel round-trip + verbatim pass-through (WIRE-SENTINEL) ----

// stubEngine returns a configured error from every verb so the adapter's
// remap and verbatim pass-through are exercised in isolation.
type stubEngine struct{ err error }

func (s stubEngine) Kind() objectstore.EngineKind { return objectstore.LocalVolume }
func (s stubEngine) ProvisionScope(context.Context, objectstore.ScopeID) error {
	return s.err
}
func (s stubEngine) TeardownScope(context.Context, objectstore.ScopeID) error { return s.err }
func (s stubEngine) List(context.Context, objectstore.ScopeID, string) ([]objectstore.FileInfo, error) {
	return []objectstore.FileInfo{{Name: "a", Size: 3, IsDir: false}}, s.err
}
func (s stubEngine) Stat(context.Context, objectstore.ScopeID, string) (objectstore.FileInfo, error) {
	return objectstore.FileInfo{Name: "a"}, s.err
}
func (s stubEngine) MakeDir(context.Context, objectstore.ScopeID, string) error { return s.err }
func (s stubEngine) MoveDir(context.Context, objectstore.ScopeID, string, string, bool) error {
	return s.err
}
func (s stubEngine) RemoveDir(context.Context, objectstore.ScopeID, string) error { return s.err }
func (s stubEngine) CopyFile(context.Context, objectstore.ScopeID, string, string, bool) error {
	return s.err
}
func (s stubEngine) MoveFile(context.Context, objectstore.ScopeID, string, string, bool) error {
	return s.err
}
func (s stubEngine) RemoveFile(context.Context, objectstore.ScopeID, string) error { return s.err }
func (s stubEngine) ReadRange(context.Context, objectstore.ScopeID, string, int64, int64, io.Writer) error {
	return s.err
}
func (s stubEngine) WriteStream(context.Context, objectstore.ScopeID, string, io.Reader, bool) error {
	return s.err
}

// TestEngineAdapterRemapsTypedSentinels feeds each engine error class through
// the adapter (via MakeDir, a representative verb) and asserts the result.
// The typed objectstore sentinels remap to the southface mirrors; the stdlib
// sentinels and the *fs.PathError/*os.LinkError escapes pass through VERBATIM
// so the spine's denyClassForEngineErr still classifies them with its
// load-bearing ordering (Pitfall 3). A non-sentinel error is the non-vacuity
// counter.
func TestEngineAdapterRemapsTypedSentinels(t *testing.T) {
	escapePathErr := &fs.PathError{Op: "openat", Path: "x", Err: errors.New("path escapes from parent")}
	escapeLinkErr := &os.LinkError{Op: "renameat", Old: "a", New: "../b", Err: errors.New("path escapes from parent")}

	for _, tc := range []struct {
		name         string
		in           error
		wantMirror   error // non-nil: adapter remaps to this southface mirror
		wantVerbatim error // non-nil: adapter passes this through unchanged
	}{
		{"already_exists_to_mirror", objectstore.ErrAlreadyExists, southface.ErrAlreadyExists, nil},
		{"invalid_path_to_mirror", objectstore.ErrInvalidPath, southface.ErrInvalidPath, nil},
		{"throttled_to_mirror", objectstore.ErrThrottled, southface.ErrBackendThrottled, nil},
		{"transient_to_mirror", objectstore.ErrTransient, southface.ErrBackendTransient, nil},
		{"fs_ErrExist_verbatim", fs.ErrExist, nil, fs.ErrExist},
		{"fs_ErrNotExist_verbatim", fs.ErrNotExist, nil, fs.ErrNotExist},
		{"path_escape_verbatim", escapePathErr, nil, escapePathErr},
		{"link_escape_verbatim", escapeLinkErr, nil, escapeLinkErr},
		{"non_sentinel_verbatim", errors.New("boom"), nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewEngine(stubEngine{err: tc.in})
			got := a.MakeDir(context.Background(), "fs1", "/d")
			if tc.wantMirror != nil {
				if !errors.Is(got, tc.wantMirror) {
					t.Fatalf("remap: got %v, want errors.Is(%v)", got, tc.wantMirror)
				}
				// Non-vacuity: a remapped error must NOT still be the raw
				// objectstore sentinel string identity leaking through.
				return
			}
			if tc.wantVerbatim != nil {
				if !errors.Is(got, tc.wantVerbatim) {
					t.Fatalf("verbatim: got %v, want the error passed through unchanged (errors.Is %v)", got, tc.wantVerbatim)
				}
				// Verbatim pass-through must NOT have been remapped to a mirror.
				if errors.Is(got, southface.ErrAlreadyExists) || errors.Is(got, southface.ErrInvalidPath) {
					t.Fatalf("stdlib/escape error %v was wrongly remapped to a southface mirror", tc.in)
				}
				return
			}
			// non_sentinel: passes through, not remapped.
			if errors.Is(got, southface.ErrAlreadyExists) || errors.Is(got, southface.ErrInvalidPath) {
				t.Fatalf("non-sentinel error %v was wrongly remapped to a mirror", tc.in)
			}
		})
	}
}

// TestEngineAdapterNilPassesThrough pins that a successful verb returns nil
// (mapEngineErr does not manufacture an error) and copies FileInfo fields.
func TestEngineAdapterNilPassesThrough(t *testing.T) {
	a := NewEngine(stubEngine{err: nil})
	infos, err := a.List(context.Background(), "fs1", ".")
	if err != nil {
		t.Fatalf("List(ok): got %v, want nil", err)
	}
	if len(infos) != 1 || infos[0].Name != "a" || infos[0].Size != 3 {
		t.Fatalf("FileInfo copy: got %+v, want one entry {a,3}", infos)
	}
}

// TestMapCeilingsErr pins the ceilings sentinel remap arms in isolation: each
// real ceilings sentinel (including an fmt-wrapped form, the shape a real
// limiter call returns through the spine) lands on the matching southface
// mirror; a nil passes through nil and a non-sentinel passes through verbatim
// (so the spine falls to denyInternal/500 rather than a spurious 429). The four
// quota mirrors are also asserted distinct from each other so a throttle is
// never confused with a bytes/fd/size verdict downstream.
func TestMapCeilingsErr(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   error
		want error // nil -> expect verbatim/no-mirror
	}{
		{"nil_passes_through", nil, nil},
		{"throttle", ceilings.ErrThrottleExceeded, southface.ErrThrottleExceeded},
		{"throttle_wrapped", fmt.Errorf("op verb: %w", ceilings.ErrThrottleExceeded), southface.ErrThrottleExceeded},
		{"bytes", ceilings.ErrBytesExceeded, southface.ErrBytesExceeded},
		{"bytes_wrapped", fmt.Errorf("acquire: %w", ceilings.ErrBytesExceeded), southface.ErrBytesExceeded},
		{"fd", ceilings.ErrFDExceeded, southface.ErrFDExceeded},
		// ErrSizeExceeded is intentionally absent: the declared-size ceiling is
		// a free-function check, not a CeilingsSession method, so it never
		// transits mapCeilingsErr (broker-01).
		{"non_sentinel_passthrough", errors.New("boom"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapCeilingsErr(tc.in)
			if tc.want == nil {
				if tc.in == nil {
					if got != nil {
						t.Fatalf("mapCeilingsErr(nil) = %v, want nil", got)
					}
					return
				}
				// Non-vacuity: an unknown error is NOT remapped to any quota
				// mirror; it passes through so the spine denies internal.
				if errors.Is(got, southface.ErrThrottleExceeded) ||
					errors.Is(got, southface.ErrBytesExceeded) ||
					errors.Is(got, southface.ErrFDExceeded) {
					t.Fatalf("non-sentinel %v was remapped to a quota mirror (got %v)", tc.in, got)
				}
				if got == nil {
					t.Fatalf("non-sentinel error dropped to nil")
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("mapCeilingsErr(%v) = %v, want errors.Is(%v)", tc.in, got, tc.want)
			}
		})
	}
	// Mirror distinctness across the three quota verdicts mapCeilingsErr emits.
	mirrors := []error{
		southface.ErrThrottleExceeded, southface.ErrBytesExceeded,
		southface.ErrFDExceeded,
	}
	for i, a := range mirrors {
		for j, b := range mirrors {
			if i != j && errors.Is(a, b) {
				t.Fatalf("quota mirror %v unexpectedly matches %v", a, b)
			}
		}
	}
}

// TestEngineAdapterListStatRemapErrors pins the error-mapping leg of the List
// and Stat adapter verbs (the success legs are covered by the real-local-verbs
// test): an engine that fails returns the remapped southface mirror, and on
// error List returns a nil slice (never a half-built one). Driving the failure
// through these two read verbs fires the error-return arm of each that the
// happy path leaves uncovered.
func TestEngineAdapterListStatRemapErrors(t *testing.T) {
	a := NewEngine(stubEngine{err: objectstore.ErrInvalidPath})

	infos, err := a.List(context.Background(), "fs1", "/x")
	if !errors.Is(err, southface.ErrInvalidPath) {
		t.Fatalf("List error remap: got %v, want ErrInvalidPath mirror", err)
	}
	if infos != nil {
		t.Fatalf("List on error: got %v, want a nil slice", infos)
	}

	_, err = a.Stat(context.Background(), "fs1", "/x")
	if !errors.Is(err, southface.ErrInvalidPath) {
		t.Fatalf("Stat error remap: got %v, want ErrInvalidPath mirror", err)
	}

	// A transient backend fault on a read verb crosses as the transient mirror
	// (distinct wire code from a path verdict).
	at := NewEngine(stubEngine{err: objectstore.ErrTransient})
	if _, err := at.Stat(context.Background(), "fs1", "/x"); !errors.Is(err, southface.ErrBackendTransient) {
		t.Fatalf("Stat transient remap: got %v, want ErrBackendTransient mirror", err)
	}
}

// shortDir returns a short-pathed temp directory cleaned up at test end.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "brk")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// TestEngineAdapterRealLocalVerbs exercises the uncovered engine adapter verbs
// (Stat, MoveDir, RemoveDir, CopyFile, MoveFile, RemoveFile) and the ceilings
// ReleaseFD method end-to-end against a real local-volume engine so that the
// delegation path — adapter narrows string to ScopeID, delegates to engine,
// remaps errors — is covered by live execution.
func TestEngineAdapterRealLocalVerbs(t *testing.T) {
	base := shortDir(t)
	eng := objectstore.NewLocalVolumeEngine(base)
	ctx := context.Background()

	// Provision a scope so the local engine has a rooted directory to work in.
	const scope = "brktest01"
	if err := eng.ProvisionScope(ctx, objectstore.ScopeID(scope)); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}
	t.Cleanup(func() { eng.TeardownScope(ctx, objectstore.ScopeID(scope)) })

	a := NewEngine(eng)

	// The engineAdapter passes paths to the objectstore engine in the relative
	// convention the engine expects (no leading slash; "." is the scope root).

	// --- WriteStream + Stat --------------------------------------------------
	content := []byte("hello delegation")
	if err := a.WriteStream(ctx, scope, "greet.txt", strings.NewReader(string(content)), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	fi, err := a.Stat(ctx, scope, "greet.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Name != "greet.txt" {
		t.Fatalf("Stat.Name = %q, want %q", fi.Name, "greet.txt")
	}
	if fi.Size != int64(len(content)) {
		t.Fatalf("Stat.Size = %d, want %d", fi.Size, len(content))
	}
	if fi.IsDir {
		t.Fatalf("Stat.IsDir = true, want false for a regular file")
	}

	// --- MakeDir (already covered) + MoveDir ---------------------------------
	if err := a.MakeDir(ctx, scope, "src"); err != nil {
		t.Fatalf("MakeDir(src): %v", err)
	}
	if err := a.MoveDir(ctx, scope, "src", "dst", false); err != nil {
		t.Fatalf("MoveDir(src→dst): %v", err)
	}
	// dst must now exist; src must be gone.
	if _, err := a.Stat(ctx, scope, "dst"); err != nil {
		t.Fatalf("Stat(dst) after MoveDir: %v", err)
	}

	// --- RemoveDir -----------------------------------------------------------
	if err := a.RemoveDir(ctx, scope, "dst"); err != nil {
		t.Fatalf("RemoveDir(dst): %v", err)
	}

	// --- CopyFile ------------------------------------------------------------
	if err := a.CopyFile(ctx, scope, "greet.txt", "greet-copy.txt", false); err != nil {
		t.Fatalf("CopyFile: %v", err)
	}
	fi2, err := a.Stat(ctx, scope, "greet-copy.txt")
	if err != nil {
		t.Fatalf("Stat(copy): %v", err)
	}
	if fi2.Size != fi.Size {
		t.Fatalf("CopyFile size mismatch: got %d, want %d", fi2.Size, fi.Size)
	}

	// --- MoveFile ------------------------------------------------------------
	if err := a.MoveFile(ctx, scope, "greet-copy.txt", "greet-moved.txt", false); err != nil {
		t.Fatalf("MoveFile: %v", err)
	}
	if _, err := a.Stat(ctx, scope, "greet-moved.txt"); err != nil {
		t.Fatalf("Stat after MoveFile: %v", err)
	}

	// --- RemoveFile ----------------------------------------------------------
	if err := a.RemoveFile(ctx, scope, "greet-moved.txt"); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
}

// TestCeilingsAdapterReleaseFD pins the ceilings adapter ReleaseFD delegation:
// TryAcquireFD followed by ReleaseFD must leave the session in a state where
// another TryAcquireFD succeeds (the fd counter returned to zero). This covers
// the ReleaseFD wrapper at line 158 of broker.go, which was 0% covered.
func TestCeilingsAdapterReleaseFD(t *testing.T) {
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         1000,
		OpsBurst:             1000,
		InFlightBytesCeiling: 1 << 30,
		FDCeiling:            1, // ceiling of exactly 1 so the acquire/release cycle is observable
		Clock:                time.Now,
	})
	a := NewCeilings(reg)
	sess := a.Session("fd-release-key")

	// Acquire the one available fd slot.
	if err := sess.TryAcquireFD(); err != nil {
		t.Fatalf("TryAcquireFD (first): %v", err)
	}
	// With FDCeiling=1 a second acquire must fail.
	if err := sess.TryAcquireFD(); !errors.Is(err, southface.ErrFDExceeded) {
		t.Fatalf("TryAcquireFD (second, ceiling=1): got %v, want ErrFDExceeded", err)
	}
	// ReleaseFD returns the slot; the next acquire must succeed again.
	sess.ReleaseFD()
	if err := sess.TryAcquireFD(); err != nil {
		t.Fatalf("TryAcquireFD after ReleaseFD: %v", err)
	}
	sess.ReleaseFD() // clean up
}

// TestMapEngineErr_TransientThrottled pins the W1 resilience remap
// round-trip: the objectstore throttle/transient sentinels — including
// fmt-wrapped forms, the shape a real engine verb returns — land on the
// southface mirrors, and the mirrors are distinct from each other and from
// the earlier mirrors (a throttle is a pacing verdict, a transient is an
// availability verdict; they map to different wire codes downstream).
func TestMapEngineErr_TransientThrottled(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   error
		want error
	}{
		{"throttled", objectstore.ErrThrottled, southface.ErrBackendThrottled},
		{"throttled_wrapped", fmt.Errorf("write verb: %w", objectstore.ErrThrottled), southface.ErrBackendThrottled},
		{"transient", objectstore.ErrTransient, southface.ErrBackendTransient},
		{"transient_wrapped", fmt.Errorf("read verb: %w", objectstore.ErrTransient), southface.ErrBackendTransient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapEngineErr(tc.in)
			if !errors.Is(got, tc.want) {
				t.Fatalf("mapEngineErr(%v) = %v, want errors.Is(%v)", tc.in, got, tc.want)
			}
		})
	}
	// Mirror distinctness: the two new mirrors never cross-match each other
	// or the earlier engine mirrors.
	mirrors := []error{
		southface.ErrBackendThrottled, southface.ErrBackendTransient,
		southface.ErrAlreadyExists, southface.ErrInvalidPath,
	}
	for i, a := range mirrors {
		for j, b := range mirrors {
			if i != j && errors.Is(a, b) {
				t.Fatalf("mirror %v unexpectedly matches %v", a, b)
			}
		}
	}
}
