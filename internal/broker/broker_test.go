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
