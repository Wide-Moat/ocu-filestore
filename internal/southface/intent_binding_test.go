// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// intentResolver mirrors the real three-axis resolver's intent axis (the
// in-package fakeResolver deliberately does not): it denies ErrIntentDenied
// when the requested intent is absent from the caller's granted set
// (deny-by-default, NFR-SEC-49) and otherwise returns the configured grant.
// It records the last ResolveRequest so tests can pin that the spine derives
// the authz intent from the ROUTE OP, never the wire hint.
type intentResolver struct {
	rec     *callRecorder
	grant   Grant
	mu      sync.Mutex
	lastReq ResolveRequest
}

func (r *intentResolver) Resolve(_ context.Context, caller any, req ResolveRequest) (Grant, error) {
	if r.rec != nil {
		r.rec.record("resolve")
	}
	r.mu.Lock()
	r.lastReq = req
	r.mu.Unlock()
	ev, ok := caller.(CallerEvidence)
	if !ok {
		return Grant{}, ErrScopeMismatch
	}
	for _, g := range ev.GrantedIntents {
		if g == req.Intent {
			return r.grant, nil
		}
	}
	return Grant{}, ErrIntentDenied
}

// mutationOpBody returns a valid op body for each write-class phase-9 op,
// stamped with the given wire intent. The paths target seeded objects so a
// wrongly-allowed call would actually mutate (the engine fake records it).
func mutationOpBody(op Op, scope string, intent Intent) string {
	am := fmt.Sprintf(`"authorization_metadata":{"intent":%q,"downloadable":false}`, intent)
	switch op {
	case OpMakeDirectory:
		return fmt.Sprintf(`{"filesystem_id":%q,"path":"/newdir",%s}`, scope, am)
	case OpMoveDirectory:
		return fmt.Sprintf(`{"filesystem_id":%q,"source":"/seeded-dir","destination":"/moved-dir",%s}`, scope, am)
	case OpRemoveDirectory:
		return fmt.Sprintf(`{"filesystem_id":%q,"path":"/seeded-dir","recursive":true,%s}`, scope, am)
	case OpCopyFile:
		return fmt.Sprintf(`{"filesystem_id":%q,"source":"/seeded.txt","destination":"/copied.txt","overwrite_existing":false,%s}`, scope, am)
	case OpMoveFile:
		return fmt.Sprintf(`{"filesystem_id":%q,"source":"/seeded.txt","destination":"/moved.txt","overwrite_existing":false,%s}`, scope, am)
	case OpRemoveFile:
		return fmt.Sprintf(`{"filesystem_id":%q,"path":"/seeded.txt",%s}`, scope, am)
	default:
		// Generic body for the unimplemented write-class ops (createFile,
		// importFiles, importZip, migrateFilesystem, removeFilesystem): the
		// spine's envelope decode is lenient on op fields, so the minimal
		// envelope shape suffices to reach STAGE 2.
		return fmt.Sprintf(`{"filesystem_id":%q,"path":"/x",%s}`, scope, am)
	}
}

// mutationOps is every implemented phase-9 mutation op the binding must cover.
var mutationOps = []Op{
	OpMakeDirectory, OpMoveDirectory, OpRemoveDirectory,
	OpCopyFile, OpMoveFile, OpRemoveFile,
}

// writeClassUnaryOps is EVERY write-class unary op (implemented or not): the
// route-op binding refuses a mismatching wire intent before the registry, so
// even an unimplemented mutation route never resolves under a read intent.
var writeClassUnaryOps = []Op{
	OpMakeDirectory, OpMoveDirectory, OpRemoveDirectory,
	OpCreateFile, OpCopyFile, OpMoveFile, OpRemoveFile,
	OpImportFiles, OpImportZip, OpMigrateFilesystem, OpRemoveFilesystem,
}

// seededEngine returns a fake engine with the objects the mutation bodies
// target, so a wrongly-allowed mutation is observable.
func seededEngine() *fakeEngine {
	eng := newFakeEngine()
	eng.mkdirSeed(opScope, "seeded-dir")
	eng.putFile(opScope, "seeded.txt", 3)
	return eng
}

// TestRouteOpIntentBindingMapClosed pins that the closed route-op map covers
// EXACTLY the frozen op set: every routable op has a required intent and no
// row exists outside the op set. An uncovered op would fail closed at
// dispatch; this test makes the gap loud at build time instead.
func TestRouteOpIntentBindingMapClosed(t *testing.T) {
	for op := range knownOps {
		intent, ok := requiredIntentForOp(op)
		if !ok {
			t.Errorf("op %q has no required-intent row (would fail closed at dispatch)", op)
		}
		if intent != IntentRead && intent != IntentWrite {
			t.Errorf("op %q maps to %q, want read or write (preview is never a south-face op intent)", op, intent)
		}
	}
	for op := range opRequiredIntent {
		if _, ok := knownOps[op]; !ok {
			t.Errorf("required-intent map carries unknown op %q", op)
		}
	}
}

// TestReadOnlySessionDeniedOnEveryMutationOp is the AUTHZ-01 pin: a session
// granted ONLY IntentRead is denied on EVERY write-class unary op, BOTH ways:
//
//   - declaring the honest intent=write -> the resolver's intent axis denies
//     (permission_denied 403, x-deny-reason intent_denied);
//   - lying intent=read on the mutation route -> the route-op binding refuses
//     (invalid_argument 400, errRouteOpMismatch) and the RESOLVER IS NEVER
//     REACHED, so the per-intent allow grant can never be minted.
//
// In both cases the engine records ZERO mutations.
func TestReadOnlySessionDeniedOnEveryMutationOp(t *testing.T) {
	for _, op := range writeClassUnaryOps {
		t.Run(string(op)+"/honest_write_intent_denied", func(t *testing.T) {
			eng := seededEngine()
			rec := &callRecorder{}
			res := &intentResolver{rec: rec}
			d := newDispatcherWithEngine(res, &fakeGuard{}, okCeilings(), 1<<20, eng)

			w := serveOp(d, op, mutationOpBody(op, opScope, IntentWrite), opScope, []Intent{IntentRead})
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (intent_denied); body %s", w.Code, w.Body.String())
			}
			if h := w.Header().Get("x-deny-reason"); h != denyIntentDenied {
				t.Fatalf("x-deny-reason = %q, want %q", h, denyIntentDenied)
			}
			if got := len(eng.mutations()); got != 0 {
				t.Fatalf("engine mutated %d times on a read-only session, want 0: %v", got, eng.mutations())
			}
		})

		t.Run(string(op)+"/lying_read_intent_refused_pre_resolve", func(t *testing.T) {
			eng := seededEngine()
			rec := &callRecorder{}
			res := &intentResolver{rec: rec}
			d := newDispatcherWithEngine(res, &fakeGuard{}, okCeilings(), 1<<20, eng)

			w := serveOp(d, op, mutationOpBody(op, opScope, IntentRead), opScope, []Intent{IntentRead})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (route-op intent mismatch); body %s", w.Code, w.Body.String())
			}
			if ce := decodeErrBody(t, w); ce.Code != wireCodeInvalidArgument {
				t.Fatalf("code = %q, want invalid_argument", ce.Code)
			}
			for _, c := range rec.snapshot() {
				if c == "resolve" || c == "mandate" {
					t.Fatalf("call %q reached after a route-op intent mismatch, want refusal before STAGE 2", c)
				}
			}
			if got := len(eng.mutations()); got != 0 {
				t.Fatalf("engine mutated %d times on a mismatched intent, want 0: %v", got, eng.mutations())
			}
		})
	}
}

// TestWriteSessionMutatesWithHonestIntent is the positive control: a session
// granted write succeeds on every implemented mutation op when declaring the
// route's required intent.
func TestWriteSessionMutatesWithHonestIntent(t *testing.T) {
	for _, op := range mutationOps {
		t.Run(string(op), func(t *testing.T) {
			eng := seededEngine()
			res := &intentResolver{}
			d := newDispatcherWithEngine(res, &fakeGuard{}, okCeilings(), 1<<20, eng)

			w := serveOp(d, op, mutationOpBody(op, opScope, IntentWrite), opScope, []Intent{IntentRead, IntentWrite})
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
			}
			if got := len(eng.mutations()); got == 0 {
				t.Fatalf("write session with honest intent mutated nothing (positive control broken)")
			}
		})
	}
}

// TestResolverSeesRouteDerivedIntent pins that the intent handed to
// Resolve is the ROUTE-derived one — the closed map's value for the op — for
// both a read-class and a write-class op.
func TestResolverSeesRouteDerivedIntent(t *testing.T) {
	cases := []struct {
		op   Op
		body string
		want Intent
	}{
		{OpReadFile, readBody(opScope, "/seeded.txt", 0, 1, false), IntentRead},
		{OpRemoveFile, mutationOpBody(OpRemoveFile, opScope, IntentWrite), IntentWrite},
	}
	for _, c := range cases {
		t.Run(string(c.op), func(t *testing.T) {
			eng := seededEngine()
			res := &intentResolver{grant: Grant{Downloadable: true}}
			d := newDispatcherWithEngine(res, &fakeGuard{}, okCeilings(), 1<<20, eng)
			serveOp(d, c.op, c.body, opScope, okIntents())
			res.mu.Lock()
			got := res.lastReq.Intent
			res.mu.Unlock()
			if got != c.want {
				t.Fatalf("resolver saw intent %q for %s, want the route-derived %q", got, c.op, c.want)
			}
		})
	}
}

// TestReadOpsRefuseWriteIntent pins the inverse mismatch: a write intent
// declared on a read-class route is refused (the wire hint never widens or
// narrows what the route does).
func TestReadOpsRefuseWriteIntent(t *testing.T) {
	bodies := map[Op]string{
		OpReadFile: fmt.Sprintf(
			`{"filesystem_id":%q,"path":"/seeded.txt","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope),
		OpListDirectory: fmt.Sprintf(
			`{"filesystem_id":%q,"path":"/","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope),
	}
	for op, body := range bodies {
		t.Run(string(op), func(t *testing.T) {
			eng := seededEngine()
			d := newDispatcherWithEngine(&intentResolver{}, &fakeGuard{}, okCeilings(), 1<<20, eng)
			w := serveOp(d, op, body, opScope, okIntents())
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (route-op intent mismatch); body %s", w.Code, w.Body.String())
			}
		})
	}
}

// TestPreviewSessionNeverWritesOrDownloads pins the preview rule on this
// face: a session granted ONLY IntentPreview can neither mutate (the write
// resolve denies) nor download (the read resolve denies before the grant),
// and a preview wire intent is refused on every route (no south-face op maps
// to preview).
func TestPreviewSessionNeverWritesOrDownloads(t *testing.T) {
	previewOnly := []Intent{IntentPreview}

	t.Run("mutations_denied", func(t *testing.T) {
		for _, op := range mutationOps {
			eng := seededEngine()
			d := newDispatcherWithEngine(&intentResolver{}, &fakeGuard{}, okCeilings(), 1<<20, eng)
			w := serveOp(d, op, mutationOpBody(op, opScope, IntentWrite), opScope, previewOnly)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s status = %d, want 403 (intent_denied)", op, w.Code)
			}
			if got := len(eng.mutations()); got != 0 {
				t.Fatalf("%s mutated under a preview-only grant: %v", op, eng.mutations())
			}
		}
	})

	t.Run("read_denied_no_download", func(t *testing.T) {
		eng := seededEngine()
		d := newDispatcherWithEngine(&intentResolver{}, &fakeGuard{}, okCeilings(), 1<<20, eng)
		w := serveOp(d, OpReadFile, readBody(opScope, "/seeded.txt", 0, 1, false), opScope, previewOnly)
		if w.Code != http.StatusForbidden {
			t.Fatalf("readFile status = %d, want 403 (intent_denied for a preview-only grant)", w.Code)
		}
	})

	t.Run("preview_wire_intent_refused_on_every_route", func(t *testing.T) {
		for op := range knownOps {
			if op == OpFileUpload || op == OpFileDownload {
				continue // the data-plane ops have dedicated REST entrypoints (upload hardcodes write)
			}
			eng := seededEngine()
			d := newDispatcherWithEngine(&intentResolver{}, &fakeGuard{}, okCeilings(), 1<<20, eng)
			body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/x","authorization_metadata":{"intent":"preview","downloadable":false}}`, opScope)
			w := serveOp(d, op, body, opScope, []Intent{IntentRead, IntentWrite, IntentPreview})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s with intent=preview: status = %d, want 400 (no south-face op maps to preview)", op, w.Code)
			}
		}
	})
}

// TestMutationHandlersAssertWriteGrant pins the defense-in-depth layer in
// ISOLATION from the spine: each mutation handler, invoked directly with a
// channel grant set lacking IntentWrite, refuses intent_denied and never
// touches the engine — even though no spine stage ran. This is the
// handler-level mirror of handleReadFile's grant check.
func TestMutationHandlersAssertWriteGrant(t *testing.T) {
	handlers := map[Op]opHandler{
		OpMakeDirectory:   handleMakeDirectory,
		OpMoveDirectory:   handleMoveDirectory,
		OpRemoveDirectory: handleRemoveDirectory,
		OpCopyFile:        handleCopyFile,
		OpMoveFile:        handleMoveFile,
		OpRemoveFile:      handleRemoveFile,
	}
	for op, h := range handlers {
		t.Run(string(op), func(t *testing.T) {
			eng := seededEngine()
			deps := &handlerDeps{engine: eng, ids: newObjectIDStore()}
			w := httptest.NewRecorder()
			var deniedReason string
			hc := handlerCtx{
				w:    w,
				op:   op,
				body: []byte(mutationOpBody(op, opScope, IntentWrite)),
				ps:   PeerScope{FilesystemID: opScope, GrantedIntents: []Intent{IntentRead}},
				mandateDeny: func(auditReason, wireClass, message string) {
					deniedReason = auditReason
					writeRESTDeny(w, mapDenyDegraded(auditReason, wireClass), message)
				},
			}
			h(deps, hc)
			if deniedReason != denyIntentDenied {
				t.Fatalf("handler deny reason = %q, want %q (defense-in-depth write gate)", deniedReason, denyIntentDenied)
			}
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", w.Code)
			}
			if got := len(eng.mutations()); got != 0 {
				t.Fatalf("handler mutated the engine without a write grant: %v", eng.mutations())
			}
		})
	}
}
