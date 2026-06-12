// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// deepChain returns an engine-relative path of n components (d/d/d/...).
func deepChain(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "d"
	}
	return strings.Join(parts, "/")
}

// TestWalkDeepTreeNoStackOverflow pins CONC-03: a recursive listDirectory of
// a tree deeper than maxWalkDepth refuses CLEANLY (a deny, not a process
// fatal) — the pre-fix recursive descent translated tree depth into goroutine
// stack depth, and a hostile make_parents tree could hit Go's non-recoverable
// max-stack fatal and kill the single-session daemon. A tree under the cap
// lists fully (positive control).
func TestWalkDeepTreeNoStackOverflow(t *testing.T) {
	t.Run("over_cap_refuses_cleanly", func(t *testing.T) {
		eng := newFakeEngine()
		eng.mkdirSeed(opScope, deepChain(maxWalkDepth+100))
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

		w := serveOp(d, OpListDirectory, listBody(opScope, "/", 1<<20, "", true), opScope, okIntents())
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("over-cap walk status = %d, want 500 (clean refusal, not a fatal); body %s", w.Code, w.Body.String())
		}
	})

	t.Run("under_cap_lists_fully", func(t *testing.T) {
		const depth = 50
		eng := newFakeEngine()
		eng.mkdirSeed(opScope, deepChain(depth))
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

		w := serveOp(d, OpListDirectory, listBody(opScope, "/", 1<<10, "", true), opScope, okIntents())
		resp := decodeList(t, w)
		if len(resp.Entries) != depth {
			t.Fatalf("under-cap walk emitted %d entries, want %d", len(resp.Entries), depth)
		}
	})
}

// TestWalkLimitBoundsVisits pins the O(limit) walk: a recursive listing with
// limit=1 over a wide tree touches at most TWO engine List calls (the root
// plus the one look-ahead descent), never the whole tree — the pre-fix walk
// materialized the entire subtree before paginating.
func TestWalkLimitBoundsVisits(t *testing.T) {
	eng := newFakeEngine()
	for i := 0; i < 10; i++ {
		for j := 0; j < 5; j++ {
			eng.putFile(opScope, fmt.Sprintf("dir%02d/f%d", i, j), 1)
		}
	}
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	w := serveOp(d, OpListDirectory, listBody(opScope, "/", 1, "", true), opScope, okIntents())
	resp := decodeList(t, w)
	if len(resp.Entries) != 1 {
		t.Fatalf("limit=1 emitted %d entries, want 1", len(resp.Entries))
	}
	if resp.Cursor == "" {
		t.Fatal("limit=1 over a 60-entry tree minted no cursor")
	}
	if got := len(eng.listed); got > 2 {
		t.Fatalf("limit=1 drove %d engine List calls (%v), want <= 2 (O(limit), not O(tree))", got, eng.listed)
	}
}

// TestWalkCancelledContextAborts pins that the walk runs under the REQUEST
// context: a cancelled request aborts the traversal after at most the
// in-flight List call instead of walking the whole tree for a disconnected
// client.
func TestWalkCancelledContextAborts(t *testing.T) {
	eng := newFakeEngine()
	for i := 0; i < 20; i++ {
		eng.putFile(opScope, fmt.Sprintf("dir%02d/f", i), 1)
	}
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	r := scopedRequest(OpListDirectory, listBody(opScope, "/", 1<<10, "", true), opScope, okIntents())
	ctx, cancel := context.WithCancel(r.Context())
	cancel() // the client is already gone
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r.WithContext(ctx))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("cancelled walk status = %d, want 500 (aborted); body %s", w.Code, w.Body.String())
	}
	if got := len(eng.listed); got > 1 {
		t.Fatalf("cancelled walk drove %d engine List calls, want <= 1 (abort on cancel)", got)
	}
}

// TestMakeParentsDepthBomb pins the make_parents side of CONC-03: a path of
// thousands of components (well under the body ceiling) refuses BEFORE any
// engine call instead of creating an arbitrarily deep tree one level at a
// time.
func TestMakeParentsDepthBomb(t *testing.T) {
	eng := newFakeEngine()
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	body := fmt.Sprintf(
		`{"filesystem_id":%q,"path":"/%s","make_parents":true,"authorization_metadata":{"intent":"write","downloadable":false}}`,
		opScope, deepChain(2000))
	w := serveOp(d, OpMakeDirectory, body, opScope, okIntents())
	if w.Code != http.StatusNotFound {
		t.Fatalf("depth-bomb makeDirectory status = %d, want 404 (lexical reject, wire-degraded); body %s", w.Code, w.Body.String())
	}
	if got := len(eng.mutations()); got != 0 {
		t.Fatalf("depth-bomb makeDirectory created %d levels, want 0: %v", got, eng.mutations())
	}
}
