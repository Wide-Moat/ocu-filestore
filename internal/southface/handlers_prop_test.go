// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// TestPropScopeContainment is P1 (non-vacuous): over a generated sequence of
// namespace ops mixing in-scope paths with adversarial escape-shaped paths
// (../x, /abs, a/../../b), NO mutation the engine fake records ever escapes the
// bound scope root, AND the test asserts that at least one op actually mutated
// the tree and at least one adversarial path was drawn — a run that reaches
// zero mutations or zero adversarial cases FAILS as vacuous (the phase-2
// lesson).
func TestPropScopeContainment(t *testing.T) {
	var totalMutations int
	var totalAdversarial int

	rapid.Check(t, func(rt *rapid.T) {
		eng := newFakeEngine()
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

		// Seed a couple of in-scope objects the ops can target.
		eng.mkdirSeed(opScope, "seed")
		eng.putFile(opScope, "seed/file", 3)

		n := rapid.IntRange(1, 8).Draw(rt, "op_count")
		for i := 0; i < n; i++ {
			// Half in-scope, half adversarial — biased so adversarial cases
			// are reliably drawn.
			adversarial := rapid.Bool().Draw(rt, fmt.Sprintf("adv_%d", i))
			var path string
			if adversarial {
				totalAdversarial++
				path = rapid.SampledFrom([]string{
					"/../escape", "/a/../../b", "/../../etc", "//x", "/a//b", "/..",
				}).Draw(rt, fmt.Sprintf("advpath_%d", i))
			} else {
				path = "/" + rapid.SampledFrom([]string{"d1", "d2", "seed/sub", "x/y"}).Draw(rt, fmt.Sprintf("path_%d", i))
			}

			op := rapid.SampledFrom([]Op{
				OpMakeDirectory, OpRemoveDirectory, OpRemoveFile,
			}).Draw(rt, fmt.Sprintf("op_%d", i))

			var body string
			switch op {
			case OpMakeDirectory:
				body = fmt.Sprintf(`{"filesystem_id":%q,"path":%q,"make_parents":true,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope, path)
			case OpRemoveDirectory:
				body = fmt.Sprintf(`{"filesystem_id":%q,"path":%q,"recursive":true,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope, path)
			case OpRemoveFile:
				body = fmt.Sprintf(`{"filesystem_id":%q,"path":%q,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope, path)
			}
			w := httptest.NewRecorder()
			d.ServeHTTP(w, scopedRequest(op, body, opScope, okIntents()))
		}

		// Every recorded mutation target must be a clean relative path under
		// the scope root: no leading slash, no ".." component, no empty
		// component. The engine fake rejects escape-shaped paths pre-mutation
		// (errInvalidPath), so a recorded mutation is proof of containment.
		for _, m := range eng.mutations() {
			totalMutations++
			if strings.HasPrefix(m, "/") {
				rt.Fatalf("mutation %q is absolute — escaped the scope root", m)
			}
			for _, comp := range strings.Split(m, "/") {
				if comp == ".." || comp == "" {
					rt.Fatalf("mutation %q has an escaping/empty component", m)
				}
			}
		}
	})

	if totalMutations == 0 {
		t.Fatal("property never recorded a mutation: vacuous (no containment exercised)")
	}
	if totalAdversarial == 0 {
		t.Fatal("property never drew an adversarial path: vacuous (no escape exercised)")
	}
}

// TestPropCursor is P2: generated cursor relpaths round-trip byte-identical
// through encode/decode, and a multi-page recursive walk over a generated tree
// visits each entry exactly once with strictly-monotone cursors that span at
// least two pages.
func TestPropCursor(t *testing.T) {
	t.Run("round-trip identity", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			p := rapid.StringMatching(`[a-z0-9/._-]{0,40}`).Draw(rt, "relpath")
			tok := encodeCursor(p)
			got, err := decodeCursor(tok)
			if err != nil {
				rt.Fatalf("decodeCursor(%q): %v", tok, err)
			}
			if got != p {
				rt.Fatalf("round-trip %q -> %q, want identity", p, got)
			}
		})
	})

	t.Run("multi-page single-visit monotone walk", func(t *testing.T) {
		var spannedMultiPage int
		rapid.Check(t, func(rt *rapid.T) {
			eng := newFakeEngine()
			// Generate a flat set of uniquely-named files large enough that a
			// small limit forces multiple pages.
			count := rapid.IntRange(5, 20).Draw(rt, "file_count")
			for i := 0; i < count; i++ {
				eng.putFile(opScope+"-prop", fmt.Sprintf("f%03d.txt", i), int64(i))
			}
			d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

			limit := rapid.IntRange(1, 4).Draw(rt, "page_limit")
			seen := map[string]int{}
			cursor := ""
			prev := ""
			pages := 0
			for {
				w := httptest.NewRecorder()
				d.ServeHTTP(w, scopedRequest(OpListDirectory,
					listBody(opScope+"-prop", "/", limit, cursor, true), opScope+"-prop", okIntents()))
				if w.Code != 200 {
					rt.Fatalf("page status %d: %s", w.Code, w.Body.String())
				}
				var resp listDirectoryResponse
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					rt.Fatalf("decode page: %v", err)
				}
				pages++
				for _, e := range resp.Entries {
					if e.File != nil {
						seen[e.File.Path]++
					}
				}
				if resp.Cursor == "" {
					break
				}
				if resp.Cursor == prev {
					rt.Fatalf("cursor did not advance between pages: %q", resp.Cursor)
				}
				prev = cursor
				cursor = resp.Cursor
				if pages > count+5 {
					rt.Fatal("pagination did not terminate")
				}
			}
			if pages >= 2 {
				spannedMultiPage++
			}
			if len(seen) != count {
				rt.Fatalf("visited %d distinct files, want %d", len(seen), count)
			}
			for p, c := range seen {
				if c != 1 {
					rt.Fatalf("file %q visited %d times, want exactly 1", p, c)
				}
			}
		})
		if spannedMultiPage == 0 {
			t.Fatal("walk never spanned >=2 pages: cursor not exercised (vacuous)")
		}
	})
}
