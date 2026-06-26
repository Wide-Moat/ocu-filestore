// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

// This guard enforces CONSTITUTION invariant #10 (north and south never share a
// listener, router, or resolver) at the import-boundary level. The north
// Files-API package (internal/filesapi) is permitted to import the south
// package for its SEAM TYPES (the resolver/guard/engine mirrors and error
// sentinels) — that shared vocabulary is how the two faces agree on shapes
// without sharing a request path. What it must NEVER reference is the south
// REQUEST-ROUTING surface: the router, the dispatcher, and their per-op stage
// entrypoints. The moment a south router symbol appears under a filesapi
// selector, the physical trust boundary has been crossed and the
// confused-deputy that the dual-listener split exists to prevent becomes
// reachable in code.
//
// The guard is mechanical and non-vacuous: it parses every non-test source
// file in this package, collects every `southface.X` selector expression, and
// fails if X names any member of the forbidden router/dispatch set. It reds
// deterministically the instant anyone wires the south router into the north
// package.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// forbiddenSouthRouterSymbols is the south REQUEST-ROUTING surface that the
// north Files-API package must never reference. These are the router, the
// dispatcher, their constructors, the per-op stage entrypoints, and the REST
// route base. Importing south for seam TYPES stays allowed; touching any of
// these means north and south now share a router or dispatch path.
var forbiddenSouthRouterSymbols = map[string]struct{}{
	"restRouter":               {},
	"newRESTRouter":            {},
	"dispatcher":               {},
	"newDispatcher":            {},
	"newDispatcherWithEngine":  {},
	"serveUploadMultipart":     {},
	"serveDownloadOctetStream": {},
	"routeOp":                  {},
	"restBase":                 {},
}

// collectSouthfaceSelectors parses every non-test .go file in the current
// package directory and returns the set of identifiers X that appear as a
// `southface.X` selector expression, together with the file each was seen in.
func collectSouthfaceSelectors(t *testing.T) map[string][]string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	seen := map[string][]string{}
	fset := token.NewFileSet()

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		path := filepath.Clean(name)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "southface" {
				return true
			}
			sym := sel.Sel.Name
			seen[sym] = append(seen[sym], path)
			return true
		})
	}

	return seen
}

// TestFilesapiNeverImportsSouthRouter asserts the north Files-API package never
// references the south request-routing surface. It reds if any forbidden south
// router/dispatch symbol is reached through a southface selector in a non-test
// source file of this package.
func TestFilesapiNeverImportsSouthRouter(t *testing.T) {
	selectors := collectSouthfaceSelectors(t)

	var violations []string
	for sym, files := range selectors {
		if _, forbidden := forbiddenSouthRouterSymbols[sym]; forbidden {
			sort.Strings(files)
			violations = append(violations, "southface."+sym+" referenced in "+strings.Join(uniq(files), ", "))
		}
	}
	sort.Strings(violations)

	if len(violations) != 0 {
		t.Fatalf("north Files-API references the south request-routing surface "+
			"(violates CONSTITUTION invariant #10 — north and south must never "+
			"share a router/dispatch path):\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestNorthSouthListenerSeparation is a documenting alias that ties the
// import-boundary guard to the listener-separation invariant by name. The
// physical bind separation lives in the dual-server wiring; this test asserts
// the code-level half of that boundary: the north package cannot reach the
// south router/dispatch surface, so the two faces cannot collapse onto one
// router even if they were ever bound to one listener.
func TestNorthSouthListenerSeparation(t *testing.T) {
	selectors := collectSouthfaceSelectors(t)

	for sym := range forbiddenSouthRouterSymbols {
		if files, used := selectors[sym]; used {
			t.Fatalf("north/south listener separation breached: south router symbol "+
				"southface.%s reached from north Files-API in %s", sym, strings.Join(uniq(files), ", "))
		}
	}
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seenSet := map[string]struct{}{}
	out := in[:0]
	for _, v := range in {
		if _, ok := seenSet[v]; ok {
			continue
		}
		seenSet[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
