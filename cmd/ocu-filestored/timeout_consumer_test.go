// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// --- TIMEOUT-CONSUMER -------------------------------------------------------
//
// A timeout constant is a promise about a call: this operation is bounded, and
// bounded by THIS much. Delete the call and the constant does not fall over. It
// keeps its name, its comment and its number, and it keeps being read as if the
// bound were still in force — by the next implementer, by the documents that
// cite it, and by the tests that assert it is positive.
//
// That is not hypothetical. A ten-minute teardown bound outlived the teardown
// call it bounded, and two tests went on documenting "the rollback latch's
// TeardownScope call uses a context bounded by teardownTimeout" while the
// rollback had become release-only. Both tests passed: their assertion was that
// a constant is greater than zero.
//
// Nothing else catches this. staticcheck's unused counts a reference from a
// _test.go file as a use, so a constant with a live test and a dead subject is
// invisible to it — and the test is exactly what a dead constant tends to keep.
// So this guard counts references in PRODUCT source only.

// durationConstDecl is one duration-valued constant declared in product source.
type durationConstDecl struct {
	pkgDir   string // repo-relative directory = Go package
	file     string // repo-relative
	line     int
	name     string
	exported bool
}

func (d durationConstDecl) String() string { return d.file + ":" + strconv.Itoa(d.line) + " " + d.name }

// isDurationValue reports whether a constant's value expression names a unit of
// the time package. It is deliberately looser than the `<int> * time.<Unit>`
// form evalDurationExpr evaluates: this guard needs only to RECOGNISE a duration
// constant, so a constant written in some other arithmetic still gets counted
// rather than slipping out of the census on a technicality.
func isDurationValue(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "time" {
			return true
		}
		if _, isUnit := timeUnits[sel.Sel.Name]; isUnit {
			found = true
		}
		return true
	})
	return found
}

// productSourceFiles walks the product source trees and yields every non-test
// Go file. _test.go is excluded on purpose: a test reference is the very thing
// that hides a dead constant.
func productSourceFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, tree := range []string{"cmd", "internal"} {
		base := filepath.Join(root, tree)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case d.IsDir(), !strings.HasSuffix(path, ".go"), strings.HasSuffix(path, "_test.go"):
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
	if len(files) == 0 {
		t.Fatal("found no product source files under cmd/ and internal/; the census is vacuous")
	}
	sort.Strings(files)
	return files
}

// censusDurationConsts returns every duration constant declared in product
// source and, per package, how often each identifier is referenced from product
// source OUTSIDE its own declaration.
func censusDurationConsts(t *testing.T, root string) ([]durationConstDecl, map[string]map[string]int, map[string]int) {
	t.Helper()

	var decls []durationConstDecl
	perPkg := make(map[string]map[string]int) // package dir -> identifier -> references
	anywhere := make(map[string]int)          // identifier -> references across all product source

	for _, path := range productSourceFiles(t, root) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		pkgDir := filepath.ToSlash(filepath.Dir(rel))

		// The declaring identifiers themselves are not references to themselves.
		declaring := make(map[token.Pos]bool)
		ast.Inspect(f, func(n ast.Node) bool {
			gd, ok := n.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				return true
			}
			for _, s := range gd.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) || !isDurationValue(vs.Values[i]) {
						continue
					}
					declaring[name.Pos()] = true
					decls = append(decls, durationConstDecl{
						pkgDir:   pkgDir,
						file:     rel,
						line:     fset.Position(name.Pos()).Line,
						name:     name.Name,
						exported: ast.IsExported(name.Name),
					})
				}
			}
			return true
		})

		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || declaring[id.Pos()] {
				return true
			}
			if perPkg[pkgDir] == nil {
				perPkg[pkgDir] = make(map[string]int)
			}
			perPkg[pkgDir][id.Name]++
			anywhere[id.Name]++
			return true
		})
	}

	sort.Slice(decls, func(i, j int) bool {
		if decls[i].file != decls[j].file {
			return decls[i].file < decls[j].file
		}
		return decls[i].line < decls[j].line
	})
	return decls, perPkg, anywhere
}

// TestEveryTimeoutConstantHasAProductConsumer asserts that every duration
// constant the product declares is read by the product. A constant only tests
// read bounds nothing: whatever call it was written for is gone, and the number
// is documentation of a guarantee the daemon no longer makes.
func TestEveryTimeoutConstantHasAProductConsumer(t *testing.T) {
	root := repoRoot(t)

	decls, perPkg, anywhere := censusDurationConsts(t, root)
	if len(decls) == 0 {
		t.Fatal("census found no duration constants in product source; the recogniser is broken and every dead bound would pass")
	}

	consumed := 0
	for _, d := range decls {
		// An unexported constant can only be read from its own package; an
		// exported one from anywhere in the product source.
		refs := perPkg[d.pkgDir][d.name]
		if d.exported {
			refs = anywhere[d.name]
		}
		if refs > 0 {
			consumed++
			continue
		}
		t.Errorf("%s is declared but no product source reads it — the call it bounds is gone, and the constant is left documenting a guarantee the daemon no longer makes.\n"+
			"  Wire it to the call it bounds, or delete it together with any test whose subject went with it.\n"+
			"  staticcheck will not tell you: its unused check counts a reference from a _test.go file as a use.",
			d)
	}

	// Non-vacuity, proven in-run: the reference counter must find consumers for
	// the constants that HAVE them. A counter that scored every constant zero
	// would red on everything; one that scored every constant non-zero (the
	// silent failure) would pass forever, so both ends are asserted.
	if consumed == 0 {
		t.Fatal("no duration constant was scored as consumed; the reference counter is not working")
	}
	t.Logf("census: %d duration constant(s) in product source, %d with a product consumer", len(decls), consumed)
}

// TestBootProvisionRunsUnderTheBoundedContext is the other half of the same
// idea: a constant with a consumer still guarantees nothing if the consumer is
// not the call. The daemon makes exactly one engine lifecycle call — the boot
// scaffold — and provisionTimeout is what keeps a hung backend from wedging
// startup forever. So this reads the wiring out of the source: the deadline is
// created from provisionTimeout, the context it produces is passed on, and no
// provision call anywhere in the product takes a bare, deadline-free context.
func TestBootProvisionRunsUnderTheBoundedContext(t *testing.T) {
	root := repoRoot(t)

	mainPath := filepath.Join(root, "cmd", "ocu-filestored", "main.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mainPath, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	// The context built from provisionTimeout, by the name it is bound to.
	var boundedCtx string
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || !isSelectorCall(call, "context", "WithTimeout") {
			return true
		}
		for _, arg := range call.Args {
			if id, ok := arg.(*ast.Ident); ok && id.Name == "provisionTimeout" {
				if name, ok := as.Lhs[0].(*ast.Ident); ok {
					boundedCtx = name.Name
				}
			}
		}
		return true
	})
	if boundedCtx == "" {
		t.Fatal("main.go builds no context from provisionTimeout; the boot provision is no longer bounded and a hung backend wedges startup indefinitely")
	}

	// A deadline nothing carries is not a deadline. The bounded context must be
	// handed to something other than its own cancel.
	passedOn := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if id, ok := arg.(*ast.Ident); ok && id.Name == boundedCtx {
				passedOn = true
			}
		}
		return true
	})
	if !passedOn {
		t.Fatalf("main.go builds the bounded context %q from provisionTimeout and passes it to nothing; the boot provision runs unbounded", boundedCtx)
	}

	// And no provision call may be handed a context that carries no deadline at
	// all — the failure mode the bound exists to prevent.
	sites := 0
	for _, path := range productSourceFiles(t, root) {
		pfset := token.NewFileSet()
		pf, perr := parser.ParseFile(pfset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		ast.Inspect(pf, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "ProvisionScope" || len(call.Args) == 0 {
				return true
			}
			sites++
			inner, ok := call.Args[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, bare := range []string{"Background", "TODO"} {
				if isSelectorCall(inner, "context", bare) {
					t.Errorf("%s:%d calls ProvisionScope with a bare context.%s(); it must run under the context bounded by provisionTimeout, or a hung backend wedges startup with no way out",
						filepath.ToSlash(rel), pfset.Position(call.Lparen).Line, bare)
				}
			}
			return true
		})
	}
	if sites == 0 {
		t.Fatal("found no ProvisionScope call in product source; the bare-context check inspected nothing")
	}
	t.Logf("boot provision bounded by provisionTimeout via %s; %d product provision call site(s) checked", boundedCtx, sites)
}

// isSelectorCall reports whether a call is of the form pkg.Fn(...).
func isSelectorCall(call *ast.CallExpr, pkg, fn string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != fn {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}
