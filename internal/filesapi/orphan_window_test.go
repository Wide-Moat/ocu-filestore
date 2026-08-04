// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- ORPHAN-WINDOW ----------------------------------------------------------
//
// serveCreate commits the uploaded bytes to the engine BEFORE it Puts the
// durable handle. If the Put fails, the object is written and no file_id
// references it: an orphan no Files-API verb can reach, which nothing collects,
// because provision sweeps only the staging area and no product path erases a
// scope. The window is accepted on ordering grounds — the alternative mints a
// file_id that resolves to absent bytes, and a dangling id is the worse
// contract — and the acceptance is written down at the Put in create.go.
//
// A written-down acceptance is a claim about the code, and claims rot. This
// guard holds the four things the note asserts:
//
//   - the ordering it accepts (bytes durable, THEN handle),
//   - that nothing reclaims on the failure path,
//   - that the ledger it defers the erase question to still exists,
//   - that the open question it routes the reader to is still where it says.
//
// Each of those changing is a real event, not a hypothetical: reclamation is a
// fix somebody will one day write, and the erase-trigger question is open with
// the owner. When one changes, the note stops being true, and a note that
// documents an accepted risk in terms that no longer hold is worse than no note
// — so this reds and sends whoever changed it back to the paragraph.

// orphanWindowSource is the file the acceptance is written in.
const orphanWindowSource = "create.go"

// orphanWindowMarker is the note's own heading, in the source.
const orphanWindowMarker = "ORPHAN WINDOW"

// orphanWindowAnchors are the two documents the note routes a reader to, each
// with the text that must still be found there. A citation that has rotted
// sends the next reader nowhere.
var orphanWindowAnchors = []struct {
	cited string // as written in the note
	path  string // repo-relative
	must  string // text that must still exist at that path
}{
	{
		cited: "cmd/ocu-filestored/erase_trigger_test.go",
		path:  "cmd/ocu-filestored/erase_trigger_test.go",
		must:  "func TestNoProductPathTriggersScopeErase(",
	},
	{
		cited: "docs/architecture/05-lifecycle.md §3.5",
		path:  "docs/architecture/05-lifecycle.md",
		must:  "### 3.5 Open question — the erase trigger",
	},
}

// reclaimVerbs are the method names that would mean the orphan is being
// collected. The note's load-bearing sentence is that none of this happens;
// when one of them appears on the failure path, the sentence is false.
var reclaimVerbs = map[string]struct{}{
	"Remove":        {},
	"RemoveAll":     {},
	"RemoveFile":    {},
	"RemoveDir":     {},
	"Delete":        {},
	"DeleteFile":    {},
	"DeleteObject":  {},
	"Unlink":        {},
	"Discard":       {},
	"Reclaim":       {},
	"TeardownScope": {},
}

// reclaimCallsIn returns the reclaim-shaped calls inside a node, by name and
// line.
func reclaimCallsIn(fset *token.FileSet, n ast.Node) []string {
	var found []string
	ast.Inspect(n, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		if _, isReclaim := reclaimVerbs[sel.Sel.Name]; !isReclaim {
			return true
		}
		found = append(found, fset.Position(call.Lparen).String()+" "+sel.Sel.Name)
		return true
	})
	return found
}

// TestOrphanWindowNoteStillDescribesTheCode holds the accepted-risk note at the
// handle Put to the code it describes.
func TestOrphanWindowNoteStillDescribesTheCode(t *testing.T) {
	src, err := os.ReadFile(orphanWindowSource)
	if err != nil {
		t.Fatalf("read %s: %v", orphanWindowSource, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, orphanWindowSource, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", orphanWindowSource, err)
	}

	// The note itself.
	if !strings.Contains(string(src), orphanWindowMarker) {
		t.Fatalf("%s no longer carries the %q note. The window is a property of the ordering, not of the comment: if the ordering still stands, restore the acceptance in words; if reclamation landed, retire this guard with it.",
			orphanWindowSource, orphanWindowMarker)
	}

	var serveCreate *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name != nil && fn.Name.Name == "serveCreate" {
			serveCreate = fn
		}
		return true
	})
	if serveCreate == nil {
		t.Fatalf("%s declares no serveCreate; re-point this guard at the handler that commits bytes before it Puts the handle", orphanWindowSource)
	}

	// Anchor 1: the moment the engine write is known durable. That is the
	// receive whose result the handler KEEPS (writeRes) — not the bare receives
	// on the abort paths above it, which only drain the pipe goroutine after the
	// upload has already been refused. Anchoring on the first receive in the
	// function would put the anchor on a drain and pass a Put moved ahead of the
	// commit.
	writeCommit := token.NoPos
	ast.Inspect(serveCreate, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || len(as.Lhs) != 1 {
			return true
		}
		unary, ok := as.Rhs[0].(*ast.UnaryExpr)
		if !ok || unary.Op != token.ARROW {
			return true
		}
		src, ok := unary.X.(*ast.Ident)
		if !ok || src.Name != "writeErrCh" {
			return true
		}
		lhs, ok := as.Lhs[0].(*ast.Ident)
		if !ok || lhs.Name != "writeRes" {
			return true
		}
		if !writeCommit.IsValid() {
			writeCommit = as.Pos()
		}
		return true
	})
	if !writeCommit.IsValid() {
		t.Fatal("serveCreate no longer keeps the WriteStream outcome in writeRes; the guard cannot see where the bytes become durable. Re-point it at whatever now marks the commit, after checking the handle is still Put AFTER it")
	}

	// Anchor 2: the durable handle Put.
	handlePut := token.NoPos
	ast.Inspect(serveCreate, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Put" {
			return true
		}
		inner, ok := sel.X.(*ast.SelectorExpr)
		if !ok || inner.Sel == nil || inner.Sel.Name != "Store" {
			return true
		}
		if !handlePut.IsValid() {
			handlePut = call.Lparen
		}
		return true
	})
	if !handlePut.IsValid() {
		t.Fatal("serveCreate no longer Puts a record into the handle store; re-point this guard, or retire it if the north write plane no longer mints durable handles")
	}

	// The ordering the note accepts.
	if writeCommit > handlePut {
		t.Fatalf("%s: the handle is Put at %s, BEFORE the bytes are known durable at %s. That inverts the window the note accepts: a Put that lands before a failed write mints a file_id resolving to bytes that are not there, and a dangling id is the worse contract. Restore the ordering, or rewrite the note to describe the one you meant.",
			orphanWindowSource, fset.Position(handlePut), fset.Position(writeCommit))
	}

	// The claim that nothing is reclaimed, checked on the branch where the
	// orphan is created.
	var failure *ast.IfStmt
	ast.Inspect(serveCreate, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || ifs.Pos() < handlePut {
			return true
		}
		bin, ok := ifs.Cond.(*ast.BinaryExpr)
		if !ok || bin.Op != token.NEQ {
			return true
		}
		if id, ok := bin.X.(*ast.Ident); ok && id.Name == "perr" && failure == nil {
			failure = ifs
		}
		return true
	})
	if failure == nil {
		t.Fatal("serveCreate no longer branches on a handle-store Put error named perr; the guard cannot find the path that creates the orphan")
	}

	if reclaimed := reclaimCallsIn(fset, failure); len(reclaimed) != 0 {
		t.Errorf("the handle-Put failure path now reclaims: %s.\nThat is a change worth making — and it makes the %q note false, because the note's load-bearing sentence is that nothing sweeps these bytes. Rewrite the note, say what the reclaim guarantees on a crash between the two steps, and settle the open question the note defers to (docs/architecture/05-lifecycle.md §3.5).",
			strings.Join(reclaimed, ", "), orphanWindowMarker)
	}

	// Non-vacuity, proven in-run: the reclaim detector must find a reclaim in
	// code that has one. Without this, a detector that matched nothing would
	// report a clean failure path forever.
	probeFset := token.NewFileSet()
	probe, perr := parser.ParseFile(probeFset, "probe.go", "package p\nfunc f() { if err != nil { engine.Remove(ctx, ref) } }\n", parser.SkipObjectResolution)
	if perr != nil {
		t.Fatalf("parse the reclaim-detector probe: %v", perr)
	}
	if got := reclaimCallsIn(probeFset, probe); len(got) == 0 {
		t.Fatal("the reclaim detector found no reclaim in a probe that calls Remove; it would pass a real one too")
	}

	// The citations the note sends a reader to.
	note := string(src)
	for _, a := range orphanWindowAnchors {
		if !strings.Contains(note, a.cited) {
			t.Errorf("the %q note no longer cites %q; a reader who hits this window has nowhere to go for the decision behind it", orphanWindowMarker, a.cited)
			continue
		}
		b, rerr := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(a.path)))
		if rerr != nil {
			t.Errorf("the note cites %s and it cannot be read (%v); repair the citation or the file", a.cited, rerr)
			continue
		}
		if !strings.Contains(string(b), a.must) {
			t.Errorf("the note cites %s but %q is no longer there; the citation now points at nothing. Re-point the note at where the question moved to.", a.cited, a.must)
		}
	}
}
