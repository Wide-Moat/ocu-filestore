// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
)

// TestErrNotFoundCarriesNotFoundToken pins that ErrNotFound carries the
// denyclass.NotFound token in its message — the only resolution-failure the
// file_id path emits, and the token the audit record stamps.
func TestErrNotFoundCarriesNotFoundToken(t *testing.T) {
	if !strings.Contains(ErrNotFound.Error(), denyclass.NotFound) {
		t.Fatalf("ErrNotFound = %q, want it to carry the %q token", ErrNotFound.Error(), denyclass.NotFound)
	}
	if got := AuditReason(ErrNotFound); got != denyclass.NotFound {
		t.Fatalf("AuditReason(ErrNotFound) = %q, want %q", got, denyclass.NotFound)
	}
	// errors.Is must match through a wrapping (the disk store returns the
	// sentinel directly today, but callers may wrap it with context).
	wrapped := errors.Join(errors.New("read /files/x"), ErrNotFound)
	if !errors.Is(wrapped, ErrNotFound) {
		t.Fatal("errors.Is(wrapped, ErrNotFound) = false, want true")
	}
	if got := AuditReason(wrapped); got != denyclass.NotFound {
		t.Fatalf("AuditReason(wrapped ErrNotFound) = %q, want %q", got, denyclass.NotFound)
	}
}

// TestErrStoreUnavailableIsInternal pins the latched-store sentinel and its
// audit token: a store fault is a broker-internal state, not a client deny
// class.
func TestErrStoreUnavailableIsInternal(t *testing.T) {
	if got := AuditReason(ErrStoreUnavailable); got != denyclass.Internal {
		t.Fatalf("AuditReason(ErrStoreUnavailable) = %q, want %q", got, denyclass.Internal)
	}
}

// TestNoExportedErrorMapsToScopeMismatch is the SELF-EXPANDING structural
// guard: NONE of the package's exported error vars may carry the scope_mismatch
// token. scope_mismatch is reserved for the credscope axis; a file_id
// resolution failure that named it would leak that a probed handle exists in
// another scope.
//
// Rather than hand-enumerate the sentinel set (which a future exported Err*
// would silently slip past), this parses the package's own .go source with
// go/ast, discovers EVERY package-scope `var Err... = ...` declaration, then
// reflects the live value of each via the runtime error-var registry, and
// asserts none carries the scope_mismatch token (in its message OR via
// AuditReason). Adding a new exported Err* is automatically covered.
//
// NON-VACUOUS PROOF (the documented mutation): add to the package
//
//	var ErrCrossScopeDenied = fmt.Errorf("handlestore: cross-scope [%s]", denyclass.ScopeMismatch)
//
// The ast scan discovers ErrCrossScopeDenied, the registry resolves its value,
// and its message contains scope_mismatch -> this test goes RED. (The registry
// below must also gain the new name, which is the one intentional manual step;
// the discovery half is fully automatic, so a new Err* added WITHOUT a registry
// entry fails the completeness assertion loudly rather than passing silently.)
func TestNoExportedErrorMapsToScopeMismatch(t *testing.T) {
	// registry maps every exported package-scope error var NAME to its live
	// value. The ast scan asserts this registry is COMPLETE (every discovered
	// Err* var is present), so a newly-added exported error that is not wired
	// here fails the completeness check — it cannot slip past unexamined.
	registry := map[string]error{
		"ErrNotFound":         ErrNotFound,
		"ErrStoreUnavailable": ErrStoreUnavailable,
	}

	discovered := exportedErrorVarNames(t)
	if len(discovered) == 0 {
		t.Fatal("ast scan found no exported Err* vars; the guard would be vacuous")
	}

	for _, name := range discovered {
		val, ok := registry[name]
		if !ok {
			t.Fatalf("exported error var %q is declared in the package but missing from the test registry; "+
				"add it so the scope_mismatch guard examines it (self-expanding guard, followup-1)", name)
		}
		if strings.Contains(val.Error(), denyclass.ScopeMismatch) {
			t.Fatalf("%s = %q carries the reserved %q token; file_id failures must never name scope_mismatch", name, val.Error(), denyclass.ScopeMismatch)
		}
		if AuditReason(val) == denyclass.ScopeMismatch {
			t.Fatalf("AuditReason(%s) = scope_mismatch; reserved for the credscope axis", name)
		}
	}
}

// exportedErrorVarNames parses every non-test .go file in the package directory
// and returns the names of all package-scope `var Err... = ...` declarations
// (exported error sentinels). It is the discovery half of the self-expanding
// guard: a new exported Err* var lands in this list automatically.
func exportedErrorVarNames(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		// Skip _test.go files: the guard examines production sentinels only.
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package dir: %v", err)
	}
	var names []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, ident := range vs.Names {
						if strings.HasPrefix(ident.Name, "Err") && ident.IsExported() {
							names = append(names, ident.Name)
						}
					}
				}
			}
		}
	}
	return names
}

// TestAuditReasonUnknownIsEmpty pins the fall-through: a foreign error yields
// the empty string so the caller falls back to its own classification.
func TestAuditReasonUnknownIsEmpty(t *testing.T) {
	if got := AuditReason(errors.New("some other error")); got != "" {
		t.Fatalf("AuditReason(foreign) = %q, want empty", got)
	}
	if got := AuditReason(nil); got != "" {
		t.Fatalf("AuditReason(nil) = %q, want empty", got)
	}
}
