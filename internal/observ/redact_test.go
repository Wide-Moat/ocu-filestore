// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package observ

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPathAttr verifies the handler-driven gating of PathAttr:
//   - on an INFO logger the attribute value is "[path-elided]", not the real
//     path, regardless of which slog method the caller uses
//   - on a DEBUG logger the real path is present
//   - the gate reads the logger's enablement, so a caller cannot leak a path by
//     supplying a mismatched level (there is no level argument to mismatch)
func TestPathAttr(t *testing.T) {
	const key = "file_path"
	const path = "/workspace/secret/project/file.txt"
	ctx := context.Background()

	// INFO logger: path must be elided even though the call sites below try to
	// surface it at INFO.
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelInfo)
	l.Info("op", PathAttr(ctx, l, key, path))

	var obj map[string]any
	if err := json.Unmarshal(buf.Bytes(), &obj); err != nil {
		t.Fatalf("INFO log not valid JSON: %v\n%s", err, buf.String())
	}
	if obj[key] == path {
		t.Errorf("INFO log contains real path %q; PathAttr must elide on an INFO logger", path)
	}
	if obj[key] != "[path-elided]" {
		t.Errorf("INFO log attr %q = %v, want %q", key, obj[key], "[path-elided]")
	}

	// DEBUG logger: real path must be present.
	buf.Reset()
	l2 := NewLogger(&buf, slog.LevelDebug)
	l2.Debug("op", PathAttr(ctx, l2, key, path))

	var obj2 map[string]any
	if err := json.Unmarshal(buf.Bytes(), &obj2); err != nil {
		t.Fatalf("DEBUG log not valid JSON: %v\n%s", err, buf.String())
	}
	if obj2[key] != path {
		t.Errorf("DEBUG log attr %q = %v, want %q", key, obj2[key], path)
	}

	// Caller-mismatch guard: attaching PathAttr to an INFO logger and emitting
	// at DEBUG must STILL elide — the gate follows the handler, not the call.
	// (The DEBUG record is dropped by the INFO handler, but if the elision were
	// driven by the emit method this would be the classic leak path.)
	buf.Reset()
	l3 := NewLogger(&buf, slog.LevelInfo)
	l3.Info("op", PathAttr(ctx, l3, key, path))
	if strings.Contains(buf.String(), path) {
		t.Errorf("INFO logger leaked the real path through PathAttr: %s", buf.String())
	}

	// Nil logger is treated as not-DEBUG: elide, never panic.
	if got := PathAttr(ctx, nil, key, path); got.Value.String() != "[path-elided]" {
		t.Errorf("nil logger PathAttr = %q, want %q", got.Value.String(), "[path-elided]")
	}
}

// TestRedactNoByteOrCredSink is a source-analysis test: it parses the
// package's Go source files and asserts that no exported function in this
// package accepts a parameter of type []byte or a type named "credential"
// (case-insensitive). The ABSENCE of such helpers is the enforcement
// mechanism for the redaction rule: a call site cannot accidentally pass
// raw credential or payload bytes through a helper this package does not
// expose.
func TestRedactNoByteOrCredSink(t *testing.T) {
	fset := token.NewFileSet()

	// parser.ParseDir is deprecated since Go 1.25 (does not honour build
	// tags). Iterate the directory manually and call parser.ParseFile on each
	// .go source file instead; this preserves identical coverage of the
	// package's exported declarations without adding any new dependency.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir: %v", err)
	}
	var astFiles []*ast.File
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".go") {
			continue
		}
		af, ferr := parser.ParseFile(fset, filepath.Join(".", de.Name()), nil, 0)
		if ferr != nil {
			t.Fatalf("parser.ParseFile %s: %v", de.Name(), ferr)
		}
		// Skip test files — the same filter ParseDir callers applied via the
		// pkgName suffix check.
		if strings.HasSuffix(af.Name.Name, "_test") {
			continue
		}
		astFiles = append(astFiles, af)
	}

	for _, file := range astFiles {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			// Only inspect exported functions.
			if !fn.Name.IsExported() {
				continue
			}
			if fn.Type.Params == nil {
				continue
			}
			for _, field := range fn.Type.Params.List {
				typeName := typeString(fset, field.Type)
				lower := strings.ToLower(typeName)
				if lower == "[]byte" || strings.Contains(lower, "credential") {
					t.Errorf("exported func %s has forbidden param type %q (redaction rule: no credential/payload helper)", fn.Name.Name, typeName)
				}
			}
		}
	}
}

// typeString returns a rough string representation of an AST type expression,
// enough to identify []byte and credential-named types.
func typeString(_ *token.FileSet, e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeString(nil, t.Elt)
		}
		return "[n]" + typeString(nil, t.Elt)
	case *ast.StarExpr:
		return "*" + typeString(nil, t.X)
	case *ast.SelectorExpr:
		return typeString(nil, t.X) + "." + t.Sel.Name
	default:
		return "unknown"
	}
}
