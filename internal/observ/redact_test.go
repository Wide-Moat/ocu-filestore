// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package observ

import (
	"bytes"
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

// TestPathAttr verifies the debug-gating behaviour of PathAttr:
// - at INFO the attribute value is "[path-elided]", not the real path
// - at DEBUG the real path is present
func TestPathAttr(t *testing.T) {
	const key = "file_path"
	const path = "/workspace/secret/project/file.txt"

	// INFO level: path must be elided.
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelInfo)
	l.Info("op", PathAttr(slog.LevelInfo, key, path))

	var obj map[string]any
	if err := json.Unmarshal(buf.Bytes(), &obj); err != nil {
		t.Fatalf("INFO log not valid JSON: %v\n%s", err, buf.String())
	}
	if obj[key] == path {
		t.Errorf("INFO log contains real path %q; PathAttr must elide at INFO", path)
	}
	if obj[key] != "[path-elided]" {
		t.Errorf("INFO log attr %q = %v, want %q", key, obj[key], "[path-elided]")
	}

	// DEBUG level: real path must be present.
	buf.Reset()
	l2 := NewLogger(&buf, slog.LevelDebug)
	l2.Debug("op", PathAttr(slog.LevelDebug, key, path))

	var obj2 map[string]any
	if err := json.Unmarshal(buf.Bytes(), &obj2); err != nil {
		t.Fatalf("DEBUG log not valid JSON: %v\n%s", err, buf.String())
	}
	if obj2[key] != path {
		t.Errorf("DEBUG log attr %q = %v, want %q", key, obj2[key], path)
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
