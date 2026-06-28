// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package northface

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The SUPERSEDED 7-op PoC Op enum and ErrEmbedTokenInvalid were dropped
// (ADR-0023 recut the surface to the five Files-API endpoints on component-08
// plus the file_id handle-store here; embed-token verification is
// component-08's, NFR-SEC-82). This file pins the SURVIVING northface symbols
// and guards against a re-introduction of the retired ones.

// TestSurvivingSymbols asserts the package still exports the two symbols Mount B
// and the daemon depend on: the Server listener seam and the ErrNotImplemented
// scaffold sentinel. A compile reference is the strongest possible assertion —
// if either were removed this test would not build.
func TestSurvivingSymbols(t *testing.T) {
	var _ Server // the listener seam survives (Mount B implements it)

	if ErrNotImplemented == nil {
		t.Fatal("ErrNotImplemented sentinel was removed")
	}
	if !errors.Is(ErrNotImplemented, ErrNotImplemented) {
		t.Fatal("ErrNotImplemented does not match itself under errors.Is")
	}
}

// TestRetiredSymbolsStayRetired parses the package source and asserts the
// retired identifiers (the 7-op Op enum constants, the Op type, and
// ErrEmbedTokenInvalid) are NOT re-introduced as top-level declarations. It is
// the drift alarm that keeps the dead PoC scaffold from creeping back: deadcode
// would only flag an UNREACHABLE export, but a re-introduced symbol referenced
// by a stray test would slip past it — this source-level scan does not.
func TestRetiredSymbolsStayRetired(t *testing.T) {
	retired := map[string]bool{
		"Op":                   true,
		"OpUpload":             true,
		"OpListFiles":          true,
		"OpGetManifest":        true,
		"OpDownload":           true,
		"OpDownloadArchive":    true,
		"OpPreviewRender":      true,
		"OpDelete":             true,
		"ErrEmbedTokenInvalid": true,
	}

	// Scan every production .go file in the package directory (test files
	// excluded — the scan targets production declarations only). parser.ParseFile
	// is the non-deprecated per-file API; ParseDir is deprecated.
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package files: %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, fileName := range goFiles {
		if strings.HasSuffix(fileName, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, fileName, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", fileName, perr)
		}
		scanned++
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if retired[s.Name.Name] {
							t.Errorf("%s re-introduces retired type %q", fileName, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if retired[n.Name] {
								t.Errorf("%s re-introduces retired identifier %q", fileName, n.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && retired[d.Name.Name] {
					t.Errorf("%s re-introduces retired function %q", fileName, d.Name.Name)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no production .go files scanned; the retired-symbol guard is vacuous")
	}
}
