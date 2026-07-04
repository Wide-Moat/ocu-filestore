// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestCreateUploadParamsMatchesContract is the mechanical drift-guard for the
// create write plane: it asserts that createUploadParams implements EXACTLY the
// property set the frozen CreateFileParams schema declares — no more, no fewer.
//
// This closes the whole fake-green class that let a real defect ship: the struct
// strict-decodes with DisallowUnknownFields, so a contract field the struct OMITS
// 400s every conforming upload (the authorization_metadata bug), and a struct
// field the contract does NOT declare would silently accept a smuggled parameter.
// A hand-maintained "sends all 10 fields" fixture only proves the fields it
// happens to list; it does not red when the contract GROWS a field the fixture
// never mentions. This guard reds on drift in BOTH directions:
//   - a NEW contract property the struct has not caught up to (struct behind);
//   - a struct json field the contract does not declare (struct ahead).
//
// It reads the struct by AST (createUploadParams is unexported; reflection across
// a package boundary cannot reach it, and the same go/parser pass the northface
// retired-symbol guard uses reaches it here), and the contract by a minimal
// indentation parser over the frozen YAML (the module carries no YAML dependency;
// adding one for a single test violates the zero-extra-dependency shelf, and the
// contract is frozen so a tiny slice-parser is sufficient — the same "model only
// the contract slice under test" posture the southface parity test takes).
func TestCreateUploadParamsMatchesContract(t *testing.T) {
	structFields := createUploadParamsJSONTags(t)
	contractProps := createFileParamsContractProperties(t)

	if len(structFields) == 0 {
		t.Fatal("no json tags parsed from createUploadParams; the guard is vacuous")
	}
	if len(contractProps) == 0 {
		t.Fatal("no properties parsed from the CreateFileParams contract; the guard is vacuous")
	}

	missingFromStruct := setDifference(contractProps, structFields)
	if len(missingFromStruct) > 0 {
		t.Errorf("createUploadParams is BEHIND the contract — missing json fields for CreateFileParams properties %v; "+
			"DisallowUnknownFields will 400 a conforming client that sends them", missingFromStruct)
	}
	extraInStruct := setDifference(structFields, contractProps)
	if len(extraInStruct) > 0 {
		t.Errorf("createUploadParams is AHEAD of the contract — json fields %v are not declared by CreateFileParams "+
			"(additionalProperties:false); a struct field with no contract property lets a smuggled parameter through", extraInStruct)
	}
}

// createUploadParamsJSONTags parses internal/filesapi/create.go and returns the
// json tag names on the createUploadParams struct fields. An empty json tag, a
// "-" tag, or an embedded field is skipped (none apply to this struct, but the
// parser stays honest).
func createUploadParamsJSONTags(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", "create.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse create.go: %v", err)
	}

	var tags []string
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "createUploadParams" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		found = true
		for _, f := range st.Fields.List {
			if f.Tag == nil {
				continue
			}
			raw, err := strconv.Unquote(f.Tag.Value)
			if err != nil {
				t.Fatalf("unquote struct tag %q: %v", f.Tag.Value, err)
			}
			name := jsonTagName(raw)
			if name == "" || name == "-" {
				continue
			}
			tags = append(tags, name)
		}
		return false
	})
	if !found {
		t.Fatal("createUploadParams struct not found in create.go")
	}
	sort.Strings(tags)
	return tags
}

// jsonTagName extracts the field name from a struct tag's `json:"..."` value,
// dropping any ,omitempty / ,string options. Returns "" when there is no json
// tag.
func jsonTagName(structTag string) string {
	// reflect.StructTag.Get without importing reflect for one lookup: scan for
	// json:"...". The frozen struct uses simple `json:"name"` tags.
	tag := structTagLookup(structTag, "json")
	if tag == "" {
		return ""
	}
	if i := strings.IndexByte(tag, ','); i >= 0 {
		return tag[:i]
	}
	return tag
}

// structTagLookup returns the value for key in a raw struct tag string (the
// space-separated `key:"value"` form). It mirrors reflect.StructTag.Get's parse
// without pulling reflect in for a single field lookup.
func structTagLookup(tag, key string) string {
	for tag != "" {
		// Skip leading spaces.
		i := 0
		for i < len(tag) && tag[i] == ' ' {
			i++
		}
		tag = tag[i:]
		if tag == "" {
			break
		}
		// Scan to the colon that ends the key.
		i = 0
		for i < len(tag) && tag[i] != ':' && tag[i] != ' ' && tag[i] != '"' {
			i++
		}
		if i == 0 || i+1 >= len(tag) || tag[i] != ':' || tag[i+1] != '"' {
			break
		}
		name := tag[:i]
		tag = tag[i+1:]
		// Scan the quoted value.
		i = 1
		for i < len(tag) && tag[i] != '"' {
			if tag[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(tag) {
			break
		}
		qvalue := tag[:i+1]
		tag = tag[i+1:]
		if name == key {
			value, err := strconv.Unquote(qvalue)
			if err != nil {
				return ""
			}
			return value
		}
	}
	return ""
}

// createFileParamsContractProperties reads the frozen files-api.openapi.yaml and
// returns the property names declared under CreateFileParams.properties. It is a
// minimal indentation parser, not a general YAML loader: it finds the
// `CreateFileParams:` schema, then its `properties:` block, then collects the
// keys indented one level under it, stopping at the first line dedented to or
// below the properties key. The contract is frozen 2-space-indented YAML, so this
// is sufficient and pulls in no YAML dependency.
func createFileParamsContractProperties(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "openapi", "files-api.openapi.yaml"))
	if err != nil {
		t.Fatalf("read the files-api contract: %v", err)
	}
	lines := strings.Split(string(raw), "\n")

	schemaIndent, propsIndent, keyIndent := -1, -1, -1
	inSchema, inProps := false, false
	var props []string

	for _, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := indentOf(line)
		trimmed := strings.TrimSpace(line)

		if !inSchema {
			if trimmed == "CreateFileParams:" {
				inSchema = true
				schemaIndent = indent
			}
			continue
		}
		// Inside the schema: a line dedented to or past the schema key ends it.
		if indent <= schemaIndent {
			break
		}
		if !inProps {
			if trimmed == "properties:" {
				inProps = true
				propsIndent = indent
			}
			continue
		}
		// Inside properties: a line dedented to or past `properties:` ends it.
		if indent <= propsIndent {
			break
		}
		// The property keys are the shallowest lines under properties: fix that
		// level on the first key seen; deeper lines (a property's own fields, e.g.
		// type:/description:) are ignored.
		if keyIndent == -1 {
			keyIndent = indent
		}
		if indent != keyIndent {
			continue
		}
		if strings.HasSuffix(trimmed, ":") {
			props = append(props, strings.TrimSuffix(trimmed, ":"))
		}
	}
	sort.Strings(props)
	return props
}

// indentOf returns the count of leading spaces on a line.
func indentOf(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// setDifference returns the elements of a that are not in b (both sorted).
func setDifference(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}
	var diff []string
	for _, s := range a {
		if !inB[s] {
			diff = append(diff, s)
		}
	}
	return diff
}
