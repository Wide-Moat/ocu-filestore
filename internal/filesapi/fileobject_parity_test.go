// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestFileObjectMatchesContract is the FileObject twin of
// TestCreateUploadParamsMatchesContract (task #86): it keeps the FileObject struct
// and the frozen files-api.openapi.yaml FileObject schema in lockstep, so neither
// can drift silently. FileObject.additionalProperties is false, so an EMITTED json
// field the schema does not declare (e.g. the D6 `sha256` addition) is a contract
// violation a conformance check rejects; and a schema property the struct never
// emits is a dead contract field. This guard reds on either drift.
func TestFileObjectMatchesContract(t *testing.T) {
	structFields := fileObjectJSONTags()
	contractProps := fileObjectContractProperties(t)

	if len(structFields) == 0 {
		t.Fatal("no json tags parsed from the FileObject struct; the guard is vacuous")
	}
	if len(contractProps) == 0 {
		t.Fatal("no properties parsed from the FileObject contract; the guard is vacuous")
	}

	// A struct field the contract does not declare would be REJECTED by a
	// FileObject conformance check (additionalProperties:false) -- exactly the
	// class the D6 `sha256` addition would have shipped without the schema bump.
	extraInStruct := setDifference(structFields, contractProps)
	if len(extraInStruct) > 0 {
		t.Errorf("FileObject emits json fields the contract does not declare %v; "+
			"the FileObject schema is additionalProperties:false, so a conforming client rejects an undeclared field. "+
			"Add the property to files-api.openapi.yaml FileObject.", extraInStruct)
	}
	// A contract property the struct never emits is a dead field the server can
	// never populate -- a contract-ahead drift.
	missingFromStruct := setDifference(contractProps, structFields)
	if len(missingFromStruct) > 0 {
		t.Errorf("FileObject is BEHIND the contract -- missing json fields for FileObject properties %v", missingFromStruct)
	}
}

// fileObjectJSONTags returns the json tag names on the EXPORTED FileObject struct
// (reflection, since it is exported -- no AST needed). It strips the ,omitempty
// suffix and skips a "-" or empty tag.
func fileObjectJSONTags() []string {
	var tags []string
	rt := reflect.TypeOf(FileObject{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		tags = append(tags, name)
	}
	sort.Strings(tags)
	return tags
}

// fileObjectContractProperties reads the frozen files-api.openapi.yaml and returns
// the property names declared under FileObject.properties, using the same minimal
// 2-space-indent parser TestCreateUploadParamsMatchesContract uses (indentOf and
// setDifference are shared from createparams_parity_test.go). It finds the
// `FileObject:` schema, then its `properties:` block, and collects the keys at the
// shallowest level under it, stopping when the block dedents.
func fileObjectContractProperties(t *testing.T) []string {
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
			if trimmed == "FileObject:" {
				inSchema = true
				schemaIndent = indent
			}
			continue
		}
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
		if indent <= propsIndent {
			break
		}
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
