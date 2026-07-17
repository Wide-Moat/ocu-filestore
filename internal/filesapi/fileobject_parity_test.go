// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fileObjectLedgeredAheadOfContract is the EXPLICIT exception set for response
// fields the struct deliberately carries ahead of the frozen contract, keyed by
// json name with the ruling that admits each. An ahead-of-contract field NOT in
// this ledger is drift and reds the guard; a ledgered field that LANDS in the
// contract also reds (the entry is stale and must be dropped), and a ledgered
// field missing from the struct reds too -- the ledger can never rot into a
// silent blanket.
var fileObjectLedgeredAheadOfContract = map[string]string{
	// ADR-0028 froze the six-field body and DEFERRED a checksum field; sha256
	// is that deferred field (D6, PARITY-LEDGER-147, canon ADR in flight),
	// additive and omitempty so a pre-digest record simply lacks it.
	"sha256": "D6, PARITY-LEDGER-147 (ADR-0028 deferred checksum; canon ADR in flight)",
}

// TestFileObjectMatchesContract is the read-plane mirror of the create-plane
// drift-guard: the FileObject struct (the shape create, metadata, and every
// list item serialize) must carry EXACTLY the property set the frozen contract
// FileObject schema declares -- no fewer (a missing field silently drops data
// a conforming client is promised) and no more (additionalProperties:false
// makes an undeclared emitted field a non-conforming response), except the
// explicitly ledgered deferred fields above. It reds on drift in BOTH
// directions and on a rotten ledger entry in either direction.
func TestFileObjectMatchesContract(t *testing.T) {
	structTags := jsonTagsOfStruct(t, reflect.TypeOf(FileObject{}))
	contractProps := contractSchemaProps(t, "FileObject:")

	if len(structTags) == 0 || len(contractProps) == 0 {
		t.Fatalf("vacuous guard: struct tags %d, contract props %d", len(structTags), len(contractProps))
	}

	if missing := setDifference(contractProps, keys(structTags)); len(missing) > 0 {
		t.Errorf("FileObject is BEHIND the contract -- missing json fields for properties %v", missing)
	}
	for _, extra := range setDifference(keys(structTags), contractProps) {
		if _, ok := fileObjectLedgeredAheadOfContract[extra]; !ok {
			t.Errorf("FileObject is AHEAD of the contract -- json field %q is not declared by the FileObject schema "+
				"(additionalProperties:false) and is not ledgered", extra)
		}
	}
	for name, ruling := range fileObjectLedgeredAheadOfContract {
		if _, inStruct := structTags[name]; !inStruct {
			t.Errorf("ledger entry %q (%s) names no FileObject json field -- stale entry, drop it", name, ruling)
		}
		for _, p := range contractProps {
			if p == name {
				t.Errorf("ledger entry %q (%s) is now declared by the contract -- the exception is stale, drop it", name, ruling)
			}
		}
	}

	// Every contract-REQUIRED property must serialize unconditionally: an
	// omitempty on a required field drops the property at its zero value
	// (size_bytes 0, filename "") and the response stops conforming.
	for _, req := range contractSchemaRequired(t, "FileObject:") {
		omitempty, ok := structTags[req]
		if !ok {
			continue // already reported as BEHIND above
		}
		if omitempty {
			t.Errorf("FileObject field %q is contract-required but tagged omitempty -- its zero value drops a required property", req)
		}
	}
}

// TestListResponseMatchesContract pins the list envelope against the frozen
// FileListEnvelope schema the same way, with NO ledgered exceptions.
func TestListResponseMatchesContract(t *testing.T) {
	structTags := jsonTagsOfStruct(t, reflect.TypeOf(ListResponse{}))
	contractProps := contractSchemaProps(t, "FileListEnvelope:")

	if len(structTags) == 0 || len(contractProps) == 0 {
		t.Fatalf("vacuous guard: struct tags %d, contract props %d", len(structTags), len(contractProps))
	}
	if missing := setDifference(contractProps, keys(structTags)); len(missing) > 0 {
		t.Errorf("ListResponse is BEHIND the contract -- missing json fields for properties %v", missing)
	}
	if extra := setDifference(keys(structTags), contractProps); len(extra) > 0 {
		t.Errorf("ListResponse is AHEAD of the contract -- json fields %v are not declared by FileListEnvelope "+
			"(additionalProperties:false)", extra)
	}
	for _, req := range contractSchemaRequired(t, "FileListEnvelope:") {
		if omitempty, ok := structTags[req]; ok && omitempty {
			t.Errorf("ListResponse field %q is contract-required but tagged omitempty", req)
		}
	}
}

// jsonTagsOfStruct returns the json field names of typ mapped to whether the
// tag carries omitempty. An empty tag, "-", or an embedded field is skipped.
func jsonTagsOfStruct(t *testing.T, typ reflect.Type) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" {
			continue
		}
		omitempty := false
		for _, p := range parts[1:] {
			if p == "omitempty" {
				omitempty = true
			}
		}
		out[name] = omitempty
	}
	return out
}

// keys returns the map's keys as a slice (order irrelevant; consumers sort or
// set-difference).
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// contractSchemaProps returns the property names of the named schema in the
// frozen files-api contract, via the same minimal indentation walk the
// create-plane guard uses (the module carries no YAML dependency; the contract
// is frozen, so a slice-parser over the schema under test is sufficient).
func contractSchemaProps(t *testing.T, schemaKey string) []string {
	t.Helper()
	lines := contractLines(t)

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
			if trimmed == schemaKey {
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
		if indent == keyIndent && strings.HasSuffix(trimmed, ":") {
			props = append(props, strings.TrimSuffix(trimmed, ":"))
		}
	}
	return props
}

// contractSchemaRequired returns the named schema's `required: [...]` list.
func contractSchemaRequired(t *testing.T, schemaKey string) []string {
	t.Helper()
	lines := contractLines(t)

	schemaIndent := -1
	inSchema := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := indentOf(line)
		trimmed := strings.TrimSpace(line)
		if !inSchema {
			if trimmed == schemaKey {
				inSchema = true
				schemaIndent = indent
			}
			continue
		}
		if indent <= schemaIndent {
			break
		}
		if strings.HasPrefix(trimmed, "required:") {
			inner := strings.TrimSpace(strings.TrimPrefix(trimmed, "required:"))
			inner = strings.TrimPrefix(inner, "[")
			inner = strings.TrimSuffix(inner, "]")
			var out []string
			for _, part := range strings.Split(inner, ",") {
				if p := strings.TrimSpace(part); p != "" {
					out = append(out, p)
				}
			}
			return out
		}
	}
	t.Fatalf("no required: list found for schema %s", schemaKey)
	return nil
}

// contractLines reads the frozen vendored contract once per call.
func contractLines(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "openapi", "files-api.openapi.yaml"))
	if err != nil {
		t.Fatalf("read the files-api contract: %v", err)
	}
	return strings.Split(string(raw), "\n")
}
