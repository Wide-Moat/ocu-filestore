// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// fileObjectLedgeredAheadOfContract is the EXPLICIT exception set: response
// fields the FileObject struct deliberately emits ahead of the frozen contract,
// keyed by json name, valued by the ruling that admits each one. It is a named
// exception list, NOT a blanket allow-extra -- an ahead-of-contract field that is
// not listed here reds the guard.
//
// The ledger cannot rot into a silent lie, because it is asserted in both
// directions: an entry naming no struct field reds (stale entry), and an entry
// the contract has since declared reds too (the exception is no longer needed).
// Emptying the map reds as well, since the AHEAD arm then has nothing to admit
// the field with.
var fileObjectLedgeredAheadOfContract = map[string]string{
	// PARITY-LEDGER-147. Canon froze the read FileObject at six fields
	// {id, type, filename, mime_type, size_bytes, created_at} and deferred a
	// content checksum for v1 (ADR-0028:42), ruling that "a manifest or dedup
	// consumer re-opens it under ADR-0023 Open Question 5" (ADR-0028:56).
	// ADR-0023 Open Question 5 names the content-hash manifest for dedup sync;
	// the D6 dedup consumer built here IS that named re-open trigger, and it
	// standardises on sha256 because the engine already computes that digest in
	// its single write pass. It is additive and omitempty, so a pre-digest
	// record simply lacks it (canon ADR in flight).
	//
	// This is a CARRIED VIOLATION, not a blessed extension: the contract at the
	// CI-pinned canon SHA declares no checksum property, and FileObject is
	// additionalProperties:false, so a strict client is entitled to reject the
	// emitted field. We carry it knowingly until canon re-opens the checksum,
	// rather than editing a frozen upstream artifact to match our code.
	"sha256": "PARITY-LEDGER-147: D6 dedup consumer, the ADR-0028:56 re-open trigger for the checksum deferred at ADR-0028:42 (ADR-0023 Open Question 5); carried ahead of the frozen contract, additive and omitempty, canon ADR in flight",
}

// TestFileObjectMatchesContract is the read-plane drift-guard: the FileObject
// struct -- the shape create, metadata, and every list item serialize -- must
// carry EXACTLY the property set the frozen contract's FileObject schema
// declares, except for the explicitly ledgered fields above. Both directions
// are drift: a contract property with no struct field silently drops data a
// conforming client is promised, and an emitted field the schema does not
// declare is a non-conforming response under additionalProperties:false.
//
// The guard's oracle is the VENDORED contract copy, which is a file this repo
// can edit -- so this guard alone cannot stop someone making it green by editing
// the schema instead of the struct. What closes that loop is the separate
// byte-identity gate (scripts/check-contract-identity.sh, CI job `checks`, canon
// checked out at the workflow-pinned SHA). This guard's job is to make the
// divergence NAMED and self-shrinking; the byte-identity gate's job is to keep
// the oracle honest. Neither substitutes for the other.
//
// Both canon futures force a decision here rather than going silently green: if
// canon lands `sha256`, the stale-ledger arm reds; if canon lands `checksum_md5`
// instead, the BEHIND arm reds on the property the struct does not emit.
func TestFileObjectMatchesContract(t *testing.T) {
	structTags := jsonTagsOfStruct(t, reflect.TypeOf(FileObject{}))
	contractProps := contractSchemaProps(t, "FileObject:")

	if len(structTags) == 0 {
		t.Fatal("no json tags parsed from the FileObject struct; the guard is vacuous")
	}
	if len(contractProps) == 0 {
		t.Fatal("no properties parsed from the FileObject contract schema; the guard is vacuous")
	}

	// Always show what is being carried, so a passing run still reports the
	// divergence instead of hiding it.
	for _, name := range slices.Sorted(maps.Keys(fileObjectLedgeredAheadOfContract)) {
		t.Logf("ledgered ahead of the frozen contract: %q -- %s", name, fileObjectLedgeredAheadOfContract[name])
	}

	// BEHIND: a contract property the struct never emits is a field the server
	// promises and never populates.
	structNames := slices.Sorted(maps.Keys(structTags))
	if missing := setDifference(contractProps, structNames); len(missing) > 0 {
		t.Errorf("FileObject is BEHIND the contract -- missing json fields for FileObject properties %v", missing)
	}

	// AHEAD: an emitted field the schema does not declare, admitted only by an
	// explicit ledger entry.
	for _, extra := range setDifference(structNames, contractProps) {
		if _, ledgered := fileObjectLedgeredAheadOfContract[extra]; !ledgered {
			t.Errorf("FileObject is AHEAD of the contract -- json field %q is not declared by the FileObject schema "+
				"(additionalProperties:false, so a conforming client rejects it) and is not ledgered in "+
				"fileObjectLedgeredAheadOfContract; either drop the field or record the ruling that admits it", extra)
		}
	}

	// The ledger shrinks itself: neither half of an entry may go stale.
	for _, name := range slices.Sorted(maps.Keys(fileObjectLedgeredAheadOfContract)) {
		ruling := fileObjectLedgeredAheadOfContract[name]
		if _, inStruct := structTags[name]; !inStruct {
			t.Errorf("ledger entry %q (%s) names no FileObject json field -- stale entry, drop it", name, ruling)
		}
		if slices.Contains(contractProps, name) {
			t.Errorf("ledger entry %q (%s) is now declared by the contract -- the exception is stale, drop it", name, ruling)
		}
	}

	// A contract-REQUIRED property must serialize unconditionally: omitempty on
	// a required field drops the property at its zero value (size_bytes 0,
	// filename "") and the response stops conforming.
	for _, req := range contractSchemaRequired(t, "FileObject:") {
		omitempty, ok := structTags[req]
		if !ok {
			continue // already reported by the BEHIND arm
		}
		if omitempty {
			t.Errorf("FileObject field %q is contract-required but tagged omitempty -- its zero value drops a required property", req)
		}
	}
}

// TestListResponseMatchesContract pins the list envelope against the frozen
// FileListEnvelope schema, with NO ledgered exceptions: unlike FileObject, this
// shape carries nothing ahead of canon, so any divergence in either direction
// is drift. A missing field drops a page attribute a paginating client relies
// on (next_cursor above all -- without it the walk cannot resume), and an
// undeclared emitted field is non-conforming under additionalProperties:false.
//
// data and has_more are contract-required, so neither may be tagged omitempty:
// an empty final page (data []) and a last page (has_more false) are exactly
// the cases where the zero value would drop the property, which is when a
// client most needs to read it.
func TestListResponseMatchesContract(t *testing.T) {
	structTags := jsonTagsOfStruct(t, reflect.TypeOf(ListResponse{}))
	contractProps := contractSchemaProps(t, "FileListEnvelope:")

	if len(structTags) == 0 {
		t.Fatal("no json tags parsed from the ListResponse struct; the guard is vacuous")
	}
	if len(contractProps) == 0 {
		t.Fatal("no properties parsed from the FileListEnvelope contract schema; the guard is vacuous")
	}

	structNames := slices.Sorted(maps.Keys(structTags))
	if missing := setDifference(contractProps, structNames); len(missing) > 0 {
		t.Errorf("ListResponse is BEHIND the contract -- missing json fields for FileListEnvelope properties %v", missing)
	}
	if extra := setDifference(structNames, contractProps); len(extra) > 0 {
		t.Errorf("ListResponse is AHEAD of the contract -- json fields %v are not declared by FileListEnvelope "+
			"(additionalProperties:false, so a conforming client rejects them)", extra)
	}

	for _, req := range contractSchemaRequired(t, "FileListEnvelope:") {
		omitempty, ok := structTags[req]
		if !ok {
			continue // already reported by the BEHIND arm
		}
		if omitempty {
			t.Errorf("ListResponse field %q is contract-required but tagged omitempty -- its zero value "+
				"(an empty page, a final page) drops a required property", req)
		}
	}
}

// jsonTagsOfStruct returns the json field names typ serializes, mapped to
// whether the tag carries omitempty. An empty tag, a "-" tag, and an embedded
// field are skipped.
func jsonTagsOfStruct(t *testing.T, typ reflect.Type) map[string]bool {
	t.Helper()
	out := make(map[string]bool, typ.NumField())
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
		out[name] = slices.Contains(parts[1:], "omitempty")
	}
	return out
}

// contractSchemaProps returns the property names the named schema declares in
// the frozen files-api contract, via the same minimal indentation walk the
// create-plane guard uses (the module carries no YAML dependency; the contract
// is frozen 2-space-indented YAML, so a slice-parser over the schema under test
// is sufficient). indentOf is shared from createparams_parity_test.go.
func contractSchemaProps(t *testing.T, schemaKey string) []string {
	t.Helper()

	schemaIndent, propsIndent, keyIndent := -1, -1, -1
	inSchema, inProps := false, false
	var props []string

	for _, line := range contractLines(t) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := indentOf(line)

		if !inSchema {
			if trimmed == schemaKey {
				inSchema = true
				schemaIndent = indent
			}
			continue
		}
		// A line dedented to or past the schema key ends the schema.
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
		// A line dedented to or past `properties:` ends the block.
		if indent <= propsIndent {
			break
		}
		// The property keys are the shallowest lines under properties: fix that
		// level on the first key seen; deeper lines (a property's own type:/
		// description:) are ignored.
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
	slices.Sort(props)
	return props
}

// contractSchemaRequired returns the named schema's inline `required: [...]`
// list. A schema with no required list is a parse failure, not an empty set --
// the frozen schemas this guard reads all declare one, so a silent empty return
// would make the required/omitempty arm vacuous.
func contractSchemaRequired(t *testing.T, schemaKey string) []string {
	t.Helper()

	schemaIndent := -1
	inSchema := false

	for _, line := range contractLines(t) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := indentOf(line)

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
		if !strings.HasPrefix(trimmed, "required:") {
			continue
		}
		inner := strings.TrimSpace(strings.TrimPrefix(trimmed, "required:"))
		inner = strings.TrimSuffix(strings.TrimPrefix(inner, "["), "]")
		var required []string
		for _, part := range strings.Split(inner, ",") {
			if p := strings.TrimSpace(part); p != "" {
				required = append(required, p)
			}
		}
		if len(required) == 0 {
			t.Fatalf("schema %s declares an empty required list; the required/omitempty arm would be vacuous", schemaKey)
		}
		return required
	}
	t.Fatalf("no required: list found for schema %s in the files-api contract", schemaKey)
	return nil
}

// contractLines reads the vendored frozen files-api contract and splits it into
// lines. This copy is the guard's oracle AND an editable file in this tree; the
// CI byte-identity job is what pins it to canon (see the doc comment above).
func contractLines(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "openapi", "files-api.openapi.yaml"))
	if err != nil {
		t.Fatalf("read the files-api contract: %v", err)
	}
	return strings.Split(string(raw), "\n")
}
