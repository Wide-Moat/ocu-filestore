// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestListQueryParamsAreDeclaredInTheContract binds the query parameters the
// list handler READS to the parameters the frozen contract DECLARES.
//
// This guards a drift class no schema diff can see. `oasdiff` compares schema
// documents, and a handler that starts reading a new query parameter never
// touches the schema — so the gate that exists to catch contract drift is
// structurally blind to exactly this. It happened: `?order=` shipped on the
// north list on 2026-07-19 with no contract row, and eighteen days later
// ADR-0036 read the contract, found no order parameter, and ratified the
// sentence "the dialect carries no order parameter on either face". ADR-0037
// corrected that; this test is what stops the next one.
//
// It reads the handler's own param constants rather than a hand-copied list, so
// a renamed constant cannot leave the test asserting a name nothing serves.
func TestListQueryParamsAreDeclaredInTheContract(t *testing.T) {
	// The parameters the list handler actually consults. Sourced from the
	// constants the handler uses, not from a literal.
	read := map[string]string{
		"limit": listLimitParam,
		"after": listAfterParam,
		"order": listOrderParam,
	}

	declared := declaredQueryParamNames(t)
	for label, name := range read {
		if !declared[name] {
			t.Errorf("the list handler reads query parameter %q (%s) but the frozen "+
				"contract declares no such parameter: a wire-visible knob is "+
				"undocumented, and no schema diff will catch it", name, label)
		}
	}
}

// declaredQueryParamNames collects every `name:` under a `in: query` parameter
// in the vendored contract. It scans line-wise, matching the storage parity
// tests: a YAML library on this path would be a dependency bought for one
// assertion, and the shape being read is two adjacent flat keys.
func declaredQueryParamNames(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "openapi", "files-api.openapi.yaml"))
	if err != nil {
		t.Fatalf("read the files-api contract: %v", err)
	}
	lines := strings.Split(string(raw), "\n")

	nameRe := regexp.MustCompile(`^\s+name:\s*(\S+)\s*$`)
	out := map[string]bool{}
	for i, ln := range lines {
		m := nameRe.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		// A parameter block is `name:` followed closely by `in:`; look ahead a
		// couple of lines rather than parsing the whole document.
		for _, next := range lines[i+1 : min(i+4, len(lines))] {
			if strings.TrimSpace(next) == "in: query" {
				out[strings.Trim(m[1], `"'`)] = true
				break
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no query parameters found in the contract: the scan is wrong, so " +
			"this test would pass against any handler")
	}
	return out
}
