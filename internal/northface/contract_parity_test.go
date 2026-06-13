// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package northface

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// artifactAPISchema models just the slice this test asserts against: the
// north-face OperationName enum. The vendored copy is byte-identical to the
// canonical contract (enforced by scripts/check-contract-identity.sh); this
// test is the in-repo drift alarm between the Go Op set and the pinned wire
// surface, mirroring the south-face contract-parity test.
type artifactAPISchema struct {
	Defs struct {
		OperationName struct {
			Enum []string `json:"enum"`
		} `json:"OperationName"`
	} `json:"$defs"`
}

func loadArtifactAPIContract(t *testing.T) artifactAPISchema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "storage", "file-artifact-api.schema.json"))
	if err != nil {
		t.Fatalf("read vendored artifact-api contract: %v", err)
	}
	var s artifactAPISchema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parse vendored artifact-api contract: %v", err)
	}
	return s
}

// TestOpEnumMatchesContract asserts the Go Op constants and the contract's
// OperationName enum are the same set: every contract name has an Op value
// and no Op value exists outside the contract. The Op constants are hand
// copied from the frozen enum, so this test is what ties them to it — adding
// an operation is a contract change in the architecture repo first.
func TestOpEnumMatchesContract(t *testing.T) {
	contract := loadArtifactAPIContract(t)

	goOps := []Op{
		OpUpload, OpListFiles, OpGetManifest, OpDownload,
		OpDownloadArchive, OpPreviewRender, OpDelete,
	}

	contractSet := make(map[string]bool, len(contract.Defs.OperationName.Enum))
	for _, name := range contract.Defs.OperationName.Enum {
		if contractSet[name] {
			t.Fatalf("contract enum carries duplicate %q: %v", name, contract.Defs.OperationName.Enum)
		}
		contractSet[name] = true
	}
	if len(contractSet) == 0 {
		t.Fatal("contract OperationName enum is empty; vendored copy is wrong")
	}

	goSet := make(map[string]bool, len(goOps))
	for _, op := range goOps {
		if goSet[string(op)] {
			t.Fatalf("duplicate Go Op value %q", op)
		}
		goSet[string(op)] = true
		if !contractSet[string(op)] {
			t.Errorf("Go Op %q is not in the contract OperationName enum", op)
		}
	}
	for name := range contractSet {
		if !goSet[name] {
			t.Errorf("contract operation %q has no Go Op constant", name)
		}
	}
}
