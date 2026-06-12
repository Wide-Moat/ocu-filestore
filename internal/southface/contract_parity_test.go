// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fileOpsSchema models just the contract slices this test asserts against:
// the operation-name enum, the deny vocabulary, and the intent axis. The
// vendored copy is byte-identical to the canonical contract (enforced by
// scripts/check-contract-identity.sh); this test is the in-repo drift alarm
// between the Go Op set and the pinned wire surface.
type fileOpsSchema struct {
	Defs struct {
		OperationName struct {
			Enum []string `json:"enum"`
		} `json:"OperationName"`
		DenyReason struct {
			Properties struct {
				XDenyReason struct {
					Enum []string `json:"enum"`
				} `json:"x_deny_reason"`
			} `json:"properties"`
		} `json:"DenyReason"`
		Intent struct {
			Enum []string `json:"enum"`
		} `json:"Intent"`
	} `json:"$defs"`
}

func loadContract(t *testing.T) fileOpsSchema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "storage", "file-ops.schema.json"))
	if err != nil {
		t.Fatalf("read vendored contract: %v", err)
	}
	var s fileOpsSchema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parse vendored contract: %v", err)
	}
	return s
}

// TestOpEnumMatchesContract asserts the Go Op constants and the contract's
// OperationName enum are the same set: every contract name has an Op value
// and no Op value exists outside the contract. Adding an operation is a
// contract change in the architecture repo first.
func TestOpEnumMatchesContract(t *testing.T) {
	contract := loadContract(t)

	goOps := []Op{
		OpListDirectory, OpMakeDirectory, OpMoveDirectory, OpRemoveDirectory,
		OpCreateFile, OpReadFile, OpReadMetadata, OpGetFileMetadata,
		OpListFiles, OpCopyFile, OpMoveFile, OpRemoveFile,
		OpFileUpload, OpFileDownload, OpImportFiles, OpImportZip,
		OpMigrateFilesystem, OpRemoveFilesystem,
	}

	contractSet := make(map[string]bool, len(contract.Defs.OperationName.Enum))
	for _, name := range contract.Defs.OperationName.Enum {
		contractSet[name] = true
	}
	if len(contractSet) != len(contract.Defs.OperationName.Enum) {
		t.Fatalf("contract enum carries duplicates: %v", contract.Defs.OperationName.Enum)
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

// TestDenyVocabularyPinned asserts the deny vocabulary this package will map
// sentinels onto matches the contract's x_deny_reason enum exactly. The
// vocabulary is an OCU default pending NFR-SEC-51 sign-off; if it moves, it
// moves in the architecture repo first and this test catches the drift.
func TestDenyVocabularyPinned(t *testing.T) {
	contract := loadContract(t)

	want := []string{
		"scope_mismatch",
		"intent_denied",
		"not_downloadable",
		"lease_expired",
		"size_exceeded",
		"not_found",
	}

	got := contract.Defs.DenyReason.Properties.XDenyReason.Enum
	if len(got) != len(want) {
		t.Fatalf("deny vocabulary size: got %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i, reason := range want {
		if got[i] != reason {
			t.Errorf("deny vocabulary[%d]: got %q, want %q", i, got[i], reason)
		}
	}
}

// TestIntentAxisPinned asserts the contract's intent enum matches the three
// storage intents the authz resolver is built on (NFR-SEC-49).
func TestIntentAxisPinned(t *testing.T) {
	contract := loadContract(t)

	want := []string{"read", "write", "preview"}
	got := contract.Defs.Intent.Enum
	if len(got) != len(want) {
		t.Fatalf("intent axis: got %v, want %v", got, want)
	}
	for i, intent := range want {
		if got[i] != intent {
			t.Errorf("intent axis[%d]: got %q, want %q", i, got[i], intent)
		}
	}
}
