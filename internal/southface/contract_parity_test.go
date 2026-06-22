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
			Type                 string   `json:"type"`
			AdditionalProperties bool     `json:"additionalProperties"`
			Required             []string `json:"required"`
			Properties           struct {
				ReasonCode struct {
					Type    string `json:"type"`
					Pattern string `json:"pattern"`
				} `json:"reason_code"`
				Message struct {
					Type      string `json:"type"`
					MaxLength int    `json:"maxLength"`
				} `json:"message"`
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
		// Frozen enum names whose bodies are x-ocu-tbd and which have no
		// handler yet: they exist as Op constants so the set covers the WHOLE
		// frozen OperationName enum, not only the routable subset (knownOps).
		OpFileDelete, OpReadFileMetadata, OpReleaseQuarantinedFiles,
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

// TestDenyVocabularyPinned pins the FROZEN parts of the contract's DenyReason
// (the storage-surface BoundedReason): the reason_code field is required, its
// code pattern is frozen, and the {reason_code, message} envelope shape is
// frozen. It deliberately does NOT pin a fixed N-member code list: the contract
// marks the reason_code vocabulary as an OCU-default ADDITIVE set (an engine may
// add a code), so what is invariant is the PATTERN and the ENVELOPE, not the
// enumeration. If either the pattern or the envelope shape moves, it moves in
// the architecture repo first and this test catches the drift.
func TestDenyVocabularyPinned(t *testing.T) {
	contract := loadContract(t)
	dr := contract.Defs.DenyReason

	// (1) reason_code is REQUIRED on the BoundedReason/DenyReason object.
	requiredReasonCode := false
	for _, r := range dr.Required {
		if r == "reason_code" {
			requiredReasonCode = true
		}
	}
	if !requiredReasonCode {
		t.Errorf("DenyReason.required = %v, want it to include %q", dr.Required, "reason_code")
	}

	// (2) the reason_code pattern is exactly the frozen code shape — an
	// uppercase-anchored token. The vocabulary is additive; this pattern is not.
	const frozenPattern = `^[A-Z][A-Z0-9_]{1,63}$`
	if got := dr.Properties.ReasonCode.Pattern; got != frozenPattern {
		t.Errorf("reason_code pattern = %q, want frozen %q", got, frozenPattern)
	}
	if got := dr.Properties.ReasonCode.Type; got != "string" {
		t.Errorf("reason_code type = %q, want %q", got, "string")
	}

	// (3) the BoundedReason envelope shape is frozen: an object that admits no
	// extra properties, carrying a string reason_code and a bounded string
	// message (maxLength 256 — the shared exec/control BoundedReason bound).
	if dr.Type != "object" {
		t.Errorf("DenyReason type = %q, want %q", dr.Type, "object")
	}
	if dr.AdditionalProperties {
		t.Errorf("DenyReason additionalProperties = true, want false (envelope is closed)")
	}
	if got := dr.Properties.Message.Type; got != "string" {
		t.Errorf("message type = %q, want %q", got, "string")
	}
	if got := dr.Properties.Message.MaxLength; got != 256 {
		t.Errorf("message maxLength = %d, want frozen 256", got)
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
