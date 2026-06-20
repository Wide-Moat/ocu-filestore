// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"sort"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// allOps is the authoritative south-face Op constant set, enumerated the same
// way contract_parity_test.go enumerates the 18 operations. A new Op constant
// added to southface.go MUST be appended here; the contract-parity test pins
// this list against the frozen wire enum, so this list cannot silently drift
// from southface.go without that test failing first.
var allOps = []Op{
	OpListDirectory, OpMakeDirectory, OpMoveDirectory, OpRemoveDirectory,
	OpCreateFile, OpReadFile, OpReadMetadata, OpGetFileMetadata,
	OpListFiles, OpCopyFile, OpMoveFile, OpRemoveFile,
	OpFileUpload, OpFileDownload, OpImportFiles, OpImportZip,
	OpMigrateFilesystem, OpRemoveFilesystem,
}

// TestTelemetryKnownOpsMatchesSouthfaceOps is the drift guard for telemetry-12:
// the op-name label enum telemetry mirrors (telemetry.KnownOps) MUST be exactly
// the south-face Op constant set. telemetry is a leaf package that cannot import
// southface (that would cycle, since southface imports telemetry), so the mirror
// in metrics.go is hand-maintained — and a new Op forgotten there makes RecordOp
// panic at dispatch AFTER the handler ran (the client already saw 2xx) while
// ops_total silently drops the cell. This test lives in the package that imports
// BOTH and fails the build the moment the two sets diverge — element-wise and by
// count, in either direction (an Op in southface missing from telemetry, or a
// stale telemetry label with no Op).
func TestTelemetryKnownOpsMatchesSouthfaceOps(t *testing.T) {
	got := telemetry.KnownOps()

	want := make([]string, len(allOps))
	for i, op := range allOps {
		want[i] = string(op)
	}

	sort.Strings(got)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("op-label drift: telemetry.KnownOps() count = %d, southface Op set = %d\n got: %v\nwant: %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("op-label drift at index %d: telemetry has %q, southface Op set has %q\n got: %v\nwant: %v",
				i, got[i], want[i], got, want)
		}
	}
}
