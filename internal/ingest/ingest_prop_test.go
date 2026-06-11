// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"testing"
)

// TestPropNamespaceContainment asserts that no accepted archive ever
// yields an out-of-namespace staged name, and that every rejection aborts
// the sink (ARC-02, NFR-SEC-80). The body draws adversarial entry-name
// slices with rapid, builds the zip in-memory, runs ValidateZip against a
// recordingSink, and asserts every staged name is filepath.IsLocal and
// never ".". Non-vacuity: a reject counter increments in the err != nil
// branch and must be > 0 at the end of the run — a hand-built
// guaranteed-traversal sub-case keeps it from ever being vacuous.
func TestPropNamespaceContainment(t *testing.T) {
	t.Fatal("unimplemented: namespace-containment property (ARC-02)")
}

// TestPropCeilingAlwaysRejects asserts that every archive whose
// decompressed total exceeds the ceiling is rejected with ErrTotalExceeded
// and an aborted sink (ARC-01, NFR-SEC-80). Non-vacuity: the reject
// counter increments on every draw and must be > 0 at the end of the run.
func TestPropCeilingAlwaysRejects(t *testing.T) {
	t.Fatal("unimplemented: ceiling-always-rejects property (ARC-01)")
}
