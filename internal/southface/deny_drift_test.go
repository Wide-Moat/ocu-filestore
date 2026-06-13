// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"sort"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// TestDenyTableMatchesSharedVocabulary is the drift guard for telemetry-01:
// the deny classes the south face can actually emit (the denyTable keys) MUST
// be exactly the shared denyclass vocabulary that telemetry derives its
// ops_total{deny_class} label enum from. If the south face gains a deny class
// that is not in the shared source — or the shared source lists one the south
// face never tables — this fails, forcing the single-source edit instead of a
// silent counter undercount.
func TestDenyTableMatchesSharedVocabulary(t *testing.T) {
	got := make([]string, 0, len(denyTable))
	for k := range denyTable {
		got = append(got, k)
	}
	want := denyclass.DenyClasses()

	sort.Strings(got)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("denyTable key count = %d, shared denyclass.DenyClasses() = %d\n got: %v\nwant: %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("deny vocabulary drift at index %d: denyTable has %q, shared source has %q\n got: %v\nwant: %v",
				i, got[i], want[i], got, want)
		}
	}
}

// TestEverySouthfaceDenyClassIsAcceptedByMetrics drives the real broker metric
// set with every deny class the south face can emit, asserting none panics —
// the end-to-end proof that the deny counter can no longer undercount, now
// that the recover() crutch in dispatch.go is gone. A future deny class added
// without updating the shared source would make this panic loudly (telemetry-02).
func TestEverySouthfaceDenyClassIsAcceptedByMetrics(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")
	for k := range denyTable {
		k := k
		t.Run(k, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("metrics RecordOp panicked on south-face deny class %q: %v", k, r)
				}
			}()
			m.RecordOp("readFile", "deny", k)
		})
	}
}
