// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// TestEveryDenyClassIsAnAcceptedLabel drives RecordOp with EVERY value in the
// shared deny-class vocabulary (the single source of truth the south face
// emits) and asserts none panics and each increments ops_total with the
// correct deny_class. This is the regression for telemetry-01: the old
// hand-maintained mirror invented five labels the south face never emits and
// omitted nine it does, so RecordOp panicked (and the deny counter
// undercounted) on every omitted security-relevant denial.
func TestEveryDenyClassIsAnAcceptedLabel(t *testing.T) {
	classes := denyclass.DenyClasses()
	if len(classes) == 0 {
		t.Fatal("denyclass.DenyClasses() returned empty — vocabulary not initialized")
	}

	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	for _, class := range classes {
		class := class
		t.Run(class, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("RecordOp panicked on deny class %q (not an accepted label): %v", class, r)
				}
			}()
			// readFile is an arbitrary valid op; we are exercising the
			// deny_class axis here.
			m.RecordOp("readFile", "deny", class)
		})
	}

	// Every class must now appear in the exposition with a count of exactly 1.
	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	out := buf.String()
	for _, class := range classes {
		want := `deny_class="` + class + `",op="readFile",outcome="deny"} 1`
		if !strings.Contains(out, want) {
			t.Errorf("ops_total missing or wrong count for deny class %q\nwant line containing: %s\ngot:\n%s",
				class, want, out)
		}
	}
}

// TestAllowSentinelIsAnAcceptedLabel pins that the allow-outcome sentinel
// "none" is part of the derived label enum (denyclass.All() prepends it) and
// is accepted by RecordOp without panic.
func TestAllowSentinelIsAnAcceptedLabel(t *testing.T) {
	m := telemetry.NewBrokerMetrics("v0.0.0-test")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RecordOp panicked on the allow sentinel %q: %v", denyclass.None, r)
		}
	}()
	m.RecordOp("readFile", "allow", denyclass.None)

	all := denyclass.All()
	if len(all) != len(denyclass.DenyClasses())+1 {
		t.Fatalf("denyclass.All() = %d entries, want DenyClasses()+1 (the None sentinel)", len(all))
	}
	if all[0] != denyclass.None {
		t.Fatalf("denyclass.All()[0] = %q, want the None sentinel %q", all[0], denyclass.None)
	}
}
