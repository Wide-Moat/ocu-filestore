// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
)

// closedWireCodes is the closed set of Connect wire codes the deny mapper may
// legitimately emit. A code outside this set is a typo or an unwired class and
// would fall through statusForWireCode's default arm to 500.
var closedWireCodes = map[string]bool{
	wireCodeInvalidArgument:   true,
	wireCodeUnauthenticated:   true,
	wireCodePermissionDenied:  true,
	wireCodeNotFound:          true,
	wireCodeAlreadyExists:     true,
	wireCodeAborted:           true,
	wireCodeResourceExhausted: true,
	wireCodeUnimplemented:     true,
	wireCodeUnavailable:       true,
	// wireCodeInternal is deliberately EXCLUDED: it is the fail-closed
	// fallback, never a sane verdict for a real vocabulary class.
}

// TestDenyMappingTotalityOverVocabulary closes the gap that the three existing
// deny guards leave open. TestDenyMapperTable is a HAND-MAINTAINED table — it
// omits denyDirNotEmpty (directory_not_empty), which is never passed through
// mapDeny anywhere. TestDenyTableMatchesSharedVocabulary checks only denyTable
// KEY-SET equality with the shared vocabulary; it never asserts that each class
// maps to a sane wire verdict. TestEverySouthfaceDenyClassIsAcceptedByMetrics
// checks only that the metrics counter does not panic. None of the three would
// catch a class wired to a typo wire-code (falling through statusForWireCode's
// default to 500) or a class present in the vocabulary but absent from
// denyTable — either would silently degrade a real refusal to internal/500 on
// the wire while all three stay green.
//
// This asserts, for EVERY class in the shared closed vocabulary, that mapDeny
// returns a wire code whose status agrees with statusForWireCode and that no
// class OTHER THAN the dedicated denyInternal class degrades to the
// internal/500 fail-closed fallback. denyInternal ("internal") is itself a
// vocabulary member — it is the fail-closed class by definition and legitimately
// maps to internal/500; it is the single allowed exception. Every other class
// must map to a defined NON-internal wire code with a status that is NOT 500 and
// is NOT the default arm of statusForWireCode. A class wired to a typo code, or
// a vocabulary class missing from denyTable, would land on internal/500 and
// fail here — exactly the silent degrade the three existing guards miss.
//
// The vocabulary is closed and small, so this is enumerative-total rather than
// randomized. Non-vacuity is the count-equals-vocabulary assertion: the loop
// body must run exactly len(DenyClasses()) times and at least once, drawing the
// classes from the SHARED source (denyclass.DenyClasses()) rather than a
// hand-written list, so a class added to the vocabulary is automatically
// covered here too. A second guard asserts that at least one NON-internal class
// was checked, so a hypothetical future vocabulary of only "internal" cannot
// pass vacuously.
func TestDenyMappingTotalityOverVocabulary(t *testing.T) {
	classes := denyclass.DenyClasses()
	if len(classes) == 0 {
		t.Fatal("denyclass.DenyClasses() is empty — vacuous, the totality loop never runs")
	}

	var checked, nonInternalChecked int
	for _, class := range classes {
		class := class
		t.Run(class, func(t *testing.T) {
			v := mapDeny(class)

			// AuditReason always carries the truth class unchanged.
			if v.AuditReason != class {
				t.Fatalf("mapDeny(%q).AuditReason = %q, want the class unchanged", class, v.AuditReason)
			}

			// Status must always agree with the derivation from the wire code.
			derived := statusForWireCode(v.WireCode)
			if derived != v.WireStatus {
				t.Fatalf("mapDeny(%q).WireStatus = %d but statusForWireCode(%q) = %d — disagreement", class, v.WireStatus, v.WireCode, derived)
			}

			// denyInternal is the ONE class for which internal/500 is correct:
			// it is the fail-closed class itself. Pin that exact mapping and
			// stop — it must not be held to the non-500 obligation below.
			if class == denyInternal {
				if v.WireCode != wireCodeInternal || v.WireStatus != 500 {
					t.Fatalf("mapDeny(%q) = %q/%d, want the deliberate internal/500 fail-closed mapping", class, v.WireCode, v.WireStatus)
				}
				return
			}

			// Every OTHER vocabulary class must NOT degrade to the fail-closed
			// fallback code or status, and its code must be a member of the
			// closed non-internal wire-code set (catches a typo code).
			if v.WireCode == wireCodeInternal {
				t.Fatalf("mapDeny(%q).WireCode = internal — a real vocabulary class fell through to the fail-closed fallback (absent from denyTable, or wired to a typo code?)", class)
			}
			if !closedWireCodes[v.WireCode] {
				t.Fatalf("mapDeny(%q).WireCode = %q is not in the closed non-internal wire-code set — typo or unwired code", class, v.WireCode)
			}
			if v.WireStatus == 500 {
				t.Fatalf("mapDeny(%q).WireStatus = 500 — a real class degraded to the internal fail-closed status on the wire", class)
			}
			// statusForWireCode must not have used its default-500 arm for a
			// non-internal class.
			if derived == 500 {
				t.Fatalf("statusForWireCode(%q) hit its default-500 arm for vocabulary class %q", v.WireCode, class)
			}
		})
		checked++
		if class != denyInternal {
			nonInternalChecked++
		}
	}

	// Non-vacuity: the loop body ran exactly once per vocabulary class, and at
	// least one of them exercised the non-internal (real-refusal) obligation.
	if checked != len(classes) {
		t.Fatalf("checked %d classes, vocabulary has %d — loop did not cover the closed vocabulary exactly", checked, len(classes))
	}
	if nonInternalChecked == 0 {
		t.Fatal("no non-internal vocabulary class was checked — the non-500 totality obligation was never exercised, vacuous run")
	}
	t.Logf("deny-mapping totality verified over %d vocabulary classes (%d non-internal, shared source)", checked, nonInternalChecked)
}
