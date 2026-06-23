// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"testing"

	"pgregory.net/rapid"
)

// TestPropValidatePathIdempotent asserts the load-bearing, named invariant the
// engine's defense-in-depth re-validation relies on: ValidatePath is
// idempotent on its OWN output. For every input
// ValidatePath accepts, feeding the cleaned result back through ValidatePath
// must return that exact byte string with a nil error — i.e. filepath.Clean is
// stable on the accepted form. If a future normalization change made Clean
// non-stable for some accepted shape, the wire boundary (the single cleaner the
// wire calls) and the engine (ScopeRoot.Open → ValidatePath) would disagree on
// the bytes for one object, splitting authorization, the downloadable tag, the
// uuid store, and the audit record for that object (PATH-01, NFR-SEC-73).
//
// TestPropLexicalNeverEscapes covers one pass only — that an accepted path is
// local; nothing there checks that a SECOND pass is a fixed point. This is the
// direct coverage for that gap.
//
// Non-vacuity: the generator mixes the same rapid.String() default table that
// feeds TestPropLexicalNeverEscapes (its rune table already includes '/', '\\',
// '.', '\x00', and control runes) with explicitly sampled multi-segment and
// trailing-dot shapes so the Clean-NORMALIZING branch is exercised, not just
// strings that are already clean. Inputs ValidatePath rejects are skipped. A
// run-level counter records how many inputs were ACCEPTED and re-validated;
// the run fails as vacuous if that count is zero, so a run that happens to
// reject everything cannot pass silently. A second counter records how many of
// those accepted inputs were NORMALIZED by the first pass (clean != raw), and
// the run fails if Clean's normalizing arm was never observed — otherwise the
// property would only ever prove idempotence on already-clean strings.
func TestPropValidatePathIdempotent(t *testing.T) {
	var accepted, normalized int
	rapid.Check(t, func(rt *rapid.T) {
		// Bias the draw toward shapes that filepath.Clean actually rewrites:
		// inner "." segments, ".." pops, trailing separators, redundant
		// separators, and nested forms — mixed with the random rune table so
		// genuine fuzz value is retained.
		p := rapid.OneOf(
			rapid.SampledFrom([]string{
				"a/./b", "a/..", "a/b/", "a//b", "./a", "a/b/../c",
				"a/.", "a/b/.", "dir/", "x/./y/./z", "a/b/c/..",
			}),
			rapid.String(),
		).Draw(rt, "path")

		clean, err := ValidatePath(p)
		if err != nil {
			// Rejection is always acceptable — skip; the run-level counter
			// guards against a run that rejects everything.
			return
		}
		accepted++
		if clean != p {
			normalized++
		}

		// The fixed-point assertion: a second pass on the accepted output must
		// return the identical bytes with no error.
		clean2, err2 := ValidatePath(clean)
		if err2 != nil {
			rt.Fatalf("ValidatePath rejected its OWN accepted output: input=%q clean=%q err=%v", p, clean, err2)
		}
		if clean2 != clean {
			rt.Fatalf("ValidatePath is not idempotent: input=%q clean=%q second-pass=%q", p, clean, clean2)
		}
	})
	t.Logf("accepted-and-re-validated inputs: %d (of which normalized on first pass: %d)", accepted, normalized)
	if accepted == 0 {
		t.Fatal("property completed without a single accepted input — vacuous run")
	}
	if normalized == 0 {
		t.Fatal("property never observed an input that filepath.Clean normalized — the Clean-normalizing branch was not exercised, idempotence proven only on already-clean strings")
	}
}
