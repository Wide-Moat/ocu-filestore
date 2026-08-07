// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The engine verifies the injected credential against the CREDENTIAL-ISSUER's
// public key (NFR-SEC-31), never Control's. The two are easy to conflate: both
// are JWKS documents on the same storage path, and the shipped help text and
// doc comments claimed Control's for long enough to reach a release.
//
// Following that claim inverts the trust anchor in both directions at once —
// the engine accepts a guest's own weak session JWT presented straight at the
// south face (the edge bypass ADR-0013/0019 exist to close) while rejecting
// every legitimate injected credential 401.
//
// A comment cannot be unit-tested for truth, but it CAN be tested for the
// specific false claim that already happened once. This is a cheap guard on an
// expensive mistake.
func TestVerifierDocsDoNotAnchorOnControl(t *testing.T) {
	// The claim to catch: prose tying the verifier's JWKS to Control. Matched
	// loosely (any "Control" within a few words of "JWKS") so a reworded version
	// of the same error still reds.
	// The specific false claim: prose that makes Control the SOURCE or OWNER of
	// the JWKS this engine reads. Bare co-occurrence is too broad — a true
	// sentence can mention both (e.g. "the edge owns weak-JWT validation; the
	// control mint lands later"), and a guard that reds on those gets deleted
	// rather than obeyed.
	claim := regexp.MustCompile(`(?i)Control'?s?\s+(rendered\s+|published\s+)?JWKS` +
		`|JWKS\s+(artifact\s+|document\s+)?(that\s+|which\s+)?Control\s+(renders|writes|publishes)` +
		`|(SAME|same)\s+(artifact|document|file)\s+Control` +
		`|JWKS[^.]{0,40}\bthe one Control\b`)
	mentionsControl := regexp.MustCompile(`(?i)\bControl\b`)

	for _, path := range []string{"jwtverify.go", "../../cmd/ocu-filestored/main.go"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		// Matched per COMMENT BLOCK, not per line. A correction spans several
		// lines, and its negation ("NOT Control's ...") often sits on a different
		// line from the word "JWKS" — judging line by line reds the very fix that
		// removes the defect.
		negation := regexp.MustCompile(`(?i)\bNOT\b|never|would invert|belongs to the edge|the edge consumes`)
		for i, block := range commentBlocks(string(raw)) {
			_ = i
			if !claim.MatchString(block.text) || !mentionsControl.MatchString(block.text) {
				continue
			}
			if negation.MatchString(block.text) {
				continue
			}
			t.Errorf("%s:%d ties the engine's JWKS to Control:\n  %s\n"+
				"The engine verifies against the CREDENTIAL-ISSUER's public key "+
				"(NFR-SEC-31); Control's JWKS belongs to the edge. Anchoring here on "+
				"Control admits a guest's weak session JWT at the south face.",
				path, block.line, strings.TrimSpace(block.text))
		}
	}
}

// commentBlock is a run of consecutive // lines with the line number it starts
// at, so a multi-line correction is judged as one statement.
type commentBlock struct {
	line int
	text string
}

func commentBlocks(src string) []commentBlock {
	var out []commentBlock
	var cur []string
	start := 0
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			if len(cur) == 0 {
				start = i + 1
			}
			cur = append(cur, trimmed)
			continue
		}
		// A flag registration carries its help string on a non-comment line; treat
		// it as its own single-line block so a wrong help text is still caught.
		if len(cur) > 0 {
			out = append(out, commentBlock{line: start, text: strings.Join(cur, " ")})
			cur = nil
		}
		if strings.Contains(line, "fs.String(") || strings.Contains(line, "fs.Bool(") || strings.Contains(line, "\"") {
			out = append(out, commentBlock{line: i + 1, text: line})
		}
	}
	if len(cur) > 0 {
		out = append(out, commentBlock{line: start, text: strings.Join(cur, " ")})
	}
	return out
}
