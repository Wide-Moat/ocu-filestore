// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// --- CONSTITUTION-PATHS -----------------------------------------------------
//
// Every invariant in CONSTITUTION.md ends with an "Enforced:" line naming the
// file that enforces it. That naming is the whole load: a reader who wants to
// know whether a never-rule is real opens the file it names. When the file stops
// existing, the invariant stops being checkable and starts being a claim — and
// the deletion that broke it looks like ordinary progress, because nothing in
// the tree points back at the sentence.
//
// It has already happened once. Invariant #11 named a fenced handler and its
// test; both files were deleted when the write plane landed, and the invariant
// went on naming them, unbroken-looking, for a dozen commits.
//
// This guard is the general form and it is cheap: every repo path CONSTITUTION.md
// names must exist. It cannot tell whether the named file still enforces what the
// sentence says — a guard for THAT would have to read the invariant — but a path
// that no longer resolves is decidable, and it is the failure mode that survives
// longest, because a missing file produces no diff anywhere near the sentence.

// constitutionFile is the document under guard, relative to the repo root.
const constitutionFile = "CONSTITUTION.md"

// pathRefPattern extracts the repo paths named in CONSTITUTION.md. A reference
// is a backticked token, so the document's own punctuation cannot bleed into it,
// and it must carry a directory separator and a known source extension — that
// pair is what separates `internal/filesapi/route.go` from the identifiers,
// contract markers and route shapes the document also backticks.
//
// A trailing `:symbol` (the "file:function" form the Enforced lines use) and a
// trailing `'s` are stripped by the capture, which stops at the extension.
var pathRefPattern = regexp.MustCompile("`([A-Za-z0-9_.][A-Za-z0-9_./-]*/[A-Za-z0-9_.-]+\\.(?:go|md|ya?ml|json|toml|sh|service))")

// pathRefProbes are instances the extractor must handle, checked before the
// document is read. They are the forms CONSTITUTION.md actually uses; a rotted
// pattern that extracted nothing would otherwise report a clean scan forever.
var pathRefProbes = []struct {
	line string
	want []string
}{
	{"- Enforced: `internal/southface/credscope.go:deriveCredScope` — the scope source",
		[]string{"internal/southface/credscope.go"}},
	{"  `internal/auditgate/filesink.go:FileSink.Mandate` (write + `Sync`), returning",
		[]string{"internal/auditgate/filesink.go"}},
	{"named `docs/architecture/05-lifecycle.md` §3.4 and `.github/workflows/go.yml` too",
		[]string{"docs/architecture/05-lifecycle.md", ".github/workflows/go.yml"}},
	{"  ephemeral object-id store (`internal/southface/objectid.go`'s `objectIDStore`,",
		[]string{"internal/southface/objectid.go"}},
	{"  `contrib/systemd/ocu-filestored.service` and `examples/k8s/broker-deployment.yaml`",
		[]string{"contrib/systemd/ocu-filestored.service", "examples/k8s/broker-deployment.yaml"}},
	// Not paths: an identifier, a contract marker, a route shape, a bare
	// filename with no directory. None may be extracted.
	{"the contract's `x-ocu-tbd-bodies` marker and `TeardownScope` and `POST /v1/files`", nil},
	{"CLAUDE.md's \"never invent a body\" rule and `Store handlestore.Store`", nil},
}

// pathRef is one repo path named by the document, with the line it sits on.
type pathRef struct {
	path string
	line int
}

// namedPaths returns every repo path CONSTITUTION.md names, in document order.
func namedPaths(text string) []pathRef {
	var refs []pathRef
	for i, line := range strings.Split(text, "\n") {
		for _, m := range pathRefPattern.FindAllStringSubmatch(line, -1) {
			refs = append(refs, pathRef{path: m[1], line: i + 1})
		}
	}
	return refs
}

// TestConstitutionNamesOnlyLivePaths asserts every repo path CONSTITUTION.md
// names resolves in the tree. It reds when a file an invariant points at is
// deleted or moved without the invariant being restated — the way #11 came to
// name a guard that had not existed for a dozen commits.
func TestConstitutionNamesOnlyLivePaths(t *testing.T) {
	root := repoRoot(t)

	// The extractor must still read the forms the document is written in, and
	// must still refuse the backticked non-paths beside them.
	for _, p := range pathRefProbes {
		var got []string
		for _, r := range namedPaths(p.line) {
			got = append(got, r.path)
		}
		if strings.Join(got, ",") != strings.Join(p.want, ",") {
			t.Fatalf("extractor read %v from %q, want %v; the pattern has rotted and the scan is unreliable", got, p.line, p.want)
		}
	}

	b, err := os.ReadFile(filepath.Join(root, constitutionFile))
	if err != nil {
		t.Fatalf("read %s: %v", constitutionFile, err)
	}

	refs := namedPaths(string(b))
	if len(refs) == 0 {
		t.Fatalf("%s names no repo path at all; either the document stopped citing its enforcement sites or the extractor is dead", constitutionFile)
	}

	missing := 0
	seen := make(map[string]bool, len(refs))
	for _, r := range refs {
		if _, serr := os.Stat(filepath.Join(root, filepath.FromSlash(r.path))); serr != nil {
			missing++
			t.Errorf("%s:%d names %s, which does not exist — the invariant on this line points at nothing a reader can open. Re-point it at the file that enforces the rule today, or state plainly that nothing does.",
				constitutionFile, r.line, r.path)
		}
		seen[r.path] = true
	}
	if missing == 0 {
		distinct := make([]string, 0, len(seen))
		for p := range seen {
			distinct = append(distinct, p)
		}
		sort.Strings(distinct)
		t.Logf("%s names %d live path(s) across %d reference(s)", constitutionFile, len(distinct), len(refs))
	}
}
