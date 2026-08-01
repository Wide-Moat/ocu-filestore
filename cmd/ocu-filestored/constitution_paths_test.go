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
//
// REPO path is the operative word, and the document names three kinds. A canon
// citation points into the architecture repository, which is where the specs,
// the ADRs and the NFR rows live and where a decision is made before it is
// implemented here; this repo is directed to read them by exactly those paths
// and none of them resolves in this tree. A module-qualified citation names a
// package in a module namespace. Neither is this repo's file to keep alive, and
// stat'ing either against this working copy reds the build for a citation that
// is perfectly correct — the first canon ADR anyone cited would have done it.
// classifyPath draws the line; the qualified form of THIS module is the one
// exception, stripped back to the repo path it names so the citation still gets
// checked.
//
// Stated limits, both from the extractor rather than the check. A reference is
// recognised by a directory separator and a source extension, so an
// extensionless target (a Makefile, a LICENSE, a shell entry point without a
// suffix) and a bare directory (`internal/authz/`) are invisible to it — the
// extension is what separates a path from the identifiers, contract markers and
// route shapes the document also backticks, and dropping it would trade this
// guard's reliability for that reach. A path written without backticks is
// invisible for the same reason.

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

// pathClassProbes are the placements classifyPath must get right. Each one is a
// citation this document can plausibly carry, and each of the first two was a
// false red before the classification existed.
var pathClassProbes = []struct {
	path string
	kind pathKind
	repo string
}{
	// A canon ADR. This repo is directed to read its decisions there, and the
	// tree has no adr/ under docs/architecture — so the first ADR anyone cited
	// reddened the build.
	{"docs/architecture/adr/0011-storage-egress-lane.md", canonPath, ""},
	// The same file named the way an import names it. It IS this tree's file, so
	// the module prefix comes off and the check still applies.
	{"github.com/Wide-Moat/ocu-filestore/internal/southface/credscope.go", repoPath, "internal/southface/credscope.go"},
	{"docs/architecture/components/04-object-store-service.md", canonPath, ""},
	{"manifesto/02-nfrs.md", canonPath, ""},
	// A foreign module: a real file, in someone else's checkout.
	{"github.com/rclone/rclone/fs/operations.go", modulePath, ""},
	// This repo's own, in the forms the document already uses. The architecture
	// docs THIS repo ships sit under docs/architecture too and stay checked —
	// only the canon subtrees are held out. The vendored contracts are in the
	// tree, so they are ours to keep alive.
	{"internal/southface/credscope.go", repoPath, "internal/southface/credscope.go"},
	{"docs/architecture/05-lifecycle.md", repoPath, "docs/architecture/05-lifecycle.md"},
	{".github/workflows/go.yml", repoPath, ".github/workflows/go.yml"},
	{"contracts/storage/file-ops.schema.json", repoPath, "contracts/storage/file-ops.schema.json"},
}

// pathKind is where a cited path lives, and so who is answerable for it.
type pathKind int

const (
	// repoPath is this repository's own file. It must exist.
	repoPath pathKind = iota
	// canonPath is a specification, ADR or NFR row in the architecture
	// repository. It is not in this tree by design.
	canonPath
	// modulePath is a file named through a foreign module's import path.
	modulePath
)

func (k pathKind) String() string {
	switch k {
	case canonPath:
		return "canon"
	case modulePath:
		return "module"
	default:
		return "repo"
	}
}

// canonPrefixes are the architecture repository's own layout: components hold
// the specs, adr the decisions, manifesto the NFR rows. A citation under one of
// them is a canon citation.
//
// The prefixes are asserted NOT to resolve in this tree. If one ever did, it
// would stop being an unambiguous marker of canon and start silently exempting
// this repository's own files from the check — the guard would go quiet exactly
// where it was working.
var canonPrefixes = []string{
	"docs/architecture/adr/",
	"docs/architecture/components/",
	"manifesto/",
}

// domainSegment recognises a host name — the first segment of a module path. A
// dot INSIDE the segment is what marks it; a leading dot does not, which is what
// keeps `.github/workflows/go.yml` a repo path.
var domainSegment = regexp.MustCompile(`(?i)^[a-z0-9-]+(?:\.[a-z0-9-]+)+$`)

// classifyPath places a cited path and, for a repo path, returns the
// repo-relative location to stat. A citation qualified by THIS module's own path
// is a repo path with the module prefix stripped: it names a file in this tree,
// spelled the way an import spells it.
func classifyPath(module, p string) (pathKind, string) {
	if module != "" && strings.HasPrefix(p, module+"/") {
		return repoPath, strings.TrimPrefix(p, module+"/")
	}
	if first, _, ok := strings.Cut(p, "/"); ok && domainSegment.MatchString(first) {
		return modulePath, ""
	}
	for _, prefix := range canonPrefixes {
		if strings.HasPrefix(p, prefix) {
			return canonPath, ""
		}
	}
	return repoPath, p
}

// moduleName reads this module's path out of go.mod. It is read rather than
// written down here so a module rename cannot leave the classification behind.
func moduleName(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod for the module path: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatal("go.mod declares no module path; a citation written as an import path could not be told from a foreign module's")
	return ""
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
	module := moduleName(t, root)

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

	// A canon prefix that resolves here is no longer a marker of canon: it would
	// exempt this repository's own files from the check without saying so.
	for _, prefix := range canonPrefixes {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(prefix))); err == nil {
			t.Fatalf("%s exists in this tree, so it can no longer stand for the architecture repository; a citation under it would be skipped as canon while naming a file this repo owns", prefix)
		}
	}

	// And the classification itself, on the forms the document can carry.
	for _, p := range pathClassProbes {
		kind, rel := classifyPath(module, p.path)
		if kind != p.kind || rel != p.repo {
			t.Fatalf("classifyPath read %q as a %s path resolving to %q, want a %s path resolving to %q; a misplaced citation is either an unchecked repo file or a red build against a correct reference",
				p.path, kind, rel, p.kind, p.repo)
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
	elsewhere := 0
	seen := make(map[string]bool, len(refs))
	for _, r := range refs {
		kind, rel := classifyPath(module, r.path)
		if kind != repoPath {
			elsewhere++
			continue
		}
		if _, serr := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); serr != nil {
			missing++
			t.Errorf("%s:%d names %s, which does not exist — the invariant on this line points at nothing a reader can open. Re-point it at the file that enforces the rule today, or state plainly that nothing does.",
				constitutionFile, r.line, r.path)
		}
		seen[rel] = true
	}
	if len(seen) == 0 {
		t.Fatalf("%s names no path in THIS repository at all; either every citation now points elsewhere or classifyPath has started reading repo paths as canon", constitutionFile)
	}
	if missing == 0 {
		distinct := make([]string, 0, len(seen))
		for p := range seen {
			distinct = append(distinct, p)
		}
		sort.Strings(distinct)
		t.Logf("%s names %d live repo path(s) across %d reference(s); %d further reference(s) point at canon or another module and are not this repo's to keep alive",
			constitutionFile, len(distinct), len(refs)-elsewhere, elsewhere)
	}
}
