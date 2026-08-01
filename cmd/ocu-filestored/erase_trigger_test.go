// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// --- ERASE-TRIGGER-054 ------------------------------------------------------
//
// The engine seam implements a scope-erase verb (Engine.TeardownScope) on both
// engines. Nothing in the product invokes it. That is deliberate on one axis and
// a gap on the other, and this file pins both so neither can drift silently.
//
// Deliberate: erase is keyed to an OWNER CHANGE, never to the process
// lifecycle. Keying it to boot or to SIGTERM once wiped every object of a live
// owner on an ordinary restart. ProvisionScope is now ensure-scaffold-if-absent
// and Close does not erase, so a restart preserves owner bytes.
//
// The gap: no owner-change trigger was ever built to take the erase verb's other
// end. There is no flag, no admin route, and no signal path that reaches it, and
// the two whole-filesystem verbs that could host one (removeFilesystem,
// migrateFilesystem) are unimplemented because the frozen contract leaves their
// bodies TBD. So the verb is reachable only from tests.
//
// This is not a decision this repository may take on its own. The architecture
// canon does not give this service an owner-change event to observe: it re-homes
// erase-before-reuse to the Session sandbox component, states that erase and
// residue-drop are that component's invariants and not this one's, and lists no
// erase or scope-lifecycle invariant among this service's own. Until canon names
// an observable trigger and the surface it arrives on, building one here would be
// inventing a security behaviour, so the honest position is to carry the gap
// named rather than to describe a sweep that never runs.
//
// The ledger is asserted in BOTH directions. While no product path calls the
// verb, the documentation may not promise that an erase runs: those claims are
// lies and TestDocsDoNotPromiseAnUnwiredErase reds on them. The moment a product
// path DOES call the verb, TestNoProductPathTriggersScopeErase reds instead, so
// whoever wires the trigger is forced back here to retire the ledger and restate
// what the docs may now promise. Neither arm can be satisfied by weakening the
// other.

// eraseVerb is the engine method whose product-side wiring this ledger tracks.
const eraseVerb = "TeardownScope"

// eraseCallSite is one syntactic call of the erase verb.
type eraseCallSite struct {
	file string // repo-relative
	line int
}

func (c eraseCallSite) String() string { return c.file + ":" + strconv.Itoa(c.line) }

// repoRoot resolves the module root from the test's working directory and fails
// loudly rather than silently scanning nothing.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %q has no go.mod (%v); the scan would cover nothing", root, err)
	}
	return root
}

// scanEraseCallSites parses every Go file under the product source trees and
// returns each call of the erase verb. withTests selects whether _test.go files
// are parsed; the two modes share one code path so the tests-included mode is a
// live proof that the detector works.
func scanEraseCallSites(t *testing.T, root string, withTests bool) []eraseCallSite {
	t.Helper()
	var sites []eraseCallSite
	parsed := 0

	for _, tree := range []string{"cmd", "internal"} {
		base := filepath.Join(root, tree)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") && !withTests {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			parsed++
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				rel = path
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel == nil || sel.Sel.Name != eraseVerb {
					return true
				}
				sites = append(sites, eraseCallSite{
					file: filepath.ToSlash(rel),
					line: fset.Position(call.Lparen).Line,
				})
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}

	if parsed == 0 {
		t.Fatalf("parsed 0 Go files under cmd/ and internal/ (withTests=%v); the detector is vacuous", withTests)
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}
		return sites[i].line < sites[j].line
	})
	return sites
}

// TestNoProductPathTriggersScopeErase is the ERASE-TRIGGER-054 ledger's code
// arm: the erase verb is reachable from tests only. A product call site means an
// owner-change trigger now exists — a real advance, but one that invalidates
// every "the erase never runs" statement this ledger currently licenses, so it
// reds here rather than going quietly green.
//
// It is also the regression guard for the data-loss fault that made the
// decoupling necessary: a call site introduced on the boot or shutdown path
// would erase a live owner's bytes on an ordinary restart.
func TestNoProductPathTriggersScopeErase(t *testing.T) {
	root := repoRoot(t)

	// Non-vacuity, proven in-run: the same detector, over the same trees, with
	// test files included, must find call sites. If it finds none the AST match
	// is broken and the product-only result below would be a false negative.
	withTests := scanEraseCallSites(t, root, true)
	if len(withTests) == 0 {
		t.Fatalf("detector found no %s call anywhere, not even in tests; the guard is vacuous", eraseVerb)
	}
	t.Logf("detector live: %d %s call site(s) across the tests", len(withTests), eraseVerb)

	product := scanEraseCallSites(t, root, false)
	if len(product) != 0 {
		names := make([]string, 0, len(product))
		for _, s := range product {
			names = append(names, s.String())
		}
		t.Fatalf("%s is now called from product code at %s.\n"+
			"If this is the owner-change trigger canon finally named: retire ERASE-TRIGGER-054 in this file "+
			"and restate what the docs may promise, because they are currently written to say no erase runs.\n"+
			"If this wires erase to process start or stop instead: revert it. Erase is keyed to an owner change, "+
			"never to the process lifecycle — keying it to boot or SIGTERM erases a live owner's bytes on restart.",
			eraseVerb, strings.Join(names, ", "))
	}
}

// erasePromise is one prose claim shape that is true only if some product path
// invokes the erase verb.
type erasePromise struct {
	id string
	// re matches the claim.
	re *regexp.Regexp
	// lie is a canonical instance of the claim. It proves the pattern is live:
	// a pattern that no longer matches its own instance has rotted into a
	// permanent pass and is caught before the corpus is scanned.
	lie string
	// truth is what the code actually does, reported when the claim is found.
	truth string
}

var erasePromises = []erasePromise{
	{
		id:    "erase-at-provision",
		re:    regexp.MustCompile(`(?i)erase[-\s]at[-\s]provision`),
		lie:   "This is the erase-at-provision path.",
		truth: "ProvisionScope is ensure-scaffold-if-absent: it creates the scope when absent and sweeps only the staging sub-directory. Owner data at the scope root survives every provision.",
	},
	{
		id:    "stop-erases-the-workspace",
		re:    regexp.MustCompile(`(?i)erases? the workspace`),
		lie:   "Stop cleanly (drains in-flight ops, erases the workspace).",
		truth: "A clean stop drains, releases the ceilings entry and closes the handle store. It does not touch the scope on disk.",
	},
	{
		id:  "erase-is-unconditional",
		re:  regexp.MustCompile(`(?i)(?:teardown|erase)[^.\n]{0,80}\bunconditional|\bunconditional[a-z]*\b[^.\n]{0,80}(?:teardown|erase)`),
		lie: "`TeardownScope` runs **unconditionally** regardless of drain outcome.",

		truth: "No exit path calls TeardownScope. What runs unconditionally on Close is the drain, the ceilings release and the handle-store close.",
	},
	{
		id:    "erase-on-every-exit",
		re:    regexp.MustCompile(`(?i)eras[a-z]*[^.\n]{0,80}on every (?:exit|clean|signalled)|on every (?:exit|clean|signalled)[^.\n]{0,80}eras[a-z]*`),
		lie:   "erase-before-reuse on every exit path",
		truth: "No exit path erases. The scope outlives the process by design; its bytes belong to the owner, not to the daemon that served them.",
	},
	{
		id:    "signal-triggers-erase",
		re:    regexp.MustCompile(`(?i)(?:sigkill|sigterm|sigint|systemctl stop|compose stop|clean stop|stop grace)[^.\n]{0,90}erase-before-reuse|erase-before-reuse[^.\n]{0,90}(?:sigkill|sigterm|sigint|systemctl stop|compose stop|clean stop|stop grace)`),
		lie:   "so `docker compose stop` always lets erase-before-reuse complete before SIGKILL.",
		truth: "A stop signal starts a bounded drain and nothing more. No erase is scheduled behind it, so no stop-grace period needs to cover one.",
	},
	{
		id:    "erase-never-skipped",
		re:    regexp.MustCompile(`(?i)never skipped by a clean stop`),
		lie:   "the erase-before-reuse (NFR-SEC-54) is never skipped by a clean stop.",
		truth: "A clean stop skips the erase because nothing schedules one.",
	},
}

// erasePromiseCorpus is the prose this repository SHIPS: the docs a reader
// trusts and the deployment manifests whose comments justify a setting. Shipped
// is defined as tracked — untracked working material makes no promise to anyone.
// The vendored contracts are excluded on top of that: they are upstream
// artifacts this repo may not edit, so a claim inside one is not ours to fix.
func erasePromiseCorpus(t *testing.T, root string) map[string][]string {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "*.md", "*.yml", "*.yaml").Output()
	if err != nil {
		t.Fatalf("git ls-files for the doc corpus: %v", err)
	}
	corpus := make(map[string][]string)
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" || strings.HasPrefix(rel, "contracts/") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if rerr != nil {
			t.Fatalf("read tracked doc %q: %v", rel, rerr)
		}
		corpus[rel] = strings.Split(string(b), "\n")
	}
	if len(corpus) == 0 {
		t.Fatal("doc corpus is empty; the guard is vacuous")
	}
	return corpus
}

// TestDocsDoNotPromiseAnUnwiredErase is the ERASE-TRIGGER-054 ledger's prose
// arm. While no product path calls the erase verb, shipped prose may not tell a
// reader that an erase runs — an operator who believes a clean stop scrubs the
// workspace will size a stop-grace period around a sweep that does not exist and
// will assume bytes are gone that are still on disk.
//
// The arm disarms itself: if the trigger is ever built, the claims stop being
// lies and this test steps aside, leaving TestNoProductPathTriggersScopeErase to
// force the ledger's retirement.
func TestDocsDoNotPromiseAnUnwiredErase(t *testing.T) {
	root := repoRoot(t)

	// Every pattern must still match its own canonical instance. A pattern that
	// has rotted matches nothing at all and would pass the corpus scan forever.
	for _, p := range erasePromises {
		if !p.re.MatchString(p.lie) {
			t.Fatalf("promise pattern %q no longer matches its own instance %q; the pattern is dead and its arm is vacuous", p.id, p.lie)
		}
	}

	if sites := scanEraseCallSites(t, root, false); len(sites) != 0 {
		t.Skipf("%s now has %d product call site(s); the erase claims may be true again — see TestNoProductPathTriggersScopeErase", eraseVerb, len(sites))
	}

	corpus := erasePromiseCorpus(t, root)
	files := make([]string, 0, len(corpus))
	for f := range corpus {
		files = append(files, f)
	}
	sort.Strings(files)

	found := 0
	for _, f := range files {
		lines := corpus[f]
		seen := make(map[string]bool)
		for i := range lines {
			// Prose wraps, so a claim routinely straddles two lines. Match over a
			// two-line window and report the window's first line; the seen-set
			// keeps a claim from being reported once alone and again as the tail
			// of the window before it.
			window := lines[i]
			if i+1 < len(lines) {
				window += " " + lines[i+1]
			}
			for _, p := range erasePromises {
				hit := p.re.FindString(window)
				if hit == "" {
					continue
				}
				key := p.id + "\x00" + strings.Join(strings.Fields(hit), " ")
				if seen[key] {
					continue
				}
				seen[key] = true
				found++
				t.Errorf("%s:%d promises an erase that nothing triggers [%s]\n  claim: %s\n  actual: %s",
					f, i+1, p.id, strings.Join(strings.Fields(hit), " "), p.truth)
			}
		}
	}
	if found == 0 {
		t.Logf("scanned %d shipped prose files; no unwired-erase promise found", len(corpus))
	}
}
