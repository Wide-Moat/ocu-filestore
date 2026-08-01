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

// eraseDenialTail is the trailing half of an honest denial: the erase verb
// followed, through at most a copula, by the word that denies it. It is what
// lets "TeardownScope has no product caller at all" acquit a claim pattern that
// only saw the verb preceded by "calls". The copula gap is deliberately narrow
// — a negation further along the sentence belongs to a different clause and may
// not launder a claim about the verb itself.
const eraseDenialTail = `[ \t]+(?:has|had|is|are|was|were|gets?|does|do|did)?[ \t]*\b(?:never|no|not|nothing|neither)\b`

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
//
// The patterns match PHRASES, not propositions: they are deliberately blind to
// negation, so prose must state what the service does rather than deny what it
// does not. Where an honest denial has to use the forbidden phrase — the
// documents that exist precisely to say the erase never runs — the promise
// carries an `except` acquittal instead of the prose being bent around a regex.
type erasePromise struct {
	id string
	// re matches the claim.
	re *regexp.Regexp
	// lie is a canonical instance of the claim. It proves the pattern is live:
	// a pattern that no longer matches its own instance has rotted into a
	// permanent pass and is caught before the corpus is scanned.
	lie string
	// except, when set, acquits a hit that falls INSIDE one of its matches — the
	// honest-denial forms of the same phrase. Containment (not mere adjacency)
	// is what acquits: an acquittal written to cover the SENTENCE around a
	// denial cannot reach a claim in the next sentence, because `[^.\n]` stops
	// at the period. An acquittal that would swallow the promise's own lie is
	// rejected before the corpus is scanned — that is the disarm this mechanism
	// could otherwise become.
	except *regexp.Regexp
	// acquitted is a canonical instance of the honest denial. It must be matched
	// by re AND acquitted by except, which proves the acquittal is both live and
	// load-bearing. Set exactly when except is set.
	acquitted string
	// truth is what the code actually does, reported when the claim is found.
	truth string
}

// acquits reports whether p.except covers a hit at [start,end) in text — the
// hit must fall inside a single except match, not merely share a neighbourhood
// with one.
func (p erasePromise) acquits(text string, start, end int) bool {
	if p.except == nil {
		return false
	}
	for _, m := range p.except.FindAllStringIndex(text, -1) {
		if m[0] <= start && end <= m[1] {
			return true
		}
	}
	return false
}

// hits returns the index range of every unacquitted match of the promise.
func (p erasePromise) hits(text string) [][]int {
	var out [][]int
	for _, m := range p.re.FindAllStringIndex(text, -1) {
		if p.acquits(text, m[0], m[1]) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// validate proves the promise still works before it is trusted against the
// corpus. A pattern that no longer matches its own lie is dead and would pass
// forever; an acquittal that does not cover its own denial turns honest prose
// into a false red; an acquittal that covers the LIE is a disarm wearing the
// mechanism's clothes.
func (p erasePromise) validate(t *testing.T) {
	t.Helper()

	if !p.re.MatchString(p.lie) {
		t.Fatalf("promise pattern %q no longer matches its own instance %q; the pattern is dead and its arm is vacuous", p.id, p.lie)
	}
	if p.except == nil {
		if p.acquitted != "" {
			t.Fatalf("promise %q carries an acquitted instance %q but no except pattern; nothing proves the instance is acquitted", p.id, p.acquitted)
		}
		return
	}
	if p.acquitted == "" {
		t.Fatalf("promise %q carries an except pattern with no acquitted instance; an unexercised acquittal can widen without anyone noticing", p.id)
	}
	if !p.re.MatchString(p.acquitted) {
		t.Fatalf("promise %q: the acquitted instance %q is not matched by the claim pattern at all, so the acquittal carries no weight — either the instance is not the honest denial of this claim, or the except pattern is unnecessary", p.id, p.acquitted)
	}
	if len(p.hits(p.acquitted)) != 0 {
		t.Fatalf("promise %q: the except pattern does not acquit its own honest denial %q; shipped prose that states the truth would be reported as a lie", p.id, p.acquitted)
	}
	if len(p.hits(p.lie)) == 0 {
		t.Fatalf("promise %q: the except pattern acquits the promise's own lie %q; the acquittal disarms the arm it belongs to", p.id, p.lie)
	}
}

var erasePromises = []erasePromise{
	{
		id:  "erase-at-provision",
		re:  regexp.MustCompile(`(?i)erase[-\s]at[-\s]provision`),
		lie: "This is the erase-at-provision path.",
		// Prose that names the semantics as RETIRED is the opposite of a promise:
		// it tells the reader the erase is gone and often explains what an
		// assertion would have looked like while it was there.
		except:    regexp.MustCompile(`(?i)[^.\n]*\b(?:retired|removed|deleted|dropped|former(?:ly)?|old|previous(?:ly)?|superseded|no longer|never|not)\b[^.\n]*erase[-\s]at[-\s]provision`),
		acquitted: "On the retired erase-at-provision semantics the scope booted empty.",
		truth:     "ProvisionScope is ensure-scaffold-if-absent: it creates the scope when absent and sweeps only the staging sub-directory. Owner data at the scope root survives every provision.",
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
	{
		// The shape that hid in CONSTITUTION.md for five commits after the
		// rollback stopped erasing: an error path credited with erasing the
		// scope it had provisioned. The claim is about the SCOPE, so both words
		// are required — the tree is full of `teardownServer`, teardown sweeps
		// and teardown bounds that describe the verb without claiming anything
		// calls it.
		id: "scope-torn-down",
		re: regexp.MustCompile(`(?i)\bscopes?\b[^.\n]{0,60}\btorn down\b|\b(?:torn|tears?|tearing)[- ]down\b[^.\n]{0,60}\bscopes?\b`),
		lie: "If session compose fails after the scope is provisioned, the scope is torn down " +
			"before the error returns.",
		except:    regexp.MustCompile(`(?i)[^.\n]*\b(?:never|no|not|nothing)\b[^.\n]*\b(?:torn|tears?|tearing)[- ]down\b`),
		acquitted: "A provisioned scope is never torn down.",
		truth:     "The post-provision rollback latch is release-only: it closes the durable handle-store descriptor and leaves the scope exactly as provisioned. A scope outlives the composition that provisioned it and the process that served it.",
	},
	{
		// The other half of the same shape: a document that names a product
		// location and says the erase verb runs there. This is the claim an
		// implementer checks against the code, so it is the one that must not
		// outlive the call it describes.
		id: "product-path-runs-the-erase-verb",
		re: regexp.MustCompile(`(?i)\b(?:runs?|calls?|invokes?|triggers?|fires?|schedules?|performs?|executes?)\b[^.\n]{0,40}` +
			eraseVerb + `|` + eraseVerb + `[^.\n]{0,40}\b(?:is|are|gets?)\s+(?:then\s+)?(?:run|called|invoked|triggered|fired|scheduled|performed|executed)\b`),
		lie: "Enforced: `cmd/ocu-filestored/main.go:compose` — a post-`ProvisionScope` " +
			"construction error runs `TeardownScope` before returning `nil, err`.",
		// The denial acquits from EITHER side of the identifier: a sentence can
		// name the verb and only then deny it a caller, and reading only up to
		// the semicolon turns that denial into a claim. The trailing form is
		// deliberately tight — the negation must attach to the verb through at
		// most a copula, so a negation stranded in a later clause ("... on
		// rollback, so nothing leaks") cannot launder a claim about the verb.
		except:    regexp.MustCompile(`(?i)[^.\n]*\b(?:never|no|not|nothing|neither)\b[^.\n]*` + eraseVerb + `|[^.\n]*` + eraseVerb + eraseDenialTail),
		acquitted: "Nothing in the product calls `TeardownScope`.",
		truth:     "No product path calls the verb — not compose, not the rollback latch, not Close. The engines implement it and the tests exercise it; nothing else reaches it.",
	},
	{
		// The identifier-shaped variant of scope-torn-down. That arm requires the
		// literal word "scope", so it cannot see a claim that spells the scope
		// INSIDE the verb's name — there is no word boundary in the middle of
		// `TeardownScope`, and prose that says "Close tears down (engine
		// TeardownScope)" names the erase without ever writing "scope" as a word.
		// This arm keys on the lifecycle moment instead: a stop, a close or a
		// teardown said to carry the erase verb with it.
		id: "lifecycle-carries-the-erase-verb",
		re: regexp.MustCompile(`(?i)\b(?:close[sd]?|closing|shut[- ]?down|shuts down|stop(?:s|ped|ping)?|teardown|tears?[- ]down|torn[- ]down|tearing[- ]down|exit(?:s|ing)?)\b[^.\n]{0,60}\b` + eraseVerb + `\b`),
		lie: "the caller serves the returned Server and Closes it for teardown " +
			"(engine " + eraseVerb + " + registry/ceilings Release).",
		except:    regexp.MustCompile(`(?i)[^.\n]*\b(?:never|no|not|nothing|neither)\b[^.\n]*` + eraseVerb + `|[^.\n]*` + eraseVerb + eraseDenialTail),
		acquitted: "Close does NOT call TeardownScope: shutdown is not an owner change.",
		truth:     "Close drains, releases the ceilings entry and closes the handle-store fd. No lifecycle moment — not close, not stop, not exit — reaches the erase verb.",
	},
	{
		// A named pairing is a promise about a mechanism, not just a phrase: it
		// tells a reader that provisioning arms a later teardown.
		id:        "teardown-partner",
		re:        regexp.MustCompile(`(?i)\bteardown partner\b`),
		lie:       "## 7. Never a provisioned scope without a teardown partner",
		except:    regexp.MustCompile(`(?i)\bno teardown partner\b`),
		acquitted: "There is no teardown partner.",
		truth:     "Provisioning arms nothing. No path pairs a provisioned scope with a later teardown, because no owner-change event exists for one to hang on.",
	},
}

// erasePromiseCorpus is the prose this repository SHIPS: the docs a reader
// trusts, the deployment manifests whose comments justify a setting, and the Go
// comments an implementer reads next to the code they describe. Shipped is
// defined as tracked — untracked working material makes no promise to anyone.
// The vendored contracts are excluded on top of that: they are upstream
// artifacts this repo may not edit, so a claim inside one is not ours to fix.
//
// Go files enter through their COMMENTS ALONE (goCommentText). A docstring is
// the densest promise in the tree — it is read by whoever is about to change the
// function under it — and leaving .go out of the corpus is what let a compose
// docstring go on naming an erase for five commits after the erase left.
//
// One Go file in ten thousand is exempt, and only for a reason the ledger
// already draws elsewhere: a file that SYNTACTICALLY CALLS the erase verb is
// demonstrating it. Its comments describe a call the reader can step into, not a
// path that does not exist, so "call TeardownScope directly, assert the scope is
// empty" is a true sentence about a real call. Because the whole prose arm
// stands down the moment a PRODUCT path calls the verb (see the skip in
// TestDocsDoNotPromiseAnUnwiredErase), the exemption can only ever cover a test
// file. A test file that does not call the verb stays fully in the corpus:
// main_test.go, which carried a false close-time erase claim, is one.
func erasePromiseCorpus(t *testing.T, root string) map[string]string {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "*.md", "*.yml", "*.yaml", "*.go").Output()
	if err != nil {
		t.Fatalf("git ls-files for the doc corpus: %v", err)
	}

	demonstrates := make(map[string]bool)
	for _, s := range scanEraseCallSites(t, root, true) {
		demonstrates[s.file] = true
	}
	if len(demonstrates) == 0 {
		t.Fatal("no file calls the erase verb at all, not even a test; the detector behind the corpus exemption is vacuous")
	}

	corpus := make(map[string]string)
	goFiles := 0
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" || strings.HasPrefix(rel, "contracts/") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if rerr != nil {
			t.Fatalf("read tracked doc %q: %v", rel, rerr)
		}
		if strings.HasSuffix(rel, ".go") {
			if demonstrates[rel] {
				continue
			}
			corpus[rel] = goCommentText(t, rel, b)
			goFiles++
			continue
		}
		corpus[rel] = string(b)
	}
	if len(corpus) == 0 {
		t.Fatal("doc corpus is empty; the guard is vacuous")
	}
	if goFiles == 0 {
		t.Fatal("doc corpus holds no Go file; the comment arm of the guard is vacuous")
	}
	// The file that carried the docstring lie this arm was widened to catch must
	// be in the corpus, or the widening is decorative.
	if _, ok := corpus["cmd/ocu-filestored/main.go"]; !ok {
		t.Fatal("cmd/ocu-filestored/main.go is not in the doc corpus; the Go-comment arm cannot see the daemon's own docstrings")
	}
	if _, ok := corpus["cmd/ocu-filestored/main_test.go"]; !ok {
		t.Fatal("cmd/ocu-filestored/main_test.go is not in the doc corpus; a test file that does not call the erase verb must not be exempt")
	}
	return corpus
}

// goCommentText projects a Go source file onto its COMMENTS ALONE, byte for
// byte: every byte outside a comment becomes a space, every newline stays where
// it was, and each comment's own `//` or `/*`/`*/` marker is blanked too. The
// projection is exactly as long as the file, so an offset into it still indexes
// the original and lineAt still reports the real line — the same one-byte-for-
// one-byte discipline proseBlocks relies on.
//
// Code is blanked rather than dropped because only comments are prose. An
// identifier, a struct tag, or a test fixture string is not a claim to a reader,
// and reading one as a claim would make this guard fire on the very literals
// that spell out the lies it hunts (erasePromises, a few hundred lines up, is
// full of them). Blanking the comment markers is what lets a bulleted docstring
// split into blocks the way the equivalent markdown would.
func goCommentText(t *testing.T, rel string, src []byte) string {
	t.Helper()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s for the doc corpus: %v", rel, err)
	}

	out := make([]byte, len(src))
	for i, b := range src {
		if b == '\n' {
			out[i] = '\n'
			continue
		}
		out[i] = ' '
	}

	base := fset.File(f.Pos()).Base()
	for _, group := range f.Comments {
		for _, c := range group.List {
			start, end := int(c.Pos())-base, int(c.End())-base
			if start < 0 || end > len(src) || start >= end {
				t.Fatalf("%s: comment span [%d,%d) is outside the %d-byte source", rel, start, end, len(src))
			}
			copy(out[start:end], src[start:end])
			// Blank the marker so `//   - foo` reads as a list item, exactly as
			// `   - foo` would in markdown.
			blank(out[start:min(start+2, end)])
			if strings.HasPrefix(c.Text, "/*") {
				blank(out[max(start, end-2):end])
			}
		}
	}
	return string(out)
}

// blank overwrites b with spaces, leaving newlines in place so the projection
// keeps the original's line structure.
func blank(b []byte) {
	for i := range b {
		if b[i] != '\n' {
			b[i] = ' '
		}
	}
}

// proseBlock is one paragraph-sized unit of a document with its newlines
// flattened to spaces, plus the byte offset it starts at in the original. The
// substitution is one byte for one byte, so an offset inside the block plus the
// block's own offset still indexes the document — which is what lets a hit be
// reported at its own line.
type proseBlock struct {
	offset int
	text   string
}

// blockStarter recognises the markdown constructs that begin a new unit of
// prose: a heading, a list item, a table row, a block quote, a rule.
var blockStarter = regexp.MustCompile(`^(?:#{1,6}\s|[-*+]\s|\d+[.)]\s|\||>|-{3,}\s*$|\*{3,}\s*$|_{3,}\s*$)`)

// proseBlocks splits a document into the units a single claim can occupy. A
// claim routinely WRAPS across lines, so lines must be joined; it does not span
// a blank line, a heading or a neighbouring bullet, so those end the block.
//
// The block is what makes the acquittals in erasePromises safe. Judged over a
// whole flattened document, a heading's "Never" would sit in the same sentence
// as the next paragraph's claim — headings carry no full stop — and would acquit
// it. Judged over a fixed two-line window, a denial one line too far above the
// claim it acquits would be cut away and the honest prose reported as a lie.
// Judged over the block, both hold: the denial and the claim are in the unit a
// reader reads together, or they are not related at all.
func proseBlocks(text string) []proseBlock {
	var blocks []proseBlock
	start, end := -1, -1
	flush := func() {
		if start >= 0 {
			blocks = append(blocks, proseBlock{offset: start, text: strings.ReplaceAll(text[start:end], "\n", " ")})
		}
		start, end = -1, -1
	}

	offset := 0
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			flush()
		default:
			if start >= 0 && blockStarter.MatchString(trimmed) {
				flush()
			}
			if start < 0 {
				start = offset
			}
			end = offset + len(line)
		}
		offset += len(line) + 1 // + the newline that Split consumed
	}
	flush()
	return blocks
}

// lineAt maps a byte offset in a document to its 1-based line number.
func lineAt(text string, offset int) int { return 1 + strings.Count(text[:offset], "\n") }

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

	// Every pattern must still match its own canonical instance, and every
	// acquittal must cover its own denial without covering the claim.
	for _, p := range erasePromises {
		p.validate(t)
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
		text := corpus[f]
		for _, b := range proseBlocks(text) {
			for _, p := range erasePromises {
				for _, m := range p.hits(b.text) {
					found++
					t.Errorf("%s:%d promises an erase that nothing triggers [%s]\n  claim: %s\n  actual: %s",
						f, lineAt(text, b.offset+m[0]), p.id, strings.Join(strings.Fields(b.text[m[0]:m[1]]), " "), p.truth)
				}
			}
		}
	}
	if found == 0 {
		t.Logf("scanned %d shipped prose files; no unwired-erase promise found", len(corpus))
	}
}
