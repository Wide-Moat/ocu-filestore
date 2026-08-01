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

// eraseNegation is the vocabulary an honest denial is written in.
const eraseNegation = `\b(?:never|no|not|nothing|neither|nor|none)\b`

// leadingDenial and trailingDenial build the two halves of the honest-denial
// acquittal for a claim about `subject`: a SENTENCE that both names the subject
// and denies something, with the denial ahead of the subject or behind it. The
// span runs to the sentence's own bounds, so a claim pattern that matched inside
// that sentence falls inside the acquittal and is dropped.
//
// Sentence-wide is the calibrated width, and it is what an earlier copula-tight
// form got wrong: "TeardownScope is implemented by both engines but reached by
// no product path" denies the caller in as plain a sentence as English has, and
// was reported as a lie because the denial arrives four words late. A guard that
// punishes a true sentence is a guard someone switches off.
//
// The two directions are NOT symmetric, and building them separately is the
// point. Ahead of the subject, a negation is reliably ABOUT the subject: English
// puts the thing denied after the denial ("nothing calls it", "no path reaches
// it"). Behind the subject it may equally be about a consequence — and a claim
// trailed by its reassurance ("Close runs <the erase verb>, so no bytes of the
// previous session survive a restart") is the idiomatic form of the exact lie
// this file hunts, not the rare compound sentence an earlier calibration priced
// it as. An operator is reassured in precisely that shape. So the trailing
// direction alone is refused where the sentence also ASSERTS the action
// (eraseActionAssertion); the leading direction is left as it stands.
//
// Not every arm can take these forms, and validate() is what decides. The
// teardown-partner arm's own claim is phrased as a never-rule, so the general
// form would be acquitted by that arm's own lie; it keeps a bespoke acquittal
// and validate() reds if the general form is ever pasted over it.
//
// They return patterns, not compiled expressions, so an arm can OR one together
// with an acquittal of its own.
func leadingDenial(subject string) string {
	return `[^.\n]*` + eraseNegation + `[^.\n]*(?:` + subject + `)[^.\n]*`
}

func trailingDenial(subject string) string {
	return `[^.\n]*(?:` + subject + `)[^.\n]*` + eraseNegation + `[^.\n]*`
}

// eraseActionAssertion is what disqualifies a trailing denial from acquitting: a
// sentence that STATES THE ACTION cannot be read as denying it, whatever it goes
// on to deny afterwards.
//
// Two shapes, one per way this file names the action. A calling verb that
// reaches the erase verb with no other identifier in between is a call OF the
// verb; the intervening class forbids a capital, so a sentence that says the
// compose path calls ProvisionScope and then denies the erase verb a caller does
// NOT qualify — the call it asserts is of the other identifier, and what follows
// really is a denial. And the teardown said in the ACTIVE voice ("the stop path
// tears down the workspace") asserts the action the way the passive ("the
// workspace is torn down by nothing") denies it, which is what separates that
// arm's lie from that arm's own honest denial.
//
// Case folding is scoped, not global: the intervening class is written as a
// NEGATED one, and a global `(?i)` would fold `A-Z` into `A-Za-z` and forbid the
// ordinary lowercase words the gap is there to allow.
//
// Stated limit, recall side: the passive assertion is out of reach. "<the erase
// verb> is run on every stop, so nothing survives" states the call as plainly as
// the active form does and is not refused — because "<the erase verb> is called
// by nothing in the product" is the same grammar and is honest, so refusing the
// passive would buy that recall back with a false red on a plain denial.
//
// Stated limit, precision side: the first shape keys on PROXIMITY, not on
// objecthood. It reads a listed calling verb, then at most 24 characters holding
// no capital, no semicolon and no period, then the identifier — and nothing in
// that decides WHOSE verb it is. So a sentence whose listed verb governs some
// other object, and which only then denies the erase verb a caller, has its
// trailing acquittal refused and is reported as a lie.
//
// Measured at this revision: five such sentences planted as comments in a
// scanned daemon file, all five reported, all five by the product-path arm.
// "Close runs a bounded drain, and <the erase verb> has no product caller at
// all." — the leading verb belongs to the drain. "Close runs the drain and <the
// erase verb> is called by nothing in the product." "the readyz probe fires
// every 10s and <the erase verb> is reached by nothing." "the boot path calls
// the scaffold and <the erase verb> is reached by no product path."
// "Provisioning runs at boot while <the erase verb> is reached by nothing." The
// same five sentences against the revision before this refusal landed: rc=0.
// This refusal is what reports them.
//
// The 24-character gap is the whole boundary, and it is arbitrary from the
// sentence's point of view. Measured on one sentence held otherwise fixed: a gap
// of 24 reds, the same clause lengthened to 25 goes green, one capital anywhere
// inside the gap goes green, one semicolon inside it goes green. That is why the
// honest denial shipped in `internal/broker/broker.go` survives — it names a
// call of ANOTHER identifier, and the capitals and the semicolon that identifier
// happens to carry are what clear the refusal, not anything the guard
// understands about which verb governs what.
//
// When this fires on prose that is true, the cheap move is to reword: give the
// denial its own sentence, push the intervening clause past 24 characters, or
// pick a verb the list does not hold. The other move is eraseHonestProse, and it
// SUPPRESSES NOTHING. Adding the sentence there moves the red out of the corpus
// scan and into the honest-prose loop, where it is reported against the sentence
// instead of against whichever shipped file carries it, and the test still
// fails — measured. That is the point of that list: it turns a complaint about
// an author's prose into a complaint about this calibration, and the calibration
// is then what has to change.
var eraseActionAssertion = regexp.MustCompile(`\b(?i:runs?|calls?|invokes?|triggers?|fires?|schedules?|performs?|executes?)\b[^.\n;A-Z]{0,24}(?i:` +
	eraseVerb + `)\b|\b(?i:tears?|tearing)[- ]down\b`)

// eraseAttribution is what turns a lifecycle word standing near the erase verb
// into a CLAIM that the lifecycle moment performs it: an enumeration opener —
// a bracket, a colon, a dash, an equals — introducing the verb within at most
// two qualifier words, the way the docstring this arm was built for enumerated
// what a Close does: "Closes it for teardown (engine <the erase verb> +
// registry/ceilings Release)". The verb is written as a placeholder here for the
// same reason the stop-deadline guard writes its prose examples with one: an
// example that spells the identifier out IS the claim, and this file is inside
// the corpus it scans.
//
// Requiring the marker is the calibration. Mere co-occurrence is not a claim:
// "Close is the lifecycle counterpart of ProvisionScope, while TeardownScope is
// the engine's erase verb" is a definition, names no call, and was reported as a
// lie by a pattern that asked only for a lifecycle word within sixty characters
// of the identifier.
//
// Stated limits, one in each direction, because this marker costs both.
//
// Recall: a claim that joins the two with no connector at all ("Close and <the
// erase verb> run together") is invisible to this arm. The explicit-verb shapes
// belong to product-path-runs-the-erase-verb, and that hand-off covers a good
// deal less than it reads, because the arm it hands to carries a CLOSED verb
// list. That list admits runs, calls, invokes, triggers, fires, schedules,
// performs and executes, and nothing else. A same-family claim written with a
// ninth verb reaches no arm at all: this one asks for its enumeration marker and
// finds none, and that one asks for a listed verb and finds none.
//
// Measured, eight sentences of that family planted as comments in a scanned
// daemon file — reaches, hits, drives, issues, enters, completes, initiates,
// applies — eight of eight green, rc=0 over the whole corpus. Substituting a
// listed verb into those same eight sentences reported eight of eight. The verb
// is the entire difference; nothing else in them changed.
//
// The tail is unbounded by construction, which is why this is a limit to know
// rather than one to close. English closes no set of verbs meaning "to call", so
// each entry added to that list buys exactly the one synonym it spells and the
// next author reaches for the next one. Read the hand-off as covering the eight
// verbs the other arm lists, not as covering explicit-verb prose.
//
// Precision, which is narrowed here but NOT complete: an em-dash parenthetical
// CLOSES with the character an enumeration OPENS with, so "Close — drain,
// ceilings release, handle-store fd — <the erase verb> is an engine primitive,
// unreached from here" is read as an enumeration of what a Close does and
// reported as a lie. It is an honest sentence and it reds. Telling a closing
// dash from an opening one means matching the pair, and dropping the dash from
// the opener would blind the arm to the docstring shape it was built for; an
// author who meets this reaches for a comma or a bracket pair instead. The
// residue is left named rather than chased.
const eraseAttribution = "(?:[(\\[:=]|—|--)[ \t`*_\"']*(?:\\w+[ \t`*_\"']+){0,2}"

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
	// exceptTrailing acquits the same way, and is REFUSED when the sentence it
	// matched also asserts the action (eraseActionAssertion). It is where a
	// denial that arrives behind the subject goes, because that is the position a
	// negation can belong to a consequence rather than to the subject.
	exceptTrailing *regexp.Regexp
	// acquitted is a canonical instance of the honest denial. It must be matched
	// by re AND acquitted, which proves the acquittal is both live and
	// load-bearing. Set exactly when an acquittal is set.
	acquitted string
	// truth is what the code actually does, reported when the claim is found.
	truth string
}

// acquits reports whether an acquittal covers a hit at [start,end) in text — the
// hit must fall inside a single acquittal match, not merely share a
// neighbourhood with one. A match of exceptTrailing acquits only if the sentence
// it spans does not also assert the action.
func (p erasePromise) acquits(text string, start, end int) bool {
	covers := func(re *regexp.Regexp, refusable bool) bool {
		if re == nil {
			return false
		}
		for _, m := range re.FindAllStringIndex(text, -1) {
			if m[0] > start || end > m[1] {
				continue
			}
			if refusable && eraseActionAssertion.MatchString(text[m[0]:m[1]]) {
				continue
			}
			return true
		}
		return false
	}
	return covers(p.except, false) || covers(p.exceptTrailing, true)
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
	if p.except == nil && p.exceptTrailing == nil {
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
		// assertion would have looked like while it was there. The retired
		// vocabulary is not a denial, so it is spelled out here; a plain denial
		// on either side of the phrase is acquitted by the general form.
		except: regexp.MustCompile(`(?i)[^.\n]*\b(?:retired|removed|deleted|dropped|former(?:ly)?|old|previous(?:ly)?|superseded|no longer)\b[^.\n]*erase[-\s]at[-\s]provision|` +
			leadingDenial(`erase[-\s]at[-\s]provision`)),
		exceptTrailing: regexp.MustCompile(`(?i)` + trailingDenial(`erase[-\s]at[-\s]provision`)),
		acquitted:      "On the retired erase-at-provision semantics the scope booted empty.",
		truth:          "ProvisionScope is ensure-scaffold-if-absent: it creates the scope when absent and sweeps only the staging sub-directory. Owner data at the scope root survives every provision.",
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
		except:         regexp.MustCompile(`(?i)` + leadingDenial(`\b(?:torn|tears?|tearing)[- ]down\b`)),
		exceptTrailing: regexp.MustCompile(`(?i)` + trailingDenial(`\b(?:torn|tears?|tearing)[- ]down\b`)),
		acquitted:      "A provisioned scope is torn down by nothing on the stop path.",
		truth:          "The post-provision rollback latch is release-only: it closes the durable handle-store descriptor and leaves the scope exactly as provisioned. A scope outlives the composition that provisioned it and the process that served it.",
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
		// the semicolon turns that denial into a claim. The canonical instance
		// is one the earlier, copula-tight form got wrong — the denial lands
		// nine words after the verb and is no less a denial for it, and it
		// names a call of the OTHER identifier, which is what the trailing
		// direction's refusal has to tell apart from a call of this one.
		except:         regexp.MustCompile(`(?i)` + leadingDenial(eraseVerb)),
		exceptTrailing: regexp.MustCompile(`(?i)` + trailingDenial(eraseVerb)),
		acquitted:      "The compose path calls ProvisionScope; " + eraseVerb + " is implemented by both engines but reached by no product path.",
		truth:          "No product path calls the verb — not compose, not the rollback latch, not Close. The engines implement it and the tests exercise it; nothing else reaches it.",
	},
	{
		// The identifier-shaped variant of scope-torn-down. That arm requires the
		// literal word "scope", so it cannot see a claim that spells the scope
		// INSIDE the verb's name — there is no word boundary in the middle of
		// `TeardownScope`, and prose that says "Close tears down (engine
		// TeardownScope)" names the erase without ever writing "scope" as a word.
		// This arm keys on the lifecycle moment instead: a stop, a close or a
		// teardown said to CARRY the erase verb with it, which is eraseAttribution
		// — the enumeration marker that separates a claim from a definition.
		id: "lifecycle-carries-the-erase-verb",
		re: regexp.MustCompile(`(?i)\b(?:close[sd]?|closing|shut[- ]?down|shuts down|stop(?:s|ped|ping)?|teardown|tears?[- ]down|torn[- ]down|tearing[- ]down|exit(?:s|ing)?)\b[^.\n]{0,60}` +
			eraseAttribution + eraseVerb + `\b`),
		lie: "the caller serves the returned Server and Closes it for teardown " +
			"(engine " + eraseVerb + " + registry/ceilings Release).",
		except:         regexp.MustCompile(`(?i)` + leadingDenial(eraseVerb)),
		exceptTrailing: regexp.MustCompile(`(?i)` + trailingDenial(eraseVerb)),
		acquitted:      "Close is the stop path: " + eraseVerb + " is implemented by both engines but reached by no product path.",
		truth:          "Close drains, releases the ceilings entry and closes the handle-store fd. No lifecycle moment — not close, not stop, not exit — reaches the erase verb.",
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

// eraseHonestProse is prose that tells the reader the truth. No promise may hit
// any of it.
//
// It is the ledger's third direction, and the one a ledger like this usually
// lacks. The two arms above pin what a lie looks like; without this list nothing
// pins what a TRUTH looks like, and every widening of a claim pattern is free to
// buy its recall with false reds. False reds are the expensive failure here: an
// author whose honest sentence is called a lie edits the sentence to appease the
// regex, or deletes the guard.
//
// It is not sufficient on its own, and reading it as a licence to widen an
// acquittal is what cost a round of recall: it prices a false red and prices
// nothing at all for a lie that slips through. eraseClaimWithReassurance is the
// other half, and the two are meant to be read together.
//
// The first four are the sentences a calibration pass wrote into a daemon source
// file to find out; two of them were reported as lies, and the two arms they hit
// are the ones eraseAttribution and the denial builders now calibrate. The rest
// are the honest denials the acquittals must cover from either side of the verb;
// the last two are also the canonical instance their own arm carries.
var eraseHonestProse = []string{
	"on stop the daemon drains; " + eraseVerb + " is implemented by both engines but reached by no product path.",
	"Close is the lifecycle counterpart of ProvisionScope, while " + eraseVerb + " is the engine's erase verb.",
	eraseVerb + " exists on both engines: the local-volume engine removes the scope directory and the S3 engine deletes the prefix.",
	"the stop path closes both listeners and releases the ceilings entry; nothing on it reaches " + eraseVerb + ".",
	"Nothing in the product calls `" + eraseVerb + "`.",
	"Close does NOT call " + eraseVerb + ": shutdown is not an owner change.",
	"A provisioned scope is never torn down.",
	"There is no teardown partner.",
	"On the retired erase-at-provision semantics the scope booted empty.",
}

// eraseClaimWithReassurance is prose that CLAIMS the erase runs and then
// reassures the reader about what follows from it. Some arm must report every
// sentence here.
//
// It is the ledger's fourth direction and eraseHonestProse's counterweight. On
// its own that list is a one-way ratchet: it prices a false red and prices
// nothing at all for a lie that slips through, so every widening of an acquittal
// can buy its precision with recall and no arm reds. These three are the shape
// that bought it once — the claim leads, the denial trails, and the denial is
// about the CONSEQUENCE ("so no bytes survive", "nothing is left on disk")
// rather than about the call. That is not a rare compound sentence. It is how an
// operator is reassured, which makes it the idiomatic form of the exact lie this
// file exists to catch.
var eraseClaimWithReassurance = []string{
	"Close runs " + eraseVerb + ", so no bytes of the previous session survive a restart.",
	"on SIGTERM the daemon calls " + eraseVerb + "; nothing of the old scope is left on disk.",
	"the stop path tears down the session scope, so nothing of the previous run is readable afterwards.",
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

	// And no arm may call an honest sentence a lie. This runs before the corpus
	// so a widening that buys recall with false reds is reported against the
	// sentence it misreads, not against whichever shipped file happens to carry
	// one first.
	for _, honest := range eraseHonestProse {
		for _, p := range erasePromises {
			for _, m := range p.hits(honest) {
				t.Errorf("promise %q reports honest prose as a lie: %q\n  sentence: %s\n  a guard that reds on a true sentence is a guard an author edits the sentence to appease, or switches off",
					p.id, honest[m[0]:m[1]], honest)
			}
		}
	}

	// And the other direction: a claim that reassures the reader in the same
	// breath is still a claim, and some arm must report it. Without this loop the
	// honest-prose list above is a one-way ratchet — it prices a false red and
	// prices nothing for a lie that gets through.
	for _, claim := range eraseClaimWithReassurance {
		reported := ""
		for _, p := range erasePromises {
			if len(p.hits(claim)) != 0 {
				reported = p.id
				break
			}
		}
		if reported == "" {
			t.Errorf("no arm reports a claim that reassures: %s\n  the erase is claimed and the trailing denial is about the consequence, not about the call; an acquittal that reads it as a denial launders the lie", claim)
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
