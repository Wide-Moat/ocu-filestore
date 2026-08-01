// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- STOP-DEADLINE ----------------------------------------------------------
//
// Four shipped keys tell a service manager how long the daemon may take to
// stop: the systemd unit's TimeoutStopSec, two k8s manifests'
// terminationGracePeriodSeconds, and two compose files' stop_grace_period. Set
// any of them below what a stop can actually cost and the manager SIGKILLs the
// daemon mid-drain — in-flight operations die half-served on a stop the
// operator asked for gracefully.
//
// Those numbers were hand-maintained against a stop model written in prose, and
// prose drifts: they were once sized for a teardown phase that never ran, then
// re-sized for a single drain when the daemon had grown a second listener with
// its own bound. Neither pass was checked against the constants that actually
// bound the stop.
//
// So this guard derives the worst case from those constants and reads every
// stated deadline out of the shipped tree. It reds when a bound grows and when a
// shipped number shrinks, and neither side is written down twice: the durations
// come from the Go source by AST, the deadlines from the tree by scan.
//
// A deadline counts as stated wherever it is written and in whatever dialect.
// An operator who reads only a README gets the stop budget from a sentence, and
// a sentence that quotes a superseded figure misinforms exactly the same reader
// the keys inform. So the English dialect reads sentences, and the systemd
// dialect is unanchored: the same key restated inside backticks mid-paragraph is
// the same claim as the key in the unit file, and holding the second to a line
// anchor let three prose sites — the front page among them — understate the
// shipped budget by 10 s while the guard reported a clean scan.
//
// Recall and precision are pinned against each other. Every dialect must still
// read its own `samples`, and no dialect may read a value out of
// innocentDurationProse: the tree is full of honest sentences about the 25 s
// drain, the 5 s ops close and the 30 s worst case, and a pattern that reads one
// of those as a deadline reds the build against a true sentence.
//
// The model it derives is only honest while the two data-plane listeners close
// CONCURRENTLY — that is what makes the drain term a max instead of a sum.
// TestDualServerClosesBothListenersConcurrently in dualserver_test.go pins that
// shape, and its failure message points back here. The two tests are one guard.

// stopCostAnchor is one bounded phase of the daemon's stop path, named by the
// constant that bounds it. The constant is read from source rather than copied
// so growing it cannot leave this model behind.
type stopCostAnchor struct {
	phase string // what the phase is, in the operator's terms
	file  string // repo-relative Go file declaring the constant
	konst string // the constant's identifier
}

// stopCostAnchors are the three bounds that make up a worst-case graceful stop.
// The two drains overlap (dualServer.Close closes both listeners at once); the
// ops listener is closed afterwards by serveUntilSignal, so its bound is
// additive. Everything else on the stop path — the ceilings release, the
// handle-store fd close, the flock release — is a non-blocking release with no
// bound to carry.
var stopCostAnchors = struct {
	southDrain stopCostAnchor
	northDrain stopCostAnchor
	opsClose   stopCostAnchor
}{
	southDrain: stopCostAnchor{
		phase: "south mount-RPC drain",
		file:  "internal/southface/tlsserver.go",
		konst: "tlsShutdownDrainTimeout",
	},
	northDrain: stopCostAnchor{
		phase: "north Files-API drain (Mount B)",
		file:  "internal/northface/mountb.go",
		konst: "mountDrainTimeout",
	},
	opsClose: stopCostAnchor{
		phase: "ops listener shutdown",
		file:  "internal/telemetry/opslistener.go",
		konst: "opsShutdownDrainTimeout",
	},
}

// durationConst reads a `<int> * time.<Unit>` constant out of a Go source file
// by name. A constant that cannot be found or cannot be evaluated is a FATAL
// error, never a zero: a silently-missing anchor would understate the worst
// case and pass every deadline below it.
func durationConst(t *testing.T, root string, a stopCostAnchor) time.Duration {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(a.file))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s for the %s bound: %v", a.file, a.phase, err)
	}

	var value ast.Expr
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if name.Name == a.konst && i < len(spec.Values) {
				value = spec.Values[i]
			}
		}
		return true
	})
	if value == nil {
		t.Fatalf("%s declares no constant %q; the %s bound has lost its anchor and every shipped stop deadline below it is unverified. Re-point stopCostAnchors at the constant that bounds this phase now.",
			a.file, a.konst, a.phase)
	}

	d, err := evalDurationExpr(value)
	if err != nil {
		t.Fatalf("%s: constant %s is no longer an <int> * time.<Unit> product (%v); teach evalDurationExpr its new form rather than leaving the %s bound unread",
			a.file, a.konst, err, a.phase)
	}
	if d <= 0 {
		t.Fatalf("%s: constant %s evaluates to %v; a non-positive bound cannot be the %s", a.file, a.konst, d, a.phase)
	}
	return d
}

// timeUnits maps the time package's unit selectors to their durations.
var timeUnits = map[string]time.Duration{
	"Nanosecond":  time.Nanosecond,
	"Microsecond": time.Microsecond,
	"Millisecond": time.Millisecond,
	"Second":      time.Second,
	"Minute":      time.Minute,
	"Hour":        time.Hour,
}

// evalDurationExpr evaluates the `<int> * time.<Unit>` form (in either operand
// order) that the daemon's timeout constants are written in.
func evalDurationExpr(e ast.Expr) (time.Duration, error) {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.MUL {
		return 0, fmt.Errorf("want a multiplication, got %T", e)
	}
	scalar, unit := bin.X, bin.Y
	if _, isLit := scalar.(*ast.BasicLit); !isLit {
		scalar, unit = bin.Y, bin.X
	}
	lit, ok := scalar.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, fmt.Errorf("neither operand is an integer literal")
	}
	n, err := strconv.Atoi(lit.Value)
	if err != nil {
		return 0, fmt.Errorf("integer operand %q: %w", lit.Value, err)
	}
	sel, ok := unit.(*ast.SelectorExpr)
	if !ok {
		return 0, fmt.Errorf("unit operand is %T, want a time.<Unit> selector", unit)
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "time" {
		return 0, fmt.Errorf("unit operand is not qualified by the time package")
	}
	u, ok := timeUnits[sel.Sel.Name]
	if !ok {
		return 0, fmt.Errorf("unknown time unit %q", sel.Sel.Name)
	}
	return time.Duration(n) * u, nil
}

// worstCaseStopCost derives the longest a graceful stop can take from the three
// bounds that make it up, and returns the derivation so a failure can show its
// own arithmetic instead of asserting a number.
func worstCaseStopCost(t *testing.T, root string) (time.Duration, string) {
	t.Helper()

	south := durationConst(t, root, stopCostAnchors.southDrain)
	north := durationConst(t, root, stopCostAnchors.northDrain)
	ops := durationConst(t, root, stopCostAnchors.opsClose)

	// The two data-plane drains run concurrently, so the drain phase costs the
	// LONGER of the two, not their sum. The ops listener closes after them.
	drain := south
	if north > drain {
		drain = north
	}
	total := drain + ops

	derivation := fmt.Sprintf(
		"max(%s %v [%s], %s %v [%s]) = %v (concurrent) + %s %v [%s] = %v",
		stopCostAnchors.southDrain.phase, south, stopCostAnchors.southDrain.konst,
		stopCostAnchors.northDrain.phase, north, stopCostAnchors.northDrain.konst,
		drain,
		stopCostAnchors.opsClose.phase, ops, stopCostAnchors.opsClose.konst,
		total)

	return total, derivation
}

// deadlineDialect is one way of spelling a stop deadline — three of them are a
// service manager's manifest key, the fourth is that key restated in prose, the
// fifth is English. Exactly one capture group is non-empty per match and it
// holds the whole-second value.
//
// `samples` are canonical instances the pattern must still read: a rotted
// pattern matches nothing at all and would otherwise report a clean scan
// forever. Every dialect is also held against innocentDurationProse from the
// other side, because a pattern that reads too much is as useless as one that
// reads nothing — it reds on honest sentences until someone deletes it.
type deadlineDialect struct {
	kind    string
	re      *regexp.Regexp
	samples []deadlineSample
}

// deadlineSample is one instance a dialect must still read, and the
// whole-second value it carries.
type deadlineSample struct {
	text string
	want int
}

// The pieces the English dialect is built from. They are named because two
// branches share them and because each one is a decision.
const (
	// wordGap separates two words of one statement. Prose WRAPS, so it crosses
	// at most one line break: the shipped sentence that states the k8s and
	// compose budget puts "carry the" at the end of one line and "same 35 s" at
	// the start of the next, and a gap that stopped at the newline would read
	// neither half.
	wordGap = `(?:[ \t]+|[ \t]*\n[ \t]*)`
	// markupRun is the decoration that can sit between a key and the words
	// around it — a closing code tick, an emphasis marker, a quote.
	markupRun = "[`*_\"']*"
	// secondsValue is a whole-second value written for a READER rather than for
	// a parser: the digits, an optional space, and either the bare `s` suffix or
	// the spelled-out unit. The space is what made "35 s" invisible to a pattern
	// that demanded `(\d+)s`, and "35 s" is how the front page writes it.
	secondsValue = `(\d+)[ \t]*(?:s\b|seconds?\b)`
	// deadlineTail is what follows the NAME of the grace: an optional connector
	// — a colon, a copula, a "carries the same" — and then the value. Every
	// connector is spelled out. A gap that accepted any words at all would read
	// "the stop grace covers the 30s drain" as a 30-second grace, and that
	// sentence is honest: the 30 s belongs to the drain.
	deadlineTail = markupRun + `(?:` +
		`[ \t]*:` +
		`|` + wordGap + `(?:of|is|are|at|was|were|set` + wordGap + `to)` +
		`|` + wordGap + `(?:\w+` + wordGap + `)?the` + wordGap + `same` +
		`)?` + wordGap + secondsValue
)

// seconds returns the whole-second value a match carries. An alternation spells
// the number in a different group per branch, so the value is the first
// non-empty capture; no capture at all is a pattern bug, never a zero, because
// a zero would silently pass every deadline check below it.
func (d deadlineDialect) seconds(m []string) (int, error) {
	for _, g := range m[1:] {
		if g == "" {
			continue
		}
		return strconv.Atoi(g)
	}
	return 0, fmt.Errorf("dialect %q matched %q but captured no value", d.kind, m[0])
}

var deadlineDialects = []deadlineDialect{
	{
		// Not line-anchored, because the unit file is not the only place this key
		// is stated with a value. docs/operations.md restates it inside backticks
		// mid-sentence, to tell an operator what the contrib unit sets, and a
		// pattern anchored to the start and end of a line could not see it: the
		// restatement understated the budget by 10 s and the guard reported a
		// clean scan. A key is a key wherever it is written down.
		kind: "systemd TimeoutStopSec",
		re:   regexp.MustCompile(`\bTimeoutStopSec[ \t]*=[ \t]*(\d+)s?\b`),
		samples: []deadlineSample{
			{"TimeoutStopSec=35s", 35},
			{"the contrib unit sets `TimeoutStopSec=35s`, above the worst case", 35},
		},
	},
	{
		kind: "k8s terminationGracePeriodSeconds",
		re:   regexp.MustCompile(`(?m)^[ \t]*terminationGracePeriodSeconds:[ \t]*(\d+)[ \t]*$`),
		samples: []deadlineSample{
			{"      terminationGracePeriodSeconds: 35", 35},
		},
	},
	{
		kind: "compose stop_grace_period",
		re:   regexp.MustCompile(`(?m)^[ \t]*stop_grace_period:[ \t]*(\d+)s[ \t]*$`),
		samples: []deadlineSample{
			{"    stop_grace_period: 35s", 35},
		},
	},
	{
		// The English dialect. An operator reading a README learns the stop budget
		// from a sentence, not from a manifest key, and a sentence drifts on its
		// own schedule: the manifest keys were raised in one commit and three
		// prose sites went on quoting the superseded figure, understating the
		// budget by the exact margin that had been added to cover the second
		// listener. A number stated in prose is a shipped number.
		//
		// The pattern is built out of deadlineTail, and it is narrow by
		// construction: it is NOT enough for a number and the word "stop" to
		// share a sentence. The value must be ADJACENT to the name of the grace —
		// just before it ("the <N>s stop grace"), or after it through a connector
		// this file spells out one by one ("stop grace: <N>s", "a stop grace of
		// <N> seconds", "the compose key and the k8s key carry the same <N> s").
		// The third branch reads the other word order, the one the front page and
		// the operations guide both use: "the grace period on stop is <N>s".
		//
		// The examples above are written with a placeholder on purpose: an English
		// pattern matches English, and a real number in a comment would enter the
		// scan as a shipped deadline. The instances that SHOULD are `samples`, and
		// this file is declared in the ledger as carrying them.
		//
		// Stated limits. A connector the list does not name leaves the sentence
		// unread ("the compose key and the k8s key are both <N> s" states a
		// deadline this dialect does not see), and so does a value more than one
		// line break from the name it belongs to. Widening either one is what
		// would start reading honest sentences about the drain, the poll interval
		// and the CI job as stop deadlines, which innocentDurationProse pins.
		kind: "prose stop grace",
		re: regexp.MustCompile(`(?i)(?:` +
			secondsValue + wordGap + `stop[-_ ]grace\b` +
			`|\bstop[-_ ]grace(?:[-_ ]period)?\b` + deadlineTail +
			`|\bgrace(?:[-_ ]period)?` + wordGap + `on` + wordGap + `stop\b` + deadlineTail +
			`)`),
		samples: []deadlineSample{
			{"the 35s stop grace above the daemon's worst-case stop", 35},
			{"a stop grace of 35 seconds", 35},
			{"stop grace: 35s", 35},
			{"the grace period on stop is 35s", 35},
			{"`stop_grace_period` is 35 s, above the daemon's worst case", 35},
			// The wrapped form. Prose puts the connector at the end of one line
			// and the value at the start of the next; this instance is written
			// with an escape so it exercises the wrap in the pattern check
			// without entering the scan as a fifth number in this file. The live
			// proof that the wrap is read is the ledger entry for
			// docs/operations.md, which states its budget exactly this way and
			// would report a stale entry if the wrap stopped matching.
			{"the compose `stop_grace_period` carry the\nsame 35 s", 35},
		},
	},
}

// innocentDurationProse is prose that states a duration which is NOT a stop
// deadline. No dialect may read a value out of any of it.
//
// It is the recall widening's counterweight and it is not optional. Every
// sentence here was written to sit one word away from a real statement of the
// grace: the drain and the ops close are the two terms the grace is DERIVED
// from, "the stop grace covers the 30s drain" names the grace and a number in
// one breath without stating the grace, and "a 30s grace" is the grace's own
// noun with the qualifier that makes it a stop deadline missing. A dialect that
// reads any of them reports a false deadline, and a false deadline is a red
// build against an honest sentence.
var innocentDurationProse = []string{
	"the 5s poll interval",
	"a 90s CI job",
	"30 s in the worst case",
	"the 25s drain plus the 5s ops close",
	"the client retries every 10s with a 3s timeout and gives up after 60s",
	"the stop grace covers the 30s drain",
	"this deployment once inherited a 30s grace before the second listener landed",
}

// shippedStopDeadlines is the ledger of files that carry a stop deadline, and
// the dialects each one carries. It is checked in BOTH directions against a scan
// of the tracked tree: a file that sets a deadline in a dialect not listed for it
// goes unchecked until it is added here, and a listed dialect whose file stopped
// carrying one is a hard error rather than a quietly-skipped line.
//
// A file can carry more than one dialect. The two compose files state the same
// budget twice — once as the key the daemon is stopped by, once in the comment
// that justifies it — and both statements are read by someone.
var shippedStopDeadlines = map[string][]string{
	"contrib/systemd/ocu-filestored.service": {"systemd TimeoutStopSec"},
	"examples/k8s/broker-deployment.yaml":    {"k8s terminationGracePeriodSeconds"},
	"examples/k8s/sandbox-peer-pod.yaml":     {"k8s terminationGracePeriodSeconds"},
	"deploy/docker-compose.yml":              {"compose stop_grace_period", "prose stop grace"},
	"deploy/docker-compose.fleet.yml":        {"compose stop_grace_period", "prose stop grace"},
	"deploy/README.md":                       {"prose stop grace"},
	// The repository's front page states the compose grace in a sentence, and
	// the operations guide states it twice more: once as the systemd key
	// restated inside backticks, once as the k8s and compose keys carrying the
	// same figure across a line break. All three were invisible until the
	// dialects above were widened, and all three go stale the moment a manifest
	// is raised without them. README.md is the first page a reader sees.
	"README.md":          {"prose stop grace"},
	"docs/operations.md": {"prose stop grace", "systemd TimeoutStopSec"},
	// This guard's own canonical instances. Unlike the two YAML dialects, whose
	// patterns are line-anchored and so cannot match a sample sitting inside a
	// Go literal, an English sentence and an unanchored key match wherever they
	// are written — including here. Declaring them is the honest resolution: the
	// scan gets no self-exemption, and every sample is held to the same
	// worst-case coverage as a shipped number, which is what makes it canonical.
	"cmd/ocu-filestored/stop_deadline_test.go": {"prose stop grace", "systemd TimeoutStopSec"},
}

// stopDeadline is one deadline found in one shipped file.
type stopDeadline struct {
	file    string
	kind    string
	seconds int
}

func (d stopDeadline) String() string {
	return fmt.Sprintf("%s (%s) = %ds", d.file, d.kind, d.seconds)
}

// discoverStopDeadlines scans every TRACKED file for a stop deadline in any of
// the dialects. Tracked is the definition of shipped; the vendored contracts are
// excluded because they are upstream artifacts this repo may not edit.
func discoverStopDeadlines(t *testing.T, root string) []stopDeadline {
	t.Helper()

	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files for the deadline scan: %v", err)
	}
	files := strings.Split(string(out), "\x00")
	scanned := 0
	var found []stopDeadline

	for _, rel := range files {
		if rel == "" || strings.HasPrefix(rel, "contracts/") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if rerr != nil {
			t.Fatalf("read tracked file %q: %v", rel, rerr)
		}
		scanned++
		content := string(b)
		for _, d := range deadlineDialects {
			for _, m := range d.re.FindAllStringSubmatch(content, -1) {
				secs, cerr := d.seconds(m)
				if cerr != nil {
					t.Fatalf("%s: %s match %q does not yield a whole number of seconds: %v", rel, d.kind, m[0], cerr)
				}
				found = append(found, stopDeadline{file: rel, kind: d.kind, seconds: secs})
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no tracked files; the deadline scan is vacuous")
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].file != found[j].file {
			return found[i].file < found[j].file
		}
		return found[i].kind < found[j].kind
	})
	t.Logf("scanned %d tracked files; found %d shipped stop deadline(s)", scanned, len(found))
	return found
}

// TestShippedStopDeadlinesCoverWorstCaseStopCost asserts every service manager's
// stop deadline leaves room for the longest stop the daemon can take. It reds
// from either side: grow a drain bound and the deadlines stop covering it;
// shrink a shipped number and it stops clearing the bound.
func TestShippedStopDeadlinesCoverWorstCaseStopCost(t *testing.T) {
	root := repoRoot(t)

	// A pattern that no longer matches its own canonical instance is dead and
	// would report an empty scan forever.
	for _, d := range deadlineDialects {
		for _, s := range d.samples {
			m := d.re.FindStringSubmatch(s.text)
			if m == nil {
				t.Fatalf("dialect %q no longer matches its own instance %q; the pattern is dead and the scan is vacuous", d.kind, s.text)
			}
			got, err := d.seconds(m)
			if err != nil || got != s.want {
				t.Fatalf("dialect %q read %v from %q, want %d; the pattern reads the wrong field", d.kind, m[1:], s.text, s.want)
			}
		}
	}

	// And the other side: no dialect may read a deadline out of a sentence that
	// states some other duration. This runs before the scan so a widening that
	// buys recall with false reds is reported against the sentence it misreads.
	for _, innocent := range innocentDurationProse {
		for _, d := range deadlineDialects {
			m := d.re.FindStringSubmatch(innocent)
			if m == nil {
				continue
			}
			got, _ := d.seconds(m)
			t.Errorf("dialect %q reads a %ds stop deadline out of %q, which states no stop deadline; the pattern is too wide and would red on honest prose",
				d.kind, got, innocent)
		}
	}

	worst, derivation := worstCaseStopCost(t, root)
	t.Logf("worst-case graceful stop: %s", derivation)

	found := discoverStopDeadlines(t, root)

	// Both directions against the ledger, per file AND per dialect: a file that
	// sets a deadline in a dialect not declared for it would go unchecked, and a
	// declared dialect the scan no longer finds leaves a stale entry standing in
	// for a guard that no longer runs.
	seen := make(map[string]map[string]bool, len(shippedStopDeadlines))
	for _, d := range found {
		if seen[d.file] == nil {
			seen[d.file] = make(map[string]bool)
		}
		seen[d.file][d.kind] = true

		declared := false
		for _, kind := range shippedStopDeadlines[d.file] {
			if kind == d.kind {
				declared = true
				break
			}
		}
		if !declared {
			t.Errorf("%s states a stop deadline in a dialect shippedStopDeadlines does not declare for that file (declared: %v); add it so the guard covers it",
				d, shippedStopDeadlines[d.file])
		}
	}
	for file, kinds := range shippedStopDeadlines {
		for _, kind := range kinds {
			if !seen[file][kind] {
				t.Errorf("shippedStopDeadlines declares %s (%s) but the scan found no such deadline there; retire the stale entry or restore the deadline", file, kind)
			}
		}
	}

	for _, d := range found {
		if time.Duration(d.seconds)*time.Second > worst {
			continue
		}
		t.Errorf("%s does not clear the worst-case stop cost of %v — a stop that runs long is SIGKILLed mid-drain and in-flight operations die half-served.\n  derivation: %s\n  raise the deadline above %v, or lower the bound it fails to cover",
			d, worst, derivation, worst)
	}
}
