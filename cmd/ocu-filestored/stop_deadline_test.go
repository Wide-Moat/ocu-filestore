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
// A deadline counts as stated whether it is spelled as a manifest key or in
// English. An operator who reads only deploy/README.md gets the stop budget from
// a sentence, and a sentence that quotes a superseded figure misinforms exactly
// the same reader the keys inform. The prose dialect in deadlineDialects is what
// holds those sentences to the same derivation.
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

// deadlineDialect is one way of spelling a stop deadline — four of them are a
// service manager's key, the fifth is English. Exactly one capture group is
// non-empty per match and it holds the whole-second value. `sample` is a
// canonical instance the pattern must still match: a rotted pattern matches
// nothing at all and would otherwise report a clean scan forever.
type deadlineDialect struct {
	kind   string
	re     *regexp.Regexp
	sample string
	want   int
}

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
		kind:   "systemd TimeoutStopSec",
		re:     regexp.MustCompile(`(?m)^TimeoutStopSec=(\d+)s?[ \t]*$`),
		sample: "TimeoutStopSec=35s",
		want:   35,
	},
	{
		kind:   "k8s terminationGracePeriodSeconds",
		re:     regexp.MustCompile(`(?m)^[ \t]*terminationGracePeriodSeconds:[ \t]*(\d+)[ \t]*$`),
		sample: "      terminationGracePeriodSeconds: 35",
		want:   35,
	},
	{
		kind:   "compose stop_grace_period",
		re:     regexp.MustCompile(`(?m)^[ \t]*stop_grace_period:[ \t]*(\d+)s[ \t]*$`),
		sample: "    stop_grace_period: 35s",
		want:   35,
	},
	{
		// The English dialect. An operator reading deploy/README.md learns the
		// stop budget from a sentence, not from a manifest key, and a sentence
		// drifts on its own schedule: the four keys above were raised in one
		// commit and a README went on quoting the superseded figure, understating
		// the budget by the exact margin that had been added to cover the second
		// listener. A number stated in prose is a shipped number.
		//
		// The pattern is deliberately narrow. It is NOT enough for a number and
		// the word "stop" to share a sentence: the tree is full of honest prose
		// about the 30 s worst case, the 25 s drain and the 5 s ops close, and
		// every one of those would be a false red. The number must be ADJACENT to
		// the phrase "stop grace" — either just before it ("the <N>s stop grace")
		// or just after the key it names ("stop_grace_period <N>s") — because that
		// adjacency is what makes the sentence a statement of the GRACE rather
		// than of some other duration on the stop path. The examples are written
		// with a placeholder on purpose: an English pattern matches English, and
		// a real number here would enter the scan as a shipped deadline. The one
		// instance that SHOULD is `sample`, and it is declared as such below.
		kind: "prose stop grace",
		re: regexp.MustCompile(`(?i)(?:\b(\d+)s[ \t]+stop[-_ ]grace\b` +
			`|\bstop[-_ ]grace(?:[-_ ]period)?[ \t]+(?:of[ \t]+|is[ \t]+|at[ \t]+)?(\d+)s\b)`),
		sample: "the 35s stop grace above the daemon's worst-case stop",
		want:   35,
	},
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
	// The prose dialect's own canonical instance. Unlike the four key dialects,
	// whose patterns are line-anchored and so cannot match their own sample
	// sitting on a `sample:` line, an English pattern matches English wherever it
	// is written — including here. Declaring it is the honest resolution: the
	// scan gets no self-exemption, and the sample is held to the same worst-case
	// coverage as a shipped number, which is what makes it canonical.
	"cmd/ocu-filestored/stop_deadline_test.go": {"prose stop grace"},
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
		m := d.re.FindStringSubmatch(d.sample)
		if m == nil {
			t.Fatalf("dialect %q no longer matches its own instance %q; the pattern is dead and the scan is vacuous", d.kind, d.sample)
		}
		got, err := d.seconds(m)
		if err != nil || got != d.want {
			t.Fatalf("dialect %q read %v from %q, want %d; the pattern reads the wrong field", d.kind, m[1:], d.sample, d.want)
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
