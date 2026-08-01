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
// Five shipped files tell a service manager how long the daemon may take to
// stop: the systemd unit's TimeoutStopSec, two k8s manifests'
// terminationGracePeriodSeconds, and two compose files' stop_grace_period. Set
// any of them below what a stop can actually cost and the manager SIGKILLs the
// daemon mid-drain — in-flight operations die half-served on a stop the
// operator asked for gracefully.
//
// Those five numbers were hand-maintained against a stop model written in
// prose, and prose drifts: the numbers were once sized for a teardown phase
// that never ran, then re-sized for a single drain when the daemon had grown a
// second listener with its own bound. Neither pass was checked against the
// constants that actually bound the stop.
//
// So this guard derives the worst case from those constants and reads the five
// numbers out of the shipped files. It reds when a bound grows and when a
// shipped number shrinks, and neither side is written down twice: the durations
// come from the Go source by AST, the deadlines from the manifests by parse.
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

// deadlineDialect is one service manager's way of spelling a stop deadline. The
// capture group is the whole-second value. `sample` is a canonical instance the
// pattern must still match: a rotted pattern matches nothing at all and would
// otherwise report a clean scan forever.
type deadlineDialect struct {
	kind   string
	re     *regexp.Regexp
	sample string
	want   int
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
}

// shippedStopDeadlines is the ledger of files that carry a stop deadline. It is
// checked in BOTH directions against a scan of the tracked tree: a new manifest
// that sets a deadline must be added here, and an entry whose file stopped
// carrying one is a hard error rather than a quietly-skipped line.
var shippedStopDeadlines = map[string]string{
	"contrib/systemd/ocu-filestored.service": "systemd TimeoutStopSec",
	"examples/k8s/broker-deployment.yaml":    "k8s terminationGracePeriodSeconds",
	"examples/k8s/sandbox-peer-pod.yaml":     "k8s terminationGracePeriodSeconds",
	"deploy/docker-compose.yml":              "compose stop_grace_period",
	"deploy/docker-compose.fleet.yml":        "compose stop_grace_period",
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
				secs, cerr := strconv.Atoi(m[1])
				if cerr != nil {
					t.Fatalf("%s: %s value %q is not a whole number of seconds: %v", rel, d.kind, m[1], cerr)
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
		got, err := strconv.Atoi(m[1])
		if err != nil || got != d.want {
			t.Fatalf("dialect %q captured %q from %q, want %d; the pattern reads the wrong field", d.kind, m[1], d.sample, d.want)
		}
	}

	worst, derivation := worstCaseStopCost(t, root)
	t.Logf("worst-case graceful stop: %s", derivation)

	found := discoverStopDeadlines(t, root)

	// Both directions against the ledger: an undeclared file that sets a deadline
	// would go unchecked, and a declared file that stopped setting one leaves a
	// stale entry standing in for a guard that no longer runs.
	seen := make(map[string]bool, len(found))
	for _, d := range found {
		seen[d.file] = true
		want, declared := shippedStopDeadlines[d.file]
		if !declared {
			t.Errorf("%s sets a stop deadline but is not in shippedStopDeadlines; add it so the guard covers it", d)
			continue
		}
		if want != d.kind {
			t.Errorf("%s is declared as %q in shippedStopDeadlines but carries a %q deadline", d.file, want, d.kind)
		}
	}
	for file, kind := range shippedStopDeadlines {
		if !seen[file] {
			t.Errorf("shippedStopDeadlines declares %s (%s) but the scan found no deadline there; retire the stale entry or restore the deadline", file, kind)
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
