// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

// envFallbackMap is a hand-maintained mirror of the daemon's flag surface, and
// the existing coverage checks one direction only: every flag the TEST declares
// appears in the map. The test builds its own FlagSet, so it never touches the
// flags the daemon registers, and a map entry naming a flag that no longer
// exists passes unnoticed. The ADR-0042 rename left five such entries.
//
// That is not cosmetic. applyEnvFallbacks calls fs.Set(flagName, …) for every
// entry whose env var is populated, and fs.Set on an unregistered name returns
// an error — so a stale entry turns a set env var into a boot refusal naming a
// flag the binary does not have. The reverse gap is quieter and worse: a flag
// absent from the map has NO env fallback, so a deployment configuring it
// through the environment silently gets the default. For -credential-jwks-path
// that means running with no trust anchor.
//
// These bind both directions to the flags runCtx really registers, read out of
// the daemon's own usage output rather than mirrored a second time.

// flagLine matches the leading "  -name" of a flag entry in flag package usage
// output. Defaults and descriptions are indented further, so anchoring on the
// two-space + dash prefix picks out names and nothing else.
var flagLine = regexp.MustCompile(`(?m)^\s{2}-([a-z0-9-]+)`)

// registeredFlags reads the daemon's real flag surface from the usage text it
// prints when parse fails. It reads rather than mirrors, which is the point —
// a mirror is what failed.
func registeredFlags(t *testing.T) map[string]struct{} {
	t.Helper()

	// The daemon sets no FlagSet output, so flag writes usage to os.Stderr.
	// Swapping it for a pipe reads the real surface without a production seam;
	// a hook added for the test would be the same mirroring problem in a new
	// shape. Serial by construction — the package's tests do not run in
	// parallel, and t.Cleanup restores the handle either way.
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = orig })

	drained := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		drained <- string(b)
	}()

	// An undefined flag makes flag.ContinueOnError print the full usage and
	// return an error, without the daemon binding a port, writing a file, or
	// blocking.
	parseErr := run([]string{"--this-flag-does-not-exist"})
	_ = w.Close()
	os.Stderr = orig
	usage := <-drained

	if parseErr == nil {
		t.Fatal("an undefined flag was accepted; this test cannot read the surface")
	}

	got := make(map[string]struct{})
	for _, m := range flagLine.FindAllStringSubmatch(usage, -1) {
		got[m[1]] = struct{}{}
	}
	if len(got) < 10 {
		t.Fatalf("parsed only %d flags out of the usage text; the format changed and "+
			"this test now asserts almost nothing:\n%s", len(got), usage)
	}
	return got
}

// TestEveryEnvFallbackEntryNamesALiveFlag is the direction the old test could
// not check. A stale entry makes a populated env var a boot refusal.
func TestEveryEnvFallbackEntryNamesALiveFlag(t *testing.T) {
	live := registeredFlags(t)
	for name := range envFallbackMap {
		if _, ok := live[name]; !ok {
			t.Errorf("envFallbackMap names %q, which the daemon no longer registers; "+
				"setting %s would make applyEnvFallbacks call fs.Set on an unknown "+
				"flag and refuse to boot", name, envVarName(name))
		}
	}
}

// TestEveryLiveFlagHasAnEnvFallbackOrAnExclusion is the other direction. A flag
// missing from the map has no env fallback, and the omission is silent: the
// deployment sets OCU_FILESTORE_X, the daemon ignores it, the default stands.
func TestEveryLiveFlagHasAnEnvFallbackOrAnExclusion(t *testing.T) {
	for name := range registeredFlags(t) {
		if _, excluded := credentialBearingFlags[name]; excluded {
			continue
		}
		if _, ok := envFallbackMap[name]; !ok {
			t.Errorf("flag %q has no envFallbackMap entry and is not listed in "+
				"credentialBearingFlags; a deployment setting %s gets the default "+
				"and no diagnostic", name, envVarName(name))
		}
	}
}

// TestStaleEnvVarDoesNotRefuseBoot states the consequence as behaviour rather
// than as a set comparison: an env var left over from the pre-ADR-0042 flag
// names must not brick the daemon.
//
// The two comparisons above would both stay green if applyEnvFallbacks started
// ignoring unknown names instead. This one pins that the daemon tolerates the
// leftover, which is the property an operator meets at 3am.
func TestStaleEnvVarDoesNotRefuseBoot(t *testing.T) {
	for _, stale := range []string{
		"OCU_FILESTORE_CLAIMS_BIND",
		"OCU_FILESTORE_VERIFY_STORAGE_JWT",
		"OCU_FILESTORE_STORAGE_JWKS_PATH",
	} {
		t.Setenv(stale, "true")
	}
	// -version exercises parse + applyEnvFallbacks and returns before anything
	// serves, so a refusal here is the env fallback rejecting a name.
	if err := run([]string{"--version"}); err != nil {
		if strings.Contains(err.Error(), "env var") {
			t.Fatalf("a leftover pre-rename env var refused the boot: %v", err)
		}
		t.Fatalf("--version: %v", err)
	}
}
