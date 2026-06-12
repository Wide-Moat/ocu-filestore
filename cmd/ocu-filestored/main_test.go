// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
)

// TestRunRefusesNotBuilt pins the scaffold refusal: a valid flag surface
// still refuses with the typed not-built error in this build.
func TestRunRefusesNotBuilt(t *testing.T) {
	if err := run(nil); !errors.Is(err, errNotBuilt) {
		t.Fatalf("run: got %v, want errNotBuilt", err)
	}
}

// TestRunValidatesEngine pins that an unknown backend engine refuses with
// the typed sentinel, never a silent default.
func TestRunValidatesEngine(t *testing.T) {
	err := run([]string{"--engine", "gcs"})
	if !errors.Is(err, objectstore.ErrUnknownEngine) {
		t.Fatalf("run: got %v, want ErrUnknownEngine", err)
	}
}

// TestRunRejectsBadFlags pins that an unknown flag is a parse error, not a
// silent ignore.
func TestRunRejectsBadFlags(t *testing.T) {
	if err := run([]string{"--no-such-flag"}); err == nil || errors.Is(err, errNotBuilt) {
		t.Fatalf("run: got %v, want a flag parse error", err)
	}
}

// TestRunHelpIsNotAnError pins that -h/-help exits clean.
func TestRunHelpIsNotAnError(t *testing.T) {
	if err := run([]string{"-h"}); err != nil {
		t.Fatalf("run(-h): got %v, want nil", err)
	}
}

// TestRunSouthFaceFlagsParse pins that a valid full south-face flag set still
// refuses the serve path with errNotBuilt: the flags parse and validate, but
// the listener/admission/audit seams are not wired in this build.
func TestRunSouthFaceFlagsParse(t *testing.T) {
	err := run([]string{
		"--south-socket-dir", "/tmp/ocu-sessions",
		"--audit-sink", "/tmp/ocu-audit.log",
		"--profile", "internal_workforce",
		"--tenancy", "multi-tenant",
	})
	if !errors.Is(err, errNotBuilt) {
		t.Fatalf("run(full south-face flags): got %v, want errNotBuilt", err)
	}
}

// TestRunValidatesProfile pins that an unknown -profile value refuses with the
// typed sentinel before the serve-path refusal — never a silent default.
func TestRunValidatesProfile(t *testing.T) {
	err := run([]string{"--profile", "root"})
	if !errors.Is(err, errBadProfile) {
		t.Fatalf("run(--profile root): got %v, want errBadProfile", err)
	}
}

// TestRunValidatesTenancy pins that an unknown -tenancy value refuses with the
// typed sentinel before the serve-path refusal — never a silent default.
func TestRunValidatesTenancy(t *testing.T) {
	err := run([]string{"--tenancy", "omni-tenant"})
	if !errors.Is(err, errBadTenancy) {
		t.Fatalf("run(--tenancy omni-tenant): got %v, want errBadTenancy", err)
	}
}

// TestRunDefaultProfileTenancyValid pins that the default profile and tenancy
// values are themselves in the legal set (a default must not be a value the
// validator would reject).
func TestRunDefaultProfileTenancyValid(t *testing.T) {
	if err := run(nil); !errors.Is(err, errNotBuilt) {
		t.Fatalf("run(defaults): got %v, want errNotBuilt (defaults must validate)", err)
	}
}
