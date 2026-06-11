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
