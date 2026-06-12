// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"errors"
	"strings"
	"testing"
)

// TestParseEngineKnownKinds asserts both day-one engines parse to their
// declared kind (ADR-0010: local-volume and s3, both present from day one).
func TestParseEngineKnownKinds(t *testing.T) {
	for _, want := range []EngineKind{LocalVolume, S3} {
		got, err := ParseEngine(string(want))
		if err != nil {
			t.Fatalf("ParseEngine(%q): unexpected error %v", want, err)
		}
		if got != want {
			t.Fatalf("ParseEngine(%q) = %q, want %q", want, got, want)
		}
	}
}

// TestParseEngineUnknownIsRefused asserts an unknown engine name wraps
// ErrUnknownEngine and is never silently defaulted, and that the error
// names the valid kinds for the operator.
func TestParseEngineUnknownIsRefused(t *testing.T) {
	for _, bogus := range []string{"", "bogus", "LOCAL-VOLUME", "s3 ", "gcs"} {
		kind, err := ParseEngine(bogus)
		if !errors.Is(err, ErrUnknownEngine) {
			t.Fatalf("ParseEngine(%q): error %v, want ErrUnknownEngine", bogus, err)
		}
		if kind != "" {
			t.Fatalf("ParseEngine(%q) returned kind %q on error, want empty", bogus, kind)
		}
		for _, valid := range []string{string(LocalVolume), string(S3)} {
			if !strings.Contains(err.Error(), valid) {
				t.Errorf("ParseEngine(%q) error %q does not list valid kind %q", bogus, err, valid)
			}
		}
	}
}
