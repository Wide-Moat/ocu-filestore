// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"
)

// TestParseEngine pins that both engine kinds named by the seam parse from
// their deployment-config strings and that an unknown kind wraps
// ErrUnknownEngine — never a silent default (ENG-03, ADR-0010).
func TestParseEngine(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    EngineKind
		wantErr error
	}{
		{"local_volume", "local-volume", LocalVolume, nil},
		{"s3", "s3", S3, nil},
		{"unknown", "nfs", "", ErrUnknownEngine},
		{"empty", "", "", ErrUnknownEngine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEngine(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseEngine(%q): got %v, want ErrUnknownEngine", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEngine(%q): got err %v, want nil", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseEngine(%q): got %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestS3StubEngine pins the ENG-03 seam proof: a second engine kind satisfies
// the full Engine interface, every verb refuses with ErrNotImplemented, and
// Kind() names S3. The stub is never registered as a usable engine — it
// exists to keep the two-kind seam honest at compile time (ADR-0010).
func TestS3StubEngine(t *testing.T) {
	ctx := context.Background()
	var eng Engine = &s3StubEngine{}

	if eng.Kind() != S3 {
		t.Fatalf("Kind: got %q, want %q", eng.Kind(), S3)
	}

	scope := ScopeID("fs1")
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"ProvisionScope", func() error { return eng.ProvisionScope(ctx, scope) }},
		{"TeardownScope", func() error { return eng.TeardownScope(ctx, scope) }},
		{"List", func() error { _, err := eng.List(ctx, scope, "d"); return err }},
		{"Stat", func() error { _, err := eng.Stat(ctx, scope, "f"); return err }},
		{"MakeDir", func() error { return eng.MakeDir(ctx, scope, "d") }},
		{"MoveDir", func() error { return eng.MoveDir(ctx, scope, "a", "b", false) }},
		{"RemoveDir", func() error { return eng.RemoveDir(ctx, scope, "d") }},
		{"CopyFile", func() error { return eng.CopyFile(ctx, scope, "a", "b", false) }},
		{"MoveFile", func() error { return eng.MoveFile(ctx, scope, "a", "b", false) }},
		{"RemoveFile", func() error { return eng.RemoveFile(ctx, scope, "f") }},
		{"ReadRange", func() error { return eng.ReadRange(ctx, scope, "f", 0, 1, io.Discard) }},
		{"WriteStream", func() error { return eng.WriteStream(ctx, scope, "f", bytes.NewReader(nil), false) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrNotImplemented) {
				t.Fatalf("%s: got %v, want ErrNotImplemented", tc.name, err)
			}
		})
	}
}

// TestIsPathEscape pins the normalize helper that collapses the two os.Root
// escape wrappers into ONE caller-visible class: a rename escape arrives as
// *os.LinkError (renameat path family), every other escape as *fs.PathError
// (openat path family). The lexical sentinel and nil are NOT in the class.
// This pin exists BEFORE any verb relies on the helper because mapping code
// that checks only *fs.PathError silently misses rename escapes.
func TestIsPathEscape(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"path_error", &fs.PathError{Op: "openat", Path: "x", Err: errors.New("path escapes from parent")}, true},
		{"link_error", &os.LinkError{Op: "renameat", Old: "a", New: "../b", Err: errors.New("path escapes from parent")}, true},
		{"wrapped_path_error", errors.Join(errors.New("ctx"), &fs.PathError{Op: "open", Path: "x", Err: errors.New("e")}), true},
		{"lexical_sentinel", ErrInvalidPath, false},
		{"nil", nil, false},
		{"plain_error", errors.New("boring"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPathEscape(tc.err); got != tc.want {
				t.Fatalf("isPathEscape(%v): got %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
