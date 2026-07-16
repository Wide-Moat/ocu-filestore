// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// TestScopeConfinedEngine_AllowsOwnScope proves every verb is served for the
// provisioned scope: the confinement never blocks the legitimate scope.
func TestScopeConfinedEngine_AllowsOwnScope(t *testing.T) {
	inner := NewLocalVolumeEngine(t.TempDir())
	eng, err := NewScopeConfinedEngine(inner, ScopeID("own"))
	if err != nil {
		t.Fatalf("NewScopeConfinedEngine: %v", err)
	}
	ctx := context.Background()
	if err := eng.ProvisionScope(ctx, ScopeID("own")); err != nil {
		t.Fatalf("ProvisionScope(own): %v", err)
	}
	if err := eng.WriteStream(ctx, ScopeID("own"), "a.txt", strings.NewReader("hi"), false); err != nil {
		t.Fatalf("WriteStream(own): %v", err)
	}
	var buf bytes.Buffer
	if err := eng.ReadRange(ctx, ScopeID("own"), "a.txt", 0, 2, &buf); err != nil {
		t.Fatalf("ReadRange(own): %v", err)
	}
	if buf.String() != "hi" {
		t.Fatalf("ReadRange got %q, want hi", buf.String())
	}
}

// TestScopeConfinedEngine_RefusesForeignScopeEveryVerb proves the confinement is
// total: EVERY verb naming a foreign scope is ErrForeignScope, so no code path
// leaks a foreign prefix to the inner engine.
func TestScopeConfinedEngine_RefusesForeignScopeEveryVerb(t *testing.T) {
	inner := NewLocalVolumeEngine(t.TempDir())
	eng, err := NewScopeConfinedEngine(inner, ScopeID("own"))
	if err != nil {
		t.Fatalf("NewScopeConfinedEngine: %v", err)
	}
	ctx := context.Background()
	foreign := ScopeID("victim")

	checks := map[string]func() error{
		"ProvisionScope": func() error { return eng.ProvisionScope(ctx, foreign) },
		"TeardownScope":  func() error { return eng.TeardownScope(ctx, foreign) },
		"List":           func() error { _, e := eng.List(ctx, foreign, "."); return e },
		"Stat":           func() error { _, e := eng.Stat(ctx, foreign, "a"); return e },
		"MakeDir":        func() error { return eng.MakeDir(ctx, foreign, "d") },
		"MoveDir":        func() error { return eng.MoveDir(ctx, foreign, "a", "b", false) },
		"RemoveDir":      func() error { return eng.RemoveDir(ctx, foreign, "d") },
		"CopyFile":       func() error { return eng.CopyFile(ctx, foreign, "a", "b", false) },
		"MoveFile":       func() error { return eng.MoveFile(ctx, foreign, "a", "b", false) },
		"RemoveFile":     func() error { return eng.RemoveFile(ctx, foreign, "a") },
		"ReadRange":      func() error { return eng.ReadRange(ctx, foreign, "a", 0, 1, &bytes.Buffer{}) },
		"WriteStream":    func() error { return eng.WriteStream(ctx, foreign, "a", strings.NewReader("x"), false) },
	}
	for name, fn := range checks {
		if err := fn(); !errors.Is(err, ErrForeignScope) {
			t.Fatalf("%s(foreign) = %v, want ErrForeignScope", name, err)
		}
	}
}

// TestScopeConfinedEngine_FailClosedConstruction proves a nil inner or a
// malformed provisioned scope is a hard construction error, never a guard that
// silently admits everything.
func TestScopeConfinedEngine_FailClosedConstruction(t *testing.T) {
	if _, err := NewScopeConfinedEngine(nil, ScopeID("own")); err == nil {
		t.Fatalf("accepted a nil inner engine")
	}
	inner := NewLocalVolumeEngine(t.TempDir())
	for _, bad := range []string{"", ".", "..", "a/b"} {
		if _, err := NewScopeConfinedEngine(inner, ScopeID(bad)); err == nil {
			t.Fatalf("accepted a malformed provisioned scope %q", bad)
		}
	}
}
