// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// TestNewHandlerFailsLoudOnEveryNilSeam pins the fail-loud composition gate:
// NewHandler refuses with ErrSeamMissing when ANY required seam is nil, naming
// the offending one. A half-wired north plane must never bind a listener.
func TestNewHandlerFailsLoudOnEveryNilSeam(t *testing.T) {
	full := func() Deps {
		return Deps{
			Resolver:    &fakeResolver{},
			Guard:       &fakeGuard{},
			Engine:      newFakeEngine(),
			Ceilings:    newFakeCeilings(),
			Store:       newFakeStore(),
			Scope:       fakeScope{ok: true},
			MaxFileSize: 1 << 20,
		}
	}

	for _, tc := range []struct {
		name string
		mut  func(*Deps)
	}{
		{"nil Resolver", func(d *Deps) { d.Resolver = nil }},
		{"nil Guard", func(d *Deps) { d.Guard = nil }},
		{"nil Engine", func(d *Deps) { d.Engine = nil }},
		{"nil Ceilings", func(d *Deps) { d.Ceilings = nil }},
		{"nil Store", func(d *Deps) { d.Store = nil }},
		{"nil Scope", func(d *Deps) { d.Scope = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := full()
			tc.mut(&d)
			h, err := NewHandler(d)
			if h != nil {
				t.Fatal("NewHandler returned a non-nil handler on a nil seam")
			}
			if !errors.Is(err, ErrSeamMissing) {
				t.Fatalf("err = %v, want ErrSeamMissing", err)
			}
		})
	}
}

// TestNewHandlerNormalisesNilLogger pins the one permitted nil: a nil Logger is
// normalised to a discard logger, NOT a refusal. The handler must be usable
// without an explicit logger.
func TestNewHandlerNormalisesNilLogger(t *testing.T) {
	h, err := NewHandler(Deps{
		Resolver:    &fakeResolver{},
		Guard:       &fakeGuard{},
		Engine:      newFakeEngine(),
		Ceilings:    newFakeCeilings(),
		Store:       newFakeStore(),
		Scope:       fakeScope{ok: true},
		MaxFileSize: 1 << 20,
		Logger:      nil,
	})
	if err != nil {
		t.Fatalf("NewHandler with nil logger = %v, want nil", err)
	}
	if h.deps.Logger == nil {
		t.Fatal("nil logger was not normalised to a discard logger")
	}
}

// TestNewHandlerRejectsNonPositiveMaxFileSize pins the create-plane ceiling gate:
// NewHandler refuses with ErrMaxFileSizeUnset when MaxFileSize is not a positive
// whole-object ceiling. The create path's pre-assembly size reject depends on a
// real ceiling, so an unset one is a wiring fault refused before a listener binds,
// never a silent "no limit".
func TestNewHandlerRejectsNonPositiveMaxFileSize(t *testing.T) {
	for _, size := range []int64{0, -1} {
		h, err := NewHandler(Deps{
			Resolver:    &fakeResolver{},
			Guard:       &fakeGuard{},
			Engine:      newFakeEngine(),
			Ceilings:    newFakeCeilings(),
			Store:       newFakeStore(),
			Scope:       fakeScope{ok: true},
			MaxFileSize: size,
		})
		if h != nil {
			t.Fatalf("MaxFileSize=%d: NewHandler returned a non-nil handler", size)
		}
		if !errors.Is(err, ErrMaxFileSizeUnset) {
			t.Fatalf("MaxFileSize=%d: err = %v, want ErrMaxFileSizeUnset", size, err)
		}
	}
}

// TestNewHandlerAcceptsFullDeps pins the happy path: every seam wired yields a
// handler and no error.
func TestNewHandlerAcceptsFullDeps(t *testing.T) {
	h, err := NewHandler(Deps{
		Resolver:    &fakeResolver{},
		Guard:       &fakeGuard{},
		Engine:      newFakeEngine(),
		Ceilings:    newFakeCeilings(),
		Store:       newFakeStore(),
		Scope:       fakeScope{ps: southface.PeerScope{FilesystemID: "fs"}, ok: true},
		MaxFileSize: 1 << 20,
	})
	if err != nil || h == nil {
		t.Fatalf("NewHandler(full) = (%v, %v), want (handler, nil)", h, err)
	}
}
