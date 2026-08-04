// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"pgregory.net/rapid"
)

// TestPropVerbContainment asserts that for arbitrary adversarial path
// strings fed to the write-family verbs (WriteStream, MoveFile, CopyFile,
// RemoveFile, MakeDir), every call lands in exactly one of three buckets:
// lexical rejection (ErrInvalidPath), escape rejection (isPathEscape), or
// success with NO file outside the scope created or modified — the
// os.SameFile outside-marker guard (ENG-01, T-03-01).
//
// Two guards keep the property non-vacuous (the path-resolution gap-closure
// lesson: a property that never draws the planted escape names is vacuously
// green):
//
//  1. Every iteration unconditionally drives WriteStream through the planted
//     escape symlink and requires the os.Root escape class — a nil error, a
//     plain ENOENT, or the lexical sentinel each fail the property, so a run
//     can never regress to all-ENOENT.
//  2. The fuzz arm draws from the SAME biased generator as the symlink
//     property: the planted escape paths with probability ~1/2, random
//     `[a-z_/]` strings otherwise.
//
// The run-level refusal counter hard-fails at zero.
func TestPropVerbContainment(t *testing.T) {
	plantedPaths := []string{"escape", "a/escape", "mid/secret", "abs_escape"}
	ctx := context.Background()

	var escapeRefusals int
	rapid.Check(t, func(rt *rapid.T) {
		base := t.TempDir()
		eng := NewLocalVolumeEngine(base)
		scope := ScopeID("scope")
		if err := eng.ProvisionScope(ctx, scope); err != nil {
			rt.Fatalf("ProvisionScope: %v", err)
		}
		scopeDir := filepath.Join(base, string(scope))

		// Sibling dir OUTSIDE the scope with a secret marker — the untouchable
		// world. It lives alongside base (not derived from filepath.Dir(base)
		// which is shared across all rapid iterations) so each iteration gets
		// its own outside directory and its own inode for the marker file.
		// Using filepath.Dir(base) would produce the same path for every rapid
		// call (rapid issues t.TempDir() as .../001, .../002, …, all children
		// of the same parent), causing the deferred os.RemoveAll to race with
		// the next iteration's os.WriteFile and flip the marker's inode mid-run.
		outside := filepath.Join(base, "outside")
		if err := os.MkdirAll(outside, 0o755); err != nil {
			rt.Fatalf("mkdir outside: %v", err)
		}
		secretPath := filepath.Join(outside, "secret")
		if err := os.WriteFile(secretPath, []byte("escaped"), 0o644); err != nil {
			rt.Fatalf("write secret: %v", err)
		}
		secretBefore, err := os.Stat(secretPath)
		if err != nil {
			rt.Fatalf("stat secret: %v", err)
		}
		entriesBefore, err := os.ReadDir(outside)
		if err != nil {
			rt.Fatalf("readdir outside: %v", err)
		}

		// Adversarial topology covering all planted paths: direct link out,
		// chained relative link, link in the middle of a traversed path,
		// absolute link.
		if err := os.Symlink(outside, filepath.Join(scopeDir, "escape")); err != nil {
			rt.Fatalf("symlink: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(scopeDir, "hop")); err != nil {
			rt.Fatalf("symlink: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(scopeDir, "a"), 0o755); err != nil {
			rt.Fatalf("mkdir a: %v", err)
		}
		if err := os.Symlink("../hop", filepath.Join(scopeDir, "a", "escape")); err != nil {
			rt.Fatalf("symlink: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(scopeDir, "mid")); err != nil {
			rt.Fatalf("symlink: %v", err)
		}
		if err := os.Symlink("/tmp", filepath.Join(scopeDir, "abs_escape")); err != nil {
			rt.Fatalf("symlink: %v", err)
		}
		// A legitimate source the move/copy verbs can consume.
		if _, err := eng.WriteStream(ctx, scope, "seed", bytes.NewReader([]byte("inside")), false); err != nil {
			rt.Fatalf("WriteStream seed: %v", err)
		}

		// Unconditional vacuity guard: drive a write THROUGH the planted
		// escape symlink — must refuse with the os.Root escape class.
		_, err = eng.WriteStream(ctx, scope, "escape/pwn", bytes.NewReader([]byte("x")), true)
		switch {
		case err == nil:
			rt.Fatalf("WriteStream(escape/pwn): planted escape must be refused, got nil error")
		case errors.Is(err, fs.ErrNotExist):
			rt.Fatalf("WriteStream(escape/pwn): refused with ENOENT — topology never reached, property is vacuous: %v", err)
		case errors.Is(err, ErrInvalidPath):
			rt.Fatalf("WriteStream(escape/pwn): escape refusal must not be the lexical sentinel: %v", err)
		case !isPathEscape(err):
			rt.Fatalf("WriteStream(escape/pwn): want the os.Root escape class, got %T: %v", err, err)
		}
		escapeRefusals++

		// Fuzz arm: biased path draw × write-family verb draw.
		p := rapid.OneOf(
			rapid.SampledFrom(plantedPaths),
			rapid.StringMatching(`[a-z_/]{1,20}`),
		).Draw(rt, "path")
		verb := rapid.IntRange(0, 4).Draw(rt, "verb")

		var verbErr error
		switch verb {
		case 0:
			_, verbErr = eng.WriteStream(ctx, scope, p, bytes.NewReader([]byte("payload")), true)
		case 1:
			verbErr = eng.MoveFile(ctx, scope, "seed", p, true)
		case 2:
			verbErr = eng.CopyFile(ctx, scope, "seed", p, true)
		case 3:
			verbErr = eng.RemoveFile(ctx, scope, p)
		case 4:
			verbErr = eng.MakeDir(ctx, scope, p)
		}

		switch {
		case verbErr == nil:
			// Success bucket — the outside world must be untouched.
			secretAfter, statErr := os.Stat(secretPath)
			if statErr != nil {
				rt.Fatalf("verb %d on %q removed the outside marker: %v", verb, p, statErr)
			}
			if !os.SameFile(secretBefore, secretAfter) {
				rt.Fatalf("verb %d on %q replaced the outside marker", verb, p)
			}
			content, readErr := os.ReadFile(secretPath)
			if readErr != nil || string(content) != "escaped" {
				rt.Fatalf("verb %d on %q mutated the outside marker: content=%q err=%v", verb, p, content, readErr)
			}
			entriesAfter, readDirErr := os.ReadDir(outside)
			if readDirErr != nil || len(entriesAfter) != len(entriesBefore) {
				rt.Fatalf("verb %d on %q changed the outside dir: before=%d after=%d err=%v",
					verb, p, len(entriesBefore), len(entriesAfter), readDirErr)
			}
		case errors.Is(verbErr, ErrInvalidPath):
			// Lexical bucket — always acceptable.
		case isPathEscape(verbErr):
			// Escape bucket (the structural os.Root class also wraps plain
			// ENOENT/EEXIST syscall errors — only genuine refusals count
			// toward non-vacuity).
			if !errors.Is(verbErr, fs.ErrNotExist) && !errors.Is(verbErr, fs.ErrExist) {
				escapeRefusals++
			}
		default:
			rt.Fatalf("verb %d on %q: error outside the allowed classes: %T %v", verb, p, verbErr, verbErr)
		}
	})
	t.Logf("escape refusals exercised across the run: %d", escapeRefusals)
	if escapeRefusals == 0 {
		t.Fatal("property completed without exercising a single escape refusal — vacuous run")
	}
}

// TestPropEraseBeforeReuse is the NFR-SEC-54 named verification shape
// (ENG-02): write a marker at an arbitrary valid path with arbitrary bytes
// in session one, TeardownScope, re-grant the same filesystem_id, and the
// marker must read fs.ErrNotExist — erase-before-reuse, no prior-session
// bytes readable.
func TestPropEraseBeforeReuse(t *testing.T) {
	ctx := context.Background()
	rapid.Check(t, func(rt *rapid.T) {
		id := ScopeID(rapid.StringMatching(`[a-z][a-z0-9_]{0,15}`).Draw(rt, "scope_id"))
		rawPath := rapid.StringMatching(`[a-z][a-z0-9/_]{0,30}`).Draw(rt, "path")
		data := rapid.SliceOf(rapid.Byte()).Draw(rt, "content")

		base := t.TempDir()
		eng := NewLocalVolumeEngine(base)
		if err := eng.ProvisionScope(ctx, id); err != nil {
			rt.Fatalf("ProvisionScope: %v", err)
		}

		clean, err := ValidatePath(rawPath)
		if err != nil {
			return // lexically invalid draw — skip
		}
		// Test scaffolding only: create parent dirs for multi-segment draws
		// from the TRUSTED id + already-validated clean path, so deep marker
		// paths exercise the property instead of skipping on ENOENT.
		if dir := filepath.Dir(clean); dir != "." {
			if err := os.MkdirAll(filepath.Join(base, string(id), dir), 0o700); err != nil {
				return // a path component collided with a file — skip
			}
		}

		if _, err := eng.WriteStream(ctx, id, clean, bytes.NewReader(data), true); err != nil {
			return // unwritable draw (e.g. component is a file) — skip
		}
		// Session one can read its own marker.
		if _, err := eng.Stat(ctx, id, clean); err != nil {
			rt.Fatalf("marker unreadable in its own session: path=%q err=%v", clean, err)
		}

		if err := eng.TeardownScope(ctx, id); err != nil {
			rt.Fatalf("TeardownScope: %v", err)
		}

		// Re-grant of the same filesystem_id: the prior path must be gone.
		if _, err := eng.Stat(ctx, id, clean); !errors.Is(err, fs.ErrNotExist) {
			rt.Fatalf("marker still readable after TeardownScope: path=%q err=%v", clean, err)
		}
	})
}

// TestLocalEngine_ConcurrentDistinctScopes is the -race concurrency-sanity
// check: N goroutines each provision, write, range-read, list, and tear
// down their OWN scope. The engine is per-call-open, so distinct scopes
// never share a root; the race detector must stay silent and no scope may
// observe another's bytes.
func TestLocalEngine_ConcurrentDistinctScopes(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)

	const goroutines = 8
	const rounds = 3
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scope := ScopeID(fmt.Sprintf("scope_%d", i))
			data := bytes.Repeat([]byte{byte('a' + i)}, 4096)
			for r := 0; r < rounds; r++ {
				if err := eng.ProvisionScope(ctx, scope); err != nil {
					errCh <- fmt.Errorf("%s round %d provision: %w", scope, r, err)
					return
				}
				if _, err := eng.WriteStream(ctx, scope, "obj", bytes.NewReader(data), false); err != nil {
					errCh <- fmt.Errorf("%s round %d write: %w", scope, r, err)
					return
				}
				var buf bytes.Buffer
				if err := eng.ReadRange(ctx, scope, "obj", 0, int64(len(data)), &buf); err != nil {
					errCh <- fmt.Errorf("%s round %d read: %w", scope, r, err)
					return
				}
				if !bytes.Equal(buf.Bytes(), data) {
					errCh <- fmt.Errorf("%s round %d: read bytes differ — cross-scope bleed", scope, r)
					return
				}
				entries, err := eng.List(ctx, scope, ".")
				if err != nil || len(entries) != 1 {
					errCh <- fmt.Errorf("%s round %d list: entries=%v err=%w", scope, r, entries, err)
					return
				}
				if err := eng.TeardownScope(ctx, scope); err != nil {
					errCh <- fmt.Errorf("%s round %d teardown: %w", scope, r, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
