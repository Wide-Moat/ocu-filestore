// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"
)

// nopSink is a no-op ExtractSink for the fuzz body: it consumes staged
// readers so the streaming counting path runs end to end, and records only
// whether a commit ever fired (a commit on a corrupt archive would be a
// fail-open the never-panic guard would otherwise miss). It is a
// fault-free fake, not a mock of any real service.
type nopSink struct{ committed bool }

func (s *nopSink) StageEntry(_ context.Context, _ string, r io.Reader, _ fs.FileMode) error {
	_, err := io.Copy(io.Discard, r)
	return err
}
func (s *nopSink) MakeDir(_ context.Context, _ string) error                { return nil }
func (s *nopSink) MakeSymlink(_ context.Context, _ string, _ string) error  { return nil }
func (s *nopSink) Commit(_ context.Context) error                           { s.committed = true; return nil }
func (s *nopSink) Abort(_ context.Context)                                  {}

// corruptCentralDir returns a copy of a valid archive with its central
// directory deliberately damaged at the chosen mutation, so the seed reaches
// zip.NewReader's parse of the central directory rather than bouncing off the
// local-file header. The signature offset is located the same way the
// header-lie corpus does.
func corruptCentralDir(data []byte, mut func(b []byte, cidx int)) []byte {
	centralDirSig := []byte{0x50, 0x4b, 0x01, 0x02}
	cidx := bytes.Index(data, centralDirSig)
	out := append([]byte{}, data...)
	if cidx < 0 {
		return out
	}
	mut(out, cidx)
	return out
}

// fuzzCorpus is the shared seed set for FuzzValidateZip and its non-vacuity
// companion: a clean valid archive (the success branch), and a family of
// central-directory mutations that scramble entry-count, offsets, and
// extra/comment lengths or truncate the directory.
func fuzzCorpus(t failer) (valid []byte, mutations [][]byte) {
	valid = buildZip(t,
		zipEntry{name: "a.txt", body: []byte("alpha"), deflate: true},
		zipEntry{name: "dir/"},
		zipEntry{name: "dir/b.bin", body: append(elfBytes(), make([]byte, 600)...), deflate: true},
	)
	mutations = [][]byte{
		// Flip the byte right after the central-dir signature.
		corruptCentralDir(valid, func(b []byte, cidx int) { b[cidx+4] ^= 0xFF }),
		// Scramble the extra-field length (offset +30 in the CD header).
		corruptCentralDir(valid, func(b []byte, cidx int) {
			if cidx+31 < len(b) {
				b[cidx+30] = 0xFF
				b[cidx+31] = 0xFF
			}
		}),
		// Scramble the local-header offset (offset +42 in the CD header).
		corruptCentralDir(valid, func(b []byte, cidx int) {
			for k := cidx + 42; k < cidx+46 && k < len(b); k++ {
				b[k] = 0xFF
			}
		}),
		// Truncate the archive at the central-dir signature: the directory
		// is gone but the EOCD still claims entries.
		append([]byte{}, valid[:bytes.Index(valid, []byte{0x50, 0x4b, 0x01, 0x02})]...),
		// Truncate mid central-directory header.
		func() []byte {
			cidx := bytes.Index(valid, []byte{0x50, 0x4b, 0x01, 0x02})
			if cidx < 0 || cidx+10 > len(valid) {
				return append([]byte{}, valid...)
			}
			return append([]byte{}, valid[:cidx+10]...)
		}(),
	}
	return valid, mutations
}

// assertWellTyped is the invariant the fuzz body enforces on every input:
// ValidateZip returns either nil (accepted) or a typed error — an
// *ArchiveError or ErrInvalidArchive — never a bare untyped error, and never
// a commit on an input it ultimately rejected.
func assertWellTyped(t *testing.T, err error, sink *nopSink) {
	t.Helper()
	if err == nil {
		return
	}
	if sink.committed {
		t.Fatalf("ValidateZip committed yet returned error %v — fail-open on a corrupt archive", err)
	}
	var ae *ArchiveError
	if errors.As(err, &ae) {
		return
	}
	if errors.Is(err, ErrInvalidArchive) || errors.Is(err, ErrTotalExceeded) ||
		errors.Is(err, ErrEntryCountExceeded) || errors.Is(err, ErrInvalidEntry) ||
		errors.Is(err, ErrSymlinkEscape) || errors.Is(err, ErrSymlinkUnsupported) ||
		errors.Is(err, ErrTypeDenied) || errors.Is(err, ErrUnclassifiableEntry) ||
		errors.Is(err, ErrDuplicateEntry) {
		return
	}
	// Sink-wrapped faults cannot occur with nopSink (it never faults), so any
	// remaining error must be a recognised typed sentinel. An unrecognised one
	// is a bug: the package must always speak in typed errors on hostile input.
	t.Fatalf("ValidateZip returned an untyped error on corrupt input: %v", err)
}

// TestFuzzValidateZipSeedsNonVacuous is the non-vacuity companion to
// FuzzValidateZip: it proves the corpus exercises BOTH branches the fuzz body
// must cover. The valid seed must return nil (the success branch is genuinely
// hit), and at least one central-directory mutation must reach the parser and
// produce a non-nil, well-typed, non-panicking error (the post-parse / reject
// branch is genuinely hit). Without this guard a corpus that only ever
// bounced off zip.NewReader's local-header check would let the fuzz target
// pass vacuously, never testing the central-directory parse it targets.
func TestFuzzValidateZipSeedsNonVacuous(t *testing.T) {
	valid, mutations := fuzzCorpus(t)

	// Success branch: the unmutated archive is accepted.
	vsink := &nopSink{}
	if err := ValidateZip(context.Background(), valid, testConfig(), vsink); err != nil {
		t.Fatalf("valid seed: got %v, want nil (success branch must be reachable)", err)
	}
	if !vsink.committed {
		t.Fatal("valid seed: sink not committed despite a nil return")
	}

	// Reject branch: at least one mutation must reach the parser and return a
	// well-typed, non-panicking error.
	rejected := 0
	for i, m := range mutations {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("mutation %d panicked: %v", i, r)
				}
			}()
			sink := &nopSink{}
			err := ValidateZip(context.Background(), m, testConfig(), sink)
			assertWellTyped(t, err, sink)
			if err != nil {
				rejected++
			}
		}()
	}
	if rejected == 0 {
		t.Fatal("vacuous corpus: no central-directory mutation produced a reject")
	}
}

// FuzzValidateZip asserts the parser-robustness invariant over arbitrarily
// corrupted archive bytes: archive/zip is the parser and the only panic
// surface in this package, and there is no recover() anywhere — a hostile or
// malformed central directory must never panic the broker. For EVERY input
// ValidateZip must return without panicking and either accept (nil) or reject
// with a typed error; it must never commit an input it rejects. The corpus is
// seeded with a valid archive (the success path) and central-directory
// mutations (the post-parse reject path) so the burst starts from inputs that
// already reach the parser, not random noise that only ever bounces off the
// local-header check.
func FuzzValidateZip(f *testing.F) {
	valid, mutations := fuzzCorpus(f)
	f.Add(valid)
	for _, m := range mutations {
		f.Add(m)
	}
	// A few degenerate seeds so the clean-reject leg is also explored.
	f.Add([]byte(nil))
	f.Add([]byte{0x50, 0x4b})
	f.Add([]byte("plainly not a zip archive"))

	f.Fuzz(func(t *testing.T, data []byte) {
		sink := &nopSink{}
		// ValidateZip must not panic on any input; a panic here fails the fuzz
		// run with the crashing input recorded by the framework.
		err := ValidateZip(context.Background(), data, testConfig(), sink)
		assertWellTyped(t, err, sink)
	})
}
