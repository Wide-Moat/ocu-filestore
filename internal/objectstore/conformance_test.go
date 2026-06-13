// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Engine-neutral conformance suite (13-10): ONE behavioral contract, every
// Engine implementation proves it. The suite is parameterized over a factory
// and runs two legs — the local-volume engine always (t.TempDir), the S3
// engine against live MinIO when OCU_S3_TEST_ENDPOINT is set (it NEVER runs
// against a mock; the gate skips loudly with the exact rig invocation).
//
// The suite's spine is sentinel parity: every refusal is asserted with
// errors.Is against the objectstore sentinels (or the stdlib fs sentinels
// both engines mirror), never string matching.
//
// Divergences (documented, each carried by a named subtest below):
//   - MoveDir atomicity: the local engine's MoveDir is a single rename(2);
//     the S3 engine's MoveDir is a paginated per-object copy+delete and is
//     NOT atomic — a crash mid-move can leave both trees partially
//     populated (never lost bytes: copy precedes delete per object). See
//     Divergence_MoveDirAtomicity.
//   - Compare-and-swap UPDATE (S3-EDGE-CASES section 3, second sub-item) is
//     NON-APPLICABLE at this interface: Engine's `overwrite bool` exposes
//     create-if-absent (covered by Overwrite_Refused and NoReplaceRace_Prop)
//     but no conditional-update precondition surface. The digest
//     infrastructure (streamed SHA-256) exists engine-side; only the
//     update-precondition verb is absent, intentionally. See
//     Divergence_CASUpdateNotApplicable.
//   - ModTime granularity: the S3 backend reports second-granularity
//     modification times in listings; the local engine reports nanoseconds.
//     No subtest asserts sub-second ModTime ordering.
package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"pgregory.net/rapid"
)

// confTarget is one provisioned engine+scope under test plus a backend-truth
// probe: outside() reports every path/key that exists OUTSIDE the scope
// boundary, so the containment property can prove hostile writes never
// landed anywhere but inside the scope.
type confTarget struct {
	eng   Engine
	scope ScopeID
	// outside returns the set of backend entries outside the scope
	// boundary (local: paths under baseDir not in the scope dir; S3: bucket
	// keys not under the scope prefix).
	outside func(t *testing.T) map[string]bool
}

// confFactory yields a FRESH provisioned target; each subtest gets its own
// scope so cases never bleed into each other.
type confFactory func(t *testing.T) confTarget

// localConfTarget provisions a local-volume engine in a per-test temp dir.
func localConfTarget(t *testing.T) confTarget {
	t.Helper()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID(fmt.Sprintf("conf-%d", time.Now().UnixNano()))
	if err := eng.ProvisionScope(context.Background(), scope); err != nil {
		t.Fatalf("ProvisionScope(local): %v", err)
	}
	outside := func(t *testing.T) map[string]bool {
		t.Helper()
		seen := map[string]bool{}
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, rerr := filepath.Rel(base, p)
			if rerr != nil {
				return rerr
			}
			if rel == "." {
				return nil
			}
			if rel == string(scope) {
				return filepath.SkipDir // the scope subtree is INSIDE the boundary
			}
			seen[rel] = true
			return nil
		})
		if err != nil {
			t.Fatalf("outside walk: %v", err)
		}
		return seen
	}
	return confTarget{eng: eng, scope: scope, outside: outside}
}

// s3ConfTarget provisions an S3 engine against the live rig, skipping loudly
// when the env gate is unset. Cleanup is the engine's own teardown sweep.
func s3ConfTarget(t *testing.T) confTarget {
	t.Helper()
	endpoint := os.Getenv("OCU_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip(liveSkipNotice)
	}
	bucket := os.Getenv("OCU_S3_TEST_BUCKET")
	if bucket == "" {
		bucket = "ocu-conformance"
	}
	eng, err := NewS3Engine(S3Config{
		Endpoint:     endpoint,
		Region:       "us-east-1",
		Bucket:       bucket,
		UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(
			os.Getenv("OCU_S3_TEST_ACCESS_KEY"), os.Getenv("OCU_S3_TEST_SECRET_KEY"), ""),
	})
	if err != nil {
		t.Fatalf("NewS3Engine(conformance): %v", err)
	}
	e := eng.(*s3Engine)
	scope := ScopeID(fmt.Sprintf("%s-%d",
		strings.ToLower(strings.NewReplacer("/", "-", "_", "-").Replace(t.Name())),
		time.Now().UnixNano()))
	if err := eng.ProvisionScope(context.Background(), scope); err != nil {
		t.Fatalf("ProvisionScope(s3): %v", err)
	}
	t.Cleanup(func() {
		if err := eng.TeardownScope(context.Background(), scope); err != nil {
			t.Logf("conformance cleanup teardown: %v", err)
		}
	})
	outside := func(t *testing.T) map[string]bool {
		t.Helper()
		seen := map[string]bool{}
		prefix := string(scope) + "/"
		var token *string
		for {
			out, lerr := e.client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
				Bucket: aws.String(e.bucket), ContinuationToken: token,
			})
			if lerr != nil {
				t.Fatalf("outside list: %v", lerr)
			}
			for _, obj := range out.Contents {
				if k := aws.ToString(obj.Key); !strings.HasPrefix(k, prefix) {
					seen[k] = true
				}
			}
			if !aws.ToBool(out.IsTruncated) {
				return seen
			}
			token = out.NextContinuationToken
		}
	}
	return confTarget{eng: eng, scope: scope, outside: outside}
}

func TestConformance_LocalVolume(t *testing.T) { runConformance(t, localConfTarget) }

func TestConformance_S3(t *testing.T) { runConformance(t, s3ConfTarget) }

// confWrite seeds content through the engine (the suite never touches the
// backend directly — backend-truth probes live only in the factory).
func confWrite(t *testing.T, e Engine, sc ScopeID, p, content string, overwrite bool) {
	t.Helper()
	if err := e.WriteStream(context.Background(), sc, p, strings.NewReader(content), overwrite); err != nil {
		t.Fatalf("WriteStream(%q): %v", p, err)
	}
}

// confRead reads a whole small object back through the engine.
func confRead(t *testing.T, e Engine, sc ScopeID, p string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := e.ReadRange(context.Background(), sc, p, 0, 1<<20, &buf); err != nil {
		t.Fatalf("ReadRange(%q): %v", p, err)
	}
	return buf.String()
}

func runConformance(t *testing.T, f confFactory) {
	ctx := context.Background()

	// Overwrite collisions: with overwrite=false every write-family verb
	// refuses the typed collision sentinel exactly as the local engine
	// surfaces it, the destination keeps its bytes, and a refused move NEVER
	// destroys its source. With overwrite=true the destination is replaced.
	t.Run("Overwrite_Refused", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		confWrite(t, e, sc, "dst.txt", "old", false)
		if err := e.WriteStream(ctx, sc, "dst.txt", strings.NewReader("clobber"), false); !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("WriteStream(existing, overwrite=false) = %v, want ErrAlreadyExists", err)
		}
		if got := confRead(t, e, sc, "dst.txt"); got != "old" {
			t.Fatalf("destination after refused write = %q, want \"old\"", got)
		}

		confWrite(t, e, sc, "src.txt", "newer", false)
		if err := e.CopyFile(ctx, sc, "src.txt", "dst.txt", false); !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("CopyFile(existing dst, overwrite=false) = %v, want ErrAlreadyExists", err)
		}
		if err := e.MoveFile(ctx, sc, "src.txt", "dst.txt", false); !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("MoveFile(existing dst, overwrite=false) = %v, want ErrAlreadyExists", err)
		}
		// The refused move never destroyed its source.
		if _, err := e.Stat(ctx, sc, "src.txt"); err != nil {
			t.Fatalf("Stat(src after refused move) = %v, want nil (source must survive)", err)
		}
		if got := confRead(t, e, sc, "dst.txt"); got != "old" {
			t.Fatalf("destination after refused copy/move = %q, want \"old\"", got)
		}

		if err := e.MakeDir(ctx, sc, "d"); err != nil {
			t.Fatalf("MakeDir(d): %v", err)
		}
		if err := e.MakeDir(ctx, sc, "d"); !errors.Is(err, fs.ErrExist) {
			t.Fatalf("MakeDir(existing) = %v, want fs.ErrExist", err)
		}
		if err := e.MakeDir(ctx, sc, "d2"); err != nil {
			t.Fatalf("MakeDir(d2): %v", err)
		}
		if err := e.MoveDir(ctx, sc, "d2", "d", false); !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("MoveDir(existing dst, overwrite=false) = %v, want ErrAlreadyExists", err)
		}
		if fi, err := e.Stat(ctx, sc, "d2"); err != nil || !fi.IsDir {
			t.Fatalf("Stat(d2 after refused MoveDir) = %+v, %v; want surviving dir", fi, err)
		}

		// overwrite=true replaces.
		confWrite(t, e, sc, "dst.txt", "v2", true)
		if got := confRead(t, e, sc, "dst.txt"); got != "v2" {
			t.Fatalf("destination after replace = %q, want \"v2\"", got)
		}
		if err := e.CopyFile(ctx, sc, "src.txt", "dst.txt", true); err != nil {
			t.Fatalf("CopyFile(overwrite=true): %v", err)
		}
		if got := confRead(t, e, sc, "dst.txt"); got != "newer" {
			t.Fatalf("destination after replacing copy = %q, want \"newer\"", got)
		}
		if err := e.MoveFile(ctx, sc, "src.txt", "dst.txt", true); err != nil {
			t.Fatalf("MoveFile(overwrite=true): %v", err)
		}
		if _, err := e.Stat(ctx, sc, "src.txt"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Stat(src after replacing move) = %v, want fs.ErrNotExist", err)
		}
	})

	// The no-replace race property: N concurrent overwrite=false writers to
	// ONE path -> EXACTLY one success, every loser ErrAlreadyExists, and the
	// surviving bytes are the winner's (S3-EDGE-CASES section 3: the
	// conditional write is enforced per-request; an earlier existence check
	// is never trusted).
	t.Run("NoReplaceRace_Prop", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope
		var iter int
		rapid.Check(t, func(rt *rapid.T) {
			iter++
			p := fmt.Sprintf("race-%d.bin", iter)
			n := rapid.IntRange(2, 6).Draw(rt, "writers")

			contents := make([]string, n)
			for i := range contents {
				contents[i] = fmt.Sprintf("writer-%d-of-%d", i, n)
			}
			results := make([]error, n)
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					results[i] = e.WriteStream(ctx, sc, p, strings.NewReader(contents[i]), false)
				}(i)
			}
			wg.Wait()

			winner := -1
			for i, err := range results {
				switch {
				case err == nil:
					if winner != -1 {
						rt.Fatalf("two writers both succeeded (%d and %d) on %q", winner, i, p)
					}
					winner = i
				case !errors.Is(err, ErrAlreadyExists):
					rt.Fatalf("loser %d = %v, want ErrAlreadyExists", i, err)
				}
			}
			if winner == -1 {
				rt.Fatalf("no writer succeeded on %q (all %d refused)", p, n)
			}
			var buf bytes.Buffer
			if err := e.ReadRange(ctx, sc, p, 0, 1<<10, &buf); err != nil {
				rt.Fatalf("ReadRange(%q): %v", p, err)
			}
			if buf.String() != contents[winner] {
				rt.Fatalf("surviving content = %q, want winner %d's %q", buf.String(), winner, contents[winner])
			}
		})
	})

	// Missing sources: every read/copy/move/remove verb on an absent path
	// refuses fs.ErrNotExist.
	t.Run("MissingSource", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		if _, err := e.Stat(ctx, sc, "ghost.txt"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Stat(missing) = %v, want fs.ErrNotExist", err)
		}
		var buf bytes.Buffer
		if err := e.ReadRange(ctx, sc, "ghost.txt", 0, 8, &buf); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("ReadRange(missing) = %v, want fs.ErrNotExist", err)
		}
		if err := e.RemoveFile(ctx, sc, "ghost.txt"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("RemoveFile(missing) = %v, want fs.ErrNotExist", err)
		}
		if err := e.CopyFile(ctx, sc, "ghost.txt", "x.txt", false); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("CopyFile(missing src) = %v, want fs.ErrNotExist", err)
		}
		if err := e.MoveFile(ctx, sc, "ghost.txt", "x.txt", false); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("MoveFile(missing src) = %v, want fs.ErrNotExist", err)
		}
		if err := e.MoveDir(ctx, sc, "ghost-dir", "y", false); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("MoveDir(missing src) = %v, want fs.ErrNotExist", err)
		}
		if _, err := e.List(ctx, sc, "ghost-dir"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("List(missing dir) = %v, want fs.ErrNotExist", err)
		}
	})

	// Missing parents: a write-family verb into an absent parent directory
	// refuses fs.ErrNotExist (POSIX missing-parent semantics on both
	// engines; the S3 engine enforces it through the marker convention).
	t.Run("MissingParent", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		if err := e.WriteStream(ctx, sc, "nope/f.txt", strings.NewReader("x"), false); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("WriteStream(missing parent) = %v, want fs.ErrNotExist", err)
		}
		if err := e.MakeDir(ctx, sc, "nope/d"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("MakeDir(missing parent) = %v, want fs.ErrNotExist", err)
		}
		confWrite(t, e, sc, "src.txt", "x", false)
		if err := e.CopyFile(ctx, sc, "src.txt", "nope/f.txt", false); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("CopyFile(missing dst parent) = %v, want fs.ErrNotExist", err)
		}
	})

	// ReadRange EOF family: an offset at or past EOF yields zero bytes and
	// nil error — never an error (the Engine contract; on S3 that is the
	// 416 row).
	t.Run("ReadRange_PastEOF", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope
		body := "0123456789"
		confWrite(t, e, sc, "r.bin", body, false)

		for _, offset := range []int64{int64(len(body)), int64(len(body)) + 7} {
			var buf bytes.Buffer
			if err := e.ReadRange(ctx, sc, "r.bin", offset, 5, &buf); err != nil {
				t.Fatalf("ReadRange(offset=%d past EOF) = %v, want nil", offset, err)
			}
			if buf.Len() != 0 {
				t.Fatalf("ReadRange(offset=%d past EOF) wrote %d bytes, want 0", offset, buf.Len())
			}
		}
	})

	// ReadRange windows: a window extending past EOF clamps to a short read
	// without error (the 206 row on S3); interior windows are byte-exact;
	// zero-length windows return immediately with nil.
	t.Run("ReadRange_TailClamp", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope
		confWrite(t, e, sc, "r.bin", "abcdefghij", false)

		for _, tc := range []struct {
			name           string
			offset, length int64
			want           string
		}{
			{"tail clamped", 5, 100, "fghij"},
			{"interior window", 2, 5, "cdefg"},
			{"whole object", 0, 10, "abcdefghij"},
			{"zero length", 3, 0, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var buf bytes.Buffer
				if err := e.ReadRange(ctx, sc, "r.bin", tc.offset, tc.length, &buf); err != nil {
					t.Fatalf("ReadRange(%d, %d): %v", tc.offset, tc.length, err)
				}
				if buf.String() != tc.want {
					t.Fatalf("ReadRange(%d, %d) = %q, want %q", tc.offset, tc.length, buf.String(), tc.want)
				}
			})
		}
	})

	// Listing is ONE level only — nested entries are invisible — and the
	// literal path "." lists the scope root.
	t.Run("List_OneLevel", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		if err := e.MakeDir(ctx, sc, "top"); err != nil {
			t.Fatalf("MakeDir(top): %v", err)
		}
		confWrite(t, e, sc, "top/f1.txt", "one", false)
		if err := e.MakeDir(ctx, sc, "top/sub"); err != nil {
			t.Fatalf("MakeDir(top/sub): %v", err)
		}
		confWrite(t, e, sc, "top/sub/deep.txt", "deep", false)

		entries, err := e.List(ctx, sc, "top")
		if err != nil {
			t.Fatalf("List(top): %v", err)
		}
		got := map[string]bool{}
		for _, fi := range entries {
			got[fi.Name] = fi.IsDir
		}
		if len(got) != 2 || got["f1.txt"] != false || got["sub"] != true {
			t.Fatalf("List(top) = %v, want exactly {f1.txt: file, sub: dir} (one level only)", got)
		}

		root, err := e.List(ctx, sc, ".")
		if err != nil {
			t.Fatalf("List(.): %v", err)
		}
		if len(root) != 1 || root[0].Name != "top" || !root[0].IsDir {
			t.Fatalf("List(.) = %+v, want exactly [top (dir)]", root)
		}
	})

	// Directory hygiene: a freshly created directory lists empty, appears
	// as a directory entry in its parent, and no listing ever surfaces a
	// marker artifact (an empty-named entry or a name carrying a
	// separator).
	t.Run("DirMarkerHygiene", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		if err := e.MakeDir(ctx, sc, "hollow"); err != nil {
			t.Fatalf("MakeDir(hollow): %v", err)
		}
		empty, err := e.List(ctx, sc, "hollow")
		if err != nil {
			t.Fatalf("List(hollow): %v", err)
		}
		if len(empty) != 0 {
			t.Fatalf("List(fresh dir) = %+v, want empty (markers are never entries)", empty)
		}
		if fi, err := e.Stat(ctx, sc, "hollow"); err != nil || !fi.IsDir {
			t.Fatalf("Stat(hollow) = %+v, %v; want dir", fi, err)
		}

		confWrite(t, e, sc, "hollow/f.txt", "x", false)
		one, err := e.List(ctx, sc, "hollow")
		if err != nil {
			t.Fatalf("List(hollow with child): %v", err)
		}
		if len(one) != 1 || one[0].Name != "f.txt" || one[0].IsDir {
			t.Fatalf("List(hollow) = %+v, want exactly [f.txt (file)]", one)
		}
		for _, listPath := range []string{".", "hollow"} {
			entries, err := e.List(ctx, sc, listPath)
			if err != nil {
				t.Fatalf("List(%q): %v", listPath, err)
			}
			for _, fi := range entries {
				if fi.Name == "" || strings.ContainsAny(fi.Name, "/\\") {
					t.Fatalf("List(%q) surfaced marker artifact entry %+v", listPath, fi)
				}
			}
		}
	})

	// RemoveFile remove(2) parity: an EMPTY directory target is removed
	// successfully; a directory WITH children refuses ENOTEMPTY and leaves
	// the tree intact (the 13-07 WARNING-4 matrix, pinned on both engines).
	t.Run("RemoveFile_DirParity", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		if err := e.MakeDir(ctx, sc, "empty"); err != nil {
			t.Fatalf("MakeDir(empty): %v", err)
		}
		if err := e.RemoveFile(ctx, sc, "empty"); err != nil {
			t.Fatalf("RemoveFile(empty dir) = %v, want nil (remove(2) parity)", err)
		}
		if _, err := e.Stat(ctx, sc, "empty"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Stat(removed empty dir) = %v, want fs.ErrNotExist", err)
		}

		if err := e.MakeDir(ctx, sc, "full"); err != nil {
			t.Fatalf("MakeDir(full): %v", err)
		}
		confWrite(t, e, sc, "full/f.txt", "x", false)
		if err := e.RemoveFile(ctx, sc, "full"); !errors.Is(err, syscall.ENOTEMPTY) {
			t.Fatalf("RemoveFile(non-empty dir) = %v, want ENOTEMPTY", err)
		}
		if fi, err := e.Stat(ctx, sc, "full"); err != nil || !fi.IsDir {
			t.Fatalf("Stat(full after refused remove) = %+v, %v; want surviving dir", fi, err)
		}
		if _, err := e.Stat(ctx, sc, "full/f.txt"); err != nil {
			t.Fatalf("Stat(full/f.txt after refused remove) = %v, want nil", err)
		}
	})

	// Partial-write invisibility: a stream that fails mid-write leaves
	// NOTHING visible at the destination path (section 9: single-PUT-or-MPU
	// on S3, temp-then-commit on the local engine — never the final name in
	// pieces).
	t.Run("PartialNeverVisible", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		src := &failAfterReader{serve: 256 << 10, err: errors.New("conformance: source died mid-stream")}
		if err := e.WriteStream(ctx, sc, "partial.bin", src, false); err == nil {
			t.Fatal("WriteStream(failing source) = nil, want error")
		}
		if _, err := e.Stat(ctx, sc, "partial.bin"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Stat(after failed stream) = %v, want fs.ErrNotExist (partial visible)", err)
		}
		entries, err := e.List(ctx, sc, ".")
		if err != nil {
			t.Fatalf("List(.): %v", err)
		}
		for _, fi := range entries {
			if fi.Name == "partial.bin" || strings.HasPrefix(fi.Name, "partial.bin.") {
				t.Fatalf("failed stream left visible entry %+v", fi)
			}
		}
	})

	// Context cancellation mid-write surfaces ctx.Err() (errors.Is-matchable
	// through the verb's wrap) and leaves nothing visible — the 13-03
	// contract, held by BOTH engines.
	t.Run("CtxCancel_NothingVisible", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		src := &cancelAtReader{cancel: cancel, at: 256 << 10}
		if err := e.WriteStream(cctx, sc, "cancelled.bin", src, false); !errors.Is(err, context.Canceled) {
			t.Fatalf("WriteStream under cancel = %v, want errors.Is(context.Canceled)", err)
		}
		if _, err := e.Stat(ctx, sc, "cancelled.bin"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Stat(after cancelled stream) = %v, want fs.ErrNotExist", err)
		}
	})

	// SEC-54 erase-before-reuse, observable: write a tree, tear the scope
	// down, re-provision — every prior path reads fs.ErrNotExist and the
	// scope serves fresh writes.
	t.Run("SEC54_EraseBeforeReuse", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		confWrite(t, e, sc, "a.txt", "alpha", false)
		if err := e.MakeDir(ctx, sc, "d"); err != nil {
			t.Fatalf("MakeDir(d): %v", err)
		}
		confWrite(t, e, sc, "d/b.txt", "beta", false)

		if err := e.TeardownScope(ctx, sc); err != nil {
			t.Fatalf("TeardownScope: %v", err)
		}
		if err := e.ProvisionScope(ctx, sc); err != nil {
			t.Fatalf("ProvisionScope(re-grant): %v", err)
		}

		for _, p := range []string{"a.txt", "d", "d/b.txt"} {
			if _, err := e.Stat(ctx, sc, p); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Stat(%q after erase) = %v, want fs.ErrNotExist", p, err)
			}
		}
		entries, err := e.List(ctx, sc, ".")
		if err != nil {
			t.Fatalf("List(. after re-provision): %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("List(. after re-provision) = %d entries, want 0", len(entries))
		}
		confWrite(t, e, sc, "fresh.txt", "fresh", false)
		if got := confRead(t, e, sc, "fresh.txt"); got != "fresh" {
			t.Fatalf("fresh write after re-provision = %q, want \"fresh\"", got)
		}
	})

	// The containment property, THROUGH the engine: arbitrary hostile paths
	// either refuse or land INSIDE the scope; the backend-truth probe proves
	// nothing ever appeared outside the scope boundary (for S3: no key
	// outside scope+"/"; for the local engine: no path outside the scope
	// dir).
	t.Run("Containment_Prop", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		before := tg.outside(t)
		rapid.Check(t, func(rt *rapid.T) {
			p := rapid.OneOf(
				rapid.String(),
				rapid.SampledFrom([]string{
					"..", "../escape.txt", "a/../../escape.txt", "/abs.txt",
					"//", "a//b", ".", "", "./x", "a/./b", "..\\win",
					"x\x00nul", "file://host/x", "%2e%2e/enc", "\u202eevil",
					"é-nonnfc", " ", "a/", "/",
					strings.Repeat("d/", 200) + "leaf",
				}),
				rapid.Custom(func(rt *rapid.T) string {
					segs := rapid.SliceOfN(
						rapid.SampledFrom([]string{"..", ".", "a", "b c", "ä", "", "x"}),
						1, 6).Draw(rt, "segs")
					return strings.Join(segs, "/")
				}),
			).Draw(rt, "path")

			err := e.WriteStream(ctx, sc, p, strings.NewReader("contained"), true)
			if err != nil {
				return // rejection is always acceptable
			}
			// Accepted: the object must be visible INSIDE the scope.
			if _, serr := e.Stat(ctx, sc, p); serr != nil {
				rt.Fatalf("accepted write %q not visible in-scope: %v", p, serr)
			}
		})
		after := tg.outside(t)
		for k := range after {
			if !before[k] {
				t.Fatalf("hostile write escaped the scope boundary: new outside entry %q", k)
			}
		}
	})

	// Idempotent re-invocation, per the Engine interface table: re-invoking
	// after success converges (the usual exists/not-exist errors ARE the
	// convergence signal for MakeDir/RemoveFile).
	t.Run("IdempotentReinvoke", func(t *testing.T) {
		tg := f(t)
		e, sc := tg.eng, tg.scope

		if err := e.ProvisionScope(ctx, sc); err != nil {
			t.Fatalf("ProvisionScope(re-invoke) = %v, want nil", err)
		}

		if err := e.MakeDir(ctx, sc, "d"); err != nil {
			t.Fatalf("MakeDir: %v", err)
		}
		if err := e.MakeDir(ctx, sc, "d"); !errors.Is(err, fs.ErrExist) {
			t.Fatalf("MakeDir(re-invoke) = %v, want fs.ErrExist (convergence)", err)
		}

		confWrite(t, e, sc, "f.txt", "x", false)
		if err := e.RemoveFile(ctx, sc, "f.txt"); err != nil {
			t.Fatalf("RemoveFile: %v", err)
		}
		if err := e.RemoveFile(ctx, sc, "f.txt"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("RemoveFile(re-invoke) = %v, want fs.ErrNotExist (convergence)", err)
		}

		confWrite(t, e, sc, "d/in.txt", "y", false)
		if err := e.RemoveDir(ctx, sc, "d"); err != nil {
			t.Fatalf("RemoveDir: %v", err)
		}
		if err := e.RemoveDir(ctx, sc, "d"); err != nil {
			t.Fatalf("RemoveDir(re-invoke) = %v, want nil (no-op convergence)", err)
		}

		confWrite(t, e, sc, "src.txt", "bytes", false)
		if err := e.CopyFile(ctx, sc, "src.txt", "cp.txt", true); err != nil {
			t.Fatalf("CopyFile: %v", err)
		}
		if err := e.CopyFile(ctx, sc, "src.txt", "cp.txt", true); err != nil {
			t.Fatalf("CopyFile(re-invoke, overwrite=true) = %v, want nil", err)
		}
		if got := confRead(t, e, sc, "cp.txt"); got != "bytes" {
			t.Fatalf("copy content after re-invoke = %q, want \"bytes\"", got)
		}

		if err := e.TeardownScope(ctx, sc); err != nil {
			t.Fatalf("TeardownScope: %v", err)
		}
		if err := e.TeardownScope(ctx, sc); err != nil {
			t.Fatalf("TeardownScope(re-invoke) = %v, want nil", err)
		}
		if err := e.ProvisionScope(ctx, sc); err != nil {
			t.Fatalf("ProvisionScope(after teardown) = %v, want nil", err)
		}
		confWrite(t, e, sc, "again.txt", "z", false)
	})

	// Documented divergence: MoveDir atomicity differs by engine. The local
	// engine renames in one syscall; the S3 engine walks the prefix with
	// per-object copy+delete — non-atomic, but ordered so a crash never
	// loses bytes (a surviving duplicate is the failure mode).
	t.Run("Divergence_MoveDirAtomicity", func(t *testing.T) {
		tg := f(t)
		if tg.eng.Kind() == S3 {
			t.Skip("documented divergence: s3 MoveDir is a paginated per-object copy+delete (non-atomic; copy-before-delete ordering means bytes are never lost); the local engine's MoveDir is a single atomic rename")
		}
		// Local engine: nothing to assert beyond the suite's other MoveDir
		// coverage; the divergence is on the S3 side only.
	})

	// Documented non-applicability: S3-EDGE-CASES section 3's second
	// sub-item (compare-and-swap UPDATE with a stored-digest precondition)
	// has no surface at this interface — Engine's `overwrite bool` carries
	// create-if-absent only (covered by Overwrite_Refused and
	// NoReplaceRace_Prop). The streamed-digest infrastructure exists; the
	// update-precondition verb is intentionally absent.
	t.Run("Divergence_CASUpdateNotApplicable", func(t *testing.T) {
		t.Skip("section-3 CAS-update sub-item is non-applicable: the Engine interface exposes no conditional-update mode (create-if-absent is covered by Overwrite_Refused and NoReplaceRace_Prop)")
	})
}
