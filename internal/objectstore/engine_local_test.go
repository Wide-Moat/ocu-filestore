// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newLocalEngine returns a localVolumeEngine over a fresh temp base dir with
// one provisioned scope.
func newLocalEngine(t *testing.T) (Engine, string, ScopeID) {
	t.Helper()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID("fs1")
	if err := eng.ProvisionScope(context.Background(), scope); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}
	return eng, base, scope
}

// readBack streams the whole named file through ReadRange and returns its
// bytes.
func readBack(t *testing.T, eng Engine, scope ScopeID, path string, length int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := eng.ReadRange(context.Background(), scope, path, 0, length, &buf); err != nil {
		t.Fatalf("ReadRange(%q): %v", path, err)
	}
	return buf.Bytes()
}

// assertNoTempFiles walks the scope dir and fails on any leftover temp name.
func assertNoTempFiles(t *testing.T, base string, scope ScopeID) {
	t.Helper()
	err := filepath.WalkDir(filepath.Join(base, string(scope)), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(d.Name(), ".tmp.") {
			t.Fatalf("temp file left behind: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk scope: %v", err)
	}
}

// failingReader yields a few bytes then fails, simulating a caller stream
// that dies mid-copy.
type failingReader struct {
	served bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if !r.served {
		r.served = true
		n := copy(p, []byte("partial"))
		return n, nil
	}
	return 0, errors.New("simulated mid-stream failure")
}

// TestLocalEngine_WriteStream pins the write path: byte-identical readback,
// ErrAlreadyExists with overwrite=false, replacement with overwrite=true,
// and no temp name left behind on success (T-03-03 rename-into-place).
func TestLocalEngine_WriteStream(t *testing.T) {
	ctx := context.Background()
	eng, base, scope := newLocalEngine(t)

	data := []byte("the first object body")
	if err := eng.WriteStream(ctx, scope, "f.txt", bytes.NewReader(data), false); err != nil {
		t.Fatalf("WriteStream new: %v", err)
	}
	if got := readBack(t, eng, scope, "f.txt", int64(len(data))+8); !bytes.Equal(got, data) {
		t.Fatalf("readback: got %q, want %q", got, data)
	}

	if err := eng.WriteStream(ctx, scope, "f.txt", bytes.NewReader(data), false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("WriteStream overwrite=false on existing: got %v, want ErrAlreadyExists", err)
	}

	data2 := []byte("replaced")
	if err := eng.WriteStream(ctx, scope, "f.txt", bytes.NewReader(data2), true); err != nil {
		t.Fatalf("WriteStream overwrite=true: %v", err)
	}
	if got := readBack(t, eng, scope, "f.txt", 64); !bytes.Equal(got, data2) {
		t.Fatalf("readback after overwrite: got %q, want %q", got, data2)
	}

	assertNoTempFiles(t, base, scope)
}

// TestLocalEngine_WriteStreamCleanup pins that a reader failing mid-copy
// leaves NO temp file and NO destination file — the partial object is
// invisible and removed (T-03-03).
func TestLocalEngine_WriteStreamCleanup(t *testing.T) {
	ctx := context.Background()
	eng, base, scope := newLocalEngine(t)

	err := eng.WriteStream(ctx, scope, "broken.txt", &failingReader{}, false)
	if err == nil {
		t.Fatal("WriteStream with failing reader: got nil error")
	}

	entries, err := os.ReadDir(filepath.Join(base, string(scope)))
	if err != nil {
		t.Fatalf("read scope dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("scope dir not empty after failed write: %v", names)
	}
}

// TestLocalEngine_ReadRange pins the half-open [offset, offset+length)
// contract: exact bytes, short-read at EOF without error, offset 0 from
// start, and an offset past EOF yielding zero bytes without error.
func TestLocalEngine_ReadRange(t *testing.T) {
	ctx := context.Background()
	eng, _, scope := newLocalEngine(t)

	if err := eng.WriteStream(ctx, scope, "r.bin", strings.NewReader("abcdefghij"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}

	for _, tc := range []struct {
		name           string
		offset, length int64
		want           string
	}{
		{"middle", 2, 3, "cde"},
		{"from_start", 0, 4, "abcd"},
		{"short_read_at_eof", 8, 10, "ij"},
		{"offset_past_eof", 20, 5, ""},
		{"exact_to_eof", 0, 10, "abcdefghij"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := eng.ReadRange(ctx, scope, "r.bin", tc.offset, tc.length, &buf); err != nil {
				t.Fatalf("ReadRange(%d, %d): %v", tc.offset, tc.length, err)
			}
			if buf.String() != tc.want {
				t.Fatalf("ReadRange(%d, %d): got %q, want %q", tc.offset, tc.length, buf.String(), tc.want)
			}
		})
	}
}

// TestLocalEngine_List pins non-recursive listing: one level only, correct
// Name/Size/IsDir, the literal "." naming the scope root, and a nested dir
// listing only its own level.
func TestLocalEngine_List(t *testing.T) {
	ctx := context.Background()
	eng, _, scope := newLocalEngine(t)

	if err := eng.WriteStream(ctx, scope, "f1", strings.NewReader("abc"), false); err != nil {
		t.Fatalf("WriteStream f1: %v", err)
	}
	if err := eng.MakeDir(ctx, scope, "d"); err != nil {
		t.Fatalf("MakeDir d: %v", err)
	}
	if err := eng.WriteStream(ctx, scope, "d/f2", strings.NewReader("12345"), false); err != nil {
		t.Fatalf("WriteStream d/f2: %v", err)
	}

	root, err := eng.List(ctx, scope, ".")
	if err != nil {
		t.Fatalf("List scope root: %v", err)
	}
	if len(root) != 2 {
		t.Fatalf("List scope root: got %d entries, want 2: %+v", len(root), root)
	}
	byName := map[string]FileInfo{}
	for _, e := range root {
		byName[e.Name] = e
	}
	if fi, ok := byName["f1"]; !ok || fi.IsDir || fi.Size != 3 {
		t.Fatalf("entry f1: got %+v, want file of size 3", byName["f1"])
	}
	if fi, ok := byName["d"]; !ok || !fi.IsDir {
		t.Fatalf("entry d: got %+v, want directory", byName["d"])
	}

	nested, err := eng.List(ctx, scope, "d")
	if err != nil {
		t.Fatalf("List d: %v", err)
	}
	if len(nested) != 1 || nested[0].Name != "f2" || nested[0].Size != 5 || nested[0].IsDir {
		t.Fatalf("List d: got %+v, want single file f2 of size 5", nested)
	}
}

// TestLocalEngine_Stat pins Size/ModTime/IsDir for a file and a directory,
// and the fs.ErrNotExist class for a missing path.
func TestLocalEngine_Stat(t *testing.T) {
	ctx := context.Background()
	eng, _, scope := newLocalEngine(t)

	if err := eng.WriteStream(ctx, scope, "s.txt", strings.NewReader("123456"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := eng.MakeDir(ctx, scope, "dir"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}

	fi, err := eng.Stat(ctx, scope, "s.txt")
	if err != nil {
		t.Fatalf("Stat file: %v", err)
	}
	if fi.Name != "s.txt" || fi.Size != 6 || fi.IsDir || fi.ModTime.IsZero() {
		t.Fatalf("Stat file: got %+v", fi)
	}

	di, err := eng.Stat(ctx, scope, "dir")
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if !di.IsDir || di.Name != "dir" {
		t.Fatalf("Stat dir: got %+v, want directory", di)
	}

	if _, err := eng.Stat(ctx, scope, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat missing: got %v, want fs.ErrNotExist", err)
	}
}

// TestLocalEngine_MakeDir pins single-level creation: the dir exists after,
// and a missing parent refuses (Mkdir, not MkdirAll).
func TestLocalEngine_MakeDir(t *testing.T) {
	ctx := context.Background()
	eng, _, scope := newLocalEngine(t)

	if err := eng.MakeDir(ctx, scope, "d1"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	fi, err := eng.Stat(ctx, scope, "d1")
	if err != nil || !fi.IsDir {
		t.Fatalf("Stat d1: fi=%+v err=%v, want directory", fi, err)
	}

	if err := eng.MakeDir(ctx, scope, "nope/child"); err == nil {
		t.Fatal("MakeDir with missing parent: got nil, want error (single level)")
	}
}

// TestLocalEngine_Remove pins RemoveFile on a file and RemoveDir's recursive
// default on a non-empty directory.
func TestLocalEngine_Remove(t *testing.T) {
	ctx := context.Background()
	eng, _, scope := newLocalEngine(t)

	if err := eng.WriteStream(ctx, scope, "victim", strings.NewReader("x"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := eng.RemoveFile(ctx, scope, "victim"); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if _, err := eng.Stat(ctx, scope, "victim"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat removed file: got %v, want fs.ErrNotExist", err)
	}

	if err := eng.MakeDir(ctx, scope, "tree"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	if err := eng.WriteStream(ctx, scope, "tree/leaf", strings.NewReader("y"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := eng.RemoveDir(ctx, scope, "tree"); err != nil {
		t.Fatalf("RemoveDir non-empty: %v", err)
	}
	if _, err := eng.Stat(ctx, scope, "tree"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat removed dir: got %v, want fs.ErrNotExist", err)
	}
}

// TestLocalEngine_Move pins MoveFile/MoveDir rename-within-scope and the
// overwrite flag: false refuses ErrAlreadyExists, true replaces.
func TestLocalEngine_Move(t *testing.T) {
	ctx := context.Background()
	eng, _, scope := newLocalEngine(t)

	if err := eng.WriteStream(ctx, scope, "a.txt", strings.NewReader("alpha"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := eng.MoveFile(ctx, scope, "a.txt", "b.txt", false); err != nil {
		t.Fatalf("MoveFile: %v", err)
	}
	if _, err := eng.Stat(ctx, scope, "a.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat old name: got %v, want fs.ErrNotExist", err)
	}
	if got := readBack(t, eng, scope, "b.txt", 16); string(got) != "alpha" {
		t.Fatalf("readback after move: got %q, want alpha", got)
	}

	if err := eng.WriteStream(ctx, scope, "c.txt", strings.NewReader("gamma"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := eng.MoveFile(ctx, scope, "c.txt", "b.txt", false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("MoveFile overwrite=false onto existing: got %v, want ErrAlreadyExists", err)
	}
	if err := eng.MoveFile(ctx, scope, "c.txt", "b.txt", true); err != nil {
		t.Fatalf("MoveFile overwrite=true: %v", err)
	}
	if got := readBack(t, eng, scope, "b.txt", 16); string(got) != "gamma" {
		t.Fatalf("readback after overwrite move: got %q, want gamma", got)
	}

	if err := eng.MakeDir(ctx, scope, "src_dir"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	if err := eng.WriteStream(ctx, scope, "src_dir/inner", strings.NewReader("z"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := eng.MoveDir(ctx, scope, "src_dir", "dst_dir", false); err != nil {
		t.Fatalf("MoveDir: %v", err)
	}
	if got := readBack(t, eng, scope, "dst_dir/inner", 8); string(got) != "z" {
		t.Fatalf("readback after dir move: got %q, want z", got)
	}
	if _, err := eng.Stat(ctx, scope, "src_dir"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat moved dir old name: got %v, want fs.ErrNotExist", err)
	}
}

// TestLocalEngine_Copy pins CopyFile byte duplication within the scope and
// the overwrite flag semantics.
func TestLocalEngine_Copy(t *testing.T) {
	ctx := context.Background()
	eng, base, scope := newLocalEngine(t)

	if err := eng.WriteStream(ctx, scope, "orig", strings.NewReader("copy me"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := eng.CopyFile(ctx, scope, "orig", "dup", false); err != nil {
		t.Fatalf("CopyFile: %v", err)
	}
	if got := readBack(t, eng, scope, "orig", 16); string(got) != "copy me" {
		t.Fatalf("source after copy: got %q", got)
	}
	if got := readBack(t, eng, scope, "dup", 16); string(got) != "copy me" {
		t.Fatalf("destination after copy: got %q", got)
	}

	if err := eng.CopyFile(ctx, scope, "orig", "dup", false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("CopyFile overwrite=false onto existing: got %v, want ErrAlreadyExists", err)
	}
	if err := eng.WriteStream(ctx, scope, "orig2", strings.NewReader("v2"), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := eng.CopyFile(ctx, scope, "orig2", "dup", true); err != nil {
		t.Fatalf("CopyFile overwrite=true: %v", err)
	}
	if got := readBack(t, eng, scope, "dup", 16); string(got) != "v2" {
		t.Fatalf("destination after overwrite copy: got %q, want v2", got)
	}

	assertNoTempFiles(t, base, scope)
}

// TestLocalEngine_EscapeRejected pins that an escaping src/dst on
// Move/Copy/Write surfaces either the lexical sentinel or the os.Root escape
// class — and specifically that a rename escape arrives as *os.LinkError and
// is caught by isPathEscape (T-03-04, the LinkError-vs-PathError pin).
func TestLocalEngine_EscapeRejected(t *testing.T) {
	ctx := context.Background()
	eng, base, scope := newLocalEngine(t)

	// A directory OUTSIDE the base dir, reachable only through a symlink
	// planted inside the scope.
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("escaped"), 0o644); err != nil {
		t.Fatalf("write outside secret: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(base, string(scope), "esc")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}
	if err := eng.WriteStream(ctx, scope, "f.txt", strings.NewReader("in"), false); err != nil {
		t.Fatalf("WriteStream seed: %v", err)
	}

	// Rename escape: MUST be the *os.LinkError wrapper, normalized by
	// isPathEscape into the same caller-visible class.
	err := eng.MoveFile(ctx, scope, "f.txt", "esc/out.txt", false)
	if err == nil {
		t.Fatal("MoveFile into symlinked-out dir: got nil error")
	}
	var le *os.LinkError
	if !errors.As(err, &le) {
		t.Fatalf("MoveFile escape: got %T (%v), want *os.LinkError", err, err)
	}
	if !isPathEscape(err) {
		t.Fatalf("MoveFile escape not normalized by isPathEscape: %v", err)
	}

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"write_through_symlink", func() error {
			return eng.WriteStream(ctx, scope, "esc/w.txt", strings.NewReader("x"), false)
		}},
		{"copy_src_through_symlink", func() error {
			return eng.CopyFile(ctx, scope, "esc/secret", "in.txt", false)
		}},
		{"copy_dst_through_symlink", func() error {
			return eng.CopyFile(ctx, scope, "f.txt", "esc/c.txt", false)
		}},
		{"move_lexical_traversal", func() error {
			return eng.MoveFile(ctx, scope, "f.txt", "../escape.txt", false)
		}},
		{"remove_through_symlink", func() error {
			return eng.RemoveFile(ctx, scope, "esc/secret")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("escaping call: got nil error")
			}
			if !isPathEscape(err) && !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("escaping call: got %v, want escape class or ErrInvalidPath", err)
			}
		})
	}

	// The outside world is untouched.
	got, err := os.ReadFile(secret)
	if err != nil || string(got) != "escaped" {
		t.Fatalf("outside secret mutated: content=%q err=%v", got, err)
	}
}

// TestTeardownScope_SymlinkRefused pins the T-03-05 guard: a symlinked scope
// dir is refused with ErrInvalidPath and the symlink target's contents
// survive — TeardownScope never follows the link into a RemoveAll.
func TestTeardownScope_SymlinkRefused(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)

	outside := t.TempDir()
	keep := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(keep, []byte("must survive"), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "linked")); err != nil {
		t.Fatalf("plant scope symlink: %v", err)
	}

	if err := eng.TeardownScope(ctx, ScopeID("linked")); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("TeardownScope on symlinked scope: got %v, want ErrInvalidPath", err)
	}

	got, err := os.ReadFile(keep)
	if err != nil || string(got) != "must survive" {
		t.Fatalf("symlink target damaged by teardown: content=%q err=%v", got, err)
	}
}

// TestProvisionTeardownCycle is the deterministic SEC-54 companion: after
// provision + write + teardown, the prior path reads fs.ErrNotExist and the
// scope dir exists again ready for re-grant. Also pins the lifecycle edges:
// teardown of an absent scope recreates it, and a non-directory scope entry
// refuses with ErrNotADirectory.
func TestProvisionTeardownCycle(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	eng := NewLocalVolumeEngine(base)
	scope := ScopeID("recycled")

	if err := eng.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(base, string(scope))); err != nil || !fi.IsDir() {
		t.Fatalf("scope dir after provision: fi=%v err=%v", fi, err)
	}

	if err := eng.WriteStream(ctx, scope, "session1/marker", strings.NewReader("prior bytes"), false); err == nil {
		t.Log("nested write succeeded unexpectedly without parent dir")
	}
	if err := eng.WriteStream(ctx, scope, "marker", strings.NewReader("prior bytes"), false); err != nil {
		t.Fatalf("WriteStream marker: %v", err)
	}

	if err := eng.TeardownScope(ctx, scope); err != nil {
		t.Fatalf("TeardownScope: %v", err)
	}

	// Re-grant: same filesystem_id, prior path unreadable (NFR-SEC-54).
	if _, err := eng.Stat(ctx, scope, "marker"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat prior marker after teardown: got %v, want fs.ErrNotExist", err)
	}
	if fi, err := os.Stat(filepath.Join(base, string(scope))); err != nil || !fi.IsDir() {
		t.Fatalf("scope dir after teardown: fi=%v err=%v, want recreated dir", fi, err)
	}

	// Absent scope: teardown recreates and succeeds.
	if err := eng.TeardownScope(ctx, ScopeID("never_provisioned")); err != nil {
		t.Fatalf("TeardownScope absent scope: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(base, "never_provisioned")); err != nil || !fi.IsDir() {
		t.Fatalf("absent scope after teardown: fi=%v err=%v, want created dir", fi, err)
	}

	// Non-directory scope entry: refused.
	if err := os.WriteFile(filepath.Join(base, "plainfile"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write plain file: %v", err)
	}
	if err := eng.TeardownScope(ctx, ScopeID("plainfile")); !errors.Is(err, ErrNotADirectory) {
		t.Fatalf("TeardownScope on plain file: got %v, want ErrNotADirectory", err)
	}
}
