// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"
)

// fakeEngine is a real in-memory tree engine — NOT scripted returns. Each
// scope owns a root node; mutations are reflected in subsequent listings, so
// the OPS-02/03 "effects visible in a subsequent listDirectory" criterion is
// actually proven rather than hard-coded. It mirrors the objectstore engine's
// exact sentinel contract (wrapped fs.ErrExist / fs.ErrNotExist on MakeDir,
// the errAlreadyExists sentinel on Move/Copy collision, errInvalidPath on a
// lexical reject) so the deny-mapping tests bind to real semantics.
//
// Paths arrive in the engine-relative convention ("." = scope root). A "."
// or "" path names the scope root; otherwise the path is split on "/".
type node struct {
	name     string
	isDir    bool
	size     int64
	mtime    time.Time
	children map[string]*node
	// data holds the file's bytes (file nodes only). It is kept consistent
	// with size (len(data) == size for nodes seeded with bytes); a node seeded
	// by the size-only putFile helper carries nil data with a declared size,
	// which the phase-9 listing tests never read.
	data []byte
}

func newDirNode(name string) *node {
	return &node{name: name, isDir: true, mtime: time.Unix(1700000000, 0).UTC(), children: map[string]*node{}}
}

type fakeEngine struct {
	mu      sync.Mutex
	roots   map[string]*node // scope -> root dir node
	clock   int64            // monotone mtime source
	muts    []string         // recorded mutation target paths (P1 non-vacuity)
	listed  []string         // recorded List target paths (rmdir-guard witness)
	rmDirs  []string         // recorded RemoveDir target paths (no-delete witness)
	rdrange []string         // recorded ReadRange target paths (SEC-73 deny-precedes-read witness)
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{roots: map[string]*node{}, clock: 1700000000}
}

// scopeRoot returns (creating if needed) the root node for a scope.
func (e *fakeEngine) scopeRoot(scope string) *node {
	r, ok := e.roots[scope]
	if !ok {
		r = newDirNode("")
		e.roots[scope] = r
	}
	return r
}

// nextMtime advances the monotone clock so created/moved objects sort stably
// in time without colliding.
func (e *fakeEngine) nextMtime() time.Time {
	e.clock++
	return time.Unix(e.clock, 0).UTC()
}

// splitRel splits an engine-relative path into components. "." / "" -> nil
// (the scope root). A leading/trailing slash or an embedded "" component is a
// lexical fault (errInvalidPath) — the real engine rejects these pre-syscall.
func splitRel(rel string) ([]string, error) {
	if rel == "" || rel == "." {
		return nil, nil
	}
	if strings.HasPrefix(rel, "/") {
		return nil, errInvalidPath
	}
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, errInvalidPath
		}
	}
	return parts, nil
}

// walk resolves the node at rel under scope. missing reports the first
// component that did not exist (for ENOENT shaping); found is nil when missing
// is set.
func (e *fakeEngine) walk(scope, rel string) (found *node, parent *node, leaf string, parts []string, err error) {
	parts, err = splitRel(rel)
	if err != nil {
		return nil, nil, "", nil, err
	}
	cur := e.scopeRoot(scope)
	if len(parts) == 0 {
		return cur, nil, "", nil, nil
	}
	parent = cur
	for i, p := range parts {
		child, ok := cur.children[p]
		if !ok {
			if i == len(parts)-1 {
				return nil, parent, p, parts, nil // leaf missing
			}
			return nil, nil, "", parts, pathErr("open", rel, fs.ErrNotExist)
		}
		if i == len(parts)-1 {
			return child, parent, p, parts, nil
		}
		if !child.isDir {
			return nil, nil, "", parts, pathErr("open", rel, fs.ErrNotExist)
		}
		parent = child
		cur = child
	}
	return cur, parent, parts[len(parts)-1], parts, nil
}

func pathErr(op, path string, err error) error {
	return &fs.PathError{Op: op, Path: path, Err: err}
}

func (e *fakeEngine) recordMut(rel string) { e.muts = append(e.muts, rel) }

func (e *fakeEngine) List(_ context.Context, scope, path string) ([]FileInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listed = append(e.listed, path)
	n, _, _, _, err := e.walk(scope, path)
	if err != nil {
		return nil, err
	}
	if n == nil || !n.isDir {
		return nil, pathErr("open", path, fs.ErrNotExist)
	}
	out := make([]FileInfo, 0, len(n.children))
	for _, c := range n.children {
		out = append(out, FileInfo{Name: c.name, Size: c.size, ModTime: c.mtime, IsDir: c.isDir})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (e *fakeEngine) Stat(_ context.Context, scope, path string) (FileInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n, _, _, _, err := e.walk(scope, path)
	if err != nil {
		return FileInfo{}, err
	}
	if n == nil {
		return FileInfo{}, pathErr("stat", path, fs.ErrNotExist)
	}
	return FileInfo{Name: n.name, Size: n.size, ModTime: n.mtime, IsDir: n.isDir}, nil
}

func (e *fakeEngine) MakeDir(_ context.Context, scope, path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	n, parent, leaf, _, err := e.walk(scope, path)
	if err != nil {
		return err // ENOENT missing parent / errInvalidPath
	}
	if n != nil {
		// Existing dir EEXIST surfaces as a raw *fs.PathError wrapping
		// fs.ErrExist (NOT the typed sentinel) — mirrors engine MakeDir.
		return pathErr("mkdir", path, fs.ErrExist)
	}
	parent.children[leaf] = newDirNode(leaf)
	parent.children[leaf].mtime = e.nextMtime()
	e.recordMut(path)
	return nil
}

func (e *fakeEngine) RemoveDir(_ context.Context, scope, path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rmDirs = append(e.rmDirs, path)
	n, parent, leaf, _, err := e.walk(scope, path)
	if err != nil {
		return err
	}
	if n == nil || parent == nil {
		return nil // missing path is a no-op (RemoveAll semantics)
	}
	if !n.isDir {
		return pathErr("remove", path, fs.ErrNotExist)
	}
	delete(parent.children, leaf)
	e.recordMut(path)
	return nil
}

func (e *fakeEngine) RemoveFile(_ context.Context, scope, path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	n, parent, leaf, _, err := e.walk(scope, path)
	if err != nil {
		return err
	}
	if n == nil || parent == nil || n.isDir {
		return pathErr("remove", path, fs.ErrNotExist)
	}
	delete(parent.children, leaf)
	e.recordMut(path)
	return nil
}

func (e *fakeEngine) moveOrCopy(scope, src, dst string, overwrite, isDir, move bool) error {
	sn, sParent, sLeaf, _, err := e.walk(scope, src)
	if err != nil {
		return err
	}
	if sn == nil {
		return pathErr("open", src, fs.ErrNotExist)
	}
	if sn.isDir != isDir {
		return pathErr("open", src, fs.ErrNotExist)
	}
	dn, dParent, dLeaf, _, err := e.walk(scope, dst)
	if err != nil {
		return err
	}
	if dParent == nil {
		return pathErr("open", dst, fs.ErrNotExist) // dst names the scope root
	}
	if dn != nil && !overwrite {
		return errAlreadyExists
	}
	// Deep-copy the source subtree under the destination leaf name.
	cp := cloneNode(sn, dLeaf)
	cp.mtime = e.nextMtime()
	dParent.children[dLeaf] = cp
	if move {
		delete(sParent.children, sLeaf)
	}
	e.recordMut(dst)
	return nil
}

func cloneNode(n *node, newName string) *node {
	c := &node{name: newName, isDir: n.isDir, size: n.size, mtime: n.mtime}
	if n.isDir {
		c.children = map[string]*node{}
		for k, v := range n.children {
			c.children[k] = cloneNode(v, k)
		}
	}
	return c
}

func (e *fakeEngine) MoveDir(_ context.Context, scope, src, dst string, overwrite bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.moveOrCopy(scope, src, dst, overwrite, true, true)
}

func (e *fakeEngine) CopyFile(_ context.Context, scope, src, dst string, overwrite bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.moveOrCopy(scope, src, dst, overwrite, false, false)
}

func (e *fakeEngine) MoveFile(_ context.Context, scope, src, dst string, overwrite bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.moveOrCopy(scope, src, dst, overwrite, false, true)
}

// putFile is a test helper that creates a file at an engine-relative path,
// creating intermediate directories. It bypasses the verb path so a test can
// seed a tree.
func (e *fakeEngine) putFile(scope, rel string, size int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	parts, err := splitRel(rel)
	if err != nil || len(parts) == 0 {
		panic(fmt.Sprintf("putFile: bad rel %q", rel))
	}
	cur := e.scopeRoot(scope)
	for i, p := range parts {
		if i == len(parts)-1 {
			cur.children[p] = &node{name: p, isDir: false, size: size, mtime: e.nextMtime()}
			return
		}
		next, ok := cur.children[p]
		if !ok {
			next = newDirNode(p)
			cur.children[p] = next
		}
		cur = next
	}
}

// putBytes is a test helper that creates a file at an engine-relative path
// with the given bytes (and a matching size), creating intermediate
// directories. It seeds the data path that ReadRange/WriteStream exercise.
func (e *fakeEngine) putBytes(scope, rel string, b []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	parts, err := splitRel(rel)
	if err != nil || len(parts) == 0 {
		panic(fmt.Sprintf("putBytes: bad rel %q", rel))
	}
	cur := e.scopeRoot(scope)
	for i, p := range parts {
		if i == len(parts)-1 {
			cur.children[p] = &node{name: p, isDir: false, size: int64(len(b)), mtime: e.nextMtime(), data: append([]byte(nil), b...)}
			return
		}
		next, ok := cur.children[p]
		if !ok {
			next = newDirNode(p)
			cur.children[p] = next
		}
		cur = next
	}
}

// ReadRange streams the half-open window [offset, offset+length) of the file
// at path into w. A missing path or a directory is ENOENT. The window clamps
// against len(data): an offset past EOF yields an empty read, an
// offset+length past EOF short-reads to EOF — both WITHOUT error, mirroring
// the engine's past-EOF contract. A non-positive length reads from offset to
// EOF (the absent-length / full-read convention the handler relies on).
func (e *fakeEngine) ReadRange(_ context.Context, scope, path string, offset, length int64, w io.Writer) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rdrange = append(e.rdrange, path)
	n, _, _, _, err := e.walk(scope, path)
	if err != nil {
		return err
	}
	if n == nil || n.isDir {
		return pathErr("open", path, fs.ErrNotExist)
	}
	size := int64(len(n.data))
	if offset < 0 {
		offset = 0
	}
	if offset > size {
		offset = size
	}
	var end int64
	if length <= 0 {
		end = size // full read from offset to EOF
	} else {
		end = offset + length
		if end > size {
			end = size // short-read past EOF, no error
		}
	}
	_, werr := w.Write(n.data[offset:end])
	return werr
}

// WriteStream consumes r into the file at path. If the leaf already exists and
// overwrite is false it returns errAlreadyExists WITHOUT reading r (A1). It
// otherwise reads r fully (mirroring temp+rename: a reader error — including a
// pipe CloseWithError — returns that error and links NO node, so a partial or
// aborted upload is never namespace-visible). On a clean read it links a new
// file node with the read bytes.
func (e *fakeEngine) WriteStream(_ context.Context, scope, path string, r io.Reader, overwrite bool) error {
	e.mu.Lock()
	n, parent, _, _, err := e.walk(scope, path)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	if parent == nil {
		e.mu.Unlock()
		return pathErr("open", path, fs.ErrNotExist) // path names the scope root
	}
	if n != nil && !overwrite {
		e.mu.Unlock()
		return errAlreadyExists
	}
	e.mu.Unlock()

	// Read outside the lock: the producer pipes chunks in and may block, and
	// a reassembly abort surfaces here as a read error. Nothing is linked
	// until the read completes cleanly (temp+rename invisibility).
	buf, rerr := io.ReadAll(r)
	if rerr != nil {
		return rerr
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	// Re-resolve the parent under the lock before linking (the tree may have
	// changed while reading).
	_, parent, leaf, _, err := e.walk(scope, path)
	if err != nil {
		return err
	}
	if parent == nil {
		return pathErr("open", path, fs.ErrNotExist)
	}
	parent.children[leaf] = &node{name: leaf, isDir: false, size: int64(len(buf)), mtime: e.nextMtime(), data: buf}
	e.recordMut(path)
	return nil
}

// mkdirSeed creates a directory (and parents) for seeding a tree.
func (e *fakeEngine) mkdirSeed(scope, rel string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	parts, err := splitRel(rel)
	if err != nil || len(parts) == 0 {
		panic(fmt.Sprintf("mkdirSeed: bad rel %q", rel))
	}
	cur := e.scopeRoot(scope)
	for _, p := range parts {
		next, ok := cur.children[p]
		if !ok {
			next = newDirNode(p)
			cur.children[p] = next
		}
		cur = next
	}
}

// mutations returns a snapshot of every mutation target path the fake recorded
// (the P1 scope-containment non-vacuity counter source).
func (e *fakeEngine) mutations() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.muts))
	copy(out, e.muts)
	return out
}

// removeDirCalls returns the RemoveDir target paths recorded — the witness
// that a non-empty-rmdir refusal never reached the engine delete.
func (e *fakeEngine) removeDirCalls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.rmDirs))
	copy(out, e.rmDirs)
	return out
}

// readRangeCalls returns the ReadRange target paths recorded — the witness
// that a not_downloadable readFile deny precedes (and never reaches) the
// engine read (SEC-73/A2).
func (e *fakeEngine) readRangeCalls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.rdrange))
	copy(out, e.rdrange)
	return out
}

// Compile-time proof the fake satisfies the consumer-side Engine seam.
var _ Engine = (*fakeEngine)(nil)
