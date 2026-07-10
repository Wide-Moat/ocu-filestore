// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// This file holds the in-package test doubles for the Files-API seams. Each is a
// narrow, programmable fake honouring the southface consumer-seam (or
// handlestore.Store) the handler depends on. They are deliberately simple — the
// handler's logic is what is under test, not the seam implementations (those have
// their own packages' tests).

// fakeResolver returns a fixed grant and error. A non-nil err denies; otherwise
// the grant's Downloadable drives the downloadable-at-read decision.
type fakeResolver struct {
	grant southface.Grant
	err   error
}

func (f *fakeResolver) Resolve(_ context.Context, _ any, _ southface.ResolveRequest) (southface.Grant, error) {
	return f.grant, f.err
}

// fakeGuard records every Mandated event and can be programmed to fail (deny)
// via err (applied to every Mandate call).
type fakeGuard struct {
	events []auditgate.FileActivityEvent
	err    error
}

func (g *fakeGuard) Mandate(_ context.Context, event any) error {
	ev, ok := event.(auditgate.FileActivityEvent)
	if !ok {
		return auditgate.ErrAuditUnavailable
	}
	g.events = append(g.events, ev)
	return g.err
}

// fakeEngine serves Stat and ReadRange from in-memory bytes keyed by engine path.
// readRangeCalls counts ReadRange invocations so a test can prove the engine was
// (or was NOT) reached. statErr/readErr inject faults.
//
// List serves a one-level directory listing DERIVED from the keys in bytesByPath
// (the engine-relative, no-leading-slash object paths), so a test seeds objects
// with seedObject and the north-list reconcile walks the SAME namespace a real
// engine would report. listErr injects a walk fault; listCalls counts the
// per-level List invocations. Directories are synthesized from the key path
// segments (an object "outputs/report.pdf" implies a directory "outputs").
type fakeEngine struct {
	bytesByPath    map[string][]byte
	statErr        error
	readErr        error
	listErr        error
	readRangeCalls int
	statCalls      int
	listCalls      int
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{bytesByPath: map[string][]byte{}}
}

// seedObject registers an engine object at the engine-relative path (no leading
// slash) so both List (namespace) and Stat/ReadRange (bytes) see it.
func (e *fakeEngine) seedObject(engPath string, body []byte) {
	e.bytesByPath[engPath] = body
}

// List returns the one-level entries under dir ("." = scope root) synthesized
// from the object keys: the direct file children and the immediate sub-directory
// names implied by deeper keys. It mirrors the real engine's one-level List
// contract (the walk recurses per level), so the reconcile's bounded tree walk is
// exercised against a real multi-level namespace.
func (e *fakeEngine) List(_ context.Context, _ string, dir string) ([]southface.FileInfo, error) {
	e.listCalls++
	if e.listErr != nil {
		return nil, e.listErr
	}
	prefix := ""
	if dir != "." && dir != "" && dir != "/" {
		prefix = strings.TrimSuffix(strings.TrimPrefix(dir, "/"), "/") + "/"
	}
	files := map[string]int64{}
	dirs := map[string]bool{}
	for key, body := range e.bytesByPath {
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := strings.TrimPrefix(key, prefix)
		if rest == "" {
			continue
		}
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			dirs[rest[:i]] = true // an immediate sub-directory
			continue
		}
		files[rest] = int64(len(body)) // a direct file child
	}
	out := make([]southface.FileInfo, 0, len(files)+len(dirs))
	for name, size := range files {
		out = append(out, southface.FileInfo{Name: name, Size: size, IsDir: false})
	}
	for name := range dirs {
		out = append(out, southface.FileInfo{Name: name, IsDir: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (e *fakeEngine) Stat(_ context.Context, _ string, path string) (southface.FileInfo, error) {
	e.statCalls++
	if e.statErr != nil {
		return southface.FileInfo{}, e.statErr
	}
	b, ok := e.bytesByPath[path]
	if !ok {
		return southface.FileInfo{}, southface.ErrInvalidPath
	}
	return southface.FileInfo{Name: path, Size: int64(len(b))}, nil
}

func (e *fakeEngine) MakeDir(context.Context, string, string) error { return nil }
func (e *fakeEngine) MoveDir(context.Context, string, string, string, bool) error {
	return nil
}
func (e *fakeEngine) RemoveDir(context.Context, string, string) error { return nil }
func (e *fakeEngine) CopyFile(context.Context, string, string, string, bool) error {
	return nil
}
func (e *fakeEngine) MoveFile(context.Context, string, string, string, bool) error {
	return nil
}
func (e *fakeEngine) RemoveFile(context.Context, string, string) error { return nil }

func (e *fakeEngine) ReadRange(_ context.Context, _ string, path string, offset, length int64, w io.Writer) error {
	e.readRangeCalls++
	if e.readErr != nil {
		return e.readErr
	}
	b := e.bytesByPath[path]
	if offset > int64(len(b)) {
		offset = int64(len(b))
	}
	end := offset + length
	if end > int64(len(b)) {
		end = int64(len(b))
	}
	_, err := w.Write(b[offset:end])
	return err
}

func (e *fakeEngine) WriteStream(context.Context, string, string, io.Reader, bool) (string, error) {
	// The base fake is a read/delete-plane double: its WriteStream is a no-op that
	// ignores the reader, so it computes no content digest (D6). The create-plane
	// doubles (createEngine / recordingEngine) that consume the reader return a
	// real single-pass digest.
	return "", nil
}

// fakeSession is a programmable ceilings session: each Try* call consults its
// error field so a test can drive an exhausted op or fd ceiling.
type fakeSession struct {
	opErr  error
	fdErr  error
	fdHeld int
}

func (s *fakeSession) TryConsumeOp() error { return s.opErr }
func (s *fakeSession) AcquireBytes(int64) error {
	return nil
}
func (s *fakeSession) ReleaseBytes(int64) {}
func (s *fakeSession) TryAcquireFD() error {
	if s.fdErr != nil {
		return s.fdErr
	}
	s.fdHeld++
	return nil
}
func (s *fakeSession) ReleaseFD() { s.fdHeld-- }

// fakeCeilings returns one shared fakeSession for every key.
type fakeCeilings struct {
	sess *fakeSession
}

func newFakeCeilings() *fakeCeilings { return &fakeCeilings{sess: &fakeSession{}} }

func (c *fakeCeilings) Session(string) southface.CeilingsSession { return c.sess }
func (c *fakeCeilings) Release(string)                           {}

// fakeStore is an in-memory handlestore.Store keyed by file_id, scope-bound on
// Get/Delete (absent OR cross-scope -> ErrNotFound, the keystone). getErr, when
// set, overrides Get for fault injection; deleteErr overrides Delete.
//
// EnsureObject is a REAL put-if-absent keyed on (scope, normalizeRef(ObjectRef))
// with the tombstone mask — not a stub — so the north-list reconcile it drives
// exercises the actual anti-dup and delete-mask semantics through the handler
// (the keystone tests are non-vacuous). ensureCalls counts the mints so a test
// can prove a second list did NOT re-mint.
type fakeStore struct {
	recs      map[string]handlestore.Record
	refIndex  map[string]map[string]string // scope -> normalizedRef -> file_id
	tombRefs  map[string]map[string]bool   // scope -> normalizedRef -> tombstoned
	getErr    error
	deleteErr error
	ensureErr error
	latched   bool
	listPage  handlestore.ListPage
	listErr   error
	// deleted records the file_ids passed to Delete (ordering proof).
	deleted []string
	// ensureCalls counts the number of EnsureObject calls that MINTED a fresh
	// record (an already-existing ref returns without minting).
	ensureMints int
	// mintSeq mints deterministic, unique file_ids for the fake ensure/put.
	mintSeq int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		recs:     map[string]handlestore.Record{},
		refIndex: map[string]map[string]string{},
		tombRefs: map[string]map[string]bool{},
	}
}

// normRef mirrors handlestore.normalizeRef (unexported there): strip a single
// leading slash so the fake keys on the same engine-relative convention.
func normRef(ref string) string { return strings.TrimPrefix(ref, "/") }

// put seeds a record bound to scope and indexes it by (scope, ref) so the fake's
// EnsureObject dedup sees a pre-seeded handle.
func (s *fakeStore) put(fileID, scope string, rec handlestore.Record) {
	rec.FileID = fileID
	rec.Scope = scope
	s.recs[fileID] = rec
	s.indexRef(scope, rec.ObjectRef, fileID)
}

func (s *fakeStore) indexRef(scope, ref, fileID string) {
	byRef := s.refIndex[scope]
	if byRef == nil {
		byRef = map[string]string{}
		s.refIndex[scope] = byRef
	}
	byRef[normRef(ref)] = fileID
	if ts := s.tombRefs[scope]; ts != nil {
		delete(ts, normRef(ref))
	}
}

func (s *fakeStore) Put(context.Context, handlestore.PutInput) (handlestore.Record, error) {
	return handlestore.Record{}, handlestore.ErrStoreUnavailable
}

// EnsureObject is the real put-if-absent + tombstone-mask the north-list
// reconcile drives. A tombstoned ref returns ErrNotFound (not re-minted); an
// existing ref returns its record UNCHANGED; else a fresh record is minted.
func (s *fakeStore) EnsureObject(_ context.Context, in handlestore.EnsureInput) (handlestore.Record, error) {
	if s.ensureErr != nil {
		return handlestore.Record{}, s.ensureErr
	}
	if s.latched {
		return handlestore.Record{}, handlestore.ErrStoreUnavailable
	}
	key := normRef(in.ObjectRef)
	if ts := s.tombRefs[in.Scope]; ts != nil && ts[key] {
		return handlestore.Record{}, handlestore.ErrNotFound
	}
	if byRef := s.refIndex[in.Scope]; byRef != nil {
		if fid, ok := byRef[key]; ok {
			if rec, ok := s.recs[fid]; ok {
				return rec, nil
			}
		}
	}
	s.mintSeq++
	s.ensureMints++
	fid := fmt.Sprintf("ensured-%d", s.mintSeq)
	rec := handlestore.Record{
		FileID:                fid,
		Scope:                 in.Scope,
		ObjectRef:             in.ObjectRef,
		Filename:              in.Filename,
		Mime:                  in.Mime,
		Size:                  in.Size,
		CreatedAt:             "2026-01-01T00:00:00Z",
		DownloadablePolicyRef: in.DownloadablePolicyRef,
	}
	s.recs[fid] = rec
	s.indexRef(in.Scope, in.ObjectRef, fid)
	return rec, nil
}

func (s *fakeStore) Get(_ context.Context, fileID, attestedScope string) (handlestore.Record, error) {
	if s.getErr != nil {
		return handlestore.Record{}, s.getErr
	}
	rec, ok := s.recs[fileID]
	if !ok || rec.Scope != attestedScope {
		// Absent OR cross-scope -> the SAME sentinel (keystone).
		return handlestore.Record{}, handlestore.ErrNotFound
	}
	return rec, nil
}

func (s *fakeStore) Delete(_ context.Context, fileID, attestedScope string) error {
	s.deleted = append(s.deleted, fileID)
	if s.deleteErr != nil {
		return s.deleteErr
	}
	rec, ok := s.recs[fileID]
	if !ok || rec.Scope != attestedScope {
		return handlestore.ErrNotFound
	}
	// Unindex + tombstone the (scope, ref) so EnsureObject will not re-mint it —
	// the real store's delete-mask, so the handler-driven reconcile tests are
	// non-vacuous.
	if byRef := s.refIndex[rec.Scope]; byRef != nil {
		delete(byRef, normRef(rec.ObjectRef))
	}
	ts := s.tombRefs[rec.Scope]
	if ts == nil {
		ts = map[string]bool{}
		s.tombRefs[rec.Scope] = ts
	}
	ts[normRef(rec.ObjectRef)] = true
	delete(s.recs, fileID)
	return nil
}

// List returns the fixed listPage when a test set one; otherwise it synthesizes
// a scope-bound, (CreatedAt, FileID)-sorted page from s.recs so a handler that
// reconciled the engine namespace into the store (EnsureObject) sees the ensured
// records in the list. This makes the whole-tree bridge test drive real list
// output, not a pre-canned page.
func (s *fakeStore) List(_ context.Context, in handlestore.ListInput) (handlestore.ListPage, error) {
	if s.listErr != nil {
		return handlestore.ListPage{}, s.listErr
	}
	if s.listPage.Records != nil || s.listPage.HasMore || s.listPage.FirstID != "" {
		return s.listPage, nil
	}
	matched := make([]handlestore.Record, 0, len(s.recs))
	for _, rec := range s.recs {
		if rec.Scope == in.Scope {
			matched = append(matched, rec)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].CreatedAt != matched[j].CreatedAt {
			return matched[i].CreatedAt < matched[j].CreatedAt
		}
		return matched[i].FileID < matched[j].FileID
	})
	page := handlestore.ListPage{Records: matched}
	if len(matched) > 0 {
		page.FirstID = matched[0].FileID
		page.LastID = matched[len(matched)-1].FileID
	}
	return page, nil
}

func (s *fakeStore) Close() error  { return nil }
func (s *fakeStore) Latched() bool { return s.latched }

// fakeScope is a programmable ScopeSource: it returns the fixed PeerScope and
// ok flag regardless of the request, so a test can drive the fail-closed
// (ok=false) path without crafting headers.
type fakeScope struct {
	ps southface.PeerScope
	ok bool
}

func (f fakeScope) Scope(*http.Request) (southface.PeerScope, bool) { return f.ps, f.ok }

// newTestHandler builds a Handler from the given seams, defaulting any nil seam
// to a permissive fake so a test wires only what it cares about. It panics on a
// NewHandler error (a test-wiring fault).
func newTestHandler(d Deps) *Handler {
	if d.Resolver == nil {
		d.Resolver = &fakeResolver{grant: southface.Grant{Downloadable: true}}
	}
	if d.Guard == nil {
		d.Guard = &fakeGuard{}
	}
	if d.Engine == nil {
		d.Engine = newFakeEngine()
	}
	if d.Ceilings == nil {
		d.Ceilings = newFakeCeilings()
	}
	if d.Store == nil {
		d.Store = newFakeStore()
	}
	if d.Scope == nil {
		d.Scope = fakeScope{ps: southface.PeerScope{FilesystemID: "fs-test", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true}
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.SizeCeiling == 0 {
		d.SizeCeiling = 1 << 20 // 1 MiB default params/message ceiling for tests
	}
	if d.MaxFileSize == 0 {
		d.MaxFileSize = 1 << 20 // 1 MiB default whole-object ceiling for tests
	}
	h, err := NewHandler(d)
	if err != nil {
		panic("newTestHandler: " + err.Error())
	}
	return h
}

// compile-time proofs the fakes honour the seams.
var (
	_ southface.Resolver         = (*fakeResolver)(nil)
	_ southface.Guard            = (*fakeGuard)(nil)
	_ southface.Engine           = (*fakeEngine)(nil)
	_ southface.CeilingsSession  = (*fakeSession)(nil)
	_ southface.CeilingsRegistry = (*fakeCeilings)(nil)
	_ handlestore.Store          = (*fakeStore)(nil)
	_ ScopeSource                = fakeScope{}
)
