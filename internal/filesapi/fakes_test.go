// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"

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
type fakeEngine struct {
	bytesByPath    map[string][]byte
	statErr        error
	readErr        error
	readRangeCalls int
	statCalls      int
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{bytesByPath: map[string][]byte{}}
}

func (e *fakeEngine) List(context.Context, string, string) ([]southface.FileInfo, error) {
	return nil, nil
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

func (e *fakeEngine) WriteStream(context.Context, string, string, io.Reader, bool) error {
	return nil
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
type fakeStore struct {
	recs      map[string]handlestore.Record
	getErr    error
	deleteErr error
	listPage  handlestore.ListPage
	listErr   error
	// deleted records the file_ids passed to Delete (ordering proof).
	deleted []string
}

func newFakeStore() *fakeStore { return &fakeStore{recs: map[string]handlestore.Record{}} }

// put seeds a record bound to scope.
func (s *fakeStore) put(fileID, scope string, rec handlestore.Record) {
	rec.FileID = fileID
	rec.Scope = scope
	s.recs[fileID] = rec
}

func (s *fakeStore) Put(context.Context, handlestore.PutInput) (handlestore.Record, error) {
	return handlestore.Record{}, handlestore.ErrStoreUnavailable
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
	delete(s.recs, fileID)
	return nil
}

func (s *fakeStore) List(_ context.Context, _ handlestore.ListInput) (handlestore.ListPage, error) {
	if s.listErr != nil {
		return handlestore.ListPage{}, s.listErr
	}
	return s.listPage, nil
}

func (s *fakeStore) Close() error  { return nil }
func (s *fakeStore) Latched() bool { return false }

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
