// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"errors"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// budgetSession is a CeilingsSession whose op tokens are a FINITE budget: each
// TryConsumeOp decrements it and a drained budget refuses. Every other ceiling
// is permissive, so a test isolates exactly the op-charge accounting.
type budgetSession struct {
	ops int
}

func (s *budgetSession) TryConsumeOp() error {
	if s.ops <= 0 {
		return errors.New("op budget exhausted")
	}
	s.ops--
	return nil
}
func (s *budgetSession) AcquireBytes(int64) error { return nil }
func (s *budgetSession) ReleaseBytes(int64)       {}
func (s *budgetSession) TryAcquireFD() error      { return nil }
func (s *budgetSession) ReleaseFD()               {}

type budgetCeilings struct{ sess *budgetSession }

func (c *budgetCeilings) Session(string) southface.CeilingsSession { return c.sess }
func (c *budgetCeilings) Release(string)                           {}

// archiveBudgetSetup mirrors archiveSetup but wires the finite-budget ceilings.
func archiveBudgetSetup(ops int) (*Handler, *fakeEngine, *fakeStore, *budgetSession) {
	store := newFakeStore()
	eng := newFakeEngine()
	sess := &budgetSession{ops: ops}
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:    &fakeGuard{},
		Ceilings: &budgetCeilings{sess: sess},
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})
	return h, eng, store, sess
}

// TestArchiveChargesOneOpPerNamedID pins the read-path cost symmetry (D7,
// egress-amplification): an N-member archive costs 1 route op + N per-id ops
// from the SAME per-session bucket a single-object read draws on, so bundling
// can never be cheaper per object than N single reads. The budget here covers
// the route and both ids exactly, and the request succeeds consuming ALL of it.
func TestArchiveChargesOneOpPerNamedID(t *testing.T) {
	h, eng, store, sess := archiveBudgetSetup(3) // 1 route + 2 ids
	seedFile(store, eng, "fid-a", "fs-alpha", "obj/a", "a.txt", "AAA")
	seedFile(store, eng, "fid-b", "fs-alpha", "obj/b", "b.txt", "BB")

	w := doReq(h, http.MethodGet, "/v1/files/archive?file_id=fid-a&file_id=fid-b")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (budget covers route + both ids)", w.Code)
	}
	if entries := readZipEntries(t, w.Body.Bytes()); len(entries) != 2 {
		t.Fatalf("zip has %d entries, want 2", len(entries))
	}
	if sess.ops != 0 {
		t.Fatalf("op budget left = %d, want 0 (1 route + 1 per named id)", sess.ops)
	}
}

// TestArchiveOverBudgetRefusesBeforeAnyWork is the amplification keystone: a
// request naming more ids than the op budget covers is refused 429 BEFORE any
// store resolution, engine stat, or byte — the per-id charge lands on NAMED
// ids up front, so a stuffed file_id list cannot buy unpaid resolve/stat work
// (and the charge is id-count-only: nothing about resolvability leaks).
func TestArchiveOverBudgetRefusesBeforeAnyWork(t *testing.T) {
	h, eng, store, _ := archiveBudgetSetup(3) // 1 route + 2 < 1 + 4 needed
	seedFile(store, eng, "fid-a", "fs-alpha", "obj/a", "a.txt", "AAA")

	w := doReq(h, http.MethodGet,
		"/v1/files/archive?file_id=fid-a&file_id=fid-b&file_id=fid-c&file_id=fid-d")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (over the per-id op budget)", w.Code)
	}
	if store.getCalls != 0 {
		t.Fatalf("store.Get called %d times on an over-budget archive; the charge must land before ANY resolution", store.getCalls)
	}
	if eng.readRangeCalls != 0 {
		t.Fatalf("engine.ReadRange called %d times on an over-budget archive; want 0", eng.readRangeCalls)
	}
	if eng.statCalls != 0 {
		t.Fatalf("engine.Stat called %d times on an over-budget archive; want 0", eng.statCalls)
	}
}
