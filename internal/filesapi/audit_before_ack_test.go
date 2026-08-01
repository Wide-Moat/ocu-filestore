// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// orderingGuard records, in call order, an interleaving of audit-Mandate and
// the side effect each audit is supposed to PRECEDE (the engine read for
// content; the store tombstone for delete). It proves audit-before-ack: the
// ALLOW Mandate is recorded BEFORE the side effect in the trace.
type orderingGuard struct {
	trace *[]string
	err   error
}

func (g *orderingGuard) Mandate(_ context.Context, event any) error {
	ev := event.(auditgate.FileActivityEvent)
	*g.trace = append(*g.trace, "audit:"+string(ev.Outcome.DispositionID))
	return g.err
}

// tracingEngine records "engine:read" in the shared trace when ReadRange runs.
type tracingEngine struct {
	*fakeEngine
	trace *[]string
}

func (e *tracingEngine) ReadRange(ctx context.Context, scope, path string, off, length int64, w io.Writer) error {
	*e.trace = append(*e.trace, "engine:read")
	return e.fakeEngine.ReadRange(ctx, scope, path, off, length, w)
}

// tracingStore records "store:delete" in the shared trace when Delete runs and
// "store:ensure" when EnsureObject runs. EnsureObject is the DURABLE MINT the
// north list's engine-namespace reconcile drives: it writes a new handle record
// into the durable store, so it is the side effect the list's ALLOW audit must
// precede (NFR-SEC-79 — no durable store mutation before its record).
type tracingStore struct {
	*fakeStore
	trace *[]string
}

func (s *tracingStore) Delete(ctx context.Context, fileID, scope string) error {
	*s.trace = append(*s.trace, "store:delete")
	return s.fakeStore.Delete(ctx, fileID, scope)
}

func (s *tracingStore) EnsureObject(ctx context.Context, in handlestore.EnsureInput) (handlestore.Record, error) {
	*s.trace = append(*s.trace, "store:ensure")
	return s.fakeStore.EnsureObject(ctx, in)
}

// TestAuditBeforeAckContentMandatePrecedesEngine pins that on a successful
// content read the ALLOW audit Mandate is recorded BEFORE engine.ReadRange — the
// durable record lands before the first byte (NFR-SEC-79).
func TestAuditBeforeAckContentMandatePrecedesEngine(t *testing.T) {
	var trace []string
	store := newFakeStore()
	store.put("fid", "fs-alpha", handlestore.Record{ObjectRef: "obj/x", Size: 3})
	base := newFakeEngine()
	base.bytesByPath["obj/x"] = []byte("abc")
	eng := &tracingEngine{fakeEngine: base, trace: &trace}
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:    &orderingGuard{trace: &trace},
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files/fid/content")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(trace) < 2 || trace[0] != "audit:allow" || trace[1] != "engine:read" {
		t.Fatalf("trace = %v, want [audit:allow engine:read] (audit precedes the first byte)", trace)
	}
}

// TestAuditBeforeAckContentMandateFailsZeroEffect pins that an ALLOW Mandate
// failure on content denies 503 with ZERO side effects: engine.ReadRange is
// never traced.
func TestAuditBeforeAckContentMandateFailsZeroEffect(t *testing.T) {
	var trace []string
	store := newFakeStore()
	store.put("fid", "fs-alpha", handlestore.Record{ObjectRef: "obj/x", Size: 3})
	base := newFakeEngine()
	base.bytesByPath["obj/x"] = []byte("abc")
	eng := &tracingEngine{fakeEngine: base, trace: &trace}
	h := newTestHandler(Deps{
		Store:    store,
		Engine:   eng,
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:    &orderingGuard{trace: &trace, err: auditgate.ErrAuditUnavailable},
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files/fid/content")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	for _, e := range trace {
		if e == "engine:read" {
			t.Fatalf("engine read ran after a failed allow audit; trace = %v", trace)
		}
	}
}

// TestAuditBeforeAckListMandatePrecedesReconcileMint pins that on GET /v1/files
// the list's ALLOW audit Mandate is recorded BEFORE the engine-namespace
// reconcile mints a durable handle (Store.EnsureObject). The reconcile is a
// MUTATION of the durable handle store, so a mint that lands before any audit
// record is exactly the NFR-SEC-79 violation: a durable state change with no
// preceding durable record. The engine is seeded so the reconcile really walks a
// namespace and really mints.
//
// This pins ORDER, not existence — a presence-only check ("some ALLOW event was
// emitted") stays green when the Mandate is moved after the reconcile.
func TestAuditBeforeAckListMandatePrecedesReconcileMint(t *testing.T) {
	var trace []string
	base := newFakeStore()
	store := &tracingStore{fakeStore: base, trace: &trace}
	eng := newFakeEngine()
	eng.seedObject("outputs/report.pdf", []byte("pdf"))
	h := newTestHandler(Deps{
		Store:  store,
		Engine: eng,
		Guard:  &orderingGuard{trace: &trace},
		Scope:  fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if base.ensureMints == 0 {
		t.Fatal("the reconcile minted nothing; the ordering assertion below would be vacuous")
	}
	if len(trace) < 2 || trace[0] != "audit:allow" || trace[1] != "store:ensure" {
		t.Fatalf("trace = %v, want [audit:allow store:ensure ...] (the ALLOW audit precedes the durable mint)", trace)
	}
}

// TestListAuditFailureDeniesWithZeroMint is the fail-closed twin: when the audit
// gate is down the list denies 503 and the reconcile mints NOTHING — no durable
// handle is created without a durable record, and no page envelope reaches the
// caller.
func TestListAuditFailureDeniesWithZeroMint(t *testing.T) {
	var trace []string
	base := newFakeStore()
	store := &tracingStore{fakeStore: base, trace: &trace}
	eng := newFakeEngine()
	eng.seedObject("outputs/report.pdf", []byte("pdf"))
	h := newTestHandler(Deps{
		Store:  store,
		Engine: eng,
		Guard:  &orderingGuard{trace: &trace, err: auditgate.ErrAuditUnavailable},
		Scope:  fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (audit gate down); body %s", w.Code, w.Body.String())
	}
	if base.ensureMints != 0 {
		t.Fatalf("the reconcile minted %d durable handles after a failed audit; want 0", base.ensureMints)
	}
	var env map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("deny body is not JSON: %v (%q)", err, w.Body.String())
	}
	if _, present := env["data"]; present {
		t.Fatalf("a 503 audit-down list returned a page envelope: %q", w.Body.String())
	}
}

// TestAuditBeforeAckDeleteMandatePrecedesTombstone pins that on a successful
// delete the ALLOW audit is recorded BEFORE the store tombstone (Get ->
// audit -> Delete).
func TestAuditBeforeAckDeleteMandatePrecedesTombstone(t *testing.T) {
	var trace []string
	base := newFakeStore()
	base.put("fid", "fs-alpha", handlestore.Record{ObjectRef: "obj/x"})
	store := &tracingStore{fakeStore: base, trace: &trace}
	h := newTestHandler(Deps{
		Store: store,
		Guard: &orderingGuard{trace: &trace},
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})

	w := doReq(h, http.MethodDelete, "/v1/files/fid")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if len(trace) < 2 || trace[0] != "audit:allow" || trace[1] != "store:delete" {
		t.Fatalf("trace = %v, want [audit:allow store:delete] (audit precedes the tombstone)", trace)
	}
}

// TestAuditBeforeAckDeleteMandateFailsNoTombstone pins that an ALLOW Mandate
// failure on delete denies 503 with NO tombstone: store:delete is never traced.
func TestAuditBeforeAckDeleteMandateFailsNoTombstone(t *testing.T) {
	var trace []string
	base := newFakeStore()
	base.put("fid", "fs-alpha", handlestore.Record{ObjectRef: "obj/x"})
	store := &tracingStore{fakeStore: base, trace: &trace}
	h := newTestHandler(Deps{
		Store: store,
		Guard: &orderingGuard{trace: &trace, err: auditgate.ErrAuditUnavailable},
		Scope: fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha"}, ok: true},
	})

	w := doReq(h, http.MethodDelete, "/v1/files/fid")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	for _, e := range trace {
		if e == "store:delete" {
			t.Fatalf("tombstone ran after a failed allow audit; trace = %v", trace)
		}
	}
}
