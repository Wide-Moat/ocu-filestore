// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
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

// tracingStore records "store:delete" in the shared trace when Delete runs.
type tracingStore struct {
	*fakeStore
	trace *[]string
}

func (s *tracingStore) Delete(ctx context.Context, fileID, scope string) error {
	*s.trace = append(*s.trace, "store:delete")
	return s.fakeStore.Delete(ctx, fileID, scope)
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
