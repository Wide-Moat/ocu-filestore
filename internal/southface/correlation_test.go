// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

// T2-18 end-to-end correlation id tests.
//
// Assertions:
//   (a) x-request-id present on allow AND deny, unary AND streaming responses.
//   (b) The same id appears in the request's log line(s) and the audit record.
//   (c) The id is unique per request (high-cardinality, not reused).
//   (d) A deny's audit-truth correlation_uid equals the x-request-id —
//       ONE id, not two (subsumes the previous per-deny CorrelationID).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
)

// reqIDRe is the expected shape of a request id: 32 lowercase hex characters.
var reqIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// newCorrelationDispatcher returns a dispatcher wired with a log-capturing
// buffer, a fakeGuard (which stores mandated events as []any), and a real
// slog JSON handler so the request_id attribute appears in the JSON output.
func newCorrelationDispatcher(g *fakeGuard) (*dispatcher, *bytes.Buffer) {
	var logBuf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := newTestDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, g, okCeilings())
	d.logger = l
	return d, &logBuf
}

// correlationEvents returns all mandated events cast to FileActivityEvent.
func correlationEvents(g *fakeGuard) []auditgate.FileActivityEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []auditgate.FileActivityEvent
	for _, ev := range g.events {
		if fae, ok := ev.(auditgate.FileActivityEvent); ok {
			out = append(out, fae)
		}
	}
	return out
}

// TestRequestIDPresentOnUnaryDeny asserts that x-request-id is set on a deny
// response (scope-mismatch → 403). Assertion (a) [deny/unary].
func TestRequestIDPresentOnUnaryDeny(t *testing.T) {
	g := &fakeGuard{}
	d, _ := newCorrelationDispatcher(g)

	body := bodyFor("wrong-scope", IntentRead)
	r := scopedRequest(OpListDirectory, body, boundScope, []Intent{IntentRead})
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403 (scope_mismatch deny)", w.Code)
	}
	reqID := w.Header().Get(requestIDHeader)
	if !reqIDRe.MatchString(reqID) {
		t.Fatalf("x-request-id = %q, want 32-char lowercase hex", reqID)
	}
}

// TestRequestIDPresentOnUnaryAllow asserts that x-request-id is set when the
// request clears all gates (unimplemented handler → 501). Assertion (a)
// [allow/unary].
func TestRequestIDPresentOnUnaryAllow(t *testing.T) {
	g := &fakeGuard{}
	d, _ := newCorrelationDispatcher(g)

	body := bodyFor(boundScope, IntentRead)
	r := scopedRequest(OpListDirectory, body, boundScope, []Intent{IntentRead})
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)

	if w.Code != 501 {
		t.Fatalf("status = %d, want 501 (unimplemented)", w.Code)
	}
	reqID := w.Header().Get(requestIDHeader)
	if !reqIDRe.MatchString(reqID) {
		t.Fatalf("x-request-id = %q, want 32-char lowercase hex", reqID)
	}
}

// The data-plane (multipart upload / octet-stream download) x-request-id
// presence is pinned end-to-end by the REST data-plane handler tests
// (upload_multipart_test.go / download_octetstream_test.go), whose STAGE-0
// prologue stamps x-request-id on both the allow and the pre-byte deny paths.

// TestRequestIDUnique asserts that two back-to-back requests receive distinct
// request ids. Assertion (c).
func TestRequestIDUnique(t *testing.T) {
	g := &fakeGuard{}
	d, _ := newCorrelationDispatcher(g)

	body := bodyFor(boundScope, IntentRead)

	w1 := httptest.NewRecorder()
	d.ServeHTTP(w1, scopedRequest(OpListDirectory, body, boundScope, []Intent{IntentRead}))

	w2 := httptest.NewRecorder()
	d.ServeHTTP(w2, scopedRequest(OpListDirectory, body, boundScope, []Intent{IntentRead}))

	id1 := w1.Header().Get(requestIDHeader)
	id2 := w2.Header().Get(requestIDHeader)
	if !reqIDRe.MatchString(id1) || !reqIDRe.MatchString(id2) {
		t.Fatalf("ids not 32-char hex: %q, %q", id1, id2)
	}
	if id1 == id2 {
		t.Fatalf("two requests received the same id %q (not unique)", id1)
	}
}

// TestRequestIDInLogAndAuditRecord asserts (b): the same id appears in the
// structured log line and in the audit record's CorrelationUID.
//
// Uses the unary allow path: the stage-3 mandate succeeds and the dispatcher
// emits a DEBUG "broker allow" line that carries the request_id, and the
// mandated FileActivityEvent carries the same id in CorrelationUID.
func TestRequestIDInLogAndAuditRecord(t *testing.T) {
	g := &fakeGuard{}
	d, logBuf := newCorrelationDispatcher(g)

	// Valid request that passes stages 0-3 (mandate succeeds) — the DEBUG
	// allow line is emitted at STAGE 3 exit.
	body := bodyFor(boundScope, IntentRead)
	r := scopedRequest(OpListDirectory, body, boundScope, []Intent{IntentRead})
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)

	reqID := w.Header().Get(requestIDHeader)
	if !reqIDRe.MatchString(reqID) {
		t.Fatalf("x-request-id = %q, want 32-char lowercase hex", reqID)
	}

	// (b) audit record (STAGE 3 allow mandate) must carry the same id.
	events := correlationEvents(g)
	if len(events) == 0 {
		t.Fatal("no audit events mandated")
	}
	ev := events[0]
	if ev.CorrelationUID != reqID {
		t.Fatalf("audit CorrelationUID = %q, want x-request-id %q", ev.CorrelationUID, reqID)
	}

	// (b) DEBUG allow log line must carry request_id = reqID.
	foundInLog := false
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		if raw, ok := obj[observ.KeyRequestID]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil && s == reqID {
				foundInLog = true
			}
		}
	}
	if !foundInLog {
		t.Fatalf("no log line contains %q=%q:\n%s", observ.KeyRequestID, reqID, logBuf.String())
	}
}

// TestRequestIDUnifiedDenyAudit asserts (d): a deny's audit record carries
// the same CorrelationUID as the x-request-id header — one id, not two. This
// subsumes the previous D8 per-deny correlation id mechanism (T2-18). It uses
// a HANDLER-STAGE intent_denied deny, which — unlike a pre-handler scope/route
// refusal — unconditionally mandates a deny audit event before the REST deny
// response.
//
// Vehicle: OpRemoveFile with a session that grants only IntentRead (no
// IntentWrite). assertWriteGrant is the handler-stage defense-in-depth check
// (NFR-SEC-49, invariant 4): it fires mandateDeny(intent_denied) before any
// engine touch, so the deny audit event carries the request_id correlation.
func TestRequestIDUnifiedDenyAudit(t *testing.T) {
	g := &fakeGuard{}
	eng := newFakeEngine()
	eng.putBytes(boundScope, "secret.bin", []byte("S"))
	// fakeResolver returns a grant without error regardless of intent; the
	// handler-stage assertWriteGrant catches the missing IntentWrite.
	d := newDispatcherWithEngine(&fakeResolver{}, g, okCeilings(), 1<<20, eng)
	d.maxFileSize = 1 << 20
	var logBuf bytes.Buffer
	d.logger = slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Session holds only IntentRead; assertWriteGrant in OpRemoveFile fires the
	// handler-stage intent_denied deny and mandates an audit event before the 403.
	readOnly := []Intent{IntentRead}
	removeBody := fmt.Sprintf(`{"filesystem_id":%q,"path":"/secret.bin","authorization_metadata":{"intent":"write","downloadable":false}}`, boundScope)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, scopedRequest(OpRemoveFile, removeBody, boundScope, readOnly))

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403 (intent_denied handler-stage deny); body %s", w.Code, w.Body.String())
	}
	reqID := w.Header().Get(requestIDHeader)
	if !reqIDRe.MatchString(reqID) {
		t.Fatalf("x-request-id = %q, want 32-char lowercase hex", reqID)
	}

	// Deny audit event must carry CorrelationUID = reqID (d).
	events := correlationEvents(g)
	if len(events) == 0 {
		t.Fatal("no audit events mandated on the handler-stage deny")
	}
	denyEv := events[len(events)-1]
	if denyEv.CorrelationUID != reqID {
		t.Fatalf("deny audit CorrelationUID = %q, want x-request-id %q (T2-18 unified id)", denyEv.CorrelationUID, reqID)
	}

	// Log line must also carry the request id.
	if !strings.Contains(logBuf.String(), reqID) {
		t.Fatalf("deny log does not contain request id %q:\n%s", reqID, logBuf.String())
	}
}
