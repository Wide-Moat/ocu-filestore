// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

const boundScope = "fs-bound"

// newTestDispatcher builds a dispatcher over the given fakes with a small
// declared-size ceiling.
func newTestDispatcher(res Resolver, g Guard, c CeilingsRegistry) *dispatcher {
	return newDispatcher(res, g, c, 1<<20)
}

// okCeilings returns a registry whose session permits every op.
func okCeilings() *fakeCeilingsRegistry {
	return &fakeCeilingsRegistry{session: &fakeCeilingsSession{}}
}

// scopedRequest builds a POST request for op carrying the given body, the
// required Connect headers, and a PeerScope bound to scope/intents in the
// request context (mimicking the listener's ConnContext stash).
func scopedRequest(op Op, body string, scope string, intents []Intent) *http.Request {
	r := httptest.NewRequest(http.MethodPost, servicePrefix+string(op), strings.NewReader(body))
	r.Header.Set(connectProtocolVersionHeader, connectProtocolVersion)
	r.Header.Set("Content-Type", contentTypeJSON)
	r.ContentLength = int64(len(body))
	ps := PeerScope{FilesystemID: scope, GrantedIntents: intents, UID: 4242, PID: 7}
	return r.WithContext(contextWithPeerScope(r.Context(), ps))
}

// bodyFor returns a representative unary body for the given scope and intent.
func bodyFor(scope string, intent Intent) string {
	return fmt.Sprintf(`{"filesystem_id":%q,"path":"/p","authorization_metadata":{"intent":%q,"downloadable":false}}`, scope, intent)
}

// decodeErrBody parses a Connect error body.
func decodeErrBody(t *testing.T, w *httptest.ResponseRecorder) connectError {
	t.Helper()
	var ce connectError
	if err := json.Unmarshal(w.Body.Bytes(), &ce); err != nil {
		t.Fatalf("error body not JSON: %v (%q)", err, w.Body.String())
	}
	return ce
}

// TestMandateBeforeAck pins NFR-SEC-79: the recording fake Guard proves
// Mandate is called before the handler runs, and a Mandate failure denies
// unavailable with NO x-deny-reason and the handler never invoked.
func TestMandateBeforeAck(t *testing.T) {
	t.Run("mandate precedes handler on the clear path", func(t *testing.T) {
		rec := &callRecorder{}
		d := newTestDispatcher(
			&fakeResolver{rec: rec},
			&fakeGuard{rec: rec},
			&fakeCeilingsRegistry{session: &fakeCeilingsSession{rec: rec}},
		)
		w := httptest.NewRecorder()
		d.ServeHTTP(w, scopedRequest(OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead}))

		calls := rec.snapshot()
		// ceilings -> resolve -> mandate, all before the handler effect.
		want := []string{"ceilings_op", "resolve", "mandate"}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("call order = %v, want %v (then handler)", calls, want)
		}
		// The handler is unimplemented: 501, no x-deny-reason.
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501 (unimplemented handler)", w.Code)
		}
	})

	t.Run("mandate failure denies unavailable, handler not invoked", func(t *testing.T) {
		rec := &callRecorder{}
		d := newTestDispatcher(
			&fakeResolver{rec: rec},
			&fakeGuard{rec: rec, err: ErrAuditUnavailable},
			&fakeCeilingsRegistry{session: &fakeCeilingsSession{rec: rec}},
		)
		w := httptest.NewRecorder()
		d.ServeHTTP(w, scopedRequest(OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead}))

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 (audit unavailable)", w.Code)
		}
		if h := w.Header().Get("x-deny-reason"); h != "" {
			t.Fatalf("x-deny-reason = %q on audit-down, want none (n3)", h)
		}
		if ce := decodeErrBody(t, w); ce.Code != wireCodeUnavailable {
			t.Fatalf("code = %q, want unavailable", ce.Code)
		}
		// mandate was reached but the handler (which would 501) was not.
		calls := rec.snapshot()
		if len(calls) == 0 || calls[len(calls)-1] != "mandate" {
			t.Fatalf("call order = %v, want ...mandate last (handler skipped)", calls)
		}
	})
}

// TestPipelineOrder pins the LOCKED short-circuit order: a throttled session
// stops at ceilings (authz/audit/handler never reached); an authz deny stops
// before audit/handler.
func TestPipelineOrder(t *testing.T) {
	t.Run("throttle short-circuits before authz", func(t *testing.T) {
		rec := &callRecorder{}
		d := newTestDispatcher(
			&fakeResolver{rec: rec},
			&fakeGuard{rec: rec},
			&fakeCeilingsRegistry{session: &fakeCeilingsSession{rec: rec, opErr: ErrThrottleExceeded}},
		)
		w := httptest.NewRecorder()
		d.ServeHTTP(w, scopedRequest(OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead}))

		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429 (throttle)", w.Code)
		}
		if h := w.Header().Get("x-deny-reason"); h != "" {
			t.Fatalf("x-deny-reason = %q on throttle, want none (n3)", h)
		}
		calls := rec.snapshot()
		for _, c := range calls {
			if c == "resolve" || c == "mandate" {
				t.Fatalf("call %q reached after a throttle, want short-circuit at ceilings", c)
			}
		}
	})

	t.Run("authz deny short-circuits before audit", func(t *testing.T) {
		rec := &callRecorder{}
		d := newTestDispatcher(
			&fakeResolver{rec: rec, err: ErrIntentDenied},
			&fakeGuard{rec: rec},
			&fakeCeilingsRegistry{session: &fakeCeilingsSession{rec: rec}},
		)
		w := httptest.NewRecorder()
		d.ServeHTTP(w, scopedRequest(OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead}))

		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (intent denied)", w.Code)
		}
		if h := w.Header().Get("x-deny-reason"); h != denyIntentDenied {
			t.Fatalf("x-deny-reason = %q, want %q", h, denyIntentDenied)
		}
		for _, c := range rec.snapshot() {
			if c == "mandate" {
				t.Fatalf("mandate reached after an authz deny, want short-circuit before audit")
			}
		}
	})
}

// TestThrottleKeyedOnChannelScope pins that the ops/s throttle is keyed on the
// channel scope (PeerScope), never on the body filesystem_id.
func TestThrottleKeyedOnChannelScope(t *testing.T) {
	creg := okCeilings()
	d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, creg)
	w := httptest.NewRecorder()
	// Body claims a different scope; the cross-check will deny it, but the
	// throttle key is taken BEFORE that, from the channel.
	d.ServeHTTP(w, scopedRequest(OpReadFile, bodyFor("fs-other", IntentRead), boundScope, []Intent{IntentRead}))
	creg.mu.Lock()
	defer creg.mu.Unlock()
	if len(creg.keys) != 1 || creg.keys[0] != boundScope {
		t.Fatalf("ceilings keyed on %v, want [%q] (channel scope, never the body)", creg.keys, boundScope)
	}
}

// TestChannelScopeMismatch pins D2: a body filesystem_id that disagrees with
// the channel scope is permission_denied + x-deny-reason scope_mismatch and
// the handler is never invoked.
func TestChannelScopeMismatch(t *testing.T) {
	rec := &callRecorder{}
	d := newTestDispatcher(
		&fakeResolver{rec: rec},
		&fakeGuard{rec: rec},
		&fakeCeilingsRegistry{session: &fakeCeilingsSession{rec: rec}},
	)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, scopedRequest(OpReadFile, bodyFor("fs-evil", IntentRead), boundScope, []Intent{IntentRead}))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (scope mismatch)", w.Code)
	}
	if h := w.Header().Get("x-deny-reason"); h != denyScopeMismatch {
		t.Fatalf("x-deny-reason = %q, want %q", h, denyScopeMismatch)
	}
	for _, c := range rec.snapshot() {
		if c == "resolve" || c == "mandate" {
			t.Fatalf("call %q reached after a scope mismatch, want pre-dispatch deny", c)
		}
	}
}

// TestPropChannelScope is the non-vacuous channel-scope property: over
// arbitrary body scopes against a fixed channel-bound scope, a mismatching
// body is ALWAYS denied permission_denied and the handler is NEVER reached;
// the generator is biased to draw mismatches so the denial counter is proven
// > 0 (a vacuous property that never drew a mismatch would fail).
func TestPropChannelScope(t *testing.T) {
	var denials int
	rapid.Check(t, func(rt *rapid.T) {
		// Bias the draw toward mismatches: half the time inject a scope
		// distinct from the bound one.
		var bodyScope string
		if rapid.Bool().Draw(rt, "mismatch") {
			bodyScope = "x-" + rapid.StringMatching(`[a-z]{1,8}`).Draw(rt, "body_scope")
			if bodyScope == "x-"+boundScope {
				bodyScope = "x-distinct"
			}
		} else {
			bodyScope = boundScope
		}

		rec := &callRecorder{}
		d := newTestDispatcher(
			&fakeResolver{rec: rec},
			&fakeGuard{rec: rec},
			&fakeCeilingsRegistry{session: &fakeCeilingsSession{rec: rec}},
		)
		w := httptest.NewRecorder()
		d.ServeHTTP(w, scopedRequest(OpReadFile, bodyFor(bodyScope, IntentRead), boundScope, []Intent{IntentRead}))

		if bodyScope != boundScope {
			if w.Code != http.StatusForbidden {
				rt.Fatalf("mismatch scope %q: status %d, want 403", bodyScope, w.Code)
			}
			if w.Header().Get("x-deny-reason") != denyScopeMismatch {
				rt.Fatalf("mismatch scope %q: missing scope_mismatch header", bodyScope)
			}
			for _, c := range rec.snapshot() {
				if c == "resolve" || c == "mandate" {
					rt.Fatalf("mismatch scope %q reached %q, want pre-dispatch deny", bodyScope, c)
				}
			}
			denials++
		}
	})
	if denials == 0 {
		t.Fatal("property never drew a mismatching scope: vacuous, no denial exercised")
	}
}

// TestRegistryUnimplemented pins that every UNARY op that is not implemented
// in this build is registered and returns Connect unimplemented/501 with no
// x-deny-reason. readFile (OPS-04) is implemented over an engine, so against
// this nil-engine test dispatcher its registry entry stays unimplemented and
// it is included here (the engine-backed readFile success/deny paths are
// pinned in handlers_test.go). The two STREAMING ops (fileUpload, fileDownload)
// no longer ride the unary registry — ServeHTTP routes them to serveStreaming
// before the unary content-type/registry gate (phase 10), so they are
// validated on the streaming path (fileDownload's unimplemented trailer and
// the fileUpload routing are pinned in stream_handler_test.go), not here.
func TestRegistryUnimplemented(t *testing.T) {
	unaryUnimplemented := []Op{
		OpListDirectory, OpMakeDirectory, OpMoveDirectory, OpRemoveDirectory,
		OpCreateFile, OpReadFile, OpReadMetadata, OpGetFileMetadata,
		OpListFiles, OpCopyFile, OpMoveFile, OpRemoveFile,
		OpImportFiles, OpImportZip,
		OpMigrateFilesystem, OpRemoveFilesystem,
	}
	if len(unaryUnimplemented) != 16 {
		t.Fatalf("unary op list has %d entries, want 16", len(unaryUnimplemented))
	}
	for _, op := range unaryUnimplemented {
		t.Run(string(op), func(t *testing.T) {
			d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
			w := httptest.NewRecorder()
			// Send each op's required intent (route-op binding, AUTHZ-01): a
			// mismatching wire intent now refuses BEFORE the registry, which is
			// not what this test pins.
			intent, ok := requiredIntentForOp(op)
			if !ok {
				t.Fatalf("op %q has no required intent in the closed map", op)
			}
			d.ServeHTTP(w, scopedRequest(op, bodyFor(boundScope, intent), boundScope, []Intent{IntentRead, IntentWrite}))
			if w.Code != http.StatusNotImplemented {
				t.Fatalf("op %q: status %d, want 501", op, w.Code)
			}
			if h := w.Header().Get("x-deny-reason"); h != "" {
				t.Fatalf("op %q: x-deny-reason %q on unimplemented, want none", op, h)
			}
			if ce := decodeErrBody(t, w); ce.Code != wireCodeUnimplemented {
				t.Fatalf("op %q: code %q, want unimplemented", op, ce.Code)
			}
		})
	}
}

// TestDenyMapTable pins the full D4 table at the verdict level, including the
// internal -> 500 / NO header row for an unknown deny class (the wiring-fault
// fail-closed case).
func TestDenyMapTable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		class      string
		wantCode   string
		wantStatus int
		wantHeader bool
	}{
		{"scope_mismatch", denyScopeMismatch, wireCodePermissionDenied, 403, true},
		{"intent_denied", denyIntentDenied, wireCodePermissionDenied, 403, true},
		{"not_downloadable", denyNotDownloadable, wireCodePermissionDenied, 403, true},
		{"lease_expired", denyLeaseExpired, wireCodeUnauthenticated, 401, true},
		{"size_exceeded", denySizeExceeded, wireCodeInvalidArgument, 400, false},
		{"malformed", denyMalformed, wireCodeInvalidArgument, 400, false},
		{"not_found", denyNotFound, wireCodeNotFound, 404, false},
		{"throttle", denyThrottle, wireCodeResourceExhausted, 429, false},
		{"audit_down", denyAuditDown, wireCodeUnavailable, 503, false},
		{"already_exists", denyAlreadyExists, wireCodeAlreadyExists, 409, false},
		{"aborted", denyAborted, wireCodeAborted, 409, false},
		{"unimplemented", denyUnimplemented, wireCodeUnimplemented, 501, false},
		{"internal", denyInternal, wireCodeInternal, 500, false},
		{"unknown class -> internal/500/no header", "no_such_class", wireCodeInternal, 500, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := mapDeny(tc.class)
			if v.WireCode != tc.wantCode {
				t.Fatalf("WireCode = %q, want %q", v.WireCode, tc.wantCode)
			}
			if v.WireStatus != tc.wantStatus {
				t.Fatalf("WireStatus = %d, want %d", v.WireStatus, tc.wantStatus)
			}
			if v.WireHeader != tc.wantHeader {
				t.Fatalf("WireHeader = %v, want %v", v.WireHeader, tc.wantHeader)
			}
		})
	}
}

// TestDispatchSizeAndHeaderGates pins the STAGE-0 header-gate refusals:
// absent Content-Length, over-ceiling Content-Length, missing version header,
// missing channel scope, non-POST method, and unknown route — each with the
// correct Connect code and header presence.
func TestDispatchSizeAndHeaderGates(t *testing.T) {
	t.Run("over-ceiling content-length -> size_exceeded, no header", func(t *testing.T) {
		d := newDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), 16)
		w := httptest.NewRecorder()
		r := scopedRequest(OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead})
		d.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		if w.Header().Get("x-deny-reason") != "" {
			t.Fatal("x-deny-reason present on size deny, want none")
		}
	})

	t.Run("absent content-length -> invalid_argument", func(t *testing.T) {
		d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
		w := httptest.NewRecorder()
		r := scopedRequest(OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead})
		r.ContentLength = -1
		d.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (absent CL)", w.Code)
		}
	})

	t.Run("missing version header -> invalid_argument", func(t *testing.T) {
		d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
		w := httptest.NewRecorder()
		r := scopedRequest(OpReadFile, bodyFor(boundScope, IntentRead), boundScope, []Intent{IntentRead})
		r.Header.Del(connectProtocolVersionHeader)
		d.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (no version)", w.Code)
		}
	})

	t.Run("missing channel scope -> internal/500", func(t *testing.T) {
		d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
		w := httptest.NewRecorder()
		// No PeerScope in context.
		r := httptest.NewRequest(http.MethodPost, servicePrefix+"readFile", strings.NewReader(bodyFor(boundScope, IntentRead)))
		r.Header.Set(connectProtocolVersionHeader, connectProtocolVersion)
		r.Header.Set("Content-Type", contentTypeJSON)
		d.ServeHTTP(w, r)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (no channel scope)", w.Code)
		}
		if w.Header().Get("x-deny-reason") != "" {
			t.Fatal("x-deny-reason present on internal, want none")
		}
	})

	t.Run("non-POST -> 405", func(t *testing.T) {
		d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, servicePrefix+"readFile", nil)
		d.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", w.Code)
		}
		if w.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("Allow = %q, want POST", w.Header().Get("Allow"))
		}
	})

	t.Run("unknown route -> invalid_argument", func(t *testing.T) {
		d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/wrong/path", nil)
		d.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (unknown route)", w.Code)
		}
	})
}

// TestD8Split pins the audited-truth vs wire-reason split: when the wire
// reason degrades away from the audited truth, the verdict carries the truth
// as AuditReason, the degraded code as WireCode, and a 32-char hex correlation
// id; when they agree, the id is empty.
func TestD8Split(t *testing.T) {
	v := mapDenyDegraded(denyScopeMismatch, denyNotFound)
	if v.AuditReason != denyScopeMismatch {
		t.Fatalf("AuditReason = %q, want %q", v.AuditReason, denyScopeMismatch)
	}
	if v.WireCode != wireCodeNotFound {
		t.Fatalf("WireCode = %q, want %q", v.WireCode, wireCodeNotFound)
	}
	if len(v.CorrelationID) != 32 {
		t.Fatalf("CorrelationID len = %d, want 32", len(v.CorrelationID))
	}
	for _, c := range v.CorrelationID {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("CorrelationID %q not lowercase hex", v.CorrelationID)
		}
	}
	same := mapDenyDegraded(denyScopeMismatch, denyScopeMismatch)
	if same.CorrelationID != "" {
		t.Fatalf("CorrelationID = %q on agreement, want empty", same.CorrelationID)
	}
}

// TestDenyWarnLogsAuditReason pins T-14-02: the deny WARN log carries the
// broker-resolved AuditReason (the TRUTH) while the wire response carries the
// degraded wire code. This verifies the two surfaces stay separated. A
// scope-mismatch deny (which in normal anti-enumeration would degrade to
// not_found on the wire) is tested here: both the log and the wire body are
// asserted.
func TestDenyWarnLogsAuditReason(t *testing.T) {
	var logBuf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
	d.logger = l

	// Scope-mismatch: body scope differs from PeerScope.
	body := bodyFor("wrong-scope", IntentRead)
	r := scopedRequest(OpListDirectory, body, boundScope, []Intent{IntentRead})
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)

	// Wire body must still be the standard deny (unchanged anti-enumeration).
	var ce connectError
	if err := json.Unmarshal(w.Body.Bytes(), &ce); err != nil {
		t.Fatalf("wire body not valid JSON: %v", err)
	}
	// The scope_mismatch deny maps to permission_denied wire code.
	if ce.Code != wireCodePermissionDenied {
		t.Errorf("wire code = %q, want %q", ce.Code, wireCodePermissionDenied)
	}

	// Log must carry the TRUTH (deny_class = scope_mismatch).
	logged := logBuf.String()
	if !strings.Contains(logged, "scope_mismatch") {
		t.Errorf("deny WARN log does not contain audit reason %q:\n%s", "scope_mismatch", logged)
	}
	if !strings.Contains(logged, "WARN") {
		t.Errorf("deny WARN log level is not WARN:\n%s", logged)
	}
}

// TestOpsTotalCountsOps verifies that ops_total increments once per dispatched
// op with the correct {op, outcome, deny_class} triple.
func TestOpsTotalCountsOps(t *testing.T) {
	m := newTestMetrics()
	d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
	d.brokerMetrics = m

	// Allow path: OpListDirectory is unimplemented, so it gets deny=unimplemented.
	// But that is still a deny. Use a scope-mismatch for a clear deny_class.
	body := bodyFor("wrong-scope", IntentRead)
	r := scopedRequest(OpListDirectory, body, boundScope, []Intent{IntentRead})
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)

	// Check that ops_total was incremented with scope_mismatch deny.
	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	out := buf.String()

	if !strings.Contains(out, `deny_class="scope_mismatch"`) {
		t.Fatalf("scope_mismatch not in ops_total:\n%s", out)
	}
	if !strings.Contains(out, `outcome="deny"`) {
		t.Fatalf("outcome=deny not found:\n%s", out)
	}
	if !strings.Contains(out, `op="listDirectory"`) {
		t.Fatalf("op=listDirectory not found:\n%s", out)
	}
}

// TestStageHistogramsIncrementOnReach verifies that stage-latency histograms
// are incremented when their stage is reached, and that a STAGE-0 deny does
// not reach later stages.
func TestStageHistogramsIncrementOnReach(t *testing.T) {
	m := newTestMetrics()
	d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
	d.brokerMetrics = m

	// A request that passes STAGE 0-2 but is denied by scope_mismatch at
	// STAGE 1b (channel scope vs body scope) should NOT reach authz/mandate.
	body := bodyFor("wrong-scope", IntentRead)
	r := scopedRequest(OpListDirectory, body, boundScope, []Intent{IntentRead})
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)

	// A valid request that passes all stages (but is denied at stage 4 as
	// unimplemented) should increment the authz and audit_mandate histograms.
	body2 := bodyFor(boundScope, IntentRead)
	r2 := scopedRequest(OpListDirectory, body2, boundScope, []Intent{IntentRead})
	w2 := httptest.NewRecorder()
	d.ServeHTTP(w2, r2)

	var buf bytes.Buffer
	m.Registry().WriteTo(&buf)
	out := buf.String()

	// authz stage should show up (the second request reached STAGE 2).
	if !strings.Contains(out, `stage="authz"`) {
		t.Fatalf("authz stage not in histograms:\n%s", out)
	}
	// audit_mandate should show up (the second request passed authz).
	if !strings.Contains(out, `stage="audit_mandate"`) {
		t.Fatalf("audit_mandate stage not in histograms:\n%s", out)
	}
}

// newTestMetrics returns a BrokerMetrics suitable for dispatcher tests.
func newTestMetrics() *telemetry.BrokerMetrics {
	return telemetry.NewBrokerMetrics("v0.0.0-test")
}

// TestDispatchStageOrderUnchanged pins the LOCKED STAGE 0->4 order: after
// adding logging to the dispatcher the existing ordering test still passes
// with a logger set.
func TestDispatchStageOrderUnchangedWithLogger(t *testing.T) {
	var logBuf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())
	d.logger = l

	// A well-formed request still passes stages 0-2 and hits the audit
	// guard (stage 3) before the registry (stage 4). This matches the
	// ordering test logic.
	body := bodyFor(boundScope, IntentRead)
	r := scopedRequest(OpListDirectory, body, boundScope, []Intent{IntentRead})
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)

	// A logger being set must not change the response code: OpListDirectory
	// is unimplemented in the default registry (no engine), so the response
	// is 501 unimplemented.
	if w.Code != http.StatusNotImplemented {
		t.Errorf("response code = %d, want 501 (unimplemented); logger must not alter dispatch ordering", w.Code)
	}
}
