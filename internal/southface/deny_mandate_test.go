// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
)

// failAfterGuard is a Guard that succeeds for the first failFrom Mandate
// calls and fails every call after, so a test can let the STAGE-3 allow
// Mandate land and fault the sink EXACTLY at the handler-stage deny Mandate
// (the FC-04 window).
type failAfterGuard struct {
	mu       sync.Mutex
	failFrom int // calls with 0-based index >= failFrom return ErrAuditUnavailable
	calls    int
	events   []any
}

func (g *failAfterGuard) Mandate(_ context.Context, event any) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	idx := g.calls
	g.calls++
	g.events = append(g.events, event)
	if idx >= g.failFrom {
		return ErrAuditUnavailable
	}
	return nil
}

// TestUnaryDenyMandateFailureDegradesToAuditDown pins FC-04 on the unary
// path (NFR-SEC-79, invariant 8): when the sink faults exactly at the
// handler-stage DENY Mandate (the STAGE-3 allow already landed), the wire
// verdict is unavailable/503 — NOT the original refusal — and x-deny-reason
// is NEVER set: the durable chain's last record is an allow, so no truth
// header may accompany the response.
func TestUnaryDenyMandateFailureDegradesToAuditDown(t *testing.T) {
	t.Run("not_found_deny_degrades", func(t *testing.T) {
		eng := newFakeEngine()            // /ghost.txt does not exist -> handler-stage deny
		g := &failAfterGuard{failFrom: 1} // allow Mandate ok, deny Mandate fails
		d := newEngineDispatcher(&fakeResolver{}, g, okCeilings(), eng)

		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/ghost.txt","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		w := serveOp(d, OpRemoveFile, body, opScope, okIntents())

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 (deny record not durable -> audit_down); body %s", w.Code, w.Body.String())
		}
		if ce := decodeErrBody(t, w); ce.Code != wireCodeUnavailable {
			t.Fatalf("code = %q, want unavailable", ce.Code)
		}
		if h := w.Header().Get("x-deny-reason"); h != "" {
			t.Fatalf("x-deny-reason = %q on a failed deny Mandate, want none (no unrecorded truth on the wire)", h)
		}
	})

	t.Run("header_bearing_deny_loses_header", func(t *testing.T) {
		// not_downloadable normally carries x-deny-reason; with the deny
		// Mandate down, the header must vanish along with the original code.
		eng := newFakeEngine()
		eng.putBytes(opScope, "secret.bin", []byte("S"))
		g := &failAfterGuard{failFrom: 1}
		d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: false}}, g, okCeilings(), eng)

		w := serveOp(d, OpReadFile, readBodyNoRange(opScope, "/secret.bin", false), opScope, okIntents())
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503; body %s", w.Code, w.Body.String())
		}
		if h := w.Header().Get("x-deny-reason"); h != "" {
			t.Fatalf("x-deny-reason = %q, want none (the not_downloadable truth was never recorded)", h)
		}
	})

	t.Run("positive_control_deny_mandate_ok", func(t *testing.T) {
		// With a healthy sink the same refusal keeps its original verdict.
		eng := newFakeEngine()
		g := &failAfterGuard{failFrom: 99}
		d := newEngineDispatcher(&fakeResolver{}, g, okCeilings(), eng)
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/ghost.txt","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		w := serveOp(d, OpRemoveFile, body, opScope, okIntents())
		if w.Code != http.StatusNotFound {
			t.Fatalf("healthy-sink status = %d, want 404 (original deny preserved)", w.Code)
		}
	})
}

// TestStreamDenyMandateFailureDegradesToUnavailable pins FC-04 on the
// streaming path: each handler-stage deny site, faulted exactly at its deny
// Mandate, frames the unavailable trailer instead of the original refusal,
// and the deny Mandate was actually attempted (the event reached the guard).
func TestStreamDenyMandateFailureDegradesToUnavailable(t *testing.T) {
	cases := []struct {
		name     string
		failFrom int // index of the first FAILING Mandate call
		seed     func(*fakeEngine)
		frames   func(t *testing.T) []byte
		original string // the code a healthy sink would have framed
	}{
		{
			// Pre-allow site: the scope-mismatch deny is the FIRST Mandate.
			name:     "pre_allow_scope_mismatch",
			failFrom: 0,
			frames: func(t *testing.T) []byte {
				return concat(paramsFrame(t, "fs-other", "/up.bin", 8), endFrame(t))
			},
			original: wireCodePermissionDenied,
		},
		{
			// Post-allow engine reject: allow lands (call 0), already_exists
			// deny faults (call 1).
			name:     "engine_already_exists",
			failFrom: 1,
			seed:     func(e *fakeEngine) { e.putBytes(streamScope, "up.bin", []byte("OLDBYTES")) },
			frames: func(t *testing.T) []byte {
				return concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
			},
			original: wireCodeAlreadyExists,
		},
		{
			// Post-allow size mismatch at half-close.
			name:     "under_declaration",
			failFrom: 1,
			frames: func(t *testing.T) []byte {
				return concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCD")), endFrame(t))
			},
			original: wireCodeInvalidArgument,
		},
		{
			// Post-allow malformed chunk frame.
			name:     "malformed_chunk",
			failFrom: 1,
			frames: func(t *testing.T) []byte {
				return concat(paramsFrame(t, streamScope, "/up.bin", 8), frameBytes(t, []byte(`["nope"]`)), endFrame(t))
			},
			original: wireCodeInvalidArgument,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eng := newFakeEngine()
			if c.seed != nil {
				c.seed(eng)
			}
			g := &failAfterGuard{failFrom: c.failFrom}
			sess := &recordingCeilingsSession{}
			d := newDispatcherWithEngine(&fakeResolver{}, g, &recordingRegistry{sess: sess}, 1<<20, eng)
			d.maxFileSize = 1 << 20

			w := serveStream(d, OpFileUpload, bytes.NewReader(c.frames(t)), streamScope, okIntents())
			assertErrorTrailer(t, w, wireCodeUnavailable)
			if c.original == wireCodeUnavailable {
				t.Fatalf("test case is vacuous: the original code is already unavailable")
			}
			// The deny event reached the guard (the Mandate was attempted, it
			// faulted, and only then was the verdict degraded).
			g.mu.Lock()
			calls := g.calls
			g.mu.Unlock()
			if calls <= c.failFrom {
				t.Fatalf("guard saw %d Mandate calls, want > %d (the deny Mandate must be attempted)", calls, c.failFrom)
			}
			if !sess.balanced() {
				t.Fatalf("ceilings gauge unbalanced after a degraded deny")
			}
		})
	}
}
