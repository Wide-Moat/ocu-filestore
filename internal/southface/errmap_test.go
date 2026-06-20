// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
)

// errmap-01: negative range offset/length ─────────────────────────────────

// TestNegativeRangeDownloadDeniesMalformed pins errmap-01: a fileDownload with
// a negative range offset or length must be rejected BEFORE the ALLOW audit is
// emitted, producing a framed deny trailer (wireCodeInvalidArgument) and NO
// data frames — and no spurious ALLOW Mandate in the audit chain.
func TestNegativeRangeDownloadDeniesMalformed(t *testing.T) {
	const engPath = "neg.bin"
	content := []byte("NEGATIVE_RANGE_TEST_BYTES")

	eng := newFakeEngine()
	eng.putBytes(streamScope, engPath, content)

	g := &fakeGuard{}
	sess := &recordingCeilingsSession{}
	resolver := &fakeResolver{grant: Grant{Downloadable: true}}
	d := newStreamDispatcher(eng, g, sess, 1<<20)
	d.resolver = resolver

	// Mint a uuid by listing.
	w := serveOp(d, OpListDirectory,
		listBody(streamScope, "/", 0, "", false),
		streamScope, okIntents())
	resp := decodeList(t, w)
	var uuid string
	for _, e := range resp.Entries {
		if e.File != nil && e.File.Path == "/"+engPath {
			uuid = e.File.UUID
		}
	}
	if uuid == "" {
		t.Fatalf("listDirectory did not mint a uuid for %s", engPath)
	}

	cases := []struct {
		name   string
		offset int64
		length int64
	}{
		{"negative_offset", -1, 8},
		{"negative_length", 4, -1},
		{"both_negative", -5, -3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset guard events between sub-tests.
			g.mu.Lock()
			g.events = nil
			g.mu.Unlock()

			body := downloadParamsFrame(t, streamScope, uuid, &fileRange{Offset: tc.offset, Length: tc.length})
			rec := serveStream(d, OpFileDownload, bytes.NewReader(body), streamScope, okIntents())

			// The streaming path always returns HTTP 200; the verdict is in
			// the framed end-stream trailer.
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (streaming path)", rec.Code)
			}

			// Parse frames: there must be NO data frames and exactly one
			// end-stream trailer with the invalid_argument wire code.
			rb := bytes.NewReader(rec.Body.Bytes())
			dataFrames := 0
			var trailer endStreamResponse
			for {
				f, payload, err := readFrame(rb)
				if err != nil {
					break
				}
				if f == endStreamFlag {
					if jerr := json.Unmarshal(payload, &trailer); jerr != nil {
						t.Fatalf("trailer not JSON: %v", jerr)
					}
					break
				}
				if f == dataFlag {
					dataFrames++
				}
			}

			if dataFrames != 0 {
				t.Fatalf("negative range: %d data frames emitted before deny, want 0", dataFrames)
			}
			if trailer.Error == nil {
				t.Fatal("negative range: trailer has no error, want invalid_argument deny")
			}
			if trailer.Error.Code != wireCodeInvalidArgument {
				t.Fatalf("negative range: trailer wire code = %q, want %q", trailer.Error.Code, wireCodeInvalidArgument)
			}

			// The essential invariant: the audit chain must record exactly ONE
			// DENY event with no prior ALLOW. denyDownloadTrailer mandates the
			// deny audit record before writing the trailer (SEC-79); the ALLOW
			// Mandate (which fires after the range check in the normal path)
			// must never have been emitted. Assert exactly one event and that
			// it carries DispositionDeny.
			g.mu.Lock()
			events := make([]any, len(g.events))
			copy(events, g.events)
			g.mu.Unlock()
			if len(events) != 1 {
				t.Fatalf("negative range: %d audit events recorded, want exactly 1 (the deny)", len(events))
			}
			ev, ok := events[0].(auditgate.FileActivityEvent)
			if !ok {
				t.Fatalf("negative range: audit event is not FileActivityEvent: %T", events[0])
			}
			if ev.Outcome.DispositionID != auditgate.DispositionDeny {
				t.Fatalf("negative range: audit event disposition = %q, want %q (deny)", ev.Outcome.DispositionID, auditgate.DispositionDeny)
			}
		})
	}
}

// TestErrInvalidRangeClassifiesMalformed pins the sentinel-remap path for
// errmap-01: the southface mirror errInvalidRange must classify as denyMalformed
// through both denyClassForEngineErr and auditTruthForEngineErr, and must NOT
// fall through to denyInternal (the old behaviour that produced internal/500).
func TestErrInvalidRangeClassifiesMalformed(t *testing.T) {
	t.Run("denyClassForEngineErr", func(t *testing.T) {
		got := denyClassForEngineErr(errInvalidRange)
		if got != denyMalformed {
			t.Fatalf("denyClassForEngineErr(errInvalidRange) = %q, want %q", got, denyMalformed)
		}
	})
	t.Run("auditTruthForEngineErr", func(t *testing.T) {
		got := auditTruthForEngineErr(errInvalidRange)
		if got != denyMalformed {
			t.Fatalf("auditTruthForEngineErr(errInvalidRange) = %q, want %q", got, denyMalformed)
		}
	})
	t.Run("wire_code_invalid_argument", func(t *testing.T) {
		v := mapDeny(denyClassForEngineErr(errInvalidRange))
		if v.WireCode != wireCodeInvalidArgument {
			t.Fatalf("wire code for errInvalidRange = %q, want %q", v.WireCode, wireCodeInvalidArgument)
		}
		if v.WireStatus != http.StatusBadRequest {
			t.Fatalf("wire status for errInvalidRange = %d, want 400", v.WireStatus)
		}
	})
	t.Run("wrapped_still_malformed", func(t *testing.T) {
		wrapped := errors.Join(errors.New("engine detail"), errInvalidRange)
		got := denyClassForEngineErr(wrapped)
		if got != denyMalformed {
			t.Fatalf("denyClassForEngineErr(wrapped errInvalidRange) = %q, want %q", got, denyMalformed)
		}
	})
}

// errmap-02: listDirectory of a file path ─────────────────────────────────

// TestListDirectoryOfFileDeniesMalformed pins errmap-02: a listDirectory that
// targets a path which is a FILE (not a directory) must return
// invalid_argument/400 on the wire, never internal/500. The fake engine returns
// errNotADirectory on this edge — matching both the local (ENOTDIR) and S3
// engine sentinels — and denyClassForEngineErr classifies it as denyMalformed.
func TestListDirectoryOfFileDeniesMalformed(t *testing.T) {
	const scope = "fs-list-file"
	const engPath = "data.txt"
	const guestPath = "/" + engPath

	eng := newFakeEngine()
	eng.putFile(scope, engPath, 100)

	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	w := serveOp(d, OpListDirectory,
		listBody(scope, guestPath, 0, "", false),
		scope, okIntents())

	if w.Code == http.StatusInternalServerError {
		t.Fatalf("listDirectory of a file returned 500 (internal); want 400 (invalid_argument)")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("listDirectory of a file: status = %d, want 400 (invalid_argument)", w.Code)
	}

	ce := decodeErrBody(t, w)
	if ce.Code != wireCodeInvalidArgument {
		t.Fatalf("wire code = %q, want %q", ce.Code, wireCodeInvalidArgument)
	}
}

// TestErrNotADirectoryClassifiesMalformed pins the sentinel-remap path for
// errmap-02: the southface mirror errNotADirectory must classify as denyMalformed
// through both denyClassForEngineErr and auditTruthForEngineErr, and must NOT
// fall through to denyInternal (the old behaviour).
func TestErrNotADirectoryClassifiesMalformed(t *testing.T) {
	t.Run("denyClassForEngineErr", func(t *testing.T) {
		got := denyClassForEngineErr(errNotADirectory)
		if got != denyMalformed {
			t.Fatalf("denyClassForEngineErr(errNotADirectory) = %q, want %q", got, denyMalformed)
		}
	})
	t.Run("auditTruthForEngineErr", func(t *testing.T) {
		got := auditTruthForEngineErr(errNotADirectory)
		if got != denyMalformed {
			t.Fatalf("auditTruthForEngineErr(errNotADirectory) = %q, want %q", got, denyMalformed)
		}
	})
	t.Run("wire_code_invalid_argument", func(t *testing.T) {
		v := mapDeny(denyClassForEngineErr(errNotADirectory))
		if v.WireCode != wireCodeInvalidArgument {
			t.Fatalf("wire code for errNotADirectory = %q, want %q", v.WireCode, wireCodeInvalidArgument)
		}
		if v.WireStatus != http.StatusBadRequest {
			t.Fatalf("wire status for errNotADirectory = %d, want 400", v.WireStatus)
		}
	})
	t.Run("wrapped_still_malformed", func(t *testing.T) {
		wrapped := errors.Join(errors.New("engine detail"), errNotADirectory)
		got := denyClassForEngineErr(wrapped)
		if got != denyMalformed {
			t.Fatalf("denyClassForEngineErr(wrapped errNotADirectory) = %q, want %q", got, denyMalformed)
		}
	})
}

// errmap-03: context-cancelled body read ──────────────────────────────────

// cancelBody is an io.ReadCloser that reads up to n bytes successfully then
// cancels the supplied context and returns context.Canceled. It models a client
// that disconnects mid-body.
type cancelBody struct {
	inner  io.Reader
	cancel context.CancelFunc
	n      int
	read   int
}

func (b *cancelBody) Read(p []byte) (int, error) {
	if b.read >= b.n {
		b.cancel()
		return 0, context.Canceled
	}
	limit := b.n - b.read
	if len(p) > limit {
		p = p[:limit]
	}
	n, err := b.inner.Read(p)
	b.read += n
	return n, err
}

func (b *cancelBody) Close() error { return nil }

// deadlineBody always returns context.DeadlineExceeded on the first Read.
type deadlineBody struct{}

func (b *deadlineBody) Read(_ []byte) (int, error) { return 0, context.DeadlineExceeded }
func (b *deadlineBody) Close() error               { return nil }

// TestBodyReadCancelClassifiesAborted pins errmap-03: an io.ReadAll failure
// caused by a context cancellation during the unary STAGE-1 body read must
// produce denyAborted (aborted/409), NOT denyMalformed (invalid_argument/400).
// This stops a client disconnect from being durably recorded as the guest
// sending malformed bytes.
func TestBodyReadCancelClassifiesAborted(t *testing.T) {
	d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())

	fullBody := bodyFor(boundScope, IntentRead)

	// cancelBody emits the first 4 bytes then signals context.Canceled,
	// so io.ReadAll inside the dispatcher sees a mid-read cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	body := &cancelBody{
		inner:  strings.NewReader(fullBody),
		cancel: cancel,
		n:      4,
	}

	r := httptest.NewRequest(http.MethodPost, restBase+string(OpReadFile), body)
	r.Header.Set("Content-Type", contentTypeJSON)
	r.ContentLength = int64(len(fullBody))
	ps := PeerScope{FilesystemID: boundScope, GrantedIntents: []Intent{IntentRead}, UID: 4242, PID: 7}
	r = r.WithContext(contextWithPeerScope(ctx, ps))

	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)

	if w.Code == http.StatusBadRequest {
		t.Fatalf("context-cancelled body read returned 400 (malformed); want 409 (aborted)")
	}
	// HTTP 409 is the Connect mapping for wireCodeAborted.
	if w.Code != http.StatusConflict {
		t.Fatalf("context-cancelled body read: status = %d, want 409 (aborted)", w.Code)
	}

	ce := decodeErrBody(t, w)
	if ce.Code != wireCodeAborted {
		t.Fatalf("context-cancelled body read: wire code = %q, want %q", ce.Code, wireCodeAborted)
	}
}

// TestBodyReadDeadlineClassifiesAborted is the DeadlineExceeded mirror of
// TestBodyReadCancelClassifiesAborted: a body read error wrapping
// context.DeadlineExceeded must also classify as denyAborted, not denyMalformed.
func TestBodyReadDeadlineClassifiesAborted(t *testing.T) {
	d := newTestDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings())

	// Use a context that is already past its deadline so any context.Err()
	// check sees DeadlineExceeded immediately.
	deadline := time.Now().Add(-time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	body := &deadlineBody{}
	fullBody := bodyFor(boundScope, IntentRead)

	r := httptest.NewRequest(http.MethodPost, restBase+string(OpReadFile), body)
	r.Header.Set("Content-Type", contentTypeJSON)
	r.ContentLength = int64(len(fullBody))
	ps := PeerScope{FilesystemID: boundScope, GrantedIntents: []Intent{IntentRead}, UID: 4242, PID: 7}
	r = r.WithContext(contextWithPeerScope(ctx, ps))

	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)

	if w.Code == http.StatusBadRequest {
		t.Fatalf("deadline-exceeded body read returned 400 (malformed); want 409 (aborted)")
	}
	if w.Code != http.StatusConflict {
		t.Fatalf("deadline-exceeded body read: status = %d, want 409 (aborted)", w.Code)
	}

	ce := decodeErrBody(t, w)
	if ce.Code != wireCodeAborted {
		t.Fatalf("deadline-exceeded body read: wire code = %q, want %q", ce.Code, wireCodeAborted)
	}
}
