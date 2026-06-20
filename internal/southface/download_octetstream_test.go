// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
)

// downloadJSONBody encodes a fileDownload JSON request body matching the frozen
// wire (A2-octet): filesystem_id top-level, uuid axis (NOT path), an optional
// *Range pointer (omitempty — a full download OMITS range, a ranged download
// sends it), and read authorization_metadata. The downloadable hint is sent as
// false on the wire; the broker re-derives the authoritative value from its own
// grant at read time (NFR-SEC-73), so the wire flag is never trusted. The body
// is built through the parity oracle's fileDownloadReq so its field set is the
// pinned shape, never a hand-rolled drift.
func downloadJSONBody(t *testing.T, scope, uuid string, rng *rangeFixture) []byte {
	t.Helper()
	body := fileDownloadReq{
		FilesystemID:          scope,
		UUID:                  uuid,
		Range:                 rng,
		AuthorizationMetadata: readMeta(),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal download request: %v", err)
	}
	return raw
}

// downloadRequest builds a POST fileDownload request carrying the JSON body and a
// PeerScope bound to scope/intents in the request context (the unix-fallback
// identity source the dispatcher reads when no credential extractor is wired).
// The request drives the router, which routes the op to serveDownloadOctetStream.
func downloadRequest(t *testing.T, scope, uuid string, rng *rangeFixture, channelScope string, intents []Intent) *http.Request {
	t.Helper()
	body := downloadJSONBody(t, scope, uuid, rng)
	r := httptest.NewRequest(http.MethodPost, restBase+string(OpFileDownload), bytes.NewReader(body))
	r.Header.Set("Content-Type", contentTypeJSON)
	r.ContentLength = int64(len(body))
	ps := PeerScope{FilesystemID: channelScope, GrantedIntents: intents, UID: 4242, PID: 7}
	return r.WithContext(contextWithPeerScope(r.Context(), ps))
}

// serveDownload drives a fileDownload end-to-end through the router (the
// production entrypoint) and returns the recorder. scope is the request-body
// filesystem_id; channelScope is the channel-bound PeerScope scope (they differ
// only in the scope-mismatch case).
func serveDownload(t *testing.T, d *dispatcher, scope, uuid string, rng *rangeFixture, channelScope string, intents []Intent) *httptest.ResponseRecorder {
	t.Helper()
	rt := newRESTRouter(d)
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, downloadRequest(t, scope, uuid, rng, channelScope, intents))
	return w
}

// assertDownloadDenied asserts the download was refused with the wanted HTTP
// status and a BoundedReason diagnostic body — a real PRE-byte status, never a
// committed 200 with a half-written body. The octet-stream success path commits
// 200 + application/octet-stream; a deny must NOT carry that content type.
func assertDownloadDenied(t *testing.T, w *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("download status = %d, want %d; body %s", w.Code, wantStatus, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct == contentTypeOctetStream {
		t.Fatalf("a denied download committed the octet-stream content type %q (the 200 header leaked)", ct)
	}
	var br boundedReason
	if err := json.Unmarshal(w.Body.Bytes(), &br); err != nil {
		t.Fatalf("deny body not a BoundedReason JSON: %v (%q)", err, w.Body.String())
	}
	if br.ReasonCode == "" {
		t.Fatalf("deny body has no reason_code: %q", w.Body.String())
	}
}

// assertDownloadOK asserts the response is a committed HTTP 200 with the
// octet-stream content type and the wanted raw bytes (no JSON, no base64, no
// per-chunk envelope — the body IS the object bytes).
func assertDownloadOK(t *testing.T, w *httptest.ResponseRecorder, want []byte) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("download status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != contentTypeOctetStream {
		t.Fatalf("download Content-Type = %q, want %q", ct, contentTypeOctetStream)
	}
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("download body = %q, want %q (raw bytes, no framing)", w.Body.Bytes(), want)
	}
}

const downloadScope = "fs-download"

// newDownloadDispatcher builds an engine-backed dispatcher whose resolver grants
// Downloadable per the flag (broker-side resolution, NFR-SEC-73), with a
// recording ceilings session so the fd gauge can be asserted.
func newDownloadDispatcher(eng Engine, g Guard, sess *recordingCeilingsSession, downloadable bool) *dispatcher {
	d := newStreamDispatcher(eng, g, sess, 1<<20)
	d.resolver = &fakeResolver{grant: Grant{Downloadable: downloadable}}
	return d
}

// TestDownloadOctetStream is the REST fileDownload suite: it ports the surviving
// download algorithm's tests minus the Connect framing — whole-object (exact raw
// bytes, octet-stream content type), ranged offset/length window, the nil-range
// Stat path, unknown-uuid -> 404, cross-scope-uuid -> 404 with a scope_mismatch
// AUDIT truth, not-downloadable -> 403, negative-range -> 400, audit-sink-down
// degrade -> 503 (fail-closed), and a mid-stream engine error termination after
// the 200 header.
func TestDownloadOctetStream(t *testing.T) {
	content := []byte("HELLO_DOWNLOAD_BYTES_12345678")

	t.Run("whole_object_exact_bytes_octet_stream", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putBytes(downloadScope, "dl.bin", content)
		g := &fakeGuard{}
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, g, sess, true)
		uuid := d.ids.idFor(downloadScope, "/dl.bin")

		// Nil range -> the handler runs a Stat to size the whole object, then
		// streams it.
		w := serveDownload(t, d, downloadScope, uuid, nil, downloadScope, okIntents())

		assertDownloadOK(t, w, content)
		// The Stat-for-whole-object-size path ran before the read (nil range).
		if len(eng.statCalls()) == 0 {
			t.Fatalf("nil-range download did not Stat for the whole-object size")
		}
		// An allow audit event was Mandated before the first byte (audit-before-ack).
		if len(g.events) == 0 {
			t.Fatalf("no allow audit event on a successful download")
		}
		// The fd gauge balances on the success path.
		if !sess.balanced() {
			t.Fatalf("ceilings gauge unbalanced after success: fd %d/%d", sess.fdAcquired, sess.fdReleased)
		}
		// x-request-id is stamped on the success response.
		if w.Header().Get(requestIDHeader) == "" {
			t.Fatal("successful download response missing x-request-id")
		}
	})

	t.Run("ranged_offset_length_window", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putBytes(downloadScope, "dl.bin", content)
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, &fakeGuard{}, sess, true)
		uuid := d.ids.idFor(downloadScope, "/dl.bin")

		// Window [6, 8) -> "DOWNLOAD". A present range skips the whole-object Stat.
		w := serveDownload(t, d, downloadScope, uuid, &rangeFixture{Offset: 6, Length: 8}, downloadScope, okIntents())

		assertDownloadOK(t, w, content[6:6+8])
		if len(eng.statCalls()) != 0 {
			t.Fatalf("a ranged download ran a whole-object Stat (%v), want none", eng.statCalls())
		}
		if !sess.balanced() {
			t.Fatalf("ranged download gauge unbalanced")
		}
	})

	t.Run("unknown_uuid_404", func(t *testing.T) {
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, &fakeGuard{}, sess, true)

		// A uuid never minted by this session -> not_found (404).
		w := serveDownload(t, d, downloadScope, "deadbeefdeadbeefdeadbeefdeadbeef", nil, downloadScope, okIntents())

		assertDownloadDenied(t, w, http.StatusNotFound)
		// No engine read or stat on an unknown uuid.
		if len(eng.readRangeCalls()) != 0 || len(eng.statCalls()) != 0 {
			t.Fatalf("unknown-uuid deny touched the engine: read %v stat %v", eng.readRangeCalls(), eng.statCalls())
		}
		if !sess.balanced() {
			t.Fatalf("unknown-uuid gauge unbalanced")
		}
	})

	t.Run("cross_scope_uuid_404_with_scope_mismatch_audit", func(t *testing.T) {
		// A uuid minted in a FOREIGN scope, presented on this channel: the wire
		// degrades to 404 (anti-enumeration) but the AUDIT truth is scope_mismatch
		// (D8). The engine is never read.
		eng := newFakeEngine()
		g := &fakeGuard{}
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, g, sess, true)

		const foreignScope = "fs-foreign"
		// Mint the uuid in the foreign scope but present it on the downloadScope
		// channel. The request body filesystem_id must MATCH the channel scope
		// (otherwise the earlier channel-scope cross-check fires); the cross-scope
		// degrade is keyed on the STORED record scope, not the body value.
		foreignUUID := d.ids.idFor(foreignScope, "/secret.bin")

		w := serveDownload(t, d, downloadScope, foreignUUID, nil, downloadScope, okIntents())

		// Wire: 404 (degraded), NOT 403 — anti-enumeration.
		assertDownloadDenied(t, w, http.StatusNotFound)
		// The 404 wire class is header-less: a degraded scope_mismatch must NOT
		// leak the truth in x-deny-reason.
		if h := w.Header().Get(denyReasonHeader); h != "" {
			t.Fatalf("cross-scope degrade leaked x-deny-reason %q, want none (anti-enumeration)", h)
		}
		// AUDIT truth: the deny event carries scope_mismatch and names the PROBED
		// foreign handle, not the channel scope.
		if len(g.events) == 0 {
			t.Fatalf("no audit event on the cross-scope deny")
		}
		ev, ok := g.events[len(g.events)-1].(auditgate.FileActivityEvent)
		if !ok {
			t.Fatalf("audit event is not auditgate.FileActivityEvent: %T", g.events[len(g.events)-1])
		}
		if ev.Outcome.XDenyReason != denyScopeMismatch {
			t.Fatalf("cross-scope audit reason = %q, want %q (the truth)", ev.Outcome.XDenyReason, denyScopeMismatch)
		}
		// The engine was never read or stat'd.
		if len(eng.readRangeCalls()) != 0 || len(eng.statCalls()) != 0 {
			t.Fatalf("cross-scope deny touched the engine: read %v stat %v", eng.readRangeCalls(), eng.statCalls())
		}
	})

	t.Run("channel_scope_mismatch_403", func(t *testing.T) {
		// The request-body filesystem_id disagrees with the channel scope: a
		// scope_mismatch deny (permission_denied, 403) BEFORE the uuid is resolved.
		// This is distinct from the cross-scope-record degrade above (which keeps
		// the body fsid == channel scope and degrades to 404).
		eng := newFakeEngine()
		eng.putBytes(downloadScope, "dl.bin", content)
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, &fakeGuard{}, sess, true)
		uuid := d.ids.idFor(downloadScope, "/dl.bin")

		w := serveDownload(t, d, "fs-other", uuid, nil, downloadScope, okIntents())

		assertDownloadDenied(t, w, http.StatusForbidden)
		// The scope_mismatch deny carries the x-deny-reason truth header (a real
		// authorization verdict, not the anti-enumeration degrade).
		if w.Header().Get(denyReasonHeader) != denyScopeMismatch {
			t.Fatalf("channel-scope deny x-deny-reason = %q, want %q", w.Header().Get(denyReasonHeader), denyScopeMismatch)
		}
		if !sess.balanced() {
			t.Fatalf("channel-scope-deny gauge unbalanced")
		}
	})

	t.Run("not_downloadable_403", func(t *testing.T) {
		// The resolver grants Downloadable=false: the wire flag (sent false anyway)
		// is irrelevant; the broker-resolved grant denies (403). No engine read.
		eng := newFakeEngine()
		eng.putBytes(downloadScope, "dl.bin", content)
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, &fakeGuard{}, sess, false)
		uuid := d.ids.idFor(downloadScope, "/dl.bin")

		w := serveDownload(t, d, downloadScope, uuid, nil, downloadScope, okIntents())

		assertDownloadDenied(t, w, http.StatusForbidden)
		if w.Header().Get(denyReasonHeader) != denyNotDownloadable {
			t.Fatalf("not-downloadable x-deny-reason = %q, want %q", w.Header().Get(denyReasonHeader), denyNotDownloadable)
		}
		// downloadable resolves at read BEFORE the engine: no read, no stat.
		if len(eng.readRangeCalls()) != 0 {
			t.Fatalf("not-downloadable deny reached the engine read: %v", eng.readRangeCalls())
		}
		if !sess.balanced() {
			t.Fatalf("not-downloadable gauge unbalanced")
		}
	})

	t.Run("negative_range_400", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putBytes(downloadScope, "dl.bin", content)
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, &fakeGuard{}, sess, true)
		uuid := d.ids.idFor(downloadScope, "/dl.bin")

		for _, c := range []struct {
			name string
			rng  *rangeFixture
		}{
			{"negative_offset", &rangeFixture{Offset: -1, Length: 4}},
			{"negative_length", &rangeFixture{Offset: 0, Length: -4}},
		} {
			t.Run(c.name, func(t *testing.T) {
				w := serveDownload(t, d, downloadScope, uuid, c.rng, downloadScope, okIntents())
				assertDownloadDenied(t, w, http.StatusBadRequest)
				if !sess.balanced() {
					t.Fatalf("%s gauge unbalanced", c.name)
				}
			})
		}
		// A negative window is rejected before the engine read (no bytes flow).
		if len(eng.readRangeCalls()) != 0 {
			t.Fatalf("negative-range deny reached the engine read: %v", eng.readRangeCalls())
		}
	})

	t.Run("audit_sink_down_degrades_fail_closed_503", func(t *testing.T) {
		// The allow Mandate fails (audit gate down): the download is denied
		// unavailable (503) BEFORE any byte is committed — fail-closed (NFR-SEC-79).
		eng := newFakeEngine()
		eng.putBytes(downloadScope, "dl.bin", content)
		g := &fakeGuard{err: ErrAuditUnavailable}
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, g, sess, true)
		uuid := d.ids.idFor(downloadScope, "/dl.bin")

		w := serveDownload(t, d, downloadScope, uuid, &rangeFixture{Offset: 0, Length: 4}, downloadScope, okIntents())

		assertDownloadDenied(t, w, http.StatusServiceUnavailable)
		// No x-deny-reason on an audit-down verdict (the truth header only ever
		// accompanies a recorded truth).
		if w.Header().Get(denyReasonHeader) != "" {
			t.Fatalf("audit-down verdict carries x-deny-reason %q, want none", w.Header().Get(denyReasonHeader))
		}
		// No byte was committed: the engine was never read.
		if len(eng.readRangeCalls()) != 0 {
			t.Fatalf("audit-down deny reached the engine read: %v", eng.readRangeCalls())
		}
		if !sess.balanced() {
			t.Fatalf("audit-down gauge unbalanced")
		}
	})

	t.Run("mid_stream_engine_error_terminates_after_200", func(t *testing.T) {
		// The engine commits the 200 header (the read window resolved, the grant
		// cleared, the allow Mandated, the fd acquired), then faults MID-STREAM:
		// some bytes flow, then ReadRange returns an error. The status is already
		// 200 and cannot change; the stream simply terminates (a short read the
		// client detects). The fd gauge must still re-balance (the deferred
		// ReleaseFD fires on the terminal exit).
		const partial = "PARTIAL_"
		eng := &partialThenErrorEngine{prefix: []byte(partial)}
		g := &fakeGuard{}
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, g, sess, true)
		uuid := d.ids.idFor(downloadScope, "/dl.bin")

		// A present range skips the Stat (partialThenErrorEngine.Stat would
		// otherwise need to answer); the handler drives straight to ReadRange.
		w := serveDownload(t, d, downloadScope, uuid, &rangeFixture{Offset: 0, Length: 64}, downloadScope, okIntents())

		// The 200 header committed with the octet-stream content type, and the
		// partial bytes arrived before the engine faulted.
		if w.Code != http.StatusOK {
			t.Fatalf("mid-stream fault status = %d, want 200 (already committed before the fault)", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != contentTypeOctetStream {
			t.Fatalf("mid-stream fault Content-Type = %q, want %q (200 already committed)", ct, contentTypeOctetStream)
		}
		if got := w.Body.String(); got != partial {
			t.Fatalf("mid-stream fault body = %q, want the partial prefix %q (then the stream terminates)", got, partial)
		}
		// The fd gauge re-balances on the terminal exit (no leaked fd slot).
		if !sess.balanced() {
			t.Fatalf("mid-stream fault gauge unbalanced: fd %d/%d", sess.fdAcquired, sess.fdReleased)
		}
		// The allow Mandate preceded the first byte (audit-before-ack); no later
		// deny audit is Mandated post-200 (the status is already committed).
		if len(g.events) == 0 {
			t.Fatalf("no allow audit event before the committed stream")
		}
	})
}

// partialThenErrorEngine is a minimal Engine whose ReadRange writes a fixed
// prefix and then returns an error, simulating a backend that faults MID-STREAM
// after some bytes have already been flushed to the client (after the 200 header
// is committed). Every other verb is unused by the download handler on the ranged
// path (a present range skips Stat), so they return a benign error.
type partialThenErrorEngine struct{ prefix []byte }

// errMidStream is the mid-stream engine fault the partialThenErrorEngine raises
// after writing its prefix.
var errMidStream = errMidStreamSentinel{}

type errMidStreamSentinel struct{}

func (errMidStreamSentinel) Error() string { return "southface: mid-stream engine fault (test)" }

func (e *partialThenErrorEngine) ReadRange(_ context.Context, _, _ string, _, _ int64, w io.Writer) error {
	if _, err := w.Write(e.prefix); err != nil {
		return err
	}
	return errMidStream
}

func (e *partialThenErrorEngine) Stat(context.Context, string, string) (FileInfo, error) {
	return FileInfo{}, errMidStream
}

func (e *partialThenErrorEngine) List(context.Context, string, string) ([]FileInfo, error) {
	return nil, errMidStream
}
func (e *partialThenErrorEngine) MakeDir(context.Context, string, string) error { return errMidStream }
func (e *partialThenErrorEngine) RemoveDir(context.Context, string, string) error {
	return errMidStream
}
func (e *partialThenErrorEngine) RemoveFile(context.Context, string, string) error {
	return errMidStream
}
func (e *partialThenErrorEngine) MoveDir(context.Context, string, string, string, bool) error {
	return errMidStream
}
func (e *partialThenErrorEngine) CopyFile(context.Context, string, string, string, bool) error {
	return errMidStream
}
func (e *partialThenErrorEngine) MoveFile(context.Context, string, string, string, bool) error {
	return errMidStream
}
func (e *partialThenErrorEngine) WriteStream(context.Context, string, string, io.Reader, bool) error {
	return errMidStream
}

// Compile-time proof the partial-then-error engine satisfies the Engine seam.
var _ Engine = (*partialThenErrorEngine)(nil)

// TestDownloadRequestShapeMatchesOracle pins the fileDownload request shape the
// handler decodes against the parity oracle (restparity_fixtures_test.go): the
// uuid axis (no path), the *Range pointer with omitempty (a full download OMITS
// range; a ranged download sends it), and filesystem_id top-level. A handler that
// decoded a different field set would silently drift from the frozen wire.
func TestDownloadRequestShapeMatchesOracle(t *testing.T) {
	// Full download: range OMITTED, uuid present, no path.
	full := downloadJSONBody(t, "fs", "u-1", nil)
	var fullMap map[string]any
	if err := json.Unmarshal(full, &fullMap); err != nil {
		t.Fatalf("unmarshal full download body: %v", err)
	}
	if _, ok := fullMap["range"]; ok {
		t.Errorf("full download: range must be OMITTED, got %v", fullMap["range"])
	}
	if _, ok := fullMap["path"]; ok {
		t.Errorf("fileDownload is uuid-axis: must carry no path, got %v", fullMap["path"])
	}
	if _, ok := fullMap["uuid"]; !ok {
		t.Errorf("fileDownload missing the uuid axis")
	}
	if _, ok := fullMap["filesystem_id"]; !ok {
		t.Errorf("fileDownload filesystem_id is not top-level")
	}

	// The handler's strict decoder accepts the oracle's full-download shape; the
	// omitted range decodes to a nil pointer (whole-object read).
	var decoded fileDownloadRequest
	dec := json.NewDecoder(bytes.NewReader(full))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("handler strict-decode of the oracle full-download body: %v", err)
	}
	if decoded.Range != nil {
		t.Errorf("decoded range = %+v on a full download, want nil (whole object)", decoded.Range)
	}
	if decoded.UUID != "u-1" {
		t.Errorf("decoded uuid = %q, want u-1", decoded.UUID)
	}

	// Ranged download: range present with the window.
	ranged := downloadJSONBody(t, "fs", "u-1", &rangeFixture{Offset: 5, Length: 7})
	var rangedDecoded fileDownloadRequest
	rd := json.NewDecoder(bytes.NewReader(ranged))
	rd.DisallowUnknownFields()
	if err := rd.Decode(&rangedDecoded); err != nil {
		t.Fatalf("handler strict-decode of the oracle ranged-download body: %v", err)
	}
	if rangedDecoded.Range == nil || rangedDecoded.Range.Offset != 5 || rangedDecoded.Range.Length != 7 {
		t.Errorf("decoded ranged window = %+v, want {offset:5,length:7}", rangedDecoded.Range)
	}
}
