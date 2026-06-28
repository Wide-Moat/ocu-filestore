// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
)

// uploadBodyOpts carries the knobs a multipart upload body builder needs: the
// scope/path/declared-size of the params field, the raw file bytes, and whether
// the overwrite_existing key is emitted (omitempty: a create-new upload omits
// it; an overwrite-in-place upload sends true).
type uploadBodyOpts struct {
	scope         string
	path          string
	declared      int64
	overwrite     bool
	sendOverwrite bool // emit the overwrite_existing key (true) or omit it (false)
	fileBytes     []byte
}

// buildUploadBody encodes a fileUpload multipart/form-data body matching the
// frozen wire: a "params" form FIELD carrying the upload params JSON, then a
// "file" form FILE (filename "upload") carrying the raw source bytes. It returns
// the body bytes and the Content-Type header (including the generated boundary).
// The params JSON is built through the parity oracle's uploadParamsFixture so the
// field set (declared_size_bytes REQUIRED, overwrite_existing omitempty) is the
// pinned shape, never a hand-rolled drift.
func buildUploadBody(t *testing.T, o uploadBodyOpts) (body []byte, contentType string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	params := uploadParamsFixture{
		FilesystemID:          o.scope,
		Path:                  o.path,
		DeclaredSizeBytes:     o.declared,
		AuthorizationMetadata: writeMeta(),
	}
	if o.sendOverwrite {
		params.OverwriteExisting = o.overwrite
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal upload params: %v", err)
	}
	if err := mw.WriteField(multipartParamsFieldName, string(raw)); err != nil {
		t.Fatalf("write params field: %v", err)
	}

	fw, err := mw.CreateFormFile(multipartFileFieldName, multipartFileFilename)
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := fw.Write(o.fileBytes); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return buf.Bytes(), mw.FormDataContentType()
}

// uploadRequest builds a POST fileUpload multipart request with a PeerScope
// bound to scope/intents in the request context (the unix-fallback identity
// source the dispatcher reads when no credential extractor is wired). The
// request drives the router, which routes the multipart op to
// serveUploadMultipart.
func uploadRequest(t *testing.T, o uploadBodyOpts, scope string, intents []Intent) *http.Request {
	t.Helper()
	body, contentType := buildUploadBody(t, o)
	r := httptest.NewRequest(http.MethodPost, restBase+string(OpFileUpload), bytes.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	r.ContentLength = int64(len(body))
	ps := PeerScope{FilesystemID: scope, GrantedIntents: intents, UID: 4242, PID: 7}
	return r.WithContext(contextWithPeerScope(r.Context(), ps))
}

// serveUpload drives a multipart upload end-to-end through the router (the
// production entrypoint) and returns the recorder.
func serveUpload(t *testing.T, d *dispatcher, o uploadBodyOpts, scope string, intents []Intent) *httptest.ResponseRecorder {
	t.Helper()
	rt := newRESTRouter(d)
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, uploadRequest(t, o, scope, intents))
	return w
}

// assertUploadDenied asserts the upload was refused with the wanted HTTP status
// and a BoundedReason diagnostic body (a real status, never a framed trailer).
func assertUploadDenied(t *testing.T, w *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("upload status = %d, want %d; body %s", w.Code, wantStatus, w.Body.String())
	}
	var br boundedReason
	if err := json.Unmarshal(w.Body.Bytes(), &br); err != nil {
		t.Fatalf("deny body not a BoundedReason JSON: %v (%q)", err, w.Body.String())
	}
	if br.ReasonCode == "" {
		t.Fatalf("deny body has no reason_code: %q", w.Body.String())
	}
}

// assertNoObject asserts no object is staged at the engine-relative path (a
// torn/aborted/refused upload must leave nothing visible — temp+rename
// atomicity).
func assertNoObject(t *testing.T, eng *fakeEngine, scope, rel string) {
	t.Helper()
	var sink bytes.Buffer
	if err := eng.ReadRange(t.Context(), scope, rel, 0, 1, &sink); err == nil {
		t.Fatalf("an object was staged at %s:%s, want none (no torn object)", scope, rel)
	}
}

// TestUploadMultipart is the REST multipart fileUpload suite: it ports the
// surviving upload algorithm's tests minus the Connect framing — happy path,
// declared-size over/under mismatch, missing declared_size_bytes, foreign
// filesystem_id (scope deny), audit-sink-down degrade (fail-closed), ceiling
// exhaustion (fd/bytes), and the no-torn-object-on-abort assertion.
func TestUploadMultipart(t *testing.T) {
	const uploadScope = "fs-upload"

	t.Run("happy_path_object_written_with_exact_bytes", func(t *testing.T) {
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		g := &fakeGuard{}
		d := newStreamDispatcher(eng, g, sess, 1<<20)

		content := []byte("ABCDEFGH")
		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/up.bin", declared: int64(len(content)), fileBytes: content,
		}, uploadScope, okIntents())

		if w.Code != http.StatusOK {
			t.Fatalf("happy-path status = %d, want 200; body %s", w.Code, w.Body.String())
		}
		// The object is stored with the exact bytes.
		var buf bytes.Buffer
		if err := eng.ReadRange(t.Context(), uploadScope, "up.bin", 0, int64(len(content)), &buf); err != nil || buf.String() != string(content) {
			t.Fatalf("stored object = %q,%v want %q,nil", buf.String(), err, content)
		}
		// An allow audit event was Mandated (audit-before-ack).
		if len(g.events) == 0 {
			t.Fatalf("no allow audit event on a successful upload")
		}
		// The ceilings gauge balances on the success path.
		if !sess.balanced() {
			t.Fatalf("ceilings gauge unbalanced after success: bytes %d/%d fd %d/%d",
				sess.acquired, sess.released, sess.fdAcquired, sess.fdReleased)
		}
		// x-request-id is stamped on the success response.
		if w.Header().Get(requestIDHeader) == "" {
			t.Fatal("successful upload response missing x-request-id")
		}
	})

	t.Run("happy_path_multi_read_body", func(t *testing.T) {
		// A body larger than one read buffer proves the read loop does not assume
		// a single Read drains the file part (each client write is < the ceiling,
		// and a single Read may return less).
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<24)

		content := bytes.Repeat([]byte("xyz12345"), 200000) // 1.6 MiB, > uploadReadChunk
		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/big.bin", declared: int64(len(content)), fileBytes: content,
		}, uploadScope, okIntents())

		if w.Code != http.StatusOK {
			t.Fatalf("multi-read status = %d, want 200; body %s", w.Code, w.Body.String())
		}
		var buf bytes.Buffer
		if err := eng.ReadRange(t.Context(), uploadScope, "big.bin", 0, int64(len(content)), &buf); err != nil {
			t.Fatalf("multi-read ReadRange: %v", err)
		}
		if !bytes.Equal(buf.Bytes(), content) {
			t.Fatalf("multi-read stored %d bytes, want %d (content mismatch)", buf.Len(), len(content))
		}
		if !sess.balanced() {
			t.Fatalf("multi-read gauge unbalanced")
		}
	})

	t.Run("declared_size_over_mismatch_rejects_invalid_no_object", func(t *testing.T) {
		// declared 8, body 10 actual: over-declaration aborts invalid_argument
		// (400) and stages nothing.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/up.bin", declared: 8, fileBytes: []byte("ABCDEFGHIJ"),
		}, uploadScope, okIntents())

		assertUploadDenied(t, w, http.StatusBadRequest)
		assertNoObject(t, eng, uploadScope, "up.bin")
		if !sess.balanced() {
			t.Fatalf("over-mismatch gauge unbalanced")
		}
	})

	t.Run("declared_size_under_mismatch_rejects_invalid_no_object", func(t *testing.T) {
		// declared 8, body 4 actual: under-declaration aborts invalid_argument
		// (400) at the closing boundary and stages nothing.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/up.bin", declared: 8, fileBytes: []byte("ABCD"),
		}, uploadScope, okIntents())

		assertUploadDenied(t, w, http.StatusBadRequest)
		assertNoObject(t, eng, uploadScope, "up.bin")
		if !sess.balanced() {
			t.Fatalf("under-mismatch gauge unbalanced")
		}
	})

	t.Run("missing_declared_size_rejects_invalid", func(t *testing.T) {
		// declared_size_bytes 0 (<=0): invalid_argument (400), no escape hatch.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/up.bin", declared: 0, fileBytes: []byte("ABCD"),
		}, uploadScope, okIntents())

		assertUploadDenied(t, w, http.StatusBadRequest)
		assertNoObject(t, eng, uploadScope, "up.bin")
	})

	t.Run("foreign_filesystem_id_scope_deny", func(t *testing.T) {
		// The params filesystem_id disagrees with the channel scope: scope_mismatch
		// (permission_denied, 403). Nothing is staged.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		w := serveUpload(t, d, uploadBodyOpts{
			scope: "fs-other", path: "/up.bin", declared: 8, fileBytes: []byte("ABCDEFGH"),
		}, uploadScope, okIntents())

		assertUploadDenied(t, w, http.StatusForbidden)
		assertNoObject(t, eng, uploadScope, "up.bin")
		// The scope_mismatch deny carries the x-deny-reason truth header.
		if w.Header().Get(denyReasonHeader) != denyScopeMismatch {
			t.Fatalf("scope deny x-deny-reason = %q, want %q", w.Header().Get(denyReasonHeader), denyScopeMismatch)
		}
		if !sess.balanced() {
			t.Fatalf("scope-deny gauge unbalanced")
		}
	})

	t.Run("audit_sink_down_degrades_fail_closed", func(t *testing.T) {
		// The allow Mandate fails (audit gate down): the upload is denied
		// unavailable (503) BEFORE any file byte is consumed — fail-closed
		// (NFR-SEC-79). Nothing is staged.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		g := &fakeGuard{err: ErrAuditUnavailable}
		d := newStreamDispatcher(eng, g, sess, 1<<20)

		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/up.bin", declared: 8, fileBytes: []byte("ABCDEFGH"),
		}, uploadScope, okIntents())

		assertUploadDenied(t, w, http.StatusServiceUnavailable)
		assertNoObject(t, eng, uploadScope, "up.bin")
		// No x-deny-reason on an audit-down verdict (the truth header only ever
		// accompanies a recorded truth).
		if w.Header().Get(denyReasonHeader) != "" {
			t.Fatalf("audit-down verdict carries x-deny-reason %q, want none", w.Header().Get(denyReasonHeader))
		}
		if !sess.balanced() {
			t.Fatalf("audit-down gauge unbalanced")
		}
	})

	t.Run("fd_ceiling_exhaustion_rejects_retryable_no_object", func(t *testing.T) {
		// The fd ceiling is exhausted: resource_exhausted (429). The allow audit
		// already ran (audit-before-ack precedes the fd acquire), but no file byte
		// is consumed and nothing is staged.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{fdErr: ErrFDExceeded}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/up.bin", declared: 8, fileBytes: []byte("ABCDEFGH"),
		}, uploadScope, okIntents())

		assertUploadDenied(t, w, http.StatusTooManyRequests)
		assertNoObject(t, eng, uploadScope, "up.bin")
		if !sess.balanced() {
			t.Fatalf("fd-exhaustion gauge unbalanced")
		}
	})

	t.Run("bytes_ceiling_exhaustion_rejects_retryable_no_object", func(t *testing.T) {
		// The in-flight byte ceiling is exhausted on the first read: a
		// resource_exhausted (429) abort before the bytes reach the engine; the
		// destination is not staged and the gauge balances.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{bytesErr: ErrBytesExceeded, bytesErrAfter: 0}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/up.bin", declared: 8, fileBytes: []byte("ABCDEFGH"),
		}, uploadScope, okIntents())

		assertUploadDenied(t, w, http.StatusTooManyRequests)
		assertNoObject(t, eng, uploadScope, "up.bin")
		if !sess.balanced() {
			t.Fatalf("bytes-exhaustion gauge unbalanced")
		}
	})

	t.Run("already_exists_overwrite_false_leaves_original", func(t *testing.T) {
		// overwrite_existing omitted (create-new) onto an existing path refuses
		// already_exists (409); the original bytes are unchanged.
		eng := newFakeEngine()
		eng.putBytes(uploadScope, "ow.bin", []byte("OLDBYTES"))
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/ow.bin", declared: 8, fileBytes: []byte("NEWBYTES"),
		}, uploadScope, okIntents())

		assertUploadDenied(t, w, http.StatusConflict)
		var buf bytes.Buffer
		if err := eng.ReadRange(t.Context(), uploadScope, "ow.bin", 0, 8, &buf); err != nil || buf.String() != "OLDBYTES" {
			t.Fatalf("existing object changed by a refused create-new upload: %q,%v", buf.String(), err)
		}
		if !sess.balanced() {
			t.Fatalf("already-exists gauge unbalanced")
		}
	})

	t.Run("overwrite_true_replaces_existing", func(t *testing.T) {
		// overwrite_existing=true onto an existing path REPLACES the content (no
		// already_exists; the new bytes are readable).
		eng := newFakeEngine()
		eng.putBytes(uploadScope, "ow.bin", []byte("OLDBYTES"))
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		newContent := []byte("FRESHXYZ")
		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/ow.bin", declared: int64(len(newContent)),
			overwrite: true, sendOverwrite: true, fileBytes: newContent,
		}, uploadScope, okIntents())

		if w.Code != http.StatusOK {
			t.Fatalf("overwrite=true status = %d, want 200; body %s", w.Code, w.Body.String())
		}
		var buf bytes.Buffer
		if err := eng.ReadRange(t.Context(), uploadScope, "ow.bin", 0, int64(len(newContent)), &buf); err != nil {
			t.Fatalf("overwrite=true ReadRange: %v", err)
		}
		if got := buf.String(); got != string(newContent) {
			t.Fatalf("overwrite=true stored = %q, want %q", got, newContent)
		}
	})

	t.Run("unknown_params_field_rejected", func(t *testing.T) {
		// A params JSON carrying an unknown field is strict-rejected
		// (invalid_argument, 400) — the same discipline as the retired params
		// frame and every unary body.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		bad := `{"filesystem_id":"fs-upload","path":"/up.bin","declared_size_bytes":8,"metadata_retention_days":7,"authorization_metadata":{"intent":"write","downloadable":false}}`
		if err := mw.WriteField(multipartParamsFieldName, bad); err != nil {
			t.Fatalf("write params: %v", err)
		}
		fw, _ := mw.CreateFormFile(multipartFileFieldName, multipartFileFilename)
		_, _ = fw.Write([]byte("ABCDEFGH"))
		_ = mw.Close()

		r := httptest.NewRequest(http.MethodPost, restBase+string(OpFileUpload), bytes.NewReader(buf.Bytes()))
		r.Header.Set("Content-Type", mw.FormDataContentType())
		r.ContentLength = int64(buf.Len())
		ps := PeerScope{FilesystemID: uploadScope, GrantedIntents: okIntents()}
		rt := newRESTRouter(d)
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, r.WithContext(contextWithPeerScope(r.Context(), ps)))

		assertUploadDenied(t, w, http.StatusBadRequest)
		assertNoObject(t, eng, uploadScope, "up.bin")
	})

	t.Run("missing_file_part_rejected", func(t *testing.T) {
		// A body with the params field but NO file part: the second NextPart fails
		// and the upload is refused malformed (invalid_argument, 400). Nothing is
		// staged.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		params := uploadParamsFixture{FilesystemID: uploadScope, Path: "/up.bin", DeclaredSizeBytes: 8, AuthorizationMetadata: writeMeta()}
		raw, _ := json.Marshal(params)
		if err := mw.WriteField(multipartParamsFieldName, string(raw)); err != nil {
			t.Fatalf("write params: %v", err)
		}
		_ = mw.Close() // no file part

		r := httptest.NewRequest(http.MethodPost, restBase+string(OpFileUpload), bytes.NewReader(buf.Bytes()))
		r.Header.Set("Content-Type", mw.FormDataContentType())
		r.ContentLength = int64(buf.Len())
		ps := PeerScope{FilesystemID: uploadScope, GrantedIntents: okIntents()}
		rt := newRESTRouter(d)
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, r.WithContext(contextWithPeerScope(r.Context(), ps)))

		assertUploadDenied(t, w, http.StatusBadRequest)
		assertNoObject(t, eng, uploadScope, "up.bin")
	})

	t.Run("not_multipart_rejected", func(t *testing.T) {
		// A request the router classified as multipart (by media type) but whose
		// body is not parsable multipart: r.MultipartReader errors and the handler
		// refuses it malformed (400) before any part is read.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		r := httptest.NewRequest(http.MethodPost, restBase+string(OpFileUpload), strings.NewReader("not-a-multipart-body"))
		// multipart/form-data media type but NO boundary parameter.
		r.Header.Set("Content-Type", "multipart/form-data")
		ps := PeerScope{FilesystemID: uploadScope, GrantedIntents: okIntents()}
		rt := newRESTRouter(d)
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, r.WithContext(contextWithPeerScope(r.Context(), ps)))

		assertUploadDenied(t, w, http.StatusBadRequest)
	})

	t.Run("ceilings_key_on_channel_scope", func(t *testing.T) {
		// The ops/s throttle keys on the CHANNEL scope (PeerScope.FilesystemID),
		// never the params body value.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		reg := &recordingRegistry{sess: sess}
		d := newDispatcherWithEngine(&fakeResolver{}, &fakeGuard{}, reg, 1<<20, eng)
		d.maxFileSize = 1 << 20

		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/up.bin", declared: 8, fileBytes: []byte("ABCDEFGH"),
		}, uploadScope, okIntents())
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
		}
		for _, k := range reg.keys {
			if k != uploadScope {
				t.Fatalf("ceilings keyed on %q, want the channel scope %q", k, uploadScope)
			}
		}
		if len(reg.keys) == 0 {
			t.Fatalf("ceilings registry never keyed (throttle bypassed)")
		}
	})

	t.Run("size_reject_precedes_file_read_no_object", func(t *testing.T) {
		// An over-ceiling declaration rejects BEFORE the file part is consumed
		// (pre-assembly size reject) and stages nothing.
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 4) // tiny whole-object ceiling

		w := serveUpload(t, d, uploadBodyOpts{
			scope: uploadScope, path: "/up.bin", declared: 1000, fileBytes: []byte("ABCDEFGH"),
		}, uploadScope, okIntents())

		assertUploadDenied(t, w, http.StatusBadRequest)
		assertNoObject(t, eng, uploadScope, "up.bin")
		if !sess.balanced() {
			t.Fatalf("size-reject gauge unbalanced")
		}
	})
}

// TestUploadMultipartParamsMatchOracle pins the multipart params field set the
// handler decodes against the parity oracle (restparity_fixtures_test.go): the
// field names, declared_size_bytes REQUIRED, overwrite_existing omitempty (a
// create-new upload omits the key; an overwrite upload sends true), and
// filesystem_id top-level. A handler that decoded a different field set would
// silently drift from the frozen wire.
func TestUploadMultipartParamsMatchOracle(t *testing.T) {
	// The multipart field-name constants the handler uses are the same the oracle
	// pins.
	if multipartParamsField != multipartParamsFieldName || multipartFileField != multipartFileFieldName {
		t.Fatalf("handler field names (%q,%q) drifted from oracle (%q,%q)",
			multipartParamsField, multipartFileField, multipartParamsFieldName, multipartFileFieldName)
	}

	// Create-new: overwrite_existing OMITTED; declared_size_bytes present.
	create := uploadParamsFixture{FilesystemID: "fs", Path: "/a", DeclaredSizeBytes: 42, AuthorizationMetadata: writeMeta()}
	createRaw, err := json.Marshal(create)
	if err != nil {
		t.Fatalf("marshal create params: %v", err)
	}
	var createMap map[string]any
	if err := json.Unmarshal(createRaw, &createMap); err != nil {
		t.Fatalf("unmarshal create params: %v", err)
	}
	if _, ok := createMap["overwrite_existing"]; ok {
		t.Errorf("create-new params: overwrite_existing must be OMITTED, got %v", createMap["overwrite_existing"])
	}
	if _, ok := createMap["declared_size_bytes"]; !ok {
		t.Errorf("params missing declared_size_bytes (REQUIRED)")
	}
	if _, ok := createMap["filesystem_id"]; !ok {
		t.Errorf("params filesystem_id is not top-level")
	}

	// The handler's strict decoder accepts the oracle's create-new shape and
	// reads the declared size; the omitted overwrite_existing decodes to false.
	var decoded uploadParamsFrame
	dec := json.NewDecoder(bytes.NewReader(createRaw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("handler strict-decode of the oracle params frame: %v", err)
	}
	if decoded.DeclaredSizeBytes != 42 {
		t.Errorf("decoded declared_size_bytes = %d, want 42", decoded.DeclaredSizeBytes)
	}
	if decoded.OverwriteExisting {
		t.Errorf("decoded overwrite_existing = true on a create-new params frame, want false")
	}

	// Overwrite-in-place: overwrite_existing present and true.
	over := uploadParamsFixture{FilesystemID: "fs", Path: "/a", DeclaredSizeBytes: 42, OverwriteExisting: true, AuthorizationMetadata: writeMeta()}
	overRaw, _ := json.Marshal(over)
	var overDecoded uploadParamsFrame
	od := json.NewDecoder(bytes.NewReader(overRaw))
	od.DisallowUnknownFields()
	if err := od.Decode(&overDecoded); err != nil {
		t.Fatalf("handler strict-decode of the overwrite params frame: %v", err)
	}
	if !overDecoded.OverwriteExisting {
		t.Errorf("decoded overwrite_existing = false on an overwrite params frame, want true")
	}
}

// TestUploadMultipartDenyPrecedesWire pins SEC-79 on the multipart path: a
// pre-assembly reject Mandates a DENY audit event carrying the broker-resolved
// truth BEFORE the wire deny, mirroring the retired Connect denyTrailer.
func TestUploadMultipartDenyPrecedesWire(t *testing.T) {
	const uploadScope = "fs-upload"
	eng := newFakeEngine()
	sess := &recordingCeilingsSession{}
	g := &fakeGuard{}
	d := newStreamDispatcher(eng, g, sess, 4) // tiny ceiling -> size reject

	w := serveUpload(t, d, uploadBodyOpts{
		scope: uploadScope, path: "/up.bin", declared: 1000, fileBytes: []byte("ABCDEFGH"),
	}, uploadScope, okIntents())
	assertUploadDenied(t, w, http.StatusBadRequest)

	// An allow event preceded (audit-before-ack runs only after the size check,
	// so on a size reject the ONLY event is the deny). The deny audit names the
	// size-exceeded truth.
	if len(g.events) == 0 {
		t.Fatalf("no audit event on the size reject")
	}
	ev, ok := g.events[len(g.events)-1].(auditgate.FileActivityEvent)
	if !ok {
		t.Fatalf("audit event is not auditgate.FileActivityEvent: %T", g.events[len(g.events)-1])
	}
	if ev.Outcome.XDenyReason != denySizeExceeded {
		t.Fatalf("deny audit reason = %q, want %q", ev.Outcome.XDenyReason, denySizeExceeded)
	}
}
