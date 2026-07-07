// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/denyclass"
	"github.com/Wide-Moat/ocu-filestore/internal/denywire"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// ---------------------------------------------------------------------------
// Create-plane test doubles.
//
// The base fakes (fakes_test.go) are read/delete-plane doubles: fakeEngine's
// WriteStream is a no-op that ignores its reader, and fakeStore's Put always
// returns ErrStoreUnavailable. The create plane needs an engine that actually
// consumes the reader (so an aborted stream stages nothing, mirroring the
// engine's temp+rename atomicity) and a store whose Put succeeds. Following the
// established local-wrapper pattern (audit_before_ack_test.go's tracingEngine /
// tracingStore), the doubles below embed the base fakes and override only the
// create-plane verbs — the read/delete-plane behaviour is inherited unchanged.
// ---------------------------------------------------------------------------

// createEngine consumes WriteStream's reader and stores the assembled bytes into
// the embedded fakeEngine's bytesByPath on a CLEAN read, mirroring the south
// fakeEngine.WriteStream: a producer abort surfaces as a read error, so an
// aborted upload leaves nothing at the destination (temp+rename invisibility).
// It records the write count, the bytes it committed, and an ordered trace so a
// test can prove audit-before-ack and the abort-stages-nothing invariant.
type createEngine struct {
	*fakeEngine
	mu           sync.Mutex
	writeCalls   int    // WriteStream invocations
	committed    int    // WriteStream invocations that durably linked bytes
	lastPath     string // engine path of the last committed write
	alreadyExist bool   // when true and overwrite=false, refuse ErrAlreadyExists
	writeErr     error  // when non-nil, fail the write after consuming r (fault inject)
	bytesRead    int    // total bytes read off r across all WriteStream calls (incl. aborted ones)
	trace        *[]string
}

func newCreateEngine() *createEngine {
	return &createEngine{fakeEngine: newFakeEngine()}
}

func (e *createEngine) WriteStream(_ context.Context, _ string, path string, r io.Reader, overwrite bool) error {
	e.mu.Lock()
	e.writeCalls++
	if e.trace != nil {
		*e.trace = append(*e.trace, "engine:write")
	}
	// already-exists: refuse WITHOUT consuming r, exactly as the real engine does
	// on a create-new against an existing object.
	if e.alreadyExist && !overwrite {
		e.mu.Unlock()
		return southface.ErrAlreadyExists
	}
	e.mu.Unlock()

	// Read OUTSIDE the lock: the producer pipes chunks in and may block; a
	// reassembly abort (pw.CloseWithError) surfaces here as a NON-EOF read error,
	// so nothing is linked (temp+rename invisibility).
	buf, rerr := io.ReadAll(r)
	// Record the bytes that actually reached the engine reader — even on an abort
	// io.ReadAll returns the partial bytes streamed before the pipe was closed, so
	// a test can prove an EARLY abort streamed nothing (the bytes never left the
	// handler's read loop) vs a late one that streamed the whole body first.
	e.mu.Lock()
	e.bytesRead += len(buf)
	e.mu.Unlock()
	if rerr != nil {
		return rerr
	}
	if e.writeErr != nil {
		return e.writeErr
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.committed++
	e.lastPath = path
	e.bytesByPath[path] = buf
	return nil
}

// committedBytes returns the bytes durably linked at path (nil if none).
func (e *createEngine) committedBytes(path string) ([]byte, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, ok := e.bytesByPath[path]
	return b, ok
}

// createStore's Put succeeds, minting a record from the PutInput (stamping a
// deterministic file_id + created_at), and records the last PutInput and the
// Put count so a test can assert the durable handle carries the attested
// scope / declared size / canonical ObjectRef. putErr, when set, fails Put
// (fault injection for the store-latch and generic-store-error paths).
type createStore struct {
	*fakeStore
	mu       sync.Mutex
	putCalls int
	lastPut  handlestore.PutInput
	putErr   error
}

func newCreateStore() *createStore {
	return &createStore{fakeStore: newFakeStore()}
}

func (s *createStore) Put(_ context.Context, in handlestore.PutInput) (handlestore.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putCalls++
	s.lastPut = in
	if s.putErr != nil {
		return handlestore.Record{}, s.putErr
	}
	return handlestore.Record{
		FileID:    "fid-minted",
		Scope:     in.Scope,
		ObjectRef: in.ObjectRef,
		Filename:  in.Filename,
		Mime:      in.Mime,
		Size:      in.Size,
		CreatedAt: "2026-01-01T00:00:00Z",
	}, nil
}

// countingSession tracks byte and fd acquire/release balance so a test can prove
// the ceiling gauge is balanced on EVERY exit path (the deferred ReleaseBytes /
// ReleaseFD). It mirrors the south recordingCeilingsSession's balance accounting.
type countingSession struct {
	mu            sync.Mutex
	opErr         error
	fdErr         error
	bytesErr      error
	acquiredBytes int64
	releasedBytes int64
	fdAcquired    int
	fdReleased    int
}

func (s *countingSession) TryConsumeOp() error { return s.opErr }

func (s *countingSession) AcquireBytes(n int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bytesErr != nil {
		return s.bytesErr
	}
	s.acquiredBytes += n
	return nil
}

func (s *countingSession) ReleaseBytes(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releasedBytes += n
}

func (s *countingSession) TryAcquireFD() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fdErr != nil {
		return s.fdErr
	}
	s.fdAcquired++
	return nil
}

func (s *countingSession) ReleaseFD() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fdReleased++
}

func (s *countingSession) balanced() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acquiredBytes == s.releasedBytes && s.fdAcquired == s.fdReleased
}

// countingCeilings hands the same countingSession to every key.
type countingCeilings struct{ sess *countingSession }

func (c *countingCeilings) Session(string) southface.CeilingsSession { return c.sess }
func (c *countingCeilings) Release(string)                           {}

// createOrderGuard records the audit disposition in a shared trace (audit:allow
// / audit:deny), so a test can prove the ALLOW Mandate is recorded BEFORE the
// engine write. err, when set, fails every Mandate (audit-down).
type createOrderGuard struct {
	trace *[]string
	err   error
}

func (g *createOrderGuard) Mandate(_ context.Context, event any) error {
	ev, ok := event.(auditgate.FileActivityEvent)
	if !ok {
		return auditgate.ErrAuditUnavailable
	}
	if g.trace != nil {
		*g.trace = append(*g.trace, "audit:"+string(ev.Outcome.DispositionID))
	}
	return g.err
}

// compile-time proofs the create doubles honour the seams.
var (
	_ southface.Engine           = (*createEngine)(nil)
	_ handlestore.Store          = (*createStore)(nil)
	_ southface.CeilingsSession  = (*countingSession)(nil)
	_ southface.CeilingsRegistry = (*countingCeilings)(nil)
	_ southface.Guard            = (*createOrderGuard)(nil)
)

// ---------------------------------------------------------------------------
// Multipart request builders.
// ---------------------------------------------------------------------------

const createTestScope = "fs-x"

// createParams is a loose builder for the "params" JSON: only the keys a test
// sets are emitted, so a test can omit filesystem_id / media_type / filename and
// exercise the header-is-authority and path-leaf-fallback branches. It is NOT
// the handler's strict struct — it is a wire-shape map so a test can also emit an
// UNKNOWN field (strict-decode reject).
func createParamsJSON(t *testing.T, kv map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(kv)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return string(raw)
}

// buildCreateBody encodes a two-part multipart body: the "params" form FIELD
// (paramsJSON) then the "file" form FILE (body). The field/part ORDER is the
// frozen wire: params first, file second. An encode fault is a test-author bug,
// surfaced loudly via panic (mirroring the seed-corpus marshal discipline).
func buildCreateBody(paramsJSON string, body []byte) (raw []byte, contentType string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField(createParamsField, paramsJSON); err != nil {
		panic("buildCreateBody: write params field: " + err.Error())
	}
	fw, err := mw.CreateFormFile(createFileField, "upload")
	if err != nil {
		panic("buildCreateBody: create file part: " + err.Error())
	}
	if _, err := fw.Write(body); err != nil {
		panic("buildCreateBody: write file part: " + err.Error())
	}
	if err := mw.Close(); err != nil {
		panic("buildCreateBody: close multipart writer: " + err.Error())
	}
	return buf.Bytes(), mw.FormDataContentType()
}

// doCreate drives serveCreate through the router (POST /v1/files) with a
// multipart body and returns the recorder.
func doCreate(h *Handler, paramsJSON string, body []byte) *httptest.ResponseRecorder {
	raw, ct := buildCreateBody(paramsJSON, body)
	r := httptest.NewRequest(http.MethodPost, "/v1/files", bytes.NewReader(raw))
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// createSetup wires a create handler with the create doubles and a read-only
// attested scope (createTestScope). The handler ADDS write intent itself
// (createEvidenceIntents), so a read-only scope must still allow the create.
func createSetup() (*Handler, *createEngine, *createStore, *countingSession) {
	eng := newCreateEngine()
	store := newCreateStore()
	sess := &countingSession{}
	h := newTestHandler(Deps{
		Engine:   eng,
		Store:    store,
		Ceilings: &countingCeilings{sess: sess},
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:    &fakeGuard{},
		Scope: fakeScope{ps: southface.PeerScope{
			FilesystemID:   createTestScope,
			GrantedIntents: []southface.Intent{southface.IntentRead},
		}, ok: true},
	})
	return h, eng, store, sess
}

// assertCreateDenied asserts the create was refused with the wanted HTTP status
// and a BoundedReason diagnostic body (a real status, never a partial accept).
func assertCreateDenied(t *testing.T, w *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("create status = %d, want %d; body %s", w.Code, wantStatus, w.Body.String())
	}
	var br struct {
		ReasonCode string `json:"reason_code"`
		Message    string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &br); err != nil {
		t.Fatalf("deny body not a BoundedReason JSON: %v (%q)", err, w.Body.String())
	}
	if br.ReasonCode == "" {
		t.Fatalf("deny body has no reason_code: %q", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Case 1 — HAPPY PATH.
// ---------------------------------------------------------------------------

// TestCreateHappyPath pins the success shape: valid params + matching body ->
// 201 + a FileObject echoing the request's media_type/declared size/filename,
// exactly one durable Put carrying the attested scope + declared size + canonical
// ObjectRef, and the engine actually streamed the body bytes.
func TestCreateHappyPath(t *testing.T) {
	h, eng, store, sess := createSetup()
	body := []byte("ABCDEFGH")
	params := createParamsJSON(t, map[string]any{
		"path":                "/dir/up.bin",
		"declared_size_bytes": len(body),
		"media_type":          "application/octet-stream",
		"filename":            "up.bin",
	})
	w := doCreate(h, params, body)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", w.Code, w.Body.String())
	}
	var obj FileObject
	if err := json.Unmarshal(w.Body.Bytes(), &obj); err != nil {
		t.Fatalf("response not a FileObject: %v (%q)", err, w.Body.String())
	}
	if obj.ID == "" {
		t.Fatalf("FileObject.id is empty, want a minted handle")
	}
	if obj.Type != fileObjectType {
		t.Fatalf("FileObject.type = %q, want %q", obj.Type, fileObjectType)
	}
	if obj.MimeType != "application/octet-stream" {
		t.Fatalf("mime_type = %q, want the request media_type", obj.MimeType)
	}
	if obj.SizeBytes != int64(len(body)) {
		t.Fatalf("size_bytes = %d, want the declared %d", obj.SizeBytes, len(body))
	}
	if obj.Filename != "up.bin" {
		t.Fatalf("filename = %q, want the params filename up.bin", obj.Filename)
	}

	// Exactly one durable Put carrying the attested scope + declared size + the
	// canonical engine path as ObjectRef (leading slash stripped).
	if store.putCalls != 1 {
		t.Fatalf("Put called %d times, want exactly 1", store.putCalls)
	}
	if store.lastPut.Scope != createTestScope {
		t.Fatalf("Put scope = %q, want the attested %q", store.lastPut.Scope, createTestScope)
	}
	if store.lastPut.Size != int64(len(body)) {
		t.Fatalf("Put size = %d, want the declared %d", store.lastPut.Size, len(body))
	}
	if store.lastPut.Mime != "application/octet-stream" {
		t.Fatalf("Put mime = %q, want the request media_type", store.lastPut.Mime)
	}
	if store.lastPut.ObjectRef != "dir/up.bin" {
		t.Fatalf("Put ObjectRef = %q, want the canonical engine path dir/up.bin", store.lastPut.ObjectRef)
	}

	// The engine actually streamed the body bytes to the canonical path.
	if eng.writeCalls != 1 || eng.committed != 1 {
		t.Fatalf("engine writeCalls=%d committed=%d, want 1/1", eng.writeCalls, eng.committed)
	}
	got, ok := eng.committedBytes("dir/up.bin")
	if !ok || !bytes.Equal(got, body) {
		t.Fatalf("engine stored %q (%v), want %q", got, ok, body)
	}
	// Case 12 (success half): the ceiling gauge balances on the success path.
	if !sess.balanced() {
		t.Fatalf("ceiling gauge unbalanced after success: bytes %d/%d fd %d/%d",
			sess.acquiredBytes, sess.releasedBytes, sess.fdAcquired, sess.fdReleased)
	}
}

// TestCreateAcceptsAllContractParams pins that the strict decoder accepts EVERY
// property the frozen CreateFileParams schema (files-api.openapi.yaml) declares —
// not just the subset the write plane happens to consume. A conforming client
// (the webui BFF) sends authorization_metadata, metadata, tags, ttl_seconds; if
// the server struct omits any, DisallowUnknownFields 400s the whole upload with
// "malformed params JSON" and the pane can never upload. This test crosses the
// client↔server boundary the isolated unit tests never joined: it reds if the
// struct drops a contract field, greens once it implements the full schema.
func TestCreateAcceptsAllContractParams(t *testing.T) {
	h, _, _, _ := createSetup()
	body := []byte("ABCDEFGH")
	params := createParamsJSON(t, map[string]any{
		"filesystem_id":       createTestScope,
		"path":                "/dir/up.bin",
		"declared_size_bytes": len(body),
		"overwrite_existing":  false,
		"media_type":          "application/octet-stream",
		"filename":            "up.bin",
		// The create-meta the write plane may ignore but MUST accept (the exact
		// shape a conforming client sends — this is the field that 400'd live).
		"authorization_metadata": map[string]any{"intent": "write", "downloadable": true},
		"metadata":               map[string]any{"origin": "e2e"},
		"tags":                   []string{"demo"},
		"ttl_seconds":            3600,
	})
	w := doCreate(h, params, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 on a fully-populated contract params blob; body %s", w.Code, w.Body.String())
	}
}

// TestCreateFilenameFallsBackToPathLeaf pins that an OMITTED filename resolves to
// the leaf of the canonical path (createFilename), and an omitted media_type is
// echoed as empty.
func TestCreateFilenameFallsBackToPathLeaf(t *testing.T) {
	h, _, store, _ := createSetup()
	body := []byte("xyz")
	params := createParamsJSON(t, map[string]any{
		"path":                "/nested/leaf.txt",
		"declared_size_bytes": len(body),
	})
	w := doCreate(h, params, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", w.Code, w.Body.String())
	}
	var obj FileObject
	_ = json.Unmarshal(w.Body.Bytes(), &obj)
	if obj.Filename != "leaf.txt" {
		t.Fatalf("filename = %q, want the path leaf leaf.txt", obj.Filename)
	}
	if store.lastPut.Filename != "leaf.txt" {
		t.Fatalf("Put filename = %q, want the path leaf", store.lastPut.Filename)
	}
}

// ---------------------------------------------------------------------------
// Case 2 — AUDIT-BEFORE-ACK.
// ---------------------------------------------------------------------------

// TestCreateAuditBeforeAckAllowPrecedesWrite pins NFR-SEC-79: on a successful
// create the ALLOW audit Mandate is recorded BEFORE engine.WriteStream — the
// durable record lands before the first inbound byte reaches the engine.
func TestCreateAuditBeforeAckAllowPrecedesWrite(t *testing.T) {
	var trace []string
	eng := newCreateEngine()
	eng.trace = &trace
	store := newCreateStore()
	h := newTestHandler(Deps{
		Engine:   eng,
		Store:    store,
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:    &createOrderGuard{trace: &trace},
		Scope: fakeScope{ps: southface.PeerScope{
			FilesystemID: createTestScope, GrantedIntents: []southface.Intent{southface.IntentRead},
		}, ok: true},
	})
	body := []byte("ABCD")
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": len(body)})
	w := doCreate(h, params, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", w.Code, w.Body.String())
	}
	if len(trace) < 2 || trace[0] != "audit:allow" || trace[1] != "engine:write" {
		t.Fatalf("trace = %v, want [audit:allow engine:write] (audit precedes the first byte)", trace)
	}
}

// TestCreateAuditDownDeniesEngineUntouched pins that an ALLOW Mandate FAILURE
// (audit gate down) denies the create BEFORE any byte with a 503 and
// engine.WriteStream is NEVER called (zero engine writes).
func TestCreateAuditDownDeniesEngineUntouched(t *testing.T) {
	eng := newCreateEngine()
	store := newCreateStore()
	sess := &countingSession{}
	h := newTestHandler(Deps{
		Engine:   eng,
		Store:    store,
		Ceilings: &countingCeilings{sess: sess},
		Resolver: &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:    &fakeGuard{err: auditgate.ErrAuditUnavailable},
		Scope: fakeScope{ps: southface.PeerScope{
			FilesystemID: createTestScope, GrantedIntents: []southface.Intent{southface.IntentRead},
		}, ok: true},
	})
	body := []byte("ABCD")
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": len(body)})
	w := doCreate(h, params, body)

	assertCreateDenied(t, w, http.StatusServiceUnavailable)
	if eng.writeCalls != 0 {
		t.Fatalf("WriteStream called %d times after a failed allow audit; want 0", eng.writeCalls)
	}
	if store.putCalls != 0 {
		t.Fatalf("Put called after an audit-down deny; want 0")
	}
	// An audit-down verdict carries NO x-deny-reason (the truth header only ever
	// accompanies a recorded truth).
	if w.Header().Get(denywire.DenyReasonHeader) != "" {
		t.Fatalf("audit-down verdict carries x-deny-reason %q, want none", w.Header().Get(denywire.DenyReasonHeader))
	}
	if !sess.balanced() {
		t.Fatalf("audit-down gauge unbalanced")
	}
}

// ---------------------------------------------------------------------------
// Cases 3 & 4 — EXACT-BYTE over/under declaration.
// ---------------------------------------------------------------------------

// TestCreateOverDeclarationAbortsNoObject pins that a body LONGER than the
// declared size aborts size_exceeded (400) and stages nothing (the engine did
// not commit).
func TestCreateOverDeclarationAbortsNoObject(t *testing.T) {
	h, eng, store, sess := createSetup()
	// declared 4, body 8: over-declaration.
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": 4})
	w := doCreate(h, params, []byte("ABCDEFGH"))

	assertCreateDenied(t, w, http.StatusBadRequest)
	if w.Header().Get(denywire.DenyReasonHeader) != "" {
		// size_exceeded is invalid_argument (no header gating), so no x-deny-reason.
		t.Fatalf("size deny carries x-deny-reason %q, want none", w.Header().Get(denywire.DenyReasonHeader))
	}
	if eng.committed != 0 {
		t.Fatalf("engine committed %d writes on over-declaration; want 0 (aborted, stages nothing)", eng.committed)
	}
	if _, ok := eng.committedBytes("up.bin"); ok {
		t.Fatalf("an object was staged at up.bin on over-declaration; want none")
	}
	if store.putCalls != 0 {
		t.Fatalf("Put called %d times on an aborted over-declaration; want 0", store.putCalls)
	}
	// Case 12 (deny half): the ceiling gauge balances on the abort path too.
	if !sess.balanced() {
		t.Fatalf("over-declaration gauge unbalanced: bytes %d/%d fd %d/%d",
			sess.acquiredBytes, sess.releasedBytes, sess.fdAcquired, sess.fdReleased)
	}
}

// TestCreateUnderDeclarationAbortsNoObject pins that a body SHORTER than the
// declared size aborts size_exceeded (400) at the closing boundary and stages
// nothing.
func TestCreateUnderDeclarationAbortsNoObject(t *testing.T) {
	h, eng, store, sess := createSetup()
	// declared 8, body 4: under-declaration.
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": 8})
	w := doCreate(h, params, []byte("ABCD"))

	assertCreateDenied(t, w, http.StatusBadRequest)
	if eng.committed != 0 {
		t.Fatalf("engine committed %d writes on under-declaration; want 0", eng.committed)
	}
	if _, ok := eng.committedBytes("up.bin"); ok {
		t.Fatalf("an object was staged at up.bin on under-declaration; want none")
	}
	if store.putCalls != 0 {
		t.Fatalf("Put called on an aborted under-declaration; want 0")
	}
	if !sess.balanced() {
		t.Fatalf("under-declaration gauge unbalanced")
	}
}

// buildTruncatedCreateBody builds a valid multipart body then truncates it at the
// end of the file content, dropping the closing boundary delimiter. The file
// part's read therefore delivers exactly the body bytes and then a NON-EOF
// (unexpected-EOF) read error — the "torn multipart frame, no authoritative end"
// case the create.go:252-265 truncated-body branch must refuse. Because the cut
// is at the end of the content, the delivered byte count equals declared, so the
// over/under-declaration guards (:227 acc>declared and :269 acc!=declared) do NOT
// fire — the abort is decided by the truncated-body branch alone. body must be a
// distinctive byte string that does not also appear in paramsJSON.
func buildTruncatedCreateBody(paramsJSON string, body []byte) (raw []byte, contentType string) {
	full, ct := buildCreateBody(paramsJSON, body)
	idx := bytes.LastIndex(full, body)
	if idx < 0 {
		panic("buildTruncatedCreateBody: body bytes not found in the multipart frame")
	}
	return full[:idx+len(body)], ct
}

// TestCreateTruncatedBodyAbortsNoObject pins the truncated-body abort
// (create.go:252-265): a torn multipart frame that ends after exactly declared
// bytes WITHOUT the closing boundary is a non-EOF read error, which must abort
// the create, stage nothing, and mint no handle — even though the byte count
// equals declared. This is the ONE abort site of the three that had no test: its
// siblings (:227 over-declaration, :269 under-declaration) never fire here
// (acc==declared), so neutering the truncated-body branch — the sentinel at :262
// to io.EOF or the EOF check at :253 to "any error is clean" — would otherwise
// commit the partial frame as a durable handle with the whole suite green.
func TestCreateTruncatedBodyAbortsNoObject(t *testing.T) {
	h, eng, store, sess := createSetup()
	body := []byte("TORNBYTES9") // 10 distinctive bytes; declared == len(body)
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": len(body)})
	raw, ct := buildTruncatedCreateBody(params, body)

	r := httptest.NewRequest(http.MethodPost, "/v1/files", bytes.NewReader(raw))
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// A torn frame is a malformed body (400), stages nothing, mints no handle.
	assertCreateDenied(t, w, http.StatusBadRequest)
	if eng.committed != 0 {
		t.Fatalf("engine committed %d writes on a truncated body; want 0 (torn frame stages nothing)", eng.committed)
	}
	if _, ok := eng.committedBytes("up.bin"); ok {
		t.Fatalf("an object was staged at up.bin on a truncated body; want none")
	}
	if store.putCalls != 0 {
		t.Fatalf("Put called %d times on a truncated body; want 0 (no handle for a torn frame)", store.putCalls)
	}
	if !sess.balanced() {
		t.Fatalf("truncated-body gauge unbalanced")
	}
}

// TestCreateOverDeclarationEarlyAbortBoundsEngineBytes pins the EARLY abort
// (create.go:227, acc > declared) in ISOLATION from the final :269 check. On an
// over-declaration whose very first read already overflows the declared size, the
// abort must fire BEFORE any byte is streamed into the engine, so at most one read
// chunk reaches WriteStream (here: zero). The pre-existing
// TestCreateOverDeclarationAbortsNoObject passes via the :269 guard even with :227
// removed (both yield 400/committed=0/puts=0); this test instead observes
// bytes-reaching-the-engine, so neutering :227 (which lets the whole multi-chunk
// body stream into engine staging before :269 catches the size mismatch) reddens
// it, while the :269 guard alone cannot satisfy it.
func TestCreateOverDeclarationEarlyAbortBoundsEngineBytes(t *testing.T) {
	h, eng, store, _ := createSetup()
	// declared tiny, body many chunks: the first read (createReadChunk) already
	// exceeds declared, so the early abort must fire before any pw.Write.
	body := bytes.Repeat([]byte("X"), 3*createReadChunk)
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": 4})
	w := doCreate(h, params, body)

	assertCreateDenied(t, w, http.StatusBadRequest)
	if eng.bytesRead > createReadChunk {
		t.Fatalf("engine consumed %d bytes on over-declaration; want <= one chunk (%d) — the early abort must fire before streaming the body into staging", eng.bytesRead, createReadChunk)
	}
	if eng.committed != 0 {
		t.Fatalf("engine committed %d writes on over-declaration; want 0", eng.committed)
	}
	if store.putCalls != 0 {
		t.Fatalf("Put called %d times on over-declaration; want 0", store.putCalls)
	}
}

// ---------------------------------------------------------------------------
// Case 5 — declared_size_bytes <= 0.
// ---------------------------------------------------------------------------

// TestCreateNonPositiveDeclaredIs400 pins that declared_size_bytes of 0 or a
// negative value is a 400 malformed with nothing staged.
func TestCreateNonPositiveDeclaredIs400(t *testing.T) {
	for _, declared := range []int64{0, -1, -1024} {
		t.Run("declared", func(t *testing.T) {
			h, eng, store, _ := createSetup()
			params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": declared})
			w := doCreate(h, params, []byte("ABCD"))
			assertCreateDenied(t, w, http.StatusBadRequest)
			if eng.writeCalls != 0 {
				t.Fatalf("declared=%d reached the engine; want 0 writes", declared)
			}
			if store.putCalls != 0 {
				t.Fatalf("declared=%d reached the store; want 0 Puts", declared)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Case 6 — SCOPE_MISMATCH.
// ---------------------------------------------------------------------------

// TestCreateScopeMismatchIs403 pins that a params filesystem_id disagreeing with
// the attested header scope is a 403 permission_denied (NOT the 404 keystone) —
// create mints a new id, so the anti-enumeration keystone does not apply. Nothing
// is staged, and the deny carries the scope_mismatch truth header.
func TestCreateScopeMismatchIs403(t *testing.T) {
	h, eng, store, _ := createSetup()
	params := createParamsJSON(t, map[string]any{
		"filesystem_id":       "fs-other", // disagrees with the attested fs-x
		"path":                "/up.bin",
		"declared_size_bytes": 4,
	})
	w := doCreate(h, params, []byte("ABCD"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a scope mismatch (never 404)", w.Code)
	}
	if w.Code == http.StatusNotFound {
		t.Fatal("scope mismatch returned 404; a create mismatch is a 403, not the keystone")
	}
	if w.Header().Get(denywire.DenyReasonHeader) != denyclass.ScopeMismatch {
		t.Fatalf("x-deny-reason = %q, want %q", w.Header().Get(denywire.DenyReasonHeader), denyclass.ScopeMismatch)
	}
	if eng.writeCalls != 0 || store.putCalls != 0 {
		t.Fatalf("scope mismatch touched the engine/store (writes=%d puts=%d); want 0/0", eng.writeCalls, store.putCalls)
	}
}

// TestCreateEmptyFilesystemIDAllowed pins that an OMITTED params filesystem_id is
// allowed (the attested header is authority): the create succeeds on the header
// scope.
func TestCreateEmptyFilesystemIDAllowed(t *testing.T) {
	h, _, store, _ := createSetup()
	body := []byte("ABCD")
	// No filesystem_id key at all — the header scope decides.
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": len(body)})
	w := doCreate(h, params, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (omitted filesystem_id -> header is authority); body %s", w.Code, w.Body.String())
	}
	if store.lastPut.Scope != createTestScope {
		t.Fatalf("Put scope = %q, want the attested header scope %q", store.lastPut.Scope, createTestScope)
	}
}

// ---------------------------------------------------------------------------
// Case 7 — PRE-ASSEMBLY CEILING.
// ---------------------------------------------------------------------------

// TestCreatePreAssemblyCeilingRejectEngineUntouched pins SEC-46: a
// declared_size_bytes strictly greater than MaxFileSize is refused BEFORE any
// file byte / engine write (size_exceeded, 400). The engine is never touched and
// the gauge balances.
func TestCreatePreAssemblyCeilingRejectEngineUntouched(t *testing.T) {
	eng := newCreateEngine()
	store := newCreateStore()
	sess := &countingSession{}
	h := newTestHandler(Deps{
		Engine:      eng,
		Store:       store,
		Ceilings:    &countingCeilings{sess: sess},
		Resolver:    &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:       &fakeGuard{},
		MaxFileSize: 4, // tiny whole-object ceiling
		Scope: fakeScope{ps: southface.PeerScope{
			FilesystemID: createTestScope, GrantedIntents: []southface.Intent{southface.IntentRead},
		}, ok: true},
	})
	// declared 1000 > MaxFileSize 4: pre-assembly reject.
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": 1000})
	w := doCreate(h, params, []byte("ABCDEFGH"))

	assertCreateDenied(t, w, http.StatusBadRequest)
	if eng.writeCalls != 0 {
		t.Fatalf("WriteStream called %d times before the pre-assembly size reject; want 0", eng.writeCalls)
	}
	if store.putCalls != 0 {
		t.Fatalf("Put called on a pre-assembly size reject; want 0")
	}
	if !sess.balanced() {
		t.Fatalf("pre-assembly-reject gauge unbalanced")
	}
}

// TestCreateAtCeilingAdmitted pins the strict-`>` boundary: declared == MaxFileSize
// is ADMITTED (at-ceiling is allowed, only strictly-greater is refused).
func TestCreateAtCeilingAdmitted(t *testing.T) {
	eng := newCreateEngine()
	store := newCreateStore()
	body := []byte("ABCD") // exactly 4 bytes
	h := newTestHandler(Deps{
		Engine:      eng,
		Store:       store,
		Resolver:    &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:       &fakeGuard{},
		MaxFileSize: int64(len(body)), // ceiling == declared
		Scope: fakeScope{ps: southface.PeerScope{
			FilesystemID: createTestScope, GrantedIntents: []southface.Intent{southface.IntentRead},
		}, ok: true},
	})
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": len(body)})
	w := doCreate(h, params, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (declared == ceiling is admitted); body %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Case 8 — STRICT DECODE / transport shape.
// ---------------------------------------------------------------------------

// TestCreateUnknownParamsFieldIs400 pins the strict decoder: a params JSON with
// an UNKNOWN field is a 400 malformed with nothing staged.
func TestCreateUnknownParamsFieldIs400(t *testing.T) {
	h, eng, store, _ := createSetup()
	params := createParamsJSON(t, map[string]any{
		"path": "/up.bin", "declared_size_bytes": 4, "bogus_field": 7,
	})
	w := doCreate(h, params, []byte("ABCD"))
	assertCreateDenied(t, w, http.StatusBadRequest)
	if eng.writeCalls != 0 || store.putCalls != 0 {
		t.Fatalf("unknown params field reached engine/store; want 0/0")
	}
}

// TestCreateBadParamsJSONIs400 pins that a params part that is not valid JSON is
// a 400 malformed.
func TestCreateBadParamsJSONIs400(t *testing.T) {
	h, _, _, _ := createSetup()
	w := doCreate(h, `{"path":`, []byte("ABCD")) // truncated JSON
	assertCreateDenied(t, w, http.StatusBadRequest)
}

// TestCreateTrailingParamsJSONIs400 pins the single-value enforcement: a params
// part with a TRAILING second JSON value is a 400 malformed.
func TestCreateTrailingParamsJSONIs400(t *testing.T) {
	h, _, _, _ := createSetup()
	w := doCreate(h, `{"path":"/a","declared_size_bytes":4} {"extra":1}`, []byte("ABCD"))
	assertCreateDenied(t, w, http.StatusBadRequest)
}

// TestCreateWrongFirstFieldNameIs400 pins that a first part whose form-field name
// is NOT "params" is a 400 malformed.
func TestCreateWrongFirstFieldNameIs400(t *testing.T) {
	h, eng, _, _ := createSetup()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("not_params", `{"path":"/a","declared_size_bytes":4}`)
	fw, _ := mw.CreateFormFile(createFileField, "upload")
	_, _ = fw.Write([]byte("ABCD"))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/v1/files", bytes.NewReader(buf.Bytes()))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertCreateDenied(t, w, http.StatusBadRequest)
	if eng.writeCalls != 0 {
		t.Fatalf("wrong first field name reached the engine; want 0 writes")
	}
}

// TestCreateWrongSecondFieldNameIs400 pins that a second part whose name is not
// "file" is a 400 malformed.
func TestCreateWrongSecondFieldNameIs400(t *testing.T) {
	h, eng, _, _ := createSetup()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField(createParamsField, `{"path":"/a","declared_size_bytes":4}`)
	fw, _ := mw.CreateFormFile("not_file", "upload")
	_, _ = fw.Write([]byte("ABCD"))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/v1/files", bytes.NewReader(buf.Bytes()))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertCreateDenied(t, w, http.StatusBadRequest)
	if eng.writeCalls != 0 {
		t.Fatalf("wrong second field name reached the engine; want 0 writes")
	}
}

// TestCreateNonMultipartIs400 pins that a non-multipart body (application/json
// Content-Type) is a 400 malformed before any part is read.
func TestCreateNonMultipartIs400(t *testing.T) {
	h, eng, store, _ := createSetup()
	r := httptest.NewRequest(http.MethodPost, "/v1/files", strings.NewReader(`{"path":"/a"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertCreateDenied(t, w, http.StatusBadRequest)
	if eng.writeCalls != 0 || store.putCalls != 0 {
		t.Fatalf("non-multipart body reached engine/store; want 0/0")
	}
}

// TestCreateMissingFilePartIs400 pins that a body with the params field but NO
// file part is a 400 malformed (the second NextPart fails).
func TestCreateMissingFilePartIs400(t *testing.T) {
	h, eng, _, _ := createSetup()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField(createParamsField, `{"path":"/a","declared_size_bytes":4}`)
	_ = mw.Close() // no file part
	r := httptest.NewRequest(http.MethodPost, "/v1/files", bytes.NewReader(buf.Bytes()))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertCreateDenied(t, w, http.StatusBadRequest)
	if eng.writeCalls != 0 {
		t.Fatalf("missing file part reached the engine; want 0 writes")
	}
}

// TestCreateUnsafePathIs400 pins the wire-boundary path obligation
// (canonicalizeCreatePath): a NUL byte, a URL-shaped backend address, and the
// bare scope root are each a 400 malformed with nothing staged. These are refused
// BEFORE the resolver / engine. (A ".." over-climb is NOT in this set: it is
// ABSORBED into an in-scope path, not rejected — see TestCreateTraversalAbsorbed.)
func TestCreateUnsafePathIs400(t *testing.T) {
	for _, p := range []string{
		"s3://bucket/key", // URL-shaped backend address smuggled through path
		"http://x/y",      // another URL scheme
		"/ok\x00.bin",     // NUL byte
		"/",               // bare scope root (a create must name an object)
		"",                // empty path -> root
	} {
		t.Run(p, func(t *testing.T) {
			h, eng, store, _ := createSetup()
			params := createParamsJSON(t, map[string]any{"path": p, "declared_size_bytes": 4})
			w := doCreate(h, params, []byte("ABCD"))
			assertCreateDenied(t, w, http.StatusBadRequest)
			if eng.writeCalls != 0 || store.putCalls != 0 {
				t.Fatalf("unsafe path %q reached engine/store (writes=%d puts=%d); want 0/0", p, eng.writeCalls, store.putCalls)
			}
		})
	}
}

// TestCreateTraversalAbsorbed pins the containment contract (mirrors the south
// canonicalizePath): a ".." that would climb above the scope root is ABSORBED by
// anchoring at "/" — "/../escape" and "/a/../../escape" both collapse to the
// in-scope "escape", so the canonical form NEVER names an object outside the
// scope. The create SUCCEEDS at the contained in-scope path (containment, not
// rejection), and the stored ObjectRef is the clamped in-scope path — proof the
// escape never left the scope.
func TestCreateTraversalAbsorbed(t *testing.T) {
	for _, tc := range []struct {
		wire    string
		wantRef string
	}{
		{"/../escape", "escape"},       // over-climb absorbed at the root
		{"../escape", "escape"},        // rootless over-climb absorbed
		{"/a/../../escape", "escape"},  // deeper over-climb absorbed
		{"/pub/../secret", "secret"},   // sibling, in-scope after Clean
		{"/dir/../x/y.bin", "x/y.bin"}, // interior traversal cleaned in-scope
	} {
		t.Run(tc.wire, func(t *testing.T) {
			h, _, store, _ := createSetup()
			params := createParamsJSON(t, map[string]any{"path": tc.wire, "declared_size_bytes": 4})
			w := doCreate(h, params, []byte("ABCD"))
			if w.Code != http.StatusCreated {
				t.Fatalf("wire=%q status = %d, want 201 (traversal absorbed in-scope); body %s", tc.wire, w.Code, w.Body.String())
			}
			// The stored ObjectRef is the clamped in-scope path — it NEVER carries a
			// residual "/../" segment and NEVER escapes the scope root.
			if store.lastPut.ObjectRef != tc.wantRef {
				t.Fatalf("wire=%q ObjectRef = %q, want the absorbed in-scope %q", tc.wire, store.lastPut.ObjectRef, tc.wantRef)
			}
			if strings.Contains(store.lastPut.ObjectRef, "..") {
				t.Fatalf("wire=%q ObjectRef %q still carries a traversal segment (escape)", tc.wire, store.lastPut.ObjectRef)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Case 9 — RESOLVER DENY.
// ---------------------------------------------------------------------------

// TestCreateResolverIntentDeniedIs403 pins that a Resolver intent-denied maps to
// 403 permission_denied with the engine untouched and nothing Put.
func TestCreateResolverIntentDeniedIs403(t *testing.T) {
	eng := newCreateEngine()
	store := newCreateStore()
	h := newTestHandler(Deps{
		Engine:   eng,
		Store:    store,
		Resolver: &fakeResolver{err: southface.ErrIntentDenied},
		Guard:    &fakeGuard{},
		Scope: fakeScope{ps: southface.PeerScope{
			FilesystemID: createTestScope, GrantedIntents: []southface.Intent{southface.IntentRead},
		}, ok: true},
	})
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": 4})
	w := doCreate(h, params, []byte("ABCD"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an intent-denied resolver", w.Code)
	}
	if w.Header().Get(denywire.DenyReasonHeader) != denyclass.IntentDenied {
		t.Fatalf("x-deny-reason = %q, want %q", w.Header().Get(denywire.DenyReasonHeader), denyclass.IntentDenied)
	}
	if eng.writeCalls != 0 || store.putCalls != 0 {
		t.Fatalf("resolver deny touched engine/store; want 0/0")
	}
}

// TestCreateResolverScopeMismatchIs403 pins that a Resolver scope-mismatch (the
// broker-side re-derivation, distinct from the body-hint cross-check) also maps
// to 403 with the engine untouched.
func TestCreateResolverScopeMismatchIs403(t *testing.T) {
	eng := newCreateEngine()
	store := newCreateStore()
	h := newTestHandler(Deps{
		Engine:   eng,
		Store:    store,
		Resolver: &fakeResolver{err: southface.ErrScopeMismatch},
		Guard:    &fakeGuard{},
		Scope: fakeScope{ps: southface.PeerScope{
			FilesystemID: createTestScope, GrantedIntents: []southface.Intent{southface.IntentRead},
		}, ok: true},
	})
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": 4})
	w := doCreate(h, params, []byte("ABCD"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a resolver scope-mismatch", w.Code)
	}
	if eng.writeCalls != 0 {
		t.Fatalf("resolver scope-mismatch reached the engine; want 0 writes")
	}
}

// ---------------------------------------------------------------------------
// Case 10 — ALREADY_EXISTS.
// ---------------------------------------------------------------------------

// TestCreateAlreadyExistsIs409 pins that a WriteStream returning the
// already-exists sentinel (overwrite_existing=false against an existing object)
// is a 409 already_exists, and nothing is Put.
func TestCreateAlreadyExistsIs409(t *testing.T) {
	h, eng, store, sess := createSetup()
	eng.alreadyExist = true // create-new onto an existing object
	params := createParamsJSON(t, map[string]any{
		"path": "/exists.bin", "declared_size_bytes": 4, // overwrite_existing omitted -> false
	})
	w := doCreate(h, params, []byte("ABCD"))

	assertCreateDenied(t, w, http.StatusConflict)
	if store.putCalls != 0 {
		t.Fatalf("Put called on an already-exists refusal; want 0")
	}
	if eng.committed != 0 {
		t.Fatalf("engine committed on an already-exists refusal; want 0")
	}
	if !sess.balanced() {
		t.Fatalf("already-exists gauge unbalanced")
	}
}

// TestCreateMissingParentIs404 pins the north create 4xx classifier: an engine
// WriteStream that fails with fs.ErrNotExist (the client named a path whose
// parent directory does not exist) is a client-attributable 404 not_found, NOT
// an internal 500. Before the classifier fix this mis-mapped to Internal. It
// mirrors the south spine (fs.ErrNotExist -> not_found). Keystone: neuter the
// fs.ErrNotExist case in denyClassForEngineErr and this reds to 500.
func TestCreateMissingParentIs404(t *testing.T) {
	h, eng, store, sess := createSetup()
	eng.writeErr = fs.ErrNotExist // engine refuses: parent directory missing
	body := []byte("ABCD")
	params := createParamsJSON(t, map[string]any{
		"path": "/no-such-dir/child.bin", "declared_size_bytes": len(body),
	})
	w := doCreate(h, params, body)

	assertCreateDenied(t, w, http.StatusNotFound)
	if store.putCalls != 0 {
		t.Fatalf("Put called on a missing-parent refusal; want 0")
	}
	if eng.committed != 0 {
		t.Fatalf("engine committed on a missing-parent refusal; want 0")
	}
	if !sess.balanced() {
		t.Fatalf("missing-parent gauge unbalanced")
	}
}

// TestCreateOverwriteTrueStreamsNormally pins that overwrite_existing=true
// streams normally even when the engine would otherwise refuse already-exists:
// the write commits and 201 is returned.
func TestCreateOverwriteTrueStreamsNormally(t *testing.T) {
	h, eng, store, _ := createSetup()
	eng.alreadyExist = true // would refuse a create-new...
	body := []byte("FRESH")
	params := createParamsJSON(t, map[string]any{
		"path": "/exists.bin", "declared_size_bytes": len(body), "overwrite_existing": true,
	})
	w := doCreate(h, params, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (overwrite_existing=true streams normally); body %s", w.Code, w.Body.String())
	}
	if store.putCalls != 1 {
		t.Fatalf("Put called %d times on an overwrite; want 1", store.putCalls)
	}
	got, ok := eng.committedBytes("exists.bin")
	if !ok || !bytes.Equal(got, body) {
		t.Fatalf("overwrite stored %q (%v), want %q", got, ok, body)
	}
}

// ---------------------------------------------------------------------------
// Case 11 — STORE PUT FAILURE (after durable bytes).
// ---------------------------------------------------------------------------

// TestCreateStoreUnavailableIs503 pins that when the bytes write fine but Put
// returns ErrStoreUnavailable the handler surfaces a 503 (retryable store latch),
// NOT a client deny. The engine committed (the bytes are durable).
func TestCreateStoreUnavailableIs503(t *testing.T) {
	h, eng, store, _ := createSetup()
	store.putErr = handlestore.ErrStoreUnavailable
	body := []byte("ABCD")
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": len(body)})
	w := doCreate(h, params, body)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for a latched store after durable write; body %s", w.Code, w.Body.String())
	}
	// The bytes ARE durable — the store fault is surfaced, not a rolled-back write.
	if eng.committed != 1 {
		t.Fatalf("engine committed %d writes; want 1 (bytes durable before the store fault)", eng.committed)
	}
}

// TestCreateStoreGenericErrorIs500 pins that a generic (non-latch) store error
// after the durable write fails closed to 500 internal.
func TestCreateStoreGenericErrorIs500(t *testing.T) {
	h, eng, store, _ := createSetup()
	store.putErr = handlestore.ErrNotFound // any non-ErrStoreUnavailable store error
	body := []byte("ABCD")
	params := createParamsJSON(t, map[string]any{"path": "/up.bin", "declared_size_bytes": len(body)})
	w := doCreate(h, params, body)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a generic store error after durable write; body %s", w.Code, w.Body.String())
	}
	if eng.committed != 1 {
		t.Fatalf("engine committed %d writes; want 1 (bytes durable before the store fault)", eng.committed)
	}
}

// ---------------------------------------------------------------------------
// Case: exact-byte contract table (property-style — rapid is not used in this
// package, so a broad table stands in: 201 iff body length == declared, else a
// size deny).
// ---------------------------------------------------------------------------

// TestCreateExactByteContractTable pins the exact-byte contract across a spread
// of (declared, bodyLen) pairs: a 201 iff bodyLen == declared (and both > 0 and
// <= MaxFileSize), otherwise a size_exceeded (400) deny that stages nothing.
func TestCreateExactByteContractTable(t *testing.T) {
	for _, tc := range []struct {
		declared int64
		bodyLen  int
	}{
		{1, 1}, {4, 4}, {8, 8}, {64, 64}, {1024, 1024}, // exact -> 201
		{4, 8}, {8, 4}, {1, 0}, {100, 99}, {99, 100}, {2, 5}, // mismatch -> deny
	} {
		t.Run("", func(t *testing.T) {
			h, eng, store, sess := createSetup()
			body := bytes.Repeat([]byte("Z"), tc.bodyLen)
			params := createParamsJSON(t, map[string]any{"path": "/t.bin", "declared_size_bytes": tc.declared})
			w := doCreate(h, params, body)

			wantOK := tc.declared == int64(tc.bodyLen)
			if wantOK {
				if w.Code != http.StatusCreated {
					t.Fatalf("declared=%d body=%d -> status %d, want 201", tc.declared, tc.bodyLen, w.Code)
				}
				if eng.committed != 1 || store.putCalls != 1 {
					t.Fatalf("declared=%d body=%d committed=%d puts=%d, want 1/1", tc.declared, tc.bodyLen, eng.committed, store.putCalls)
				}
			} else {
				assertCreateDenied(t, w, http.StatusBadRequest)
				if eng.committed != 0 {
					t.Fatalf("declared=%d body=%d committed %d writes; want 0 (mismatch stages nothing)", tc.declared, tc.bodyLen, eng.committed)
				}
				if store.putCalls != 0 {
					t.Fatalf("declared=%d body=%d called Put; want 0", tc.declared, tc.bodyLen)
				}
			}
			if !sess.balanced() {
				t.Fatalf("declared=%d body=%d gauge unbalanced", tc.declared, tc.bodyLen)
			}
		})
	}
}
