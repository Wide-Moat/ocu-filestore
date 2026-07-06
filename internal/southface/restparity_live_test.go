// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
)

// REST parity test — the Wave-0 fixture oracle, promoted to drive the wire
// end-to-end over a real HTTP transport.
//
// Scope of "live" here — read this before counting this file toward any
// object-store coverage claim. "Live" names the TRANSPORT and the ROUTER, not
// the backend: this test crosses an actual HTTP socket (httptest.NewServer)
// through the PRODUCTION REST router and the real authz/ceilings/auditgate
// seams. The engine underneath is fakeEngine — an in-memory tree engine (a
// working implementation with real effects, not scripted returns, see
// engine_fake_test.go), NOT a real object-store backend (S3 / local-volume).
// So this file does NOT exercise a real object-store leg; that coverage lives
// at the engine layer (internal/objectstore, the S3-conformance suite). Do not
// count TestRESTParityLive as a live/composed object-store round-trip — it is a
// live-HTTP wire-parity test over a fake engine.
//
// restparity_fixtures_test.go pins the south-face REST wire as self-consistent
// Go fixtures. This file PROMOTES that oracle: it stands up the PRODUCTION REST
// router (newRESTRouter over a fakeEngine-backed dispatcher with the real
// authz/ceilings/auditgate seams and a credential-scope extractor that binds a
// known filesystem_id) behind an httptest.NewServer, drives EVERY operation
// across an actual HTTP socket, and asserts the emitted wire against the pinned
// oracle. Where the fixtures asserted shapes against themselves, this file
// asserts the SERVER'S emitted bytes against those same shapes — so the server
// is proven to satisfy the contract the shipping sibling client speaks.
//
// Coverage map (every clause is an explicit assertion below):
//   - all 16 unary routes: POST /v1/filestore/fs/<op>, JSON request with
//     filesystem_id top-level + authorization_metadata, the response shapes
//     (10 bare-ack {} ops, the metadata/union ops, readFile metadata-only).
//   - fileUpload multipart: the params/file field set + a 2xx success.
//   - fileDownload octet-stream: uuid-axis request, Range omitempty, the
//     application/octet-stream response Content-Type, raw bytes.
//   - the FULL deny status-only map, each class forced live: foreign
//     filesystem_id -> 403 permission; unknown -> 404 not_found; cross-scope
//     uuid -> 404 anti-enum; already-exists -> 409; bad/oversize -> 400/422
//     invalid; throttle -> 429 (Retry-After when set); audit-down -> 503.
//   - the BoundedReason {reason_code, message} body on every deny: the
//     reason_code matches the open pattern, the body is diagnostic and the HTTP
//     status is authoritative.

// liveFS is the filesystem_id the credential-scope extractor binds the live
// server's bearer to. Every request whose top-level filesystem_id equals this
// value is in-scope; any other value is a foreign scope (403/404 per axis).
const liveFS = "fs-live"

// liveBearer is the opaque edge-injected credential the live client presents on
// Authorization: Bearer. The extractor binds it to liveFS; its exact bytes are
// immaterial (the broker never JWKS-verifies it, A5).
const liveBearer = "edge-injected-credential-token"

// liveServer is the production REST router driven over a real HTTP socket, plus
// the seam fakes a test reaches into to force each deny class.
type liveServer struct {
	srv     *httptest.Server
	disp    *dispatcher
	engine  *fakeEngine
	guard   *fakeGuard
	ceiling *fakeCeilingsSession
}

// newLiveServer stands up the PRODUCTION restRouter over a fakeEngine-backed
// dispatcher wired with the real consumer-side seams (a fakeEngine — an
// in-memory tree engine with real effects, NOT a real object-store backend; an
// allow-by-default resolver granting Downloadable, a recording audit guard, a
// permissive ceilings session) and a CredentialScopeExtractor that binds the
// live bearer to liveFS with read+write intents. The router is served behind an
// httptest.NewServer so every assertion crosses an actual HTTP socket — the
// "live" leg is the HTTP transport, not a live object store.
func newLiveServer(t *testing.T) *liveServer {
	t.Helper()
	eng := newFakeEngine()
	guard := &fakeGuard{}
	sess := &fakeCeilingsSession{}
	reg := &fakeCeilingsRegistry{session: sess}
	// A resolver that grants every request with Downloadable=true so the read
	// path can reach the engine; the deny-class forcing below overrides this per
	// case via the engine/guard/ceilings seams, never via the resolver.
	res := &fakeResolver{grant: Grant{Downloadable: true}}

	d := newDispatcherWithEngine(res, guard, reg, 1<<20, eng)
	// maxFileSize must be positive or every upload fails closed (the unwired
	// dispatcher refuses any non-empty upload). A 1 MiB whole-object ceiling is
	// ample for the small fixtures the upload assertions stream.
	d.maxFileSize = 1 << 20
	// Bind the credential-scope extractor: the live bearer maps to liveFS with
	// the full read+write grant. This is the A5 edge-injected-credential source —
	// with it wired, STAGE 0 derives the scope from Authorization: Bearer, not
	// from a unix peer-cred context. A bearer that is not liveBearer binds to an
	// empty scope, which the extractor treats as a rejection (401).
	d.credExtractor = NewCredentialScopeExtractor(func(bearer string) (CredentialScope, error) {
		if bearer != liveBearer {
			return CredentialScope{}, nil // empty fsid -> rejection (401)
		}
		return CredentialScope{
			FilesystemID:   liveFS,
			GrantedIntents: []Intent{IntentRead, IntentWrite},
			UID:            4242,
			PID:            7,
		}, nil
	})

	srv := httptest.NewServer(newRESTRouter(d))
	t.Cleanup(srv.Close)
	return &liveServer{srv: srv, disp: d, engine: eng, guard: guard, ceiling: sess}
}

// do issues a POST to the live server for op carrying the given body bytes and
// Content-Type, with the live bearer on Authorization. It returns the response
// for the caller to assert status/headers/body against.
func (ls *liveServer) do(t *testing.T, op Op, contentType string, body []byte) *http.Response {
	t.Helper()
	return ls.doWithBearer(t, op, contentType, body, liveBearer)
}

// doWithBearer is do with an explicit bearer, so a test can present a rejected
// credential (401) by sending a bearer the extractor does not bind.
func (ls *liveServer) doWithBearer(t *testing.T, op Op, contentType string, body []byte, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ls.srv.URL+restBase+string(op), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request for %s: %v", op, err)
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set(authHeaderName, bearerScheme+bearer)
	}
	resp, err := ls.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("live %s request: %v", op, err)
	}
	return resp
}

// doJSON issues a unary JSON POST and returns the response.
func (ls *liveServer) doJSON(t *testing.T, op Op, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s body: %v", op, err)
	}
	return ls.do(t, op, string(ctJSON), raw)
}

// drainBody drains and closes a response body, returning its bytes.
func drainBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return b
}

// decodeBodyMap drains a response body and decodes it into a generic map so a
// test can assert the wire's exact key set against the oracle.
func decodeBodyMap(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	b := drainBody(t, resp)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("response body not a JSON object: %v (%q)", err, b)
	}
	return m
}

// TestRESTParityLive drives the production REST server end-to-end and asserts
// its emitted wire against the Wave-0 fixture oracle. It is the live half of the
// parity lock: where TestRESTParityFixtures proves the fixtures self-consistent,
// this proves the SERVER satisfies them across a real socket. "Live" = the HTTP
// socket and the production router; the engine underneath is a fakeEngine, so
// this is NOT a real object-store round-trip (see the file header).
func TestRESTParityLive(t *testing.T) {
	t.Run("unary/route-and-response-shapes", testLiveUnaryRoutesAndShapes)
	t.Run("unary/request-carries-fsid-top-level", testLiveRequestEnvelope)
	t.Run("readFile/response-is-metadata-only", testLiveReadFileMetadataOnly)
	t.Run("fileUpload/multipart-params-field-set-and-success", testLiveUploadMultipart)
	t.Run("fileDownload/octet-stream-uuid-axis", testLiveDownloadOctetStream)
	t.Run("fileDownload/range-omitempty-full-vs-windowed", testLiveDownloadRange)
	t.Run("deny/foreign-fsid-is-403-permission", testLiveDenyForeignScope)
	t.Run("deny/credential-rejected-is-401-permission", testLiveDenyCredentialRejected)
	t.Run("deny/unknown-uuid-is-404-not-found", testLiveDenyUnknownUUID)
	t.Run("deny/cross-scope-uuid-is-404-anti-enum", testLiveDenyCrossScopeUUID)
	t.Run("deny/already-exists-is-409", testLiveDenyAlreadyExists)
	t.Run("deny/malformed-body-is-400-invalid", testLiveDenyMalformedBody)
	t.Run("deny/oversize-body-is-400-invalid", testLiveDenyOversizeBody)
	t.Run("deny/throttle-is-429-retryable", testLiveDenyThrottle)
	t.Run("deny/audit-down-is-503-retryable", testLiveDenyAuditDown)
	t.Run("deny/method-not-post-is-405", testLiveDenyMethod)
	t.Run("deny/unknown-op-is-404", testLiveDenyUnknownOp)
	t.Run("deny/bounded-reason-body-shape", testLiveBoundedReasonShape)
}

// readMetaWire / writeMetaWire build the authorization_metadata sub-object for a
// live request body, in the same shape the oracle pins (intent + downloadable).
func readMetaWire() authzMetaFixture  { return readMeta() }
func writeMetaWire() authzMetaFixture { return writeMeta() }

// liveBodyFor builds a representative in-scope request body for op, in the exact
// pinned request shape for that op's axis (path vs uuid vs src/dst vs fsid-only).
// It is the live-request counterpart to the oracle's request-field-set fixtures.
func liveBodyFor(op Op) any {
	switch op {
	// Path-axis read ops.
	case OpListDirectory:
		return pathReadReq{FilesystemID: liveFS, Path: "/d", AuthorizationMetadata: readMetaWire()}
	case OpReadMetadata:
		return pathReadReq{FilesystemID: liveFS, Path: "/p", AuthorizationMetadata: readMetaWire()}
	case OpReadFile:
		return readFileReq{FilesystemID: liveFS, Path: "/p", AuthorizationMetadata: readMetaWire()}
	// uuid-axis read ops.
	case OpGetFileMetadata, OpListFiles:
		return uuidReadReq{FilesystemID: liveFS, UUID: "u-known", AuthorizationMetadata: readMetaWire()}
	// Path-axis write ops.
	case OpMakeDirectory, OpRemoveDirectory, OpCreateFile, OpImportFiles, OpImportZip, OpRemoveFile:
		return pathWriteReq{FilesystemID: liveFS, Path: "/w", AuthorizationMetadata: writeMetaWire()}
	// src/dst write ops.
	case OpMoveDirectory:
		return srcDstReq{FilesystemID: liveFS, Source: "/a", Destination: "/b", AuthorizationMetadata: writeMetaWire()}
	case OpCopyFile, OpMoveFile:
		return srcDstOverwriteReq{FilesystemID: liveFS, Source: "/a", Destination: "/b", AuthorizationMetadata: writeMetaWire()}
	// fsid-only write ops.
	case OpMigrateFilesystem, OpRemoveFilesystem:
		return fsidOnlyWriteReq{FilesystemID: liveFS, AuthorizationMetadata: writeMetaWire()}
	default:
		return pathWriteReq{FilesystemID: liveFS, Path: "/w", AuthorizationMetadata: writeMetaWire()}
	}
}

// testLiveUnaryRoutesAndShapes drives every UNARY op (the 16 non-data-plane
// routes) over HTTP and asserts the route resolves, the verdict is an
// authoritative HTTP status, and — for the ops whose success body the build
// pins — the body matches the oracle's shape. Ops that are unimplemented in this
// build resolve to a real 501 (the route is exercised; the body is the deferred
// shape), which still proves the route boundary and the deny envelope.
func testLiveUnaryRoutesAndShapes(t *testing.T) {
	ls := newLiveServer(t)
	// Seed the engine so the implemented read/mutation ops reach a success, each
	// op addressing a DISTINCT object so no op consumes a sibling op's target
	// (move/remove are destructive). A directory to list, a file to readFile, a
	// file to remove, a dir to remove, a dir to move, files to copy/move.
	ls.engine.mkdirSeed(liveFS, "d")
	ls.engine.putBytes(liveFS, "p", []byte("hello"))    // readFile target
	ls.engine.putBytes(liveFS, "rmfile", []byte("bye")) // removeFile target
	ls.engine.mkdirSeed(liveFS, "rmdir")                // removeDirectory target
	ls.engine.mkdirSeed(liveFS, "mvdir-src")            // moveDirectory source
	ls.engine.putBytes(liveFS, "cp-src", []byte("c"))   // copyFile source
	ls.engine.putBytes(liveFS, "mv-src", []byte("m"))   // moveFile source

	for _, rf := range routeFixtures {
		op := rf.op
		// The two data-plane ops have dedicated transport classes asserted in
		// their own subtests; this loop covers the 16 unary-JSON ops.
		if op == OpFileUpload || op == OpFileDownload {
			continue
		}
		t.Run(string(op), func(t *testing.T) {
			body := liveBodyForSeeded(op)
			resp := ls.doJSON(t, op, body)
			defer resp.Body.Close()

			// The route resolved to the unary spine: never a 404 (unknown route)
			// and never a 405 (the method is POST). A 2xx is an implemented op; a
			// 501 is an unimplemented-but-routed op. Both prove the route boundary.
			if resp.StatusCode == http.StatusNotFound {
				t.Fatalf("op %s: routed to 404 — the unary route did not resolve", op)
			}
			if resp.StatusCode == http.StatusMethodNotAllowed {
				t.Fatalf("op %s: POST returned 405 — the method gate misfired", op)
			}
			// x-request-id is stamped on every response (allow and deny alike).
			if resp.Header.Get(requestIDHeader) == "" {
				t.Errorf("op %s: response missing %s", op, requestIDHeader)
			}

			switch resp.StatusCode {
			case http.StatusOK:
				assertLiveSuccessShape(t, op, resp)
			case http.StatusNotImplemented:
				// Unimplemented-but-routed: the deny envelope is the BoundedReason
				// REST shape, and the 501 is the authoritative status.
				assertBoundedReasonBody(t, resp)
			default:
				t.Fatalf("op %s: unexpected status %d; body %q", op, resp.StatusCode, drainBody(t, resp))
			}
		})
	}
}

// liveBodyForSeeded specialises liveBodyFor for the seeded engine tree so the
// implemented ops address the objects the test planted (the directory "/d", the
// file "/p", the move/copy source "/a").
func liveBodyForSeeded(op Op) any {
	switch op {
	case OpListDirectory:
		return pathReadReq{FilesystemID: liveFS, Path: "/d", AuthorizationMetadata: readMetaWire()}
	case OpReadMetadata:
		return pathReadReq{FilesystemID: liveFS, Path: "/p", AuthorizationMetadata: readMetaWire()}
	case OpReadFile:
		return readFileReq{FilesystemID: liveFS, Path: "/p", AuthorizationMetadata: readMetaWire()}
	case OpMakeDirectory:
		return pathWriteReq{FilesystemID: liveFS, Path: "/fresh-dir", AuthorizationMetadata: writeMetaWire()}
	case OpRemoveDirectory:
		return pathWriteReq{FilesystemID: liveFS, Path: "/rmdir", AuthorizationMetadata: writeMetaWire()}
	case OpRemoveFile:
		return pathWriteReq{FilesystemID: liveFS, Path: "/rmfile", AuthorizationMetadata: writeMetaWire()}
	case OpMoveDirectory:
		return srcDstReq{FilesystemID: liveFS, Source: "/mvdir-src", Destination: "/mvdir-dst", AuthorizationMetadata: writeMetaWire()}
	case OpCopyFile:
		return srcDstOverwriteReq{FilesystemID: liveFS, Source: "/cp-src", Destination: "/cp-dst", AuthorizationMetadata: writeMetaWire()}
	case OpMoveFile:
		return srcDstOverwriteReq{FilesystemID: liveFS, Source: "/mv-src", Destination: "/mv-dst", AuthorizationMetadata: writeMetaWire()}
	default:
		return liveBodyFor(op)
	}
}

// assertLiveSuccessShape asserts the live 200 body matches the oracle's pinned
// success shape for the ops whose body is pinned in this build: the bare-ack
// ops return {} (or a body the tolerant decoder treats as one), listDirectory
// returns the entry-union list, readFile returns the metadata-only file body.
func assertLiveSuccessShape(t *testing.T, op Op, resp *http.Response) {
	t.Helper()
	// Content-Type for every unary success is application/json.
	if ct := resp.Header.Get("Content-Type"); ct != string(ctJSON) {
		t.Errorf("op %s: success Content-Type = %q, want %q", op, ct, ctJSON)
	}
	body := drainBody(t, resp)

	if isBareAckOp(op) {
		// The bare-ack body is the empty object {} (the oracle's ackFixture).
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("op %s: bare-ack body not a JSON object: %v (%q)", op, err, body)
		}
		if len(m) != 0 {
			t.Errorf("op %s: bare-ack body = %q, want {} (empty object)", op, body)
		}
		return
	}

	switch op {
	case OpListDirectory:
		// The listDirectory success is the entry-union list + opaque cursor. The
		// entries decode into the oracle's union fixture (file XOR directory).
		var got listDirectoryRespFixture
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("listDirectory body does not match the oracle list shape: %v (%q)", err, body)
		}
	case OpReadFile:
		// Asserted in detail by testLiveReadFileMetadataOnly; here just confirm it
		// decodes into the metadata-only shape.
		var got readFileRespFixture
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("readFile body does not match the oracle metadata shape: %v (%q)", err, body)
		}
	case OpReadMetadata:
		// The resolve success is the arm-discriminated {file, directory} union;
		// the seeded /p target resolves to the file arm.
		var got readMetadataRespFixture
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("readMetadata body does not match the oracle resolve shape: %v (%q)", err, body)
		}
	default:
		t.Fatalf("op %s returned 200 but has no pinned success-shape assertion", op)
	}
}

// isBareAckOp reports whether op is one of the ten bare-ack ops the oracle pins.
func isBareAckOp(op Op) bool {
	for _, a := range bareAckOps {
		if a == op {
			return true
		}
	}
	return false
}

// testLiveRequestEnvelope drives an in-scope unary request and proves the server
// accepts the pinned request envelope (filesystem_id top-level, a sibling of
// authorization_metadata) — the in-scope filesystem_id clears the STAGE-1b
// channel-scope cross-check and the request reaches a handler (200, not a 403).
func testLiveRequestEnvelope(t *testing.T) {
	ls := newLiveServer(t)
	ls.engine.mkdirSeed(liveFS, "d")

	// The request body carries filesystem_id at the TOP LEVEL (A4). Marshalling
	// the oracle's pathReadReq proves the field sits beside authorization_metadata
	// rather than nested inside it; the live server then accepts it.
	body := pathReadReq{FilesystemID: liveFS, Path: "/d", AuthorizationMetadata: readMetaWire()}
	raw, _ := json.Marshal(body)
	top := map[string]any{}
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("request body not an object: %v", err)
	}
	if _, ok := top["filesystem_id"]; !ok {
		t.Fatal("request body: filesystem_id is not a top-level field")
	}
	meta, ok := top["authorization_metadata"].(map[string]any)
	if !ok {
		t.Fatal("request body: authorization_metadata missing or not an object")
	}
	if _, nested := meta["filesystem_id"]; nested {
		t.Fatal("request body: filesystem_id is nested inside authorization_metadata")
	}

	resp := ls.do(t, OpListDirectory, string(ctJSON), raw)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("in-scope listDirectory: status = %d, want 200; body %q", resp.StatusCode, drainBody(t, resp))
	}
}

// testLiveReadFileMetadataOnly drives readFile over HTTP and asserts the live
// response is the metadata-only {"file": File} shape with NO content/data/bytes
// field — the SEC-73 metadata-only contract the oracle pins.
func testLiveReadFileMetadataOnly(t *testing.T) {
	ls := newLiveServer(t)
	ls.engine.putBytes(liveFS, "doc.txt", []byte("the quick brown fox"))

	resp := ls.doJSON(t, OpReadFile, readFileReq{
		FilesystemID:          liveFS,
		Path:                  "/doc.txt",
		AuthorizationMetadata: readMetaWire(),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readFile: status = %d, want 200; body %q", resp.StatusCode, drainBody(t, resp))
	}
	top := decodeBodyMap(t, resp)
	assertKeySet(t, top, []string{"file"})
	for _, banned := range []string{"content", "data", "bytes"} {
		if _, ok := top[banned]; ok {
			t.Errorf("readFile response carries forbidden %q field (metadata-only)", banned)
		}
	}
	file, ok := top["file"].(map[string]any)
	if !ok {
		t.Fatalf("readFile response: file is not an object: %v", top["file"])
	}
	for _, banned := range []string{"content", "data", "bytes"} {
		if _, ok := file[banned]; ok {
			t.Errorf("readFile response file carries forbidden %q field (metadata-only)", banned)
		}
	}
	// The metadata names the file the request addressed and carries a minted uuid.
	if file["path"] != "/doc.txt" {
		t.Errorf("readFile file.path = %v, want /doc.txt", file["path"])
	}
	if uuid, _ := file["uuid"].(string); uuid == "" {
		t.Error("readFile response carries no minted uuid")
	}
}

// testLiveUploadMultipart drives fileUpload as a real multipart/form-data POST:
// a "params" form field carrying the upload-params JSON, then a "file" form file
// streaming the raw bytes. It asserts the field set is the oracle's pinned set
// and the server commits a 2xx on a size-matched body.
func testLiveUploadMultipart(t *testing.T) {
	ls := newLiveServer(t)

	payload := []byte("uploaded object bytes")
	params := uploadParamsFixture{
		FilesystemID:          liveFS,
		Path:                  "/uploaded.bin",
		DeclaredSizeBytes:     int64(len(payload)),
		AuthorizationMetadata: writeMetaWire(),
	}
	// The params field set on the wire is exactly the oracle's pinned set for a
	// create-new write (overwrite_existing omitted).
	assertKeySet(t, decodeToMap(t, params), []string{"filesystem_id", "path", "declared_size_bytes", "authorization_metadata"})

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	// Part 1: the "params" form FIELD.
	paramsJSON, _ := json.Marshal(params)
	if err := mw.WriteField(multipartParamsFieldName, string(paramsJSON)); err != nil {
		t.Fatalf("write params field: %v", err)
	}
	// Part 2: the "file" form FILE streaming the raw bytes.
	fw, err := mw.CreateFormFile(multipartFileFieldName, multipartFileFilename)
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	resp := ls.do(t, OpFileUpload, mw.FormDataContentType(), buf.Bytes())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fileUpload multipart: status = %d, want 200; body %q", resp.StatusCode, drainBody(t, resp))
	}
	if resp.Header.Get(requestIDHeader) == "" {
		t.Error("fileUpload response missing x-request-id")
	}
	// The object is now visible in a subsequent listing — the upload took effect.
	infos, err := ls.engine.List(t.Context(), liveFS, ".")
	if err != nil {
		t.Fatalf("post-upload list: %v", err)
	}
	var found bool
	for _, fi := range infos {
		if fi.Name == "uploaded.bin" {
			found = true
		}
	}
	if !found {
		t.Error("uploaded object not visible in a subsequent listing")
	}
}

// mintLiveUUID seeds the engine with a file and mints the broker-held uuid for
// it through the SAME session-scoped objectIDStore the download handler resolves
// through, returning the uuid. It is how a download test obtains a valid handle
// (uuids are minted by a listing/readFile emitter; the test reaches the store
// directly, in-package, to plant one without a prior listing round-trip).
func (ls *liveServer) mintLiveUUID(scope, guestPath string, data []byte) string {
	rel := guestPath
	if len(rel) > 0 && rel[0] == '/' {
		rel = rel[1:]
	}
	ls.engine.putBytes(scope, rel, data)
	return ls.disp.ids.idFor(scope, guestPath)
}

// testLiveDownloadOctetStream drives fileDownload over HTTP and asserts the
// response is a chunked application/octet-stream of the RAW object bytes — no
// JSON envelope, no framing — for a uuid-axis request (A2-octet).
func testLiveDownloadOctetStream(t *testing.T) {
	ls := newLiveServer(t)
	payload := []byte("raw octet stream payload \x00\x01\x02 binary-safe")
	uuid := ls.mintLiveUUID(liveFS, "/obj.bin", payload)

	resp := ls.doJSON(t, OpFileDownload, fileDownloadReq{
		FilesystemID:          liveFS,
		UUID:                  uuid,
		AuthorizationMetadata: readMetaWire(),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fileDownload: status = %d, want 200; body %q", resp.StatusCode, drainBody(t, resp))
	}
	if ct := resp.Header.Get("Content-Type"); ct != string(ctOctetStream) {
		t.Errorf("fileDownload Content-Type = %q, want %q", ct, ctOctetStream)
	}
	got := drainBody(t, resp)
	if !bytes.Equal(got, payload) {
		t.Errorf("fileDownload body = %q, want the raw object bytes %q", got, payload)
	}
}

// testLiveDownloadRange drives fileDownload twice — a full download (range
// omitted) and a windowed download (range present) — and asserts the live server
// honours the *pointer-with-omitempty range discipline the oracle pins: a full
// download omits the range entirely; a windowed download returns exactly the
// requested half-open window.
func testLiveDownloadRange(t *testing.T) {
	ls := newLiveServer(t)
	payload := []byte("0123456789abcdef")
	uuid := ls.mintLiveUUID(liveFS, "/ranged.bin", payload)

	// Full download: the request OMITS the range key (Range is a nil pointer).
	fullReq := fileDownloadReq{FilesystemID: liveFS, UUID: uuid, AuthorizationMetadata: readMetaWire()}
	if _, ok := decodeToMap(t, fullReq)["range"]; ok {
		t.Fatal("full fileDownload request must OMIT the range key")
	}
	full := ls.doJSON(t, OpFileDownload, fullReq)
	if body := drainBody(t, full); !bytes.Equal(body, payload) {
		t.Errorf("full download body = %q, want %q", body, payload)
	}

	// Windowed download: range present (offset 4, length 6) -> "456789".
	winReq := fileDownloadReq{
		FilesystemID:          liveFS,
		UUID:                  uuid,
		Range:                 &rangeFixture{Offset: 4, Length: 6},
		AuthorizationMetadata: readMetaWire(),
	}
	if _, ok := decodeToMap(t, winReq)["range"]; !ok {
		t.Fatal("windowed fileDownload request must carry the range key")
	}
	win := ls.doJSON(t, OpFileDownload, winReq)
	if body := drainBody(t, win); !bytes.Equal(body, []byte("456789")) {
		t.Errorf("windowed download body = %q, want %q", body, "456789")
	}
}

// --- the deny status-only map, each class forced over a live request ---

// assertDenyStatus asserts the live response carries the expected authoritative
// HTTP status, the oracle maps that status to the expected client class, and the
// body is the BoundedReason diagnostic shape. The STATUS is authoritative; the
// body is diagnostic only.
func assertDenyStatus(t *testing.T, resp *http.Response, wantStatus int, wantClass denyClassFixture) {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Fatalf("deny status = %d, want %d; body %q", resp.StatusCode, wantStatus, drainBody(t, resp))
	}
	if got := statusDenyClass(resp.StatusCode); got != wantClass {
		t.Errorf("status %d maps to class %q, want %q", resp.StatusCode, got, wantClass)
	}
	assertBoundedReasonBody(t, resp)
}

// assertBoundedReasonBody asserts the response body is the BoundedReason
// {reason_code, message} diagnostic shape, the reason_code matches the open
// pattern, and the message is within the contract ceiling.
func assertBoundedReasonBody(t *testing.T, resp *http.Response) {
	t.Helper()
	b := drainBody(t, resp)
	var br boundedReason
	if err := json.Unmarshal(b, &br); err != nil {
		t.Fatalf("deny body is not a BoundedReason object: %v (%q)", err, b)
	}
	// Exactly {reason_code, message} on the wire.
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("deny body not an object: %v (%q)", err, b)
	}
	assertKeySet(t, raw, []string{"reason_code", "message"})
	re := regexp.MustCompile(reasonCodePattern)
	if !re.MatchString(br.ReasonCode) {
		t.Errorf("deny reason_code %q does not match the open pattern %q", br.ReasonCode, reasonCodePattern)
	}
	if len(br.Message) > boundedReasonMessageMax {
		t.Errorf("deny message length %d exceeds ceiling %d", len(br.Message), boundedReasonMessageMax)
	}
}

// testLiveDenyForeignScope forces a foreign-filesystem_id deny: a body whose
// top-level filesystem_id is not the credential-bound scope. The STAGE-1b
// channel-scope cross-check refuses it as scope_mismatch -> 403 permission.
func testLiveDenyForeignScope(t *testing.T) {
	ls := newLiveServer(t)
	resp := ls.doJSON(t, OpListDirectory, pathReadReq{
		FilesystemID:          "fs-someone-else",
		Path:                  "/d",
		AuthorizationMetadata: readMetaWire(),
	})
	assertDenyStatus(t, resp, http.StatusForbidden, denyClassPermission)
}

// testLiveDenyCredentialRejected forces a credential rejection: a bearer the
// extractor does not bind to any scope. The broker cannot attribute the request,
// so it is unauthenticated -> 401, which the oracle maps to permission.
func testLiveDenyCredentialRejected(t *testing.T) {
	ls := newLiveServer(t)
	raw, _ := json.Marshal(pathReadReq{FilesystemID: liveFS, Path: "/d", AuthorizationMetadata: readMetaWire()})
	resp := ls.doWithBearer(t, OpListDirectory, string(ctJSON), raw, "not-the-bound-bearer")
	assertDenyStatus(t, resp, http.StatusUnauthorized, denyClassPermission)
}

// testLiveDenyUnknownUUID forces a not_found deny: a fileDownload for a uuid the
// session never minted. An unknown handle is not_found -> 404.
func testLiveDenyUnknownUUID(t *testing.T) {
	ls := newLiveServer(t)
	resp := ls.doJSON(t, OpFileDownload, fileDownloadReq{
		FilesystemID:          liveFS,
		UUID:                  "uuid-never-minted",
		AuthorizationMetadata: readMetaWire(),
	})
	assertDenyStatus(t, resp, http.StatusNotFound, denyClassNotFound)
}

// testLiveDenyCrossScopeUUID forces the anti-enumeration degrade: a uuid that
// resolves to a FOREIGN scope. The audited truth is scope_mismatch, but the WIRE
// degrades to 404 (not_found) so a valid uuid from another session cannot probe
// scope membership. The client-visible status is 404 — the audited truth never
// surfaces on the wire.
func testLiveDenyCrossScopeUUID(t *testing.T) {
	ls := newLiveServer(t)
	// Mint a uuid bound to a DIFFERENT scope than the live credential's, then
	// present it on the live (in-scope) channel. The handler resolves the uuid to
	// a foreign scope and degrades to 404.
	ls.engine.putBytes("fs-other-tenant", "secret.bin", []byte("not yours"))
	foreignUUID := ls.disp.ids.idFor("fs-other-tenant", "/secret.bin")

	resp := ls.doJSON(t, OpFileDownload, fileDownloadReq{
		FilesystemID:          liveFS,
		UUID:                  foreignUUID,
		AuthorizationMetadata: readMetaWire(),
	})
	// The wire is 404 (anti-enum), NOT 403: the degrade hides scope membership.
	assertDenyStatus(t, resp, http.StatusNotFound, denyClassNotFound)
	// And the truth never leaks via the x-deny-reason header (a 404 is header-less).
	if h := resp.Header.Get("x-deny-reason"); h != "" {
		t.Errorf("cross-scope 404 carries x-deny-reason = %q, want none (anti-enum)", h)
	}
}

// testLiveDenyAlreadyExists forces a 409: makeDirectory on a path that already
// exists. The engine EEXIST maps to already_exists -> 409.
func testLiveDenyAlreadyExists(t *testing.T) {
	ls := newLiveServer(t)
	ls.engine.mkdirSeed(liveFS, "existing")
	resp := ls.doJSON(t, OpMakeDirectory, pathWriteReq{
		FilesystemID:          liveFS,
		Path:                  "/existing",
		AuthorizationMetadata: writeMetaWire(),
	})
	assertDenyStatus(t, resp, http.StatusConflict, denyClassAlreadyExists)
}

// testLiveDenyMalformedBody forces a 400: a syntactically broken JSON body. A
// malformed envelope is invalid_argument -> 400 invalid.
func testLiveDenyMalformedBody(t *testing.T) {
	ls := newLiveServer(t)
	resp := ls.do(t, OpListDirectory, string(ctJSON), []byte(`{"filesystem_id":`)) // truncated JSON
	assertDenyStatus(t, resp, http.StatusBadRequest, denyClassInvalid)
}

// testLiveDenyOversizeBody forces a 400: a body whose Content-Length exceeds the
// per-message ceiling. The declared-size pre-buffer rejects it as size_exceeded
// -> invalid_argument -> 400 invalid.
func testLiveDenyOversizeBody(t *testing.T) {
	ls := newLiveServer(t)
	// Shrink the per-message ceiling so a modest body trips it; the body is valid
	// JSON, so the refusal is the SIZE gate, not a decode fault.
	ls.disp.sizeCeiling = 32
	big := pathReadReq{
		FilesystemID:          liveFS,
		Path:                  "/" + makeString(256),
		AuthorizationMetadata: readMetaWire(),
	}
	resp := ls.doJSON(t, OpListDirectory, big)
	assertDenyStatus(t, resp, http.StatusBadRequest, denyClassInvalid)
}

// makeString returns a string of n 'x' bytes, for building an oversize body.
func makeString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}

// testLiveDenyThrottle forces a 429: the ceilings session refuses the op-rate
// consume. A throttle is resource_exhausted -> 429 retryable. It also proves the
// Retry-After header, when set, is a well-formed delta-seconds; the production
// writer leaves it unset (the diagnostic body, not a header, carries the
// retry hint), which is the documented behaviour the oracle notes.
func testLiveDenyThrottle(t *testing.T) {
	ls := newLiveServer(t)
	ls.ceiling.opErr = ErrThrottleExceeded
	resp := ls.doJSON(t, OpListDirectory, pathReadReq{
		FilesystemID:          liveFS,
		Path:                  "/d",
		AuthorizationMetadata: readMetaWire(),
	})
	assertDenyStatus(t, resp, http.StatusTooManyRequests, denyClassRetryable)
	// Retry-After is OPTIONAL on a 429 (oracle: a header behaviour, not a class).
	// If the server sets it, it must be a non-negative delta-seconds integer.
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err != nil || secs < 0 {
			t.Errorf("Retry-After = %q, want a non-negative delta-seconds integer", ra)
		}
	}
}

// testLiveDenyAuditDown forces a 503: the audit guard refuses the pre-ack
// Mandate. An audit-down verdict is unavailable -> 503 retryable, and carries NO
// x-deny-reason (the truth header only accompanies a recorded truth).
func testLiveDenyAuditDown(t *testing.T) {
	ls := newLiveServer(t)
	ls.guard.err = ErrAuditUnavailable
	resp := ls.doJSON(t, OpListDirectory, pathReadReq{
		FilesystemID:          liveFS,
		Path:                  "/d",
		AuthorizationMetadata: readMetaWire(),
	})
	assertDenyStatus(t, resp, http.StatusServiceUnavailable, denyClassRetryable)
	if h := resp.Header.Get("x-deny-reason"); h != "" {
		t.Errorf("audit-down 503 carries x-deny-reason = %q, want none", h)
	}
}

// testLiveDenyMethod forces a 405: a non-POST method to a known op route. The
// router refuses it with Allow: POST and the BoundedReason diagnostic body.
func testLiveDenyMethod(t *testing.T) {
	ls := newLiveServer(t)
	req, _ := http.NewRequest(http.MethodGet, ls.srv.URL+restBase+"readFile", nil)
	req.Header.Set(authHeaderName, bearerScheme+liveBearer)
	resp, err := ls.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET readFile: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET readFile: status = %d, want 405; body %q", resp.StatusCode, drainBody(t, resp))
	}
	if resp.Header.Get("Allow") != http.MethodPost {
		t.Errorf("405 Allow = %q, want POST", resp.Header.Get("Allow"))
	}
	assertBoundedReasonBody(t, resp)
}

// testLiveDenyUnknownOp forces a 404: a path naming an op outside the frozen
// enum. An unknown op is indistinguishable from a missing object
// (anti-enumeration) -> 404 not_found.
func testLiveDenyUnknownOp(t *testing.T) {
	ls := newLiveServer(t)
	req, _ := http.NewRequest(http.MethodPost, ls.srv.URL+restBase+"noSuchOperation", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", string(ctJSON))
	req.Header.Set(authHeaderName, bearerScheme+liveBearer)
	resp, err := ls.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST noSuchOperation: %v", err)
	}
	defer resp.Body.Close()
	assertDenyStatus(t, resp, http.StatusNotFound, denyClassNotFound)
}

// testLiveBoundedReasonShape drives one representative deny over HTTP and asserts
// the BoundedReason body is diagnostic (the reason_code matches the open
// pattern, the message is bounded) while the HTTP STATUS is authoritative — the
// two halves of the A3-deny contract on a real wire.
func testLiveBoundedReasonShape(t *testing.T) {
	ls := newLiveServer(t)
	resp := ls.doJSON(t, OpListDirectory, pathReadReq{
		FilesystemID:          "fs-foreign",
		Path:                  "/d",
		AuthorizationMetadata: readMetaWire(),
	})
	defer resp.Body.Close()
	// Status is authoritative: a foreign scope is 403.
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign-scope status = %d, want 403", resp.StatusCode)
	}
	b := drainBody(t, resp)
	var br boundedReason
	if err := json.Unmarshal(b, &br); err != nil {
		t.Fatalf("deny body not a BoundedReason: %v (%q)", err, b)
	}
	re := regexp.MustCompile(reasonCodePattern)
	if !re.MatchString(br.ReasonCode) {
		t.Errorf("reason_code %q does not match the open pattern", br.ReasonCode)
	}
	// The diagnostic carries a human-readable message; it never drives the client
	// verdict (the status already did).
	if br.Message == "" {
		t.Error("deny BoundedReason carries no diagnostic message")
	}
	// Sanity: the request-id correlation header is present on the deny too.
	if resp.Header.Get(requestIDHeader) == "" {
		t.Error("deny response missing x-request-id")
	}
}
