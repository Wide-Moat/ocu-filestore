// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

// The north Files-API create/content/archive verbs are exercised throughout
// this package against a fakeEngine. That leaves ONE thing unproven: that the
// handler drives a REAL storage engine correctly end to end. A panicking or
// mis-wired real engine would compose and pass every fake-engine test in the
// suite. This file closes that gap: it wires the REAL s3 objectstore engine
// (via the same broker.NewEngine adapter the daemon uses in production,
// main.go:1349) UNDER a real filesapi.Handler with a real durable DiskStore,
// then drives the north verbs across an actual HTTP listener and asserts the
// bytes both round-trip AND land in the real MinIO bucket (independent S3
// client). Neither a no-op engine nor a mock backend can pass both halves.
//
// Gated on OCU_S3_TEST_ENDPOINT exactly as the cmd/ composed-daemon live leg:
// absent the rig it loud-skips, so `go test ./...` without MinIO still passes.
// It runs live in the e2e-s3 CI job which boots deploy/docker-compose.test.yml.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"archive/zip"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/Wide-Moat/ocu-filestore/internal/broker"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

const (
	// reScope is the host-attested filesystem_id the real-engine leg binds to.
	reScope = "fs-real-engine-01"
	// reGuestPath is the upload path. It is a leaf directly under the scope root
	// (no intermediate directory) so the write needs no prior makeDirectory — the
	// s3 engine's WriteStream refuses a write whose parent directory does not
	// exist, and the scope root always exists after ProvisionScope. The content
	// read reaches the engine because the resolver grants Downloadable at read.
	reGuestPath = "/golden.bin"
)

// reRealS3Engine builds the REAL s3 objectstore engine against the live MinIO
// rig and wraps it as a southface.Engine with the SAME broker.NewEngine adapter
// the daemon uses. It provisions reScope so writes have a scope root, and
// registers a teardown. Returns the wrapped engine.
func reRealS3Engine(t *testing.T, endpoint, bucket, access, secret string) southface.Engine {
	t.Helper()
	eng, err := objectstore.NewS3Engine(objectstore.S3Config{
		Endpoint:     endpoint,
		Region:       "us-east-1",
		Bucket:       bucket,
		UsePathStyle: true,
		Credentials:  awscreds.NewStaticCredentialsProvider(access, secret, ""),
	})
	if err != nil {
		t.Fatalf("NewS3Engine: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := eng.ProvisionScope(ctx, objectstore.ScopeID(reScope)); err != nil {
		t.Fatalf("ProvisionScope(%s): %v", reScope, err)
	}
	t.Cleanup(func() {
		tctx, tcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer tcancel()
		_ = eng.TeardownScope(tctx, objectstore.ScopeID(reScope))
	})
	return broker.NewEngine(eng)
}

// reHandler builds a real-engine, real-store Files-API handler bound to reScope.
// Only the storage Engine and durable Store are real; the authz/audit/ceilings
// seams are the package fakes (this leg proves the ENGINE wiring, not the authz
// resolver — that has its own property tests). The resolver grants Downloadable
// so the content read reaches the engine.
func reHandler(t *testing.T, engine southface.Engine) *Handler {
	t.Helper()
	store, err := handlestore.NewDiskStore(t.TempDir() + "/handles.jsonl")
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}
	h, err := NewHandler(Deps{
		Resolver:    &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:       &fakeGuard{},
		Engine:      engine,
		Ceilings:    newFakeCeilings(),
		Store:       store,
		Scope:       fakeScope{ps: southface.PeerScope{FilesystemID: reScope, GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
		SizeCeiling: 1 << 20,
		MaxFileSize: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// reMinioClient is the INDEPENDENT S3 observer — a second reader of the same
// backend, NOT the handler's path.
func reMinioClient(endpoint, access, secret string) *awss3.Client {
	return awss3.New(awss3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
		Credentials:  awscreds.NewStaticCredentialsProvider(access, secret, ""),
	})
}

// reCreate drives POST /v1/files as a real multipart upload against srv and
// returns the minted file_id.
func reCreate(t *testing.T, srv *httptest.Server, guestPath string, payload []byte) string {
	t.Helper()
	params := map[string]any{
		"path":                guestPath,
		"declared_size_bytes": len(payload),
		"media_type":          "application/octet-stream",
		"filename":            "golden.bin",
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal create params: %v", err)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField(createParamsField, string(paramsJSON)); err != nil {
		t.Fatalf("write params field: %v", err)
	}
	fw, err := mw.CreateFormFile(createFileField, "upload")
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/files", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("new create request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("create do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status = %d, want 201; body %s", resp.StatusCode, b)
	}
	var fo struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fo); err != nil {
		t.Fatalf("decode create FileObject: %v", err)
	}
	if fo.ID == "" {
		t.Fatal("create returned an empty file_id")
	}
	return fo.ID
}

// TestFilesAPIRealS3EngineRoundTrip is the load-bearing real-engine leg: a north
// create writes through the real s3 engine to MinIO, a north content read returns
// the EXACT bytes back through the real engine, an independent S3 client reads the
// SAME object from the real bucket, and a north archive bundles the same bytes.
func TestFilesAPIRealS3EngineRoundTrip(t *testing.T) {
	endpoint := os.Getenv("OCU_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("OCU_S3_TEST_ENDPOINT not set - filesapi real-engine leg SKIPPED (boot deploy/docker-compose.test.yml)")
	}
	bucket := os.Getenv("OCU_S3_TEST_BUCKET")
	if bucket == "" {
		bucket = "ocu-conformance"
	}
	access := os.Getenv("OCU_S3_TEST_ACCESS_KEY")
	secret := os.Getenv("OCU_S3_TEST_SECRET_KEY")

	engine := reRealS3Engine(t, endpoint, bucket, access, secret)
	h := reHandler(t, engine)
	srv := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	t.Cleanup(srv.Close)

	const guestPath = reGuestPath
	payload := []byte("ABCDEFGH\x00\x01\x02 binary-safe filesapi real-engine payload")

	// CREATE — north multipart upload through the real engine into MinIO.
	fileID := reCreate(t, srv, guestPath, payload)

	// CONTENT — north read returns the EXACT bytes back through the real engine.
	cresp, err := srv.Client().Get(srv.URL + "/v1/files/" + fileID + "/content")
	if err != nil {
		t.Fatalf("content GET: %v", err)
	}
	defer cresp.Body.Close()
	if cresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(cresp.Body)
		t.Fatalf("content status = %d, want 200; body %s", cresp.StatusCode, b)
	}
	if ct := cresp.Header.Get("Content-Type"); ct != contentTypeOctetStream {
		t.Errorf("content Content-Type = %q, want %q", ct, contentTypeOctetStream)
	}
	gotContent, err := io.ReadAll(cresp.Body)
	if err != nil {
		t.Fatalf("read content body: %v", err)
	}
	if !bytes.Equal(gotContent, payload) {
		t.Fatalf("content bytes = %q, want the uploaded payload %q", gotContent, payload)
	}

	// INDEPENDENT backend assertion: read the SAME object straight from MinIO.
	// The s3 engine keys objects under "<scope>/<clean-path>"; the guest path is
	// rooted at "/", so the key is "<reScope>/pub/golden.bin".
	wantKey := reScope + guestPath
	mc := reMinioClient(endpoint, access, secret)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	obj, err := mc.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(wantKey),
	})
	if err != nil {
		t.Fatalf("independent MinIO GetObject %q: %v", wantKey, err)
	}
	defer obj.Body.Close()
	inBucket, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatalf("read MinIO object %q: %v", wantKey, err)
	}
	if !bytes.Equal(inBucket, payload) {
		t.Fatalf("MinIO object %q bytes = %q, want the uploaded payload %q (the handler write must land in the real bucket)",
			wantKey, inBucket, payload)
	}

	// ARCHIVE — north zip bundle of the same file streams the real bytes back.
	aresp, err := srv.Client().Get(srv.URL + "/v1/files/archive?file_id=" + fileID)
	if err != nil {
		t.Fatalf("archive GET: %v", err)
	}
	defer aresp.Body.Close()
	if aresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(aresp.Body)
		t.Fatalf("archive status = %d, want 200; body %s", aresp.StatusCode, b)
	}
	zipBytes, err := io.ReadAll(aresp.Body)
	if err != nil {
		t.Fatalf("read archive body: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("open archive zip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("archive has %d entries, want 1", len(zr.File))
	}
	zf, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open zip entry: %v", err)
	}
	defer zf.Close()
	entryBytes, err := io.ReadAll(zf)
	if err != nil {
		t.Fatalf("read zip entry: %v", err)
	}
	if !bytes.Equal(entryBytes, payload) {
		t.Fatalf("archive entry bytes = %q, want the uploaded payload %q", entryBytes, payload)
	}
}

// reHandlerSubtree is reHandler with a configured CreateSubtree — the north
// landing join (ADR-0029). It proves the create ensures the join-subtree parent
// marker before the write, so the real s3 engine's parentExists precondition is
// satisfied and the object lands under the subtree instead of 404ing.
func reHandlerSubtree(t *testing.T, engine southface.Engine, subtree string) *Handler {
	t.Helper()
	store, err := handlestore.NewDiskStore(t.TempDir() + "/handles.jsonl")
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}
	h, err := NewHandler(Deps{
		Resolver:      &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:         &fakeGuard{},
		Engine:        engine,
		Ceilings:      newFakeCeilings(),
		Store:         store,
		CreateSubtree: subtree,
		Scope:         fakeScope{ps: southface.PeerScope{FilesystemID: reScope, GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
		SizeCeiling:   1 << 20,
		MaxFileSize:   1 << 20,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// TestFilesAPIRealS3EngineEnsuresJoinSubtree is the LIVE keystone for the
// ADR-0029 fix: with CreateSubtree="uploads", a flat File-Pane upload
// ("/report.txt") joins to the engine key "uploads/report.txt". The real s3
// engine's WriteStream refuses a write whose parent dir marker is absent
// (parentExists -> fs.ErrNotExist), so WITHOUT the create's EnsureDir this 404s
// — the exact live-MinIO bug. The 201 plus the independent MinIO read of
// "<scope>/uploads/report.txt" proves the parent marker was materialised before
// the write against the REAL engine (the in-memory fakes cannot). Gated on
// OCU_S3_TEST_ENDPOINT exactly as the round-trip leg; the dev-lead runs it
// against the composed MinIO rig.
func TestFilesAPIRealS3EngineEnsuresJoinSubtree(t *testing.T) {
	endpoint := os.Getenv("OCU_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("OCU_S3_TEST_ENDPOINT not set - filesapi real-engine join-subtree leg SKIPPED (boot deploy/docker-compose.test.yml)")
	}
	bucket := os.Getenv("OCU_S3_TEST_BUCKET")
	if bucket == "" {
		bucket = "ocu-conformance"
	}
	access := os.Getenv("OCU_S3_TEST_ACCESS_KEY")
	secret := os.Getenv("OCU_S3_TEST_SECRET_KEY")

	engine := reRealS3Engine(t, endpoint, bucket, access, secret)
	h := reHandlerSubtree(t, engine, "uploads")
	srv := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	t.Cleanup(srv.Close)

	payload := []byte("JOIN-SUBTREE binary-safe \x00\x01\x02 payload")

	// CREATE — flat wire path; the join lands it under "uploads/". A 201 proves the
	// EnsureDir materialised the "uploads/" marker before the real engine WriteStream
	// (which would otherwise 404 on the absent parent).
	fileID := reCreate(t, srv, "/report.txt", payload)

	// INDEPENDENT backend assertion: the object lands at "<scope>/uploads/report.txt"
	// in the REAL bucket, not at the scope root — the join reached the engine and the
	// parent marker let the write commit.
	wantKey := reScope + "/uploads/report.txt"
	mc := reMinioClient(endpoint, access, secret)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	obj, err := mc.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(wantKey),
	})
	if err != nil {
		t.Fatalf("independent MinIO GetObject %q: %v (the join-subtree parent was not ensured before the write)", wantKey, err)
	}
	defer obj.Body.Close()
	inBucket, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatalf("read MinIO object %q: %v", wantKey, err)
	}
	if !bytes.Equal(inBucket, payload) {
		t.Fatalf("MinIO object %q bytes = %q, want %q", wantKey, inBucket, payload)
	}

	// The content read round-trips the same bytes through the joined handle.
	cresp, err := srv.Client().Get(srv.URL + "/v1/files/" + fileID + "/content")
	if err != nil {
		t.Fatalf("content GET: %v", err)
	}
	defer cresp.Body.Close()
	if cresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(cresp.Body)
		t.Fatalf("content status = %d, want 200; body %s", cresp.StatusCode, b)
	}
	gotContent, err := io.ReadAll(cresp.Body)
	if err != nil {
		t.Fatalf("read content body: %v", err)
	}
	if !bytes.Equal(gotContent, payload) {
		t.Fatalf("content bytes = %q, want the uploaded payload %q", gotContent, payload)
	}
}
