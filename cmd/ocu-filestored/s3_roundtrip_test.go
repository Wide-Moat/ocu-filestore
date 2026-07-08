// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

// In-process south-face round-trip helpers for the composed-daemon live leg.
// TestComposeS3RealEngineServes composes the REAL s3 engine against MinIO and
// serves on a real south-face TLS listener; these helpers drive an actual
// fileUpload -> fileDownload byte-exact round-trip across that listener and then
// read the SAME object straight from MinIO with an independent S3 client. That
// makes the composed daemon's south leg non-vacuous: a Serve() that binds but
// answers nothing, or a mock backend, could reproduce neither half.
//
// The wire literals (route base, multipart field/part names, content types) are
// duplicated here because the production constants are unexported; the daemon
// serves the frozen south-face REST wire and this test presents exactly it.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	// s3RTRestBase is the frozen south-face REST route base (POST base+<op>).
	s3RTRestBase = "/v1/filestore/fs/"

	// The fileUpload multipart shape: a form FIELD "params" carrying the
	// upload-params JSON, then a file PART "file" streaming the raw bytes.
	s3RTParamsField  = "params"
	s3RTFileField    = "file"
	s3RTFileFilename = "upload"
	s3RTContentJSON  = "application/json"
	s3RTContentOctet = "application/octet-stream"
	s3RTBearer       = "edge-injected-credential-token"
	s3RTDownloadDir  = "/pub" // dlPrefixes in validBrokerConfig; read reaches the engine here
)

// s3RTClient is an HTTPS client trusting the composed daemon's ephemeral
// self-signed loopback cert (validBrokerConfig mints one covering 127.0.0.1).
func s3RTClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // ephemeral self-signed test cert
		},
		Timeout: 15 * time.Second,
	}
}

// s3RTWaitReady polls the south listener with an unknown-op POST until it
// answers (any HTTP response proves the router is serving) or the deadline
// passes. The daemon binds after admission + engine construction + scope
// provision, so an immediate request can race the bind.
func s3RTWaitReady(t *testing.T, cl *http.Client, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodPost, baseURL+s3RTRestBase+"noSuchProbe", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", s3RTContentJSON)
		req.Header.Set("Authorization", "Bearer "+s3RTBearer)
		resp, err := cl.Do(req)
		if err == nil {
			resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("south listener never reachable: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// s3RTPostJSON sends a unary application/json south-face POST under the
// edge-injected bearer.
func s3RTPostJSON(t *testing.T, cl *http.Client, baseURL, op string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s body: %v", op, err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+s3RTRestBase+op, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new %s request: %v", op, err)
	}
	req.Header.Set("Content-Type", s3RTContentJSON)
	req.Header.Set("Authorization", "Bearer "+s3RTBearer)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("%s do: %v", op, err)
	}
	return resp
}

// s3RTUpload drives fileUpload as a real multipart/form-data POST.
func s3RTUpload(t *testing.T, cl *http.Client, baseURL string, params map[string]any, payload []byte) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal upload params: %v", err)
	}
	if err := mw.WriteField(s3RTParamsField, string(paramsJSON)); err != nil {
		t.Fatalf("write params field: %v", err)
	}
	fw, err := mw.CreateFormFile(s3RTFileField, s3RTFileFilename)
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+s3RTRestBase+"fileUpload", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("new fileUpload request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+s3RTBearer)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("fileUpload do: %v", err)
	}
	return resp
}

// s3RTListEntry is the listDirectory entry-union: exactly one of file/directory.
type s3RTListEntry struct {
	File *struct {
		Path string `json:"path"`
		UUID string `json:"uuid"`
	} `json:"file"`
}

// s3RTUUIDFor lists dir and returns the minted uuid for the file at guestPath.
func s3RTUUIDFor(t *testing.T, cl *http.Client, baseURL, scope, dir, guestPath string) string {
	t.Helper()
	resp := s3RTPostJSON(t, cl, baseURL, "listDirectory", map[string]any{
		"filesystem_id":          scope,
		"path":                   dir,
		"authorization_metadata": map[string]any{"intent": "read", "downloadable": false},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("listDirectory %q status = %d, want 200; body %s", dir, resp.StatusCode, b)
	}
	var ld struct {
		Entries []s3RTListEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ld); err != nil {
		t.Fatalf("decode listDirectory %q: %v", dir, err)
	}
	for _, e := range ld.Entries {
		if e.File != nil && e.File.Path == guestPath {
			return e.File.UUID
		}
	}
	t.Fatalf("listDirectory of %s does not contain %s after upload", dir, guestPath)
	return ""
}

// s3RTMinioClient builds a direct S3 client against the loopback-published
// MinIO — the INDEPENDENT observer that the broker's write landed in the real
// bucket, NOT the broker's own path.
func s3RTMinioClient(endpoint, access, secret string) *s3.Client {
	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(access, secret, ""),
	})
}

// s3RTRoundTrip drives the load-bearing round-trip against the composed daemon
// serving on baseURL for scope: makeDirectory -> fileUpload -> fileDownload
// byte-exact, then an independent MinIO GetObject of the SAME scope-keyed object
// returns the SAME bytes. A Serve() that answers nothing, or a mock backend,
// fails one half or the other.
func s3RTRoundTrip(t *testing.T, cl *http.Client, baseURL, scope, bucket, endpoint, access, secret string) {
	t.Helper()

	// Under the ADR-0029 default join the write and read axes resolve to DISJOINT
	// subtrees (write->outputs/, read->uploads/), so an agent cannot download the
	// object it just wrote back through the same mount: the session uuid is minted
	// only by read-class ops, which resolve under uploads/, while a write lands
	// under outputs/. The round-trip is therefore TWO independent legs, and that
	// disjointness IS the NFR-SEC-73 split (":ro"-mirage closed by construction).
	mc := s3RTMinioClient(endpoint, access, secret)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// WRITE LEG: fileUpload (intent=write) lands under outputs/. The s3 engine
	// refuses a write whose parent prefix is absent (parentExists -> ErrNotExist),
	// so create the write-subtree root first: makeDirectory "/" (intent=write)
	// joins to "outputs/" and lays down the parent marker. Then upload targets
	// "/golden.bin", which the join prepends to "outputs/golden.bin". The real
	// backend key is "<scope>/outputs/golden.bin"; an independent MinIO GetObject
	// proves the write landed there byte-exact — and NOT under uploads/, so the
	// write axis cannot reach the read-only input.
	mkRoot := s3RTPostJSON(t, cl, baseURL, "makeDirectory", map[string]any{
		"filesystem_id":          scope,
		"path":                   "/",
		"authorization_metadata": map[string]any{"intent": "write", "downloadable": false},
	})
	mkRoot.Body.Close()
	if mkRoot.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory / (write->outputs root) status = %d, want 200", mkRoot.StatusCode)
	}
	const uploadGuestPath = "/golden.bin"
	payload := []byte("ABCDEFGH\x00\x01\x02 binary-safe composed-daemon live payload")
	up := s3RTUpload(t, cl, baseURL, map[string]any{
		"filesystem_id":          scope,
		"path":                   uploadGuestPath,
		"declared_size_bytes":    len(payload),
		"authorization_metadata": map[string]any{"intent": "write", "downloadable": false},
	}, payload)
	up.Body.Close()
	if up.StatusCode != http.StatusOK {
		t.Fatalf("fileUpload %s status = %d, want 200", uploadGuestPath, up.StatusCode)
	}
	outputsKey := scope + "/outputs/golden.bin"
	obj, err := mc.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(outputsKey)})
	if err != nil {
		t.Fatalf("independent MinIO GetObject %q (write must land under outputs/): %v", outputsKey, err)
	}
	inBucket, _ := io.ReadAll(obj.Body)
	obj.Body.Close()
	if !bytes.Equal(inBucket, payload) {
		t.Fatalf("MinIO object %q bytes = %q, want the uploaded payload %q", outputsKey, inBucket, payload)
	}
	// The write did NOT alias into the read-only uploads subtree.
	uploadsAlias := scope + "/uploads/golden.bin"
	if _, err := mc.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(uploadsAlias)}); err == nil {
		t.Fatalf("write aliased into the read-only subtree %q; the :ro split is broken", uploadsAlias)
	}

	// READ/EGRESS LEG: seed an object DIRECTLY under uploads/ with the independent
	// client (the human->sandbox input direction), then drive a read through the
	// composed daemon. The read plane resolves under uploads/ and FINDS it, but the
	// egress gate denies download (403 not_downloadable): uploads/ is not a
	// configured downloadable prefix (dlPrefixes={outputs}), so a human-supplied
	// input is readable in-session yet cannot be pulled out of the sandbox — the
	// exfil-bar. If the split were broken (uploads egress-eligible) this would 200.
	// The s3 engine represents a directory with a 0-byte marker key ("uploads/"),
	// which a read listing checks for existence before walking. Seed both the marker
	// and the object with the independent client (the human->sandbox input arrives
	// out of band; the read plane holds no write lease to create either).
	uploadsMarker := scope + "/uploads/"
	if _, err := mc.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(uploadsMarker), Body: bytes.NewReader(nil),
	}); err != nil {
		t.Fatalf("independent MinIO PutObject %q (uploads dir marker): %v", uploadsMarker, err)
	}
	seedKey := scope + "/uploads/seed.bin"
	seed := []byte("human-supplied input, readable-in-session, NOT egress-eligible")
	if _, err := mc.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(seedKey), Body: bytes.NewReader(seed),
	}); err != nil {
		t.Fatalf("independent MinIO PutObject %q (seed uploads/): %v", seedKey, err)
	}
	// The uuid MUST come from a read-op listing (session-scoped, minted only on the
	// read plane). The read listing of "/" resolves under uploads/ and returns the
	// entry at its SUBTREE-STRIPPED guest path "/seed.bin" — the join is symmetric,
	// the emitter strips the active subtree so the guest can re-address, so match
	// on the stripped form.
	uuid := s3RTUUIDFor(t, cl, baseURL, scope, "/", "/seed.bin")
	dl := s3RTPostJSON(t, cl, baseURL, "fileDownload", map[string]any{
		"filesystem_id":          scope,
		"uuid":                   uuid,
		"authorization_metadata": map[string]any{"intent": "read", "downloadable": true},
	})
	defer dl.Body.Close()
	if dl.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(dl.Body)
		t.Fatalf("fileDownload of an uploads/ input status = %d, want 403 (exfil-bar: uploads is not downloadable); body %s", dl.StatusCode, b)
	}
	if r := dl.Header.Get("x-deny-reason"); r != "not_downloadable" {
		t.Fatalf("fileDownload 403 x-deny-reason = %q, want not_downloadable", r)
	}
}
