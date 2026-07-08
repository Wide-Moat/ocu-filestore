// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package composeit_test

// COMPONENT integration slice for the storage broker (component-04), contract
// v0.2. It is the honest component boundary made live: it brings the broker's
// OWN south face up on TLS (filestore:8444) plus a REAL MinIO backend via the
// component-test compose (deploy/docker-compose.yml + the it overlay), then
// drives ONE real file-op round-trip THROUGH the south-face REST API while
// presenting the edge-injected Authorization: Bearer the live edge would
// inject (the same harness pattern internal/southface and internal/broker use:
// any present bearer binds to the configured -filesystem-id; the service
// JWKS-verifies nothing — inv3). It asserts the uploaded bytes both round-trip
// back through fileDownload AND land in the real MinIO bucket (an independent
// S3 client reads the object the broker wrote), so neither a no-op transport
// nor a mock backend could pass it.
//
// No mocks: no app-edge mock (the test IS the edge-injected-Bearer presenter,
// the honest component-level emulation), no mock object store (the bytes are
// asserted in real MinIO). The whole assembled storage path is Phase 2; this
// slice proves the component in isolation, not the assembled app.
//
// Gating: the slice runs ONLY when OCU_COMPOSE_IT=1 (it builds an image and
// stands up containers). Absent that env, it loud-skips so a plain
// `go test ./...` without Docker still passes — the same env-guard discipline
// the s3 live/conformance leg uses (OCU_S3_TEST_ENDPOINT).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	// restBase is the frozen south-face REST route base (POST restBase+<op>).
	restBase = "/v1/filestore/fs/"

	// multipart shape for fileUpload: a form FIELD "params" carrying the
	// upload-params JSON, then a file PART "file" streaming the raw bytes.
	multipartParamsField  = "params"
	multipartFileField    = "file"
	multipartFileFilename = "upload"

	contentTypeJSON        = "application/json"
	contentTypeOctetStream = "application/octet-stream"

	// itScope is the filesystem_id the broker binds the edge-injected bearer to
	// (the -filesystem-id in the compose). Every in-scope request carries it at
	// the top level; the s3 engine keys objects under "<itScope>/<path>".
	itScope = "fs-component-test"

	// itBearer is the opaque edge-injected credential the harness presents on
	// Authorization: Bearer. Any present bearer binds to itScope; the exact
	// bytes are immaterial (inv3). This is the SAME pattern the live south-face
	// parity test uses — the honest component-level edge emulation.
	itBearer = "edge-injected-credential-token"

	// downloadablePrefix is configured downloadable so the read path reaches the
	// engine (downloadable resolves at read from the prefix grant — NFR-SEC-73).
	downloadablePrefix = "/pub"

	// The two SAN names the south-face leaf cert must cover: the v0.2 pin host
	// and the compose service name. The host client dials 127.0.0.1 but sets
	// ServerName=sanFilestore so TLS verification matches the leaf SAN.
	sanFilestore    = "filestore"
	sanOCUFilestore = "ocu-filestore"

	// Host-published ports the it overlay maps (loopback only).
	southHostAddr = "127.0.0.1:8444"
	minioHostURL  = "http://127.0.0.1:9000"

	// MinIO test-rig credentials / bucket (throwaway values, mirrored in the
	// compose env defaults).
	minioAccessKey = "ocu-test-root"
	minioSecretKey = "ocu-test-secret-key"
	minioBucket    = "ocu-conformance"
)

// composeFiles are the base component compose + the it overlay (published
// loopback ports). Resolved relative to the repo root from this test's CWD.
func composeFiles(t *testing.T) (base, overlay string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	base = filepath.Join(root, "deploy", "docker-compose.yml")
	overlay = filepath.Join(root, "deploy", "docker-compose.it.yml")
	for _, f := range []string{base, overlay} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("compose file %q not found: %v", f, err)
		}
	}
	return base, overlay
}

// requireComposeIT loud-skips unless OCU_COMPOSE_IT=1 (the rig builds an image
// and stands up containers). Same env-guard discipline as the s3 live leg.
func requireComposeIT(t *testing.T) {
	t.Helper()
	if os.Getenv("OCU_COMPOSE_IT") != "1" {
		t.Skip("OCU_COMPOSE_IT != 1 — component compose integration SKIPPED " +
			"(set OCU_COMPOSE_IT=1 with Docker available to bring up filestore+minio and round-trip the south face)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not on PATH (%v); cannot run the component compose slice", err)
	}
}

// generateSouthCert mints a throwaway self-signed leaf whose SAN covers BOTH
// `filestore` and `ocu-filestore` (the two names the broker is reachable as on
// ocu-edge-backend) plus loopback (the host client dials 127.0.0.1). It writes
// tls-cert.pem + tls-key.pem into dir and returns a CertPool trusting the leaf.
// The broker mounts dir read-only at /etc/ocu-filestore/tls.
func generateSouthCert(t *testing.T, dir string) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-filestore-component-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{sanFilestore, sanOCUFilestore, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// 0644 so the container's nonroot uid (65532) can read the bind-mounted
	// cert; the matching key is the throwaway server key, never a real secret.
	if err := os.WriteFile(filepath.Join(dir, "tls-cert.pem"), certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls-key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: the minted leaf did not load into the trust pool")
	}
	return pool
}

// composeUp brings the base+overlay stack up (build the broker image, wait for
// both healthchecks) with the cert dir and the test-rig env wired. It registers
// a t.Cleanup that tears the stack down with volumes. project isolates this
// run's containers/network/volumes from any other compose stack.
func composeUp(t *testing.T, certDir string) {
	t.Helper()
	base, overlay := composeFiles(t)
	const project = "ocu-filestore-it"

	// Drive compose from the repo root with repo-root-relative -f paths —
	// EXACTLY the documented invocation (`docker compose -f deploy/... up`).
	// The compose file's relative paths (build.context "..", the seccomp
	// "./deploy/seccomp/...") are authored against that repo-root CWD; running
	// from anywhere else mis-resolves one or the other.
	repoRoot := filepath.Dir(filepath.Dir(base))
	baseRel := filepath.Join("deploy", filepath.Base(base))
	overlayRel := filepath.Join("deploy", filepath.Base(overlay))

	env := append(os.Environ(),
		"OCU_FILESTORE_TLS_CERT_DIR="+certDir,
		"OCU_S3_TEST_ACCESS_KEY="+minioAccessKey,
		"OCU_S3_TEST_SECRET_KEY="+minioSecretKey,
		"OCU_S3_TEST_BUCKET="+minioBucket,
		"OCU_FILESYSTEM_ID="+itScope,
		"OCU_DOWNLOADABLE_PREFIXES="+downloadablePrefix,
	)

	run := func(timeout time.Duration, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		full := append([]string{
			"compose", "-p", project,
			"-f", baseRel, "-f", overlayRel,
		}, args...)
		cmd := exec.CommandContext(ctx, "docker", full...)
		cmd.Dir = repoRoot
		cmd.Env = env
		return cmd.CombinedOutput()
	}

	t.Cleanup(func() {
		out, err := run(2*time.Minute, "down", "-v", "--remove-orphans")
		if err != nil {
			t.Logf("compose down: %v\n%s", err, out)
		}
	})

	// Build + up + wait for both healthchecks. The build pulls a Go toolchain
	// image on a cold cache, so the timeout is generous.
	out, err := run(10*time.Minute, "up", "-d", "--build", "--wait")
	if err != nil {
		logs, _ := run(1*time.Minute, "logs", "--no-color", "ocu-filestore")
		t.Fatalf("compose up: %v\n--- up output ---\n%s\n--- broker logs ---\n%s", err, out, logs)
	}
}

// southClient is an HTTPS client trusting the throwaway leaf and pinning
// ServerName=filestore so verification matches the SAN even though the dial
// targets the loopback-published 127.0.0.1:8444.
func southClient(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
				ServerName: sanFilestore,
			},
		},
		Timeout: 15 * time.Second,
	}
}

func authMeta(intent string) map[string]any {
	return map[string]any{"intent": intent, "downloadable": false}
}

// postJSON sends a unary application/json POST for op under the edge-injected
// bearer and returns the response.
func postJSON(t *testing.T, cl *http.Client, op string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s body: %v", op, err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+southHostAddr+restBase+op, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new %s request: %v", op, err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set("Authorization", "Bearer "+itBearer)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("%s do: %v", op, err)
	}
	return resp
}

// uploadMultipart drives fileUpload as a real multipart/form-data POST.
func uploadMultipart(t *testing.T, cl *http.Client, params map[string]any, payload []byte) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal upload params: %v", err)
	}
	if err := mw.WriteField(multipartParamsField, string(paramsJSON)); err != nil {
		t.Fatalf("write params field: %v", err)
	}
	fw, err := mw.CreateFormFile(multipartFileField, multipartFileFilename)
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+southHostAddr+restBase+"fileUpload", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("new fileUpload request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+itBearer)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("fileUpload do: %v", err)
	}
	return resp
}

// listEntry is the listDirectory entry-union: exactly one of file/directory.
type listEntry struct {
	File *struct {
		Path string `json:"path"`
		UUID string `json:"uuid"`
	} `json:"file"`
}

// uuidFor lists dir and returns the minted uuid for the file at guestPath.
func uuidFor(t *testing.T, cl *http.Client, dir, guestPath string) string {
	t.Helper()
	resp := postJSON(t, cl, "listDirectory", map[string]any{
		"filesystem_id":          itScope,
		"path":                   dir,
		"authorization_metadata": authMeta("read"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("listDirectory %q status = %d, want 200; body %s", dir, resp.StatusCode, b)
	}
	var ld struct {
		Entries []listEntry `json:"entries"`
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

// minioClient builds a direct S3 client against the loopback-published MinIO,
// for the INDEPENDENT assertion that the broker's write landed in the real
// bucket. It is a second observer of the same backend, NOT the broker's path.
func minioClient() *s3.Client {
	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(minioHostURL),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(minioAccessKey, minioSecretKey, ""),
	})
}

// TestComponentRoundTripOverTLSToMinIO is the load-bearing slice: it stands up
// the broker's TLS south face + real MinIO via the component compose, then
// makeDirectory -> fileUpload -> fileDownload returns the EXACT uploaded bytes,
// AND an independent S3 client reads the SAME bytes back from the real MinIO
// bucket under the broker's scope-keyed object. A no-op transport or a mock
// backend could reproduce neither half.
func TestComponentRoundTripOverTLSToMinIO(t *testing.T) {
	requireComposeIT(t)

	certDir := t.TempDir()
	pool := generateSouthCert(t, certDir)
	composeUp(t, certDir)

	cl := southClient(pool)

	mc := minioClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Under the ADR-0029 default join the write and read axes resolve to disjoint
	// subtrees (write->outputs/, read->uploads/), so the object an agent writes is
	// undownloadable back through the same mount: the session uuid is minted only
	// by read-class ops (which resolve under uploads/), while the write lands under
	// outputs/. The round-trip is TWO independent legs — that disjointness IS the
	// NFR-SEC-73 split.

	// WRITE LEG: makeDirectory /pub (write->outputs/pub, make_parents lays outputs/)
	// then fileUpload /pub/golden.bin (write->outputs/pub/golden.bin). An
	// independent MinIO GetObject proves it landed under outputs/ byte-exact.
	mk := postJSON(t, cl, "makeDirectory", map[string]any{
		"filesystem_id":          itScope,
		"path":                   downloadablePrefix,
		"make_parents":           true,
		"authorization_metadata": authMeta("write"),
	})
	mk.Body.Close()
	if mk.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory %s status = %d, want 200", downloadablePrefix, mk.StatusCode)
	}
	const guestPath = downloadablePrefix + "/golden.bin"
	payload := []byte("ABCDEFGH\x00\x01\x02 binary-safe component-test payload")
	up := uploadMultipart(t, cl, map[string]any{
		"filesystem_id":          itScope,
		"path":                   guestPath,
		"declared_size_bytes":    len(payload),
		"authorization_metadata": authMeta("write"),
	}, payload)
	up.Body.Close()
	if up.StatusCode != http.StatusOK {
		t.Fatalf("fileUpload %s status = %d, want 200", guestPath, up.StatusCode)
	}
	wantKey := itScope + "/outputs" + guestPath // "<itScope>/outputs/pub/golden.bin"
	obj, err := mc.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(minioBucket), Key: aws.String(wantKey)})
	if err != nil {
		t.Fatalf("independent MinIO GetObject %q (write must land under outputs/): %v", wantKey, err)
	}
	inBucket, _ := io.ReadAll(obj.Body)
	obj.Body.Close()
	if !bytes.Equal(inBucket, payload) {
		t.Fatalf("MinIO object %q bytes = %q, want the uploaded payload %q", wantKey, inBucket, payload)
	}

	// READ/EGRESS LEG: seed an object DIRECTLY under uploads/ (the human->sandbox
	// input) with the independent client, read-list finds it, and fileDownload is
	// denied 403 not_downloadable — uploads/ is not a configured downloadable
	// prefix, so a human input is readable-in-session but not egress-eligible (the
	// exfil-bar). Non-vacuous: a broken split would 200.
	if _, err := mc.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(minioBucket), Key: aws.String(itScope + "/uploads/"), Body: bytes.NewReader(nil),
	}); err != nil {
		t.Fatalf("seed uploads dir marker: %v", err)
	}
	seedKey := itScope + "/uploads/seed.bin"
	seed := []byte("human-supplied input, readable-in-session, NOT egress-eligible")
	if _, err := mc.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(minioBucket), Key: aws.String(seedKey), Body: bytes.NewReader(seed),
	}); err != nil {
		t.Fatalf("seed uploads object: %v", err)
	}
	// The read listing of "/" resolves under uploads/ and returns the entry at its
	// SUBTREE-STRIPPED guest path "/seed.bin" (the emitter strips the active subtree
	// so the guest can re-address); the uuid MUST come from that read-op listing.
	uuid := uuidFor(t, cl, "/", "/seed.bin")
	dl := postJSON(t, cl, "fileDownload", map[string]any{
		"filesystem_id":          itScope,
		"uuid":                   uuid,
		"authorization_metadata": map[string]any{"intent": "read", "downloadable": true},
	})
	defer dl.Body.Close()
	if dl.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(dl.Body)
		t.Fatalf("fileDownload of an uploads/ input status = %d, want 403 (exfil-bar); body %s", dl.StatusCode, b)
	}
	if r := dl.Header.Get("x-deny-reason"); r != "not_downloadable" {
		t.Fatalf("fileDownload 403 x-deny-reason = %q, want not_downloadable", r)
	}
}
