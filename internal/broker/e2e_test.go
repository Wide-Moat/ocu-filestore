// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker_test

// This file is the release-gating live e2e slice: it drives the REAL built
// ocu-filestored daemon over its production TLS HTTPS/HTTP-2 REST listener —
// no mocks, no unix socket, no hand-rolled frame codec. The CI e2e job builds
// the binary (CGO_ENABLED=0 go build -trimpath -o ocu-filestored
// ./cmd/ocu-filestored) and runs `go test -run 'Integration|E2E' ./...` with
// OCU_BROKER_BIN pointing at it. Locally, set OCU_BROKER_BIN to the built
// binary; absent, every live test loud-skips so `go test ./...` without the
// binary does not fail. The localhost-TLS transport needs no Docker, so the
// non-vacuous file-op flow runs anywhere the binary is built.
//
// The transport is the shipped south-face REST wire: POST
// /v1/filestore/fs/<op> over HTTPS, an edge-injected Authorization: Bearer the
// daemon's CredentialScopeExtractor binds to the configured -filesystem-id,
// unary application/json bodies, a multipart/form-data fileUpload (params field
// + file part), and a chunked application/octet-stream fileDownload of the raw
// object bytes. The test generates a throwaway self-signed loopback certificate,
// hands it to the daemon via -tls-cert/-tls-key, and points an http.Client at
// the TLS listener trusting that one certificate.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// restBase is the REST route base every south-face op hangs off (POST
	// restBase+<op>). It is the frozen wire route the shipped sibling client
	// speaks; the daemon serves the production router at this prefix.
	restBase = "/v1/filestore/fs/"

	// multipartParamsField / multipartFileField / multipartFileFilename are the
	// fileUpload multipart shape: a form FIELD "params" carrying the upload-params
	// JSON, then a file PART "file" (filename "upload") streaming the raw bytes.
	multipartParamsField   = "params"
	multipartFileField     = "file"
	multipartFileFilename  = "upload"
	contentTypeJSON        = "application/json"
	contentTypeOctetStream = "application/octet-stream"

	// e2eScope is the filesystem_id the daemon binds the test's edge-injected
	// bearer to (the -filesystem-id flag). Every in-scope request carries this
	// value at the top level; a different value is a foreign scope (403).
	e2eScope = "fs-e2e-01"

	// e2eBearer is the opaque edge-injected credential the live client presents
	// on Authorization: Bearer. The daemon's interim CredentialScopeExtractor
	// binds any PRESENT bearer to the configured -filesystem-id; its exact bytes
	// are immaterial (the service JWKS-verifies nothing — inv3).
	e2eBearer = "edge-injected-credential-token"

	// downloadablePrefix is configured downloadable so the read path (readFile,
	// fileDownload) reaches the engine: downloadable resolves at read from the
	// broker-side prefix grant, never stamped at write (NFR-SEC-73).
	downloadablePrefix = "/pub"
)

// brokerBin returns the daemon binary path from OCU_BROKER_BIN (default
// ./ocu-filestored relative to the repo root when run from CI). A live test
// loud-skips when the binary is absent so a standard `go test ./...` without
// the binary passes.
func brokerBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("OCU_BROKER_BIN")
	if bin == "" {
		bin = "./ocu-filestored"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("OCU_BROKER_BIN not found (%v); set it to the built ocu-filestored to run the live e2e slice", err)
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatalf("abs(%q): %v", bin, err)
	}
	return abs
}

// daemon is a launched broker process serving one TLS REST listener.
type daemon struct {
	cmd        *exec.Cmd
	baseURL    string
	httpClient *http.Client
	engineRoot string
	auditSink  string
	stderr     *bytes.Buffer
	// waitErr carries the single result of the lone cmd.Wait() reaping the
	// process. A goroutine started right after cmd.Start() owns the wait and
	// sends exactly once; the readiness probe reads it to detect a
	// crash-on-startup deterministically, and stop() drains it so the process
	// is reaped exactly once (a second Wait() is an error).
	waitErr chan error
}

// generateLoopbackCert mints a fresh self-signed loopback certificate + key,
// writes them to two PEM files under dir, and returns their paths plus a
// *x509.CertPool trusting the certificate. The south-face TLS transport
// requires a real cert+key, so the live slice mints an ephemeral one rather
// than depend on an on-disk fixture, and the client trusts exactly that one
// certificate (no InsecureSkipVerify).
func generateLoopbackCert(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-filestore-e2e"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
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
	certFile = filepath.Join(dir, "tls-cert.pem")
	keyFile = filepath.Join(dir, "tls-key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: the minted certificate did not load into the trust pool")
	}
	return certFile, keyFile, pool
}

// freeLoopbackAddr returns a currently-free loopback host:port for the south
// face to bind. There is a small race between the probe close and the rebind,
// acceptable in a single-process test.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// startDaemon launches the real binary over a fresh loopback TLS REST listener
// and waits for the listener to answer before returning. The caller's t.Cleanup
// stops the process. The returned daemon carries an http.Client that trusts the
// daemon's own certificate and dials its bind address.
func startDaemon(t *testing.T) *daemon {
	t.Helper()
	bin := brokerBin(t)

	root, err := os.MkdirTemp("", "e2e")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	engineRoot := filepath.Join(root, "engine")
	auditSink := filepath.Join(root, "audit.jsonl")
	certFile, keyFile, pool := generateLoopbackCert(t, root)
	bindAddr := freeLoopbackAddr(t)

	args := []string{
		"-engine", "local-volume",
		"-engine-root", engineRoot,
		"-audit-sink", auditSink,
		"-south-bind", bindAddr,
		"-tls-cert", certFile,
		"-tls-key", keyFile,
		"-profile", "trusted_operator",
		"-tenancy", "single-tenant",
		"-broker-max-file-size", fmt.Sprintf("%d", 1<<20),
		"-filesystem-id", e2eScope,
		"-granted-intents", "read,write",
		"-downloadable-prefixes", downloadablePrefix,
		// The ops listener is unused here; an empty value disables it so two
		// concurrent live cases never collide on the default 127.0.0.1:9464.
		"-ops-listen", "",
	}

	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		Timeout: 10 * time.Second,
	}

	d := &daemon{
		cmd:        cmd,
		baseURL:    "https://" + bindAddr,
		httpClient: client,
		engineRoot: engineRoot,
		auditSink:  auditSink,
		stderr:     &stderr,
		waitErr:    make(chan error, 1),
	}
	// Own the single cmd.Wait() in a goroutine started immediately after Start.
	// This is the lone reaper for the process: it makes a crash-on-startup
	// observable on d.waitErr (the old d.cmd.ProcessState check was dead code —
	// ProcessState stays nil until Wait() returns, so an early exit could never
	// be seen and the probe just spun to the deadline). stop() drains the same
	// channel, so the process is waited on exactly once.
	go func() { d.waitErr <- cmd.Wait() }()
	t.Cleanup(func() { d.stop() })

	// Wait for the TLS listener to answer. The daemon binds after admission +
	// engine construction + scope provision; an unknown-op POST returns a
	// well-formed 404 once the router is serving (any HTTP answer proves the
	// listener is up). A daemon that exits before binding fails loudly and
	// deterministically the moment the reaper goroutine reports the exit.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case werr := <-d.waitErr:
			// Re-send so stop()'s drain still has a value and never blocks.
			d.waitErr <- werr
			t.Fatalf("daemon exited before serving (%v); stderr:\n%s", werr, stderr.String())
		default:
		}
		req, _ := http.NewRequest(http.MethodPost, d.baseURL+restBase+"noSuchProbe", strings.NewReader("{}"))
		req.Header.Set("Content-Type", contentTypeJSON)
		req.Header.Set("Authorization", "Bearer "+e2eBearer)
		resp, derr := client.Do(req)
		if derr == nil {
			resp.Body.Close()
			return d
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("daemon did not serve %q within the deadline; stderr:\n%s", d.baseURL, stderr.String())
	return nil
}

func (d *daemon) stop() {
	if d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
		// Drain the lone reaper rather than calling Wait() again (a second
		// Wait() is an error). The buffered send from the goroutine — or the
		// re-send the probe loop performed on early exit — guarantees a value
		// is available, so the process is reaped exactly once with no race.
		<-d.waitErr
	}
}

// authMeta builds an authorization_metadata object for a request body. The
// downloadable flag is NEVER trusted at read — the broker re-derives it from
// its own resolved prefix grant (NFR-SEC-73) — so its value here is immaterial.
func authMeta(intent string) map[string]any {
	return map[string]any{"intent": intent, "downloadable": false}
}

// postJSON sends a unary application/json POST for op with the live bearer and
// returns the response for the caller to assert.
func (d *daemon) postJSON(t *testing.T, op string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s body: %v", op, err)
	}
	req, err := http.NewRequest(http.MethodPost, d.baseURL+restBase+op, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new %s request: %v", op, err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set("Authorization", "Bearer "+e2eBearer)
	resp, err := d.httpClient.Do(req)
	if err != nil {
		t.Fatalf("%s do: %v", op, err)
	}
	return resp
}

// uploadMultipart drives fileUpload as a real multipart/form-data POST: a
// "params" form field carrying the upload-params JSON, then a "file" form file
// streaming the raw payload bytes. It returns the response.
func (d *daemon) uploadMultipart(t *testing.T, params map[string]any, payload []byte) *http.Response {
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
	req, err := http.NewRequest(http.MethodPost, d.baseURL+restBase+"fileUpload", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("new fileUpload request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+e2eBearer)
	resp, err := d.httpClient.Do(req)
	if err != nil {
		t.Fatalf("fileUpload do: %v", err)
	}
	return resp
}

// listEntry is the listDirectory entry-union the test reads back: exactly one
// of file or directory is set. The test reads the file branch's path + uuid.
type listEntry struct {
	File *struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
		UUID string `json:"uuid"`
	} `json:"file"`
	Directory *struct {
		Path string `json:"path"`
	} `json:"directory"`
}

// listDirectory lists dir and returns its decoded entries. A non-200 fails the
// test (the listing is a read the in-scope credential is granted).
func (d *daemon) listDirectory(t *testing.T, dir string) []listEntry {
	t.Helper()
	resp := d.postJSON(t, "listDirectory", map[string]any{
		"filesystem_id":          e2eScope,
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
	return ld.Entries
}

// listingContains reports whether the listing of dir contains a file at the
// given guest path, returning its minted uuid when found.
func (d *daemon) listingContains(t *testing.T, dir, guestPath string) (uuid string, found bool) {
	t.Helper()
	for _, e := range d.listDirectory(t, dir) {
		if e.File != nil && e.File.Path == guestPath {
			return e.File.UUID, true
		}
	}
	return "", false
}

// download drives fileDownload over HTTPS for a uuid-addressed object and
// returns the raw streamed bytes. It asserts the success Content-Type is the
// chunked application/octet-stream the wire pins (A2-octet).
func (d *daemon) download(t *testing.T, uuid string) []byte {
	t.Helper()
	resp := d.postJSON(t, "fileDownload", map[string]any{
		"filesystem_id":          e2eScope,
		"uuid":                   uuid,
		"authorization_metadata": map[string]any{"intent": "read", "downloadable": true},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("fileDownload status = %d, want 200; body %s", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); ct != contentTypeOctetStream {
		t.Errorf("fileDownload Content-Type = %q, want %q", ct, contentTypeOctetStream)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read fileDownload body: %v", err)
	}
	return got
}

// TestE2ELifecycleOverTLS drives the full non-vacuous file-op lifecycle against
// the REAL daemon over its production TLS REST listener: makeDirectory ->
// fileUpload -> readFile + listDirectory show the object -> fileDownload returns
// the EXACT uploaded bytes -> removeFile -> listDirectory no longer shows it. It
// asserts the VISIBLE results at every step (the bytes round-trip, the listing
// reflects each mutation), so a no-op transport could not pass it.
func TestE2ELifecycleOverTLS(t *testing.T) {
	d := startDaemon(t)

	// makeDirectory /pub. POSIX mkdir semantics require the parent to exist
	// before writing a file into a sub-path; the scope root is ready after
	// provision, /pub must be created explicitly.
	mk := d.postJSON(t, "makeDirectory", map[string]any{
		"filesystem_id":          e2eScope,
		"path":                   downloadablePrefix,
		"authorization_metadata": authMeta("write"),
	})
	mk.Body.Close()
	if mk.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory %s status = %d, want 200", downloadablePrefix, mk.StatusCode)
	}

	// fileUpload /pub/golden.bin = a known, binary-safe payload.
	const guestPath = downloadablePrefix + "/golden.bin"
	payload := []byte("ABCDEFGH\x00\x01\x02 binary-safe e2e payload")
	up := d.uploadMultipart(t, map[string]any{
		"filesystem_id":          e2eScope,
		"path":                   guestPath,
		"declared_size_bytes":    len(payload),
		"authorization_metadata": authMeta("write"),
	}, payload)
	up.Body.Close()
	if up.StatusCode != http.StatusOK {
		t.Fatalf("fileUpload %s status = %d, want 200; stderr:\n%s", guestPath, up.StatusCode, d.stderr.String())
	}

	// readFile (unary) shows the object with the uploaded size. readFile is
	// metadata-only (no content/data/bytes); the bytes come from fileDownload.
	rf := d.postJSON(t, "readFile", map[string]any{
		"filesystem_id":          e2eScope,
		"path":                   guestPath,
		"authorization_metadata": authMeta("read"),
	})
	if rf.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(rf.Body)
		rf.Body.Close()
		t.Fatalf("readFile %s status = %d, want 200; body %s", guestPath, rf.StatusCode, b)
	}
	var rfBody struct {
		File struct {
			Path string `json:"path"`
			Size int64  `json:"size"`
		} `json:"file"`
	}
	if err := json.NewDecoder(rf.Body).Decode(&rfBody); err != nil {
		rf.Body.Close()
		t.Fatalf("decode readFile: %v", err)
	}
	rf.Body.Close()
	if rfBody.File.Path != guestPath || rfBody.File.Size != int64(len(payload)) {
		t.Fatalf("readFile metadata = %+v, want path %s size %d", rfBody.File, guestPath, len(payload))
	}

	// listDirectory shows the uploaded file; capture the minted uuid for the
	// uuid-addressed download.
	uuid, found := d.listingContains(t, downloadablePrefix, guestPath)
	if !found {
		t.Fatalf("listDirectory of %s does not contain %s after upload", downloadablePrefix, guestPath)
	}
	if uuid == "" {
		t.Fatal("listDirectory entry for the uploaded file carries no minted uuid")
	}

	// fileDownload returns the EXACT uploaded bytes — the load-bearing
	// round-trip assertion (a no-op transport cannot reproduce these bytes).
	got := d.download(t, uuid)
	if !bytes.Equal(got, payload) {
		t.Fatalf("fileDownload bytes = %q, want the uploaded payload %q", got, payload)
	}

	// removeFile mutates the namespace; the listing must reflect it.
	rm := d.postJSON(t, "removeFile", map[string]any{
		"filesystem_id":          e2eScope,
		"path":                   guestPath,
		"authorization_metadata": authMeta("write"),
	})
	rm.Body.Close()
	if rm.StatusCode != http.StatusOK {
		t.Fatalf("removeFile %s status = %d, want 200", guestPath, rm.StatusCode)
	}

	// listDirectory no longer shows the removed file — the mutation is visible.
	if _, stillThere := d.listingContains(t, downloadablePrefix, guestPath); stillThere {
		t.Fatalf("listDirectory of %s still contains %s after removeFile", downloadablePrefix, guestPath)
	}
}

// TestE2EForeignScopeDeny pins the channel-scope cross-check over the real TLS
// REST wire (NFR-SEC-43): a request whose top-level filesystem_id differs from
// the credential-bound scope is denied permission_denied 403 — the broker
// re-derives the scope from the edge-injected bearer and refuses a body that
// disagrees. The deny carries the BoundedReason {reason_code, message} body.
func TestE2EForeignScopeDeny(t *testing.T) {
	d := startDaemon(t)

	resp := d.postJSON(t, "listDirectory", map[string]any{
		"filesystem_id":          "fs-attacker",
		"path":                   downloadablePrefix,
		"authorization_metadata": authMeta("read"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("foreign filesystem_id status = %d, want 403; body %s", resp.StatusCode, b)
	}
	var br struct {
		ReasonCode string `json:"reason_code"`
		Message    string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		t.Fatalf("decode deny BoundedReason: %v", err)
	}
	if br.ReasonCode == "" {
		t.Error("403 deny carries no reason_code in the BoundedReason body")
	}
}

// TestE2EMissingBearerDeny pins the credential gate over the real wire: a
// request with NO Authorization: Bearer is rejected 401 before any session
// state — the edge owns weak-JWT validation, but an ABSENT credential the
// service cannot attribute is unauthenticated (NFR-SEC-82 / inv3).
func TestE2EMissingBearerDeny(t *testing.T) {
	d := startDaemon(t)

	raw, _ := json.Marshal(map[string]any{
		"filesystem_id":          e2eScope,
		"path":                   downloadablePrefix,
		"authorization_metadata": authMeta("read"),
	})
	req, err := http.NewRequest(http.MethodPost, d.baseURL+restBase+"listDirectory", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	// Deliberately no Authorization header.
	resp, err := d.httpClient.Do(req)
	if err != nil {
		t.Fatalf("listDirectory (no bearer) do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("missing-bearer status = %d, want 401; body %s", resp.StatusCode, b)
	}
}
