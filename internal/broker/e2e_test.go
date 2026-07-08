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
	"encoding/base64"
	"encoding/hex"
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
	// broker-side prefix grant, never stamped at write (NFR-SEC-73). It is
	// ENGINE-RELATIVE with no leading slash (ADR-0029 inv-5): both the south and
	// north planes present the engine-relative path to the stored-tag lookup, so
	// the configured prefix must be engine-relative to match.
	downloadablePrefix = "pub"

	// downloadableDir is the GUEST WIRE path form of the downloadable directory
	// (leading slash), used for the makeDirectory/upload/list wire calls. The wire
	// convention is guest leading-slash; the -downloadable-prefixes flag config
	// (downloadablePrefix) is engine-relative — the two are distinct conventions
	// that ADR-0029 reconciles at the stored-tag lookup, not on the wire.
	downloadableDir = "/pub"
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
func startDaemon(t *testing.T, extraArgs ...string) *daemon {
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
	// Per-case extra flags (e.g. the ADR-0029 -subtree-rw/-subtree-ro overrides
	// the mirage probe sets to enable the join). Appended AFTER the base args so a
	// case can add flags the base set does not carry.
	args = append(args, extraArgs...)

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
		"path":                   downloadableDir,
		"authorization_metadata": authMeta("write"),
	})
	mk.Body.Close()
	if mk.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory %s status = %d, want 200", downloadableDir, mk.StatusCode)
	}

	// fileUpload /pub/golden.bin = a known, binary-safe payload.
	const guestPath = downloadableDir + "/golden.bin"
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
	uuid, found := d.listingContains(t, downloadableDir, guestPath)
	if !found {
		t.Fatalf("listDirectory of %s does not contain %s after upload", downloadableDir, guestPath)
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
	if _, stillThere := d.listingContains(t, downloadableDir, guestPath); stillThere {
		t.Fatalf("listDirectory of %s still contains %s after removeFile", downloadableDir, guestPath)
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
		"path":                   downloadableDir,
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
		"path":                   downloadableDir,
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

// mintUnsignedBearer builds an unsigned (alg=none) JWT carrying the given
// filesystem_id and intent claim. Under -claims-bind the daemon's extractor
// parses the edge-validated bearer's claims WITHOUT re-verifying the signature
// (the edge owns weak-JWT validation; the service JWKS-verifies nothing —
// inv3), so an unsigned token stands in for an edge-validated one. A random
// nonce per call keeps two mints distinct.
func mintUnsignedBearer(t *testing.T, fsid, intent, nonce string) string {
	t.Helper()
	b64 := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal jwt part: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := b64(map[string]any{"alg": "none", "typ": "JWT"})
	payload := b64(map[string]any{
		"filesystem_id": fsid,
		"intent":        intent,
		"nonce":         nonce,
	})
	// alg=none: an empty signature segment.
	return header + "." + payload + "."
}

// randomNonce returns a short random hex nonce so two mints in one run differ.
func randomNonce(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// uploadMultipartBearer is uploadMultipart with an explicit Authorization bearer
// (the mirage probe mints an intent-bearing bearer per leg instead of the fixed
// e2eBearer).
func (d *daemon) uploadMultipartBearer(t *testing.T, bearer string, params map[string]any, payload []byte) *http.Response {
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
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := d.httpClient.Do(req)
	if err != nil {
		t.Fatalf("fileUpload do: %v", err)
	}
	return resp
}

// TestE2EMirageSubtreeJoin pins the ADR-0029 inv-10 join LIVE, over the real
// daemon and its on-disk local-volume layout (engineRoot/<scope>/<rel>), with
// two PERMANENT subtests that differ only in whether the join is enabled. It is
// non-vacuous by construction: the SAME write request lands a DISTINCT on-disk
// object depending on the join, so a regression that silently stops (or wrongly
// gains) the join reds one leg or the other.
//
//   - [join-enabled] a write-intent upload addressing "/uploads/x" lands the
//     DISTINCT object "outputs/uploads/x" (the RW subtree is prepended); the RO
//     "uploads/x" seeded out-of-band is byte-UNCHANGED — the read-only subtree is
//     structurally unreachable for writing (the ":ro" mirage is closed by
//     construction).
//   - [join-disabled] the SAME upload CLOBBERS the flat "uploads/x" the RO view
//     reads — the pre-fix mirage, pinned live so leg 1 can never be vacuous.
func TestE2EMirageSubtreeJoin(t *testing.T) {
	nonceA := randomNonce(t)
	nonceB := randomNonce(t)
	if nonceA == nonceB {
		t.Fatal("nonces collided; the distinct-object witness would be vacuous")
	}

	t.Run("join_enabled_write_lands_under_outputs_ro_unreachable", func(t *testing.T) {
		d := startDaemon(t,
			"-claims-bind",
			"-subtree-rw", "outputs",
			"-subtree-ro", "uploads",
			"-subtree-preview", "uploads",
		)
		scopeDir := filepath.Join(d.engineRoot, e2eScope)

		// Seed the RO object out-of-band via the engine LAYOUT (stands in for a
		// pane upload landed under uploads/, seeded through the layout not the
		// credential under test).
		if err := os.MkdirAll(filepath.Join(scopeDir, "uploads"), 0o700); err != nil {
			t.Fatalf("seed uploads dir: %v", err)
		}
		roPath := filepath.Join(scopeDir, "uploads", "x")
		if err := os.WriteFile(roPath, []byte(nonceA), 0o600); err != nil {
			t.Fatalf("seed RO object: %v", err)
		}
		// Seed the write target's parent dir (the local engine refuses a missing
		// parent on commit); the object itself is written by the request under test.
		if err := os.MkdirAll(filepath.Join(scopeDir, "outputs", "uploads"), 0o700); err != nil {
			t.Fatalf("seed outputs/uploads dir: %v", err)
		}

		// The write-intent upload addressing "/uploads/x".
		writeBearer := mintUnsignedBearer(t, e2eScope, "write", nonceB)
		resp := d.uploadMultipartBearer(t, writeBearer, map[string]any{
			"filesystem_id":          e2eScope,
			"path":                   "/uploads/x",
			"declared_size_bytes":    len(nonceB),
			"authorization_metadata": authMeta("write"),
		}, []byte(nonceB))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// The write MUST land (a deny here would fake-green the next assert).
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("join-enabled write status = %d, want 200; body %s", resp.StatusCode, body)
		}

		// The DISTINCT joined object exists with the write bytes.
		joined := filepath.Join(scopeDir, "outputs", "uploads", "x")
		got, err := os.ReadFile(joined)
		if err != nil {
			t.Fatalf("joined object %s not written: %v", joined, err)
		}
		if string(got) != nonceB {
			t.Fatalf("joined object bytes = %q, want the write payload %q", got, nonceB)
		}

		// The RO subtree object is byte-UNCHANGED: no write-intent path string can
		// name it after the join (the ":ro" mirage is closed by construction).
		roGot, err := os.ReadFile(roPath)
		if err != nil {
			t.Fatalf("RO object vanished: %v", err)
		}
		if string(roGot) != nonceA {
			t.Fatalf("RO object bytes = %q, want the UNCHANGED seed %q; the write reached the read-only subtree", roGot, nonceA)
		}
	})

	t.Run("join_disabled_write_clobbers_flat_object", func(t *testing.T) {
		// No -claims-bind, no -subtree-* flags: the shipped static bind (join
		// disabled). The fixed e2eBearer binds to the configured scope with the
		// default read,write grant.
		d := startDaemon(t)
		scopeDir := filepath.Join(d.engineRoot, e2eScope)

		if err := os.MkdirAll(filepath.Join(scopeDir, "uploads"), 0o700); err != nil {
			t.Fatalf("seed uploads dir: %v", err)
		}
		flatPath := filepath.Join(scopeDir, "uploads", "x")
		if err := os.WriteFile(flatPath, []byte(nonceA), 0o600); err != nil {
			t.Fatalf("seed flat object: %v", err)
		}

		// The SAME upload addressing "/uploads/x" with overwrite: static mode has
		// no join, so it CLOBBERS the flat object the RO view reads.
		resp := d.uploadMultipart(t, map[string]any{
			"filesystem_id":          e2eScope,
			"path":                   "/uploads/x",
			"declared_size_bytes":    len(nonceB),
			"overwrite_existing":     true,
			"authorization_metadata": authMeta("write"),
		}, []byte(nonceB))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("join-disabled write status = %d, want 200; body %s", resp.StatusCode, body)
		}

		// The flat object was CLOBBERED (the pre-fix mirage: write reached the
		// same flat object the RO view reads).
		got, err := os.ReadFile(flatPath)
		if err != nil {
			t.Fatalf("flat object vanished: %v", err)
		}
		if string(got) != nonceB {
			t.Fatalf("flat object bytes = %q, want the CLOBBER %q (static mode must reach the flat object)", got, nonceB)
		}
		// No joined object exists in static mode.
		joined := filepath.Join(scopeDir, "outputs", "uploads", "x")
		if _, err := os.Stat(joined); err == nil {
			t.Fatalf("static-mode write gained the join (%s exists); the join must be inert without the flags", joined)
		}
	})
}
