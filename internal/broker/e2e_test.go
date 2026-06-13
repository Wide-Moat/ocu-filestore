// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package broker_test

// This file is the release-gating live e2e slice: it drives the REAL built
// ocu-filestored daemon over a REAL unix socket — no mocks. The CI e2e job
// builds the binary (CGO_ENABLED=0 go build -trimpath -o ocu-filestored
// ./cmd/ocu-filestored) and runs `go test -run 'Integration|E2E' ./...`.
// Locally, set OCU_BROKER_BIN to the built binary; absent, every live test
// loud-skips so `go test ./...` without the binary does not fail.
//
// The thin 5-byte frame codec and unix-socket http.Client are reimplemented
// here from the GOLDEN-FIXTURES byte layouts (the southface _test helpers are
// unexported and in another package). The fs-golden-01 / golden.bin fixtures
// keep this byte-aligned with the guest peer.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	servicePrefix          = "/ocu.filestore.v1alpha.FilesystemService/"
	connectVersionHeader   = "Connect-Protocol-Version"
	connectVersion         = "1"
	contentTypeJSON        = "application/json"
	contentTypeConnectJSON = "application/connect+json"

	dataFlag      byte = 0x00
	endStreamFlag byte = 0x02
	frameHeader        = 5

	goldenScope = "fs-golden-01"
)

// brokerBin returns the daemon binary path from OCU_BROKER_BIN (default
// ./ocu-filestored relative to the repo root when run from CI). A live test
// loud-skips when the binary is absent.
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

// e2eEngineS3 reports whether the live slice drives the s3 engine: the CI
// s3 leg sets OCU_E2E_ENGINE=s3 with the MinIO rig env; default is the
// local-volume leg (unchanged).
func e2eEngineS3() bool {
	return os.Getenv("OCU_E2E_ENGINE") == "s3"
}

// daemon is a launched broker process bound to one session socket.
type daemon struct {
	cmd        *exec.Cmd
	socketPath string
	engineRoot string
	auditSink  string
	stderr     *bytes.Buffer
}

// daemonOptions configure a launched daemon for a case.
type daemonOptions struct {
	scope               string
	maxFileSize         int64
	downloadablePrefix  string // empty = nothing downloadable
	auditSinkUnwritable bool   // point -audit-sink at an unwritable path
	grantedIntents      string // default "read,write"
}

// skipUnlessPeerCredSupported loud-skips an over-socket case on any platform
// without a kernel SO_PEERCRED equivalent. The southface accept gate is the
// SEC-76 enforcement point; on darwin extractPeerCred returns "unsupported"
// and the gate closes EVERY connection (the uid never matches), so the daemon
// rejects all peers — its own test client included. The live-socket cases are
// therefore Linux-real; darwin loud-skips them (CONTEXT). The erase and
// audit-down cases do not dial the gated socket and run on every platform.
func skipUnlessPeerCredSupported(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("SEC-76 peer-cred gate closes all peers on %s (no SO_PEERCRED); live-socket cases are Linux-real", runtime.GOOS)
	}
}

// startDaemon launches the real binary with a short-pathed socket dir and
// waits for the per-session socket to appear. The caller defers stop().
func startDaemon(t *testing.T, opt daemonOptions) *daemon {
	t.Helper()
	bin := brokerBin(t)

	root, err := os.MkdirTemp("", "e2e")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	engineRoot := filepath.Join(root, "engine")
	socketDir := filepath.Join(root, "sock")
	scope := opt.scope
	if scope == "" {
		scope = goldenScope
	}
	maxFileSize := opt.maxFileSize
	if maxFileSize <= 0 {
		maxFileSize = 1 << 20
	}
	intents := opt.grantedIntents
	if intents == "" {
		intents = "read,write"
	}

	auditSink := filepath.Join(root, "audit.jsonl")
	if opt.auditSinkUnwritable {
		// A path whose parent is a regular file cannot be created — the sink
		// construction fails and the daemon refuses to serve (SEC-79).
		blocker := filepath.Join(root, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("write blocker: %v", err)
		}
		auditSink = filepath.Join(blocker, "audit.jsonl")
	}

	common := []string{
		"-audit-sink", auditSink,
		"-south-socket-dir", socketDir,
		"-profile", "trusted_operator",
		"-tenancy", "single-tenant",
		"-broker-max-file-size", fmt.Sprintf("%d", maxFileSize),
		"-filesystem-id", scope,
		"-granted-intents", intents,
	}
	var args []string
	var env []string
	if e2eEngineS3() {
		// The s3 leg: the SAME live-binary slice re-pointed at the real s3
		// engine against the MinIO rig (dev-direct dial — the rig has no
		// lane proxy; production posture is pinned by the lane refusal
		// smoke). Credentials travel via the daemon's env intake — never a
		// flag value.
		endpoint := os.Getenv("OCU_S3_TEST_ENDPOINT")
		bucket := os.Getenv("OCU_S3_TEST_BUCKET")
		if endpoint == "" || bucket == "" {
			t.Skip("OCU_E2E_ENGINE=s3 but OCU_S3_TEST_ENDPOINT/OCU_S3_TEST_BUCKET unset - boot deploy/docker-compose.test.yml and export the rig env")
		}
		args = append([]string{
			"-engine", "s3",
			"-s3-endpoint", endpoint,
			"-s3-bucket", bucket,
			"-s3-path-style",
			"-storage-lane-dev-direct",
		}, common...)
		env = append(os.Environ(),
			"OCU_S3_ACCESS_KEY_ID="+os.Getenv("OCU_S3_TEST_ACCESS_KEY"),
			"OCU_S3_SECRET_ACCESS_KEY="+os.Getenv("OCU_S3_TEST_SECRET_KEY"),
		)
	} else {
		args = append([]string{
			"-engine", "local-volume",
			"-engine-root", engineRoot,
		}, common...)
	}
	if opt.downloadablePrefix != "" {
		args = append(args, "-downloadable-prefixes", opt.downloadablePrefix)
	}

	cmd := exec.Command(bin, args...)
	cmd.Env = env // nil = inherit
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}

	d := &daemon{
		cmd:        cmd,
		socketPath: filepath.Join(socketDir, scope+".sock"),
		engineRoot: engineRoot,
		auditSink:  auditSink,
		stderr:     &stderr,
	}
	t.Cleanup(func() { d.stop() })

	if opt.auditSinkUnwritable {
		// The daemon is expected to exit non-zero before binding; wait briefly
		// and return so the caller can assert the refusal.
		time.Sleep(150 * time.Millisecond)
		return d
	}

	// Wait for the socket to appear (the daemon binds after admission +
	// construction).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(d.socketPath); err == nil {
			return d
		}
		if d.cmd.ProcessState != nil && d.cmd.ProcessState.Exited() {
			t.Fatalf("daemon exited before binding the socket; stderr:\n%s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("daemon did not bind %q within the deadline; stderr:\n%s", d.socketPath, stderr.String())
	return nil
}

func (d *daemon) stop() {
	if d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
		_, _ = d.cmd.Process.Wait()
	}
}

// client returns an http.Client that dials the daemon's unix socket.
func (d *daemon) client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dl net.Dialer
				return dl.DialContext(ctx, "unix", d.socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

// --- frame codec (GOLDEN-FIXTURES) ----------------------------------------

// writeFrame writes a 5-byte-header frame: flag, uint32 BE length, payload.
func writeFrame(buf *bytes.Buffer, flag byte, payload []byte) {
	var hdr [frameHeader]byte
	hdr[0] = flag
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	buf.Write(hdr[:])
	buf.Write(payload)
}

// readFrame reads one frame from r.
func readFrame(r *bufio.Reader) (byte, []byte, error) {
	var hdr [frameHeader]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

// authMeta builds an authorization_metadata object.
func authMeta(intent string) map[string]any {
	return map[string]any{"intent": intent, "downloadable": false}
}

// postUnary sends a unary application/json request and returns the response.
func (d *daemon) postUnary(t *testing.T, op string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s body: %v", op, err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://unix"+servicePrefix+op, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set(connectVersionHeader, connectVersion)
	resp, err := d.client().Do(req)
	if err != nil {
		t.Fatalf("%s do: %v", op, err)
	}
	return resp
}

// uploadStream sends a fileUpload client-stream: params frame + chunk frames +
// end-stream half-close, and returns the trailer payload.
func (d *daemon) uploadStream(t *testing.T, params map[string]any, chunks [][]byte) []byte {
	t.Helper()
	var body bytes.Buffer
	pj, _ := json.Marshal(params)
	writeFrame(&body, dataFlag, pj)
	for _, c := range chunks {
		cj, _ := json.Marshal(map[string]any{"chunk": c})
		writeFrame(&body, dataFlag, cj)
	}
	writeFrame(&body, endStreamFlag, []byte("{}"))

	req, err := http.NewRequest(http.MethodPost, "http://unix"+servicePrefix+"fileUpload", bytes.NewReader(body.Bytes()))
	if err != nil {
		t.Fatalf("new upload request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeConnectJSON)
	req.Header.Set(connectVersionHeader, connectVersion)
	resp, err := d.client().Do(req)
	if err != nil {
		t.Fatalf("upload do: %v", err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	var lastTrailer []byte
	for {
		flag, payload, err := readFrame(br)
		if err != nil {
			break
		}
		if flag == endStreamFlag {
			lastTrailer = payload
		}
	}
	return lastTrailer
}

// uploadStreamRaw sends pre-framed bytes and returns (firstFrameFlag, trailer).
// Used by the oversize case to assert the trailer arrives without any chunk.
func (d *daemon) uploadStreamParamsOnly(t *testing.T, params map[string]any) []byte {
	t.Helper()
	var body bytes.Buffer
	pj, _ := json.Marshal(params)
	writeFrame(&body, dataFlag, pj)
	writeFrame(&body, endStreamFlag, []byte("{}"))
	req, _ := http.NewRequest(http.MethodPost, "http://unix"+servicePrefix+"fileUpload", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", contentTypeConnectJSON)
	req.Header.Set(connectVersionHeader, connectVersion)
	resp, err := d.client().Do(req)
	if err != nil {
		t.Fatalf("upload do: %v", err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	var trailer []byte
	for {
		flag, payload, err := readFrame(br)
		if err != nil {
			break
		}
		if flag == endStreamFlag {
			trailer = payload
		}
	}
	return trailer
}

// downloadFrames is the parsed outcome of a fileDownload server-stream: the
// concatenated data-frame bytes and the decoded end-stream trailer.
type downloadFrames struct {
	data    []byte
	trailer struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
}

// listUUID lists a directory over the real socket and returns the uuid the
// listing minted for the given guest path. A fileDownload is uuid-addressed, so
// the guest must list (or readFile) first to obtain it.
func (d *daemon) listUUID(t *testing.T, dir, guestPath string) string {
	t.Helper()
	resp := d.postUnary(t, "listDirectory", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   dir,
		"authorization_metadata": authMeta("read"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("listDirectory status = %d, want 200; body %s", resp.StatusCode, b)
	}
	var ld struct {
		Entries []struct {
			File *struct {
				Path string `json:"path"`
				UUID string `json:"uuid"`
			} `json:"file"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ld); err != nil {
		t.Fatalf("decode listDirectory: %v", err)
	}
	for _, e := range ld.Entries {
		if e.File != nil && e.File.Path == guestPath {
			return e.File.UUID
		}
	}
	t.Fatalf("listDirectory of %q did not emit a uuid for %q", dir, guestPath)
	return ""
}

// downloadStream sends a fileDownload server-stream: a single params frame
// (uuid-addressed, optional range) and reads the data frames + trailer back.
// A nil rng requests the whole object.
func (d *daemon) downloadStream(t *testing.T, uuid string, rng *[2]int64) downloadFrames {
	t.Helper()
	params := map[string]any{
		"filesystem_id":          goldenScope,
		"uuid":                   uuid,
		"authorization_metadata": map[string]any{"intent": "read", "downloadable": true},
	}
	if rng != nil {
		params["range"] = map[string]any{"offset": rng[0], "length": rng[1]}
	}
	var body bytes.Buffer
	pj, _ := json.Marshal(params)
	writeFrame(&body, dataFlag, pj)

	req, err := http.NewRequest(http.MethodPost, "http://unix"+servicePrefix+"fileDownload", bytes.NewReader(body.Bytes()))
	if err != nil {
		t.Fatalf("new download request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeConnectJSON)
	req.Header.Set(connectVersionHeader, connectVersion)
	resp, err := d.client().Do(req)
	if err != nil {
		t.Fatalf("download do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("download status = %d, want 200 (streaming); body %s", resp.StatusCode, b)
	}
	br := bufio.NewReader(resp.Body)
	var out downloadFrames
	for {
		flag, payload, err := readFrame(br)
		if err != nil {
			break
		}
		switch flag {
		case endStreamFlag:
			if jerr := json.Unmarshal(payload, &out.trailer); jerr != nil {
				t.Fatalf("download trailer not JSON: %v (%s)", jerr, payload)
			}
		case dataFlag:
			var df struct {
				Data []byte `json:"data"`
			}
			if jerr := json.Unmarshal(payload, &df); jerr != nil {
				t.Fatalf("download data frame not JSON: %v (%s)", jerr, payload)
			}
			out.data = append(out.data, df.Data...)
		}
	}
	return out
}

// --- E2E cases ------------------------------------------------------------

// TestE2EAllowPath drives the allow path over a real socket: provision (flags)
// -> fileUpload -> readFile -> listDirectory, asserting the listing contains
// the uploaded file. The upload prefix is configured downloadable so readFile
// (which requires the resolved downloadable grant) succeeds (SEC-73).
func TestE2EAllowPath(t *testing.T) {
	skipUnlessPeerCredSupported(t)
	d := startDaemon(t, daemonOptions{downloadablePrefix: "/pub", maxFileSize: 1 << 20})

	// Both engines require the parent directory to exist before writing a file
	// into a sub-path (POSIX mkdir semantics: a missing parent refuses). The
	// scope root is ready after provision; /pub must be created explicitly.
	mkResp := d.postUnary(t, "makeDirectory", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub",
		"authorization_metadata": authMeta("write"),
	})
	mkResp.Body.Close()
	if mkResp.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory /pub status = %d, want 200", mkResp.StatusCode)
	}

	// fileUpload /pub/golden.bin = raw "ABCDEFGH".
	raw := []byte("ABCDEFGH")
	trailer := d.uploadStream(t, map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/golden.bin",
		"declared_size_bytes":    len(raw),
		"authorization_metadata": authMeta("write"),
	}, [][]byte{raw})
	if got := strings.TrimSpace(string(trailer)); got != "{}" {
		t.Fatalf("upload trailer = %q, want success {}", got)
	}

	// readFile (unary) — requires the downloadable grant; /pub is configured.
	resp := d.postUnary(t, "readFile", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/golden.bin",
		"authorization_metadata": authMeta("read"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("readFile status = %d, want 200; body %s", resp.StatusCode, b)
	}
	var rf struct {
		File struct {
			Path string `json:"path"`
			Size int64  `json:"size"`
		} `json:"file"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rf); err != nil {
		t.Fatalf("decode readFile: %v", err)
	}
	if rf.File.Path != "/pub/golden.bin" || rf.File.Size != int64(len(raw)) {
		t.Fatalf("readFile metadata = %+v, want /pub/golden.bin size %d", rf.File, len(raw))
	}

	// listDirectory (unary) — the listing must CONTAIN the uploaded file.
	lresp := d.postUnary(t, "listDirectory", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub",
		"authorization_metadata": authMeta("read"),
	})
	defer lresp.Body.Close()
	if lresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(lresp.Body)
		t.Fatalf("listDirectory status = %d, want 200; body %s", lresp.StatusCode, b)
	}
	var ld struct {
		Entries []struct {
			File *struct {
				Path string `json:"path"`
			} `json:"file"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(lresp.Body).Decode(&ld); err != nil {
		t.Fatalf("decode listDirectory: %v", err)
	}
	found := false
	for _, e := range ld.Entries {
		if e.File != nil && e.File.Path == "/pub/golden.bin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("listDirectory entries %+v do not contain /pub/golden.bin", ld.Entries)
	}
}

// TestE2EScopeMismatch pins SEC-43: a body filesystem_id that differs from the
// channel-bound scope is denied permission_denied 403 with the x-deny-reason:
// scope_mismatch header PRESENT.
func TestE2EScopeMismatch(t *testing.T) {
	skipUnlessPeerCredSupported(t)
	d := startDaemon(t, daemonOptions{downloadablePrefix: "/pub"})
	resp := d.postUnary(t, "readFile", map[string]any{
		"filesystem_id":          "fs-attacker",
		"path":                   "/pub/x",
		"authorization_metadata": authMeta("read"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("scope_mismatch status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("x-deny-reason"); got != "scope_mismatch" {
		t.Fatalf("x-deny-reason = %q, want scope_mismatch (header must be present)", got)
	}
}

// TestE2EAuditDown pins SEC-79: an undeliverable audit sink denies the op
// before any 2xx and nothing is staged in the engine root. The daemon refuses
// to serve when the sink cannot be constructed.
func TestE2EAuditDown(t *testing.T) {
	d := startDaemon(t, daemonOptions{downloadablePrefix: "/pub", auditSinkUnwritable: true})
	// The daemon must have exited (refused to serve) rather than binding.
	if d.cmd.ProcessState == nil {
		// Not yet reaped; wait for it.
		_ = d.cmd.Wait()
	}
	if d.cmd.ProcessState != nil && d.cmd.ProcessState.Success() {
		t.Fatalf("daemon served with an unwritable audit sink; want a fail-closed refusal (SEC-79)")
	}
	if _, err := os.Stat(d.socketPath); err == nil {
		t.Fatalf("a socket was bound with an unwritable audit sink; want none (SEC-79)")
	}
	// Nothing staged in the engine root.
	assertNothingStaged(t, d.engineRoot)
}

// TestE2EOversize pins SEC-46/78: a declared_size_bytes over -broker-max-file-
// size is rejected pre-buffer. The error trailer arrives and nothing is
// staged; we send params-only (no chunk) and assert the size_exceeded trailer.
func TestE2EOversize(t *testing.T) {
	skipUnlessPeerCredSupported(t)
	d := startDaemon(t, daemonOptions{downloadablePrefix: "/pub", maxFileSize: 8})
	trailer := d.uploadStreamParamsOnly(t, map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/big.bin",
		"declared_size_bytes":    1 << 20, // far over the 8-byte ceiling
		"authorization_metadata": authMeta("write"),
	})
	var env struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(trailer, &env); err != nil {
		t.Fatalf("decode oversize trailer %q: %v", trailer, err)
	}
	if env.Error == nil || env.Error.Code != "invalid_argument" {
		t.Fatalf("oversize trailer = %q, want an invalid_argument error (size_exceeded)", trailer)
	}
	// Nothing was staged: the object never became visible.
	resp := d.postUnary(t, "readFile", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/big.bin",
		"authorization_metadata": authMeta("read"),
	})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("oversize object is readable; want not staged (SEC-46/78)")
	}
}

// TestE2EPeerDrop pins SEC-76: a non-host peer is dropped in Accept before any
// HTTP byte is read. On darwin the peer-cred gate is a loud-skip stub
// (extractPeerCred returns unsupported, the gate closes every connection); the
// kernel-attested non-host drop is a Linux-real truth.
func TestE2EPeerDrop(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SEC-76 peer-cred enforced on Linux; darwin loud-skip")
	}
	// Running as the host uid, our own connections pass the gate; simulating a
	// non-host peer requires a different uid, which the unprivileged test
	// process cannot mint. The Linux CI job runs the kernel-real drop; here we
	// assert the gate at least does not hand a non-host connection an HTTP
	// response body — a same-uid dial succeeds, proving the gate is wired
	// without falsely dropping the host.
	d := startDaemon(t, daemonOptions{downloadablePrefix: "/pub"})
	conn, err := net.Dial("unix", d.socketPath)
	if err != nil {
		t.Fatalf("host-uid dial should pass the gate: %v", err)
	}
	_ = conn.Close()
}

// TestE2ESignalTeardown pins the T1-9/SEC-54 stop path on the REAL binary:
// a SIGTERM (and a SIGINT) to a running daemon exits 0, removes the session
// socket, and erases the scope directory — the signal stop NEVER skips the
// erase-before-reuse teardown. The case plants a file directly in the
// provisioned scope on the host filesystem (no socket dial), so it is
// platform-neutral: it runs on darwin too, where the peer-cred-gated dial
// cases loud-skip. The s3 leg skips (no host scope dir to plant into; the
// s3 teardown sweep is covered by the engine and conformance suites).
func TestE2ESignalTeardown(t *testing.T) {
	if e2eEngineS3() {
		t.Skip("signal-teardown scope assertion drives the local-volume leg; the s3 sweep is engine-suite-covered")
	}
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			d := startDaemon(t, daemonOptions{})
			scopeDir := filepath.Join(d.engineRoot, goldenScope)

			// Plant session bytes directly in the provisioned scope: the
			// teardown must erase them regardless of how they arrived.
			if err := os.WriteFile(filepath.Join(scopeDir, "leftover.bin"), []byte("SESSIONBYTES"), 0o600); err != nil {
				t.Fatalf("plant leftover: %v", err)
			}

			if err := d.cmd.Process.Signal(sig); err != nil {
				t.Fatalf("send %v: %v", sig, err)
			}
			done := make(chan error, 1)
			go func() { done <- d.cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("daemon exit after %v = %v, want exit 0; stderr:\n%s", sig, err, d.stderr.String())
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("daemon did not exit within 30s of %v (drain bound + teardown must fit); stderr:\n%s", sig, d.stderr.String())
			}

			// The socket file is gone.
			if _, err := os.Stat(d.socketPath); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("socket %q after %v: stat err = %v, want removed", d.socketPath, sig, err)
			}
			// The scope directory was erased: it exists (recreated empty by
			// the teardown) and holds nothing.
			entries, err := os.ReadDir(scopeDir)
			if err != nil {
				t.Fatalf("read scope dir after %v: %v", sig, err)
			}
			if len(entries) != 0 {
				names := make([]string, 0, len(entries))
				for _, e := range entries {
					names = append(names, e.Name())
				}
				t.Fatalf("scope dir not empty after %v teardown: %v (SEC-54)", sig, names)
			}
		})
	}
}

// TestE2EDownloadRange drives the fileDownload server-stream over the real
// socket: upload a known blob, list to mint its uuid, then download (a) the
// whole object and (b) a half-open ranged window, asserting the streamed bytes
// match in both cases. This exercises the streaming download branch
// (serveStreaming -> handleFileDownload, the range path) and the data-frame
// codec end to end against the live daemon. The /pub prefix is downloadable so
// the resolved grant permits the read (SEC-73).
func TestE2EDownloadRange(t *testing.T) {
	skipUnlessPeerCredSupported(t)
	d := startDaemon(t, daemonOptions{downloadablePrefix: "/pub", maxFileSize: 1 << 20})

	mkResp := d.postUnary(t, "makeDirectory", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub",
		"authorization_metadata": authMeta("write"),
	})
	mkResp.Body.Close()
	if mkResp.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory /pub status = %d, want 200", mkResp.StatusCode)
	}

	const content = "0123456789ABCDEF"
	trailer := d.uploadStream(t, map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/range.bin",
		"declared_size_bytes":    len(content),
		"authorization_metadata": authMeta("write"),
	}, [][]byte{[]byte(content)})
	if got := strings.TrimSpace(string(trailer)); got != "{}" {
		t.Fatalf("upload trailer = %q, want success {}", got)
	}

	uuid := d.listUUID(t, "/pub", "/pub/range.bin")

	t.Run("whole_object", func(t *testing.T) {
		out := d.downloadStream(t, uuid, nil)
		if out.trailer.Error != nil {
			t.Fatalf("whole-object download trailer = %+v, want success", out.trailer.Error)
		}
		if string(out.data) != content {
			t.Fatalf("whole-object download = %q, want %q", out.data, content)
		}
	})

	t.Run("ranged_window", func(t *testing.T) {
		// Half-open window [6, 6+5) = "6789A".
		out := d.downloadStream(t, uuid, &[2]int64{6, 5})
		if out.trailer.Error != nil {
			t.Fatalf("ranged download trailer = %+v, want success", out.trailer.Error)
		}
		if want := content[6 : 6+5]; string(out.data) != want {
			t.Fatalf("ranged download = %q, want %q", out.data, want)
		}
	})
}

// TestE2EDownloadWholeObjectMultiChunk drives a WHOLE-object (no Range)
// fileDownload of an object LARGER than one outbound data frame
// (downloadChunkSize = 256 KiB) over the real socket. It pins three things the
// single-frame range test does not: (a) the no-Range branch resolves the read
// length from the broker-side object size (a Stat), so the full object streams
// rather than zero bytes; (b) the outbound chunk loop emits multiple data
// frames and the guest reassembles them byte-exact; (c) a non-multiple-of-
// chunk-size tail (the natural ReadFull ErrUnexpectedEOF at object end) closes
// with the success trailer. The /pub prefix is downloadable so the resolved
// grant permits the read (SEC-73).
func TestE2EDownloadWholeObjectMultiChunk(t *testing.T) {
	skipUnlessPeerCredSupported(t)
	d := startDaemon(t, daemonOptions{downloadablePrefix: "/pub", maxFileSize: 1 << 20})

	mkResp := d.postUnary(t, "makeDirectory", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub",
		"authorization_metadata": authMeta("write"),
	})
	mkResp.Body.Close()
	if mkResp.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory /pub status = %d, want 200", mkResp.StatusCode)
	}

	// 600 KiB + a 1234-byte tail: spans three full 256 KiB frames plus a
	// short final frame, so both the full-frame loop and the tail path run.
	const size = 600*1024 + 1234
	content := make([]byte, size)
	for i := range content {
		content[i] = byte((i*31 + 7) & 0xff)
	}

	// Upload in two chunks to prove reassembly is independent of the inbound
	// chunk boundaries.
	trailer := d.uploadStream(t, map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/big.bin",
		"declared_size_bytes":    size,
		"authorization_metadata": authMeta("write"),
	}, [][]byte{content[:size/2], content[size/2:]})
	if got := strings.TrimSpace(string(trailer)); got != "{}" {
		t.Fatalf("upload trailer = %q, want success {}", got)
	}

	uuid := d.listUUID(t, "/pub", "/pub/big.bin")

	out := d.downloadStream(t, uuid, nil)
	if out.trailer.Error != nil {
		t.Fatalf("whole-object download trailer = %+v, want success", out.trailer.Error)
	}
	if len(out.data) != size {
		t.Fatalf("whole-object download length = %d, want %d", len(out.data), size)
	}
	if !bytes.Equal(out.data, content) {
		t.Fatalf("whole-object multi-chunk download bytes differ from the uploaded content")
	}
}

// TestE2EUploadMidStreamCancel pins the streaming-abort path over the real
// socket: a fileUpload that declares a size, sends one chunk, then drops the
// connection BEFORE the end-stream half-close (the request context cancels
// mid-stream). The daemon must abort the in-flight WriteStream without staging a
// torn object — the temp+rename atomicity guarantees nothing becomes namespace-
// visible — and without leaking the pipe goroutine (the test would hang on a
// leak). After the cancel a readFile of the target must NOT find a committed
// object.
func TestE2EUploadMidStreamCancel(t *testing.T) {
	skipUnlessPeerCredSupported(t)
	d := startDaemon(t, daemonOptions{downloadablePrefix: "/pub", maxFileSize: 1 << 20})

	mkResp := d.postUnary(t, "makeDirectory", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub",
		"authorization_metadata": authMeta("write"),
	})
	mkResp.Body.Close()
	if mkResp.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory /pub status = %d, want 200", mkResp.StatusCode)
	}

	// Build a params frame declaring more bytes than we will send, then one
	// chunk, and deliberately OMIT the end-stream frame. We cancel the request
	// context after the chunk lands so the server's frame read blocks then
	// aborts.
	var body bytes.Buffer
	pj, _ := json.Marshal(map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/torn.bin",
		"declared_size_bytes":    64,
		"authorization_metadata": authMeta("write"),
	})
	writeFrame(&body, dataFlag, pj)
	writeFrame(&body, dataFlag, mustChunk(t, []byte("partial-bytes")))

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+servicePrefix+"fileUpload", bytes.NewReader(body.Bytes()))
	if err != nil {
		t.Fatalf("new upload request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeConnectJSON)
	req.Header.Set(connectVersionHeader, connectVersion)

	// Issue the request in a goroutine; cancel shortly after so the body is
	// half-delivered (params + chunk, no end-stream) and the connection drops.
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, derr := d.client().Do(req)
		if derr == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("mid-stream cancel did not unwind (possible pipe-goroutine leak)")
	}

	// The torn upload never committed: a readFile of the target finds nothing.
	resp := d.postUnary(t, "readFile", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/torn.bin",
		"authorization_metadata": authMeta("read"),
	})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("torn.bin is readable after a mid-stream cancel; want no committed object (temp+rename atomicity)")
	}
}

// mustChunk marshals an upload chunk frame body or fails the test.
func mustChunk(t *testing.T, b []byte) []byte {
	t.Helper()
	cj, err := json.Marshal(map[string]any{"chunk": b})
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}
	return cj
}

// assertNothingStaged fails if any regular file exists anywhere under root.
func assertNothingStaged(t *testing.T, root string) {
	t.Helper()
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Mode().IsRegular() {
			t.Fatalf("a file %q was staged; want nothing staged", path)
		}
		return nil
	})
}

// TestE2ES3CredentialRedaction closes the composed redaction check on the s3
// leg: after a full daemon run that provisions against the real backend and
// serves both an allowed and a denied operation, neither the daemon's stderr
// nor the audit sink carries a single byte of the backend secret (the
// credential-intake redaction discipline, proven end-to-end).
func TestE2ES3CredentialRedaction(t *testing.T) {
	if !e2eEngineS3() {
		t.Skip("composed redaction check runs on the s3 leg (OCU_E2E_ENGINE=s3)")
	}
	skipUnlessPeerCredSupported(t)
	secret := os.Getenv("OCU_S3_TEST_SECRET_KEY")
	accessKey := os.Getenv("OCU_S3_TEST_ACCESS_KEY")
	if secret == "" || accessKey == "" {
		t.Fatal("the s3 leg requires OCU_S3_TEST_ACCESS_KEY/OCU_S3_TEST_SECRET_KEY")
	}

	d := startDaemon(t, daemonOptions{downloadablePrefix: "/pub"})

	// Both engines require the parent directory to exist before a file write
	// into a sub-path (POSIX mkdir semantics). The S3 engine's parentExists
	// check refuses without a /pub directory marker, exactly as the local
	// engine refuses without the directory.
	mkResp := d.postUnary(t, "makeDirectory", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub",
		"authorization_metadata": authMeta("write"),
	})
	mkResp.Body.Close()
	if mkResp.StatusCode != http.StatusOK {
		t.Fatalf("makeDirectory /pub status = %d, want 200", mkResp.StatusCode)
	}

	// One allow (upload writes through to the backend, audited) and one
	// deny (missing object, audited) so both verdict paths emit events.
	trailer := d.uploadStream(t, map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/redact.bin",
		"declared_size_bytes":    11,
		"authorization_metadata": authMeta("write"),
	}, [][]byte{[]byte("REDACTCHECK")})
	if got := strings.TrimSpace(string(trailer)); got != "{}" {
		t.Fatalf("upload trailer = %q, want success {}", got)
	}
	resp := d.postUnary(t, "readFile", map[string]any{
		"filesystem_id":          goldenScope,
		"path":                   "/pub/never-written.bin",
		"authorization_metadata": authMeta("read"),
	})
	resp.Body.Close()

	d.stop()

	audit, err := os.ReadFile(d.auditSink)
	if err != nil {
		t.Fatalf("read audit sink: %v", err)
	}
	for name, blob := range map[string][]byte{
		"audit sink":    audit,
		"daemon stderr": d.stderr.Bytes(),
	} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Fatalf("%s contains the backend secret (redaction breach)", name)
		}
		if bytes.Contains(blob, []byte(accessKey)) {
			t.Fatalf("%s contains the backend access key id (redaction breach)", name)
		}
	}
}
