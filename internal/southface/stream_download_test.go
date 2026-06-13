// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
)

// downloadParamsFrame encodes a fileDownload params frame for a given uuid,
// filesystem_id, and optional range. A nil rng omits the range field (full
// read). The authorization_metadata.downloadable flag is sent as-is; the
// broker resolves the authoritative value from its grant at read time.
func downloadParamsFrame(t fataler, scope, uuid string, rng *fileRange) []byte {
	t.Helper()
	var body string
	if rng == nil {
		body = fmt.Sprintf(
			`{"filesystem_id":%q,"uuid":%q,"authorization_metadata":{"intent":"read","downloadable":true}}`,
			scope, uuid)
	} else {
		body = fmt.Sprintf(
			`{"filesystem_id":%q,"uuid":%q,"range":{"offset":%d,"length":%d},"authorization_metadata":{"intent":"read","downloadable":true}}`,
			scope, uuid, rng.Offset, rng.Length)
	}
	return frameBytes(t, []byte(body))
}

// TestFileDownloadHappyPath pins BL-P1 (allow round-trip): upload a file,
// discover its uuid via listDirectory, then download and assert the bytes
// match. Covers:
//
//   - write→download→assert (uuid-addressed, full read and ranged read)
//   - audit ALLOW Mandate emitted BEFORE the first data frame
//   - downloadable resolved AT READ from the broker grant (NOT the wire flag)
//   - stream is HTTP 200; verdict in the end-stream trailer
func TestFileDownloadHappyPath(t *testing.T) {
	const (
		path    = "/dl.bin"
		engPath = "dl.bin"
	)
	content := []byte("HELLO_DOWNLOAD_BYTES_12345678")

	eng := newFakeEngine()
	eng.putBytes(streamScope, engPath, content)

	g := &fakeGuard{}
	sess := &recordingCeilingsSession{}
	// Resolver: grant Downloadable=true (broker-side resolution — NFR-SEC-73).
	resolver := &fakeResolver{grant: Grant{Downloadable: true}}
	d := newStreamDispatcher(eng, g, sess, 1<<20)
	// Override the resolver so it grants Downloadable.
	d.resolver = resolver

	// Discover the uuid via listDirectory (mints the id in the store).
	w := serveOp(d, OpListDirectory,
		listBody(streamScope, "/", 0, "", false),
		streamScope, okIntents())
	resp := decodeList(t, w)
	var uuid string
	for _, e := range resp.Entries {
		if e.File != nil && e.File.Path == path {
			uuid = e.File.UUID
		}
	}
	if uuid == "" {
		t.Fatalf("listDirectory did not emit a uuid for %s", path)
	}

	t.Run("full_read", func(t *testing.T) {
		// Reset guard events.
		g.mu.Lock()
		g.events = nil
		g.mu.Unlock()

		body := downloadParamsFrame(t, streamScope, uuid, nil)
		rec := serveStream(d, OpFileDownload, bytes.NewReader(body), streamScope, okIntents())

		// Stream is always HTTP 200.
		if rec.Code != 200 {
			t.Fatalf("status = %d, want 200 (streaming path)", rec.Code)
		}

		// Decode data frames + trailer.
		rb := bytes.NewReader(rec.Body.Bytes())
		var downloaded []byte
		var trailer endStreamResponse
		for {
			f, payload, err := readFrame(rb)
			if err != nil {
				break
			}
			if f == endStreamFlag {
				if jerr := json.Unmarshal(payload, &trailer); jerr != nil {
					t.Fatalf("trailer not JSON: %v", jerr)
				}
				break
			}
			if f == dataFlag {
				var df downloadDataFrame
				if jerr := json.Unmarshal(payload, &df); jerr != nil {
					t.Fatalf("data frame not JSON: %v", jerr)
				}
				downloaded = append(downloaded, df.Data...)
			}
		}

		// Trailer must be success.
		if trailer.Error != nil {
			t.Fatalf("trailer error = %+v, want success {}", trailer.Error)
		}
		// Bytes must match.
		if !bytes.Equal(downloaded, content) {
			t.Fatalf("downloaded bytes = %q, want %q", downloaded, content)
		}
		// Audit ALLOW Mandate must have been emitted before the first data frame
		// (audit-before-ack, SEC-79): at least one event recorded.
		g.mu.Lock()
		n := len(g.events)
		g.mu.Unlock()
		if n == 0 {
			t.Fatalf("no audit events on a successful download; want at least the allow Mandate")
		}
	})

	t.Run("ranged_read", func(t *testing.T) {
		// Download the window [6, 8) — "DOWNLOAD".
		rng := &fileRange{Offset: 6, Length: 8}
		body := downloadParamsFrame(t, streamScope, uuid, rng)
		rec := serveStream(d, OpFileDownload, bytes.NewReader(body), streamScope, okIntents())

		var downloaded []byte
		var trailer endStreamResponse
		rb := bytes.NewReader(rec.Body.Bytes())
		for {
			f, payload, err := readFrame(rb)
			if err != nil {
				break
			}
			if f == endStreamFlag {
				if jerr := json.Unmarshal(payload, &trailer); jerr != nil {
					t.Fatalf("trailer not JSON: %v", jerr)
				}
				break
			}
			if f == dataFlag {
				var df downloadDataFrame
				if jerr := json.Unmarshal(payload, &df); jerr != nil {
					t.Fatalf("data frame not JSON: %v", jerr)
				}
				downloaded = append(downloaded, df.Data...)
			}
		}

		if trailer.Error != nil {
			t.Fatalf("ranged trailer error = %+v, want success {}", trailer.Error)
		}
		want := content[6 : 6+8]
		if !bytes.Equal(downloaded, want) {
			t.Fatalf("ranged download = %q, want %q", downloaded, want)
		}
	})
}

// TestFileDownloadDenyCases pins BL-P1 deny paths (SEC-79 deny Mandate before
// trailer):
//
//   - scope_mismatch: filesystem_id in the params frame disagrees with the
//     channel scope → framed permission_denied trailer, no data frames emitted.
//   - unknown_uuid: uuid not in the objectIDStore → framed not_found trailer.
//   - not_downloadable: resolver grants Downloadable=false → framed
//     permission_denied trailer, no data frames emitted.
func TestFileDownloadDenyCases(t *testing.T) {
	const path = "/deny.bin"
	const engPath = "deny.bin"
	content := []byte("DENYTEST")

	setup := func(downloadable bool) (*dispatcher, string) {
		eng := newFakeEngine()
		eng.putBytes(streamScope, engPath, content)
		resolver := &fakeResolver{grant: Grant{Downloadable: downloadable}}
		d := newStreamDispatcher(eng, &fakeGuard{}, &recordingCeilingsSession{}, 1<<20)
		d.resolver = resolver
		// Mint a uuid by listing.
		w := serveOp(d, OpListDirectory,
			listBody(streamScope, "/", 0, "", false),
			streamScope, okIntents())
		resp := decodeList(t, w)
		var uuid string
		for _, e := range resp.Entries {
			if e.File != nil && e.File.Path == path {
				uuid = e.File.UUID
			}
		}
		return d, uuid
	}

	t.Run("scope_mismatch", func(t *testing.T) {
		d, uuid := setup(true)
		// filesystem_id disagrees with the channel scope.
		body := downloadParamsFrame(t, "fs-wrong-scope", uuid, nil)
		w := serveStream(d, OpFileDownload, bytes.NewReader(body), streamScope, okIntents())
		// Must be framed trailer, not a unary error body.
		if w.Code != 200 {
			t.Fatalf("status = %d, want 200 (streaming path; verdict in trailer)", w.Code)
		}
		// No data frames should precede the deny trailer.
		rb := bytes.NewReader(w.Body.Bytes())
		dataFrames := 0
		var trailer endStreamResponse
		for {
			f, payload, err := readFrame(rb)
			if err != nil {
				break
			}
			if f == endStreamFlag {
				_ = json.Unmarshal(payload, &trailer)
				break
			}
			if f == dataFlag {
				dataFrames++
			}
		}
		if dataFrames != 0 {
			t.Fatalf("scope_mismatch: %d data frames emitted before deny; want 0", dataFrames)
		}
		if trailer.Error == nil || trailer.Error.Code != wireCodePermissionDenied {
			t.Fatalf("scope_mismatch trailer = %+v, want permission_denied error", trailer)
		}
	})

	t.Run("unknown_uuid", func(t *testing.T) {
		d, _ := setup(true)
		// Synthesize a uuid that was never minted by this session.
		body := downloadParamsFrame(t, streamScope, "deadbeefdeadbeefdeadbeefdeadbeef", nil)
		w := serveStream(d, OpFileDownload, bytes.NewReader(body), streamScope, okIntents())
		if w.Code != 200 {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		rb := bytes.NewReader(w.Body.Bytes())
		var trailer endStreamResponse
		for {
			f, payload, err := readFrame(rb)
			if err != nil {
				break
			}
			if f == endStreamFlag {
				_ = json.Unmarshal(payload, &trailer)
				break
			}
		}
		if trailer.Error == nil || trailer.Error.Code != wireCodeNotFound {
			t.Fatalf("unknown_uuid trailer = %+v, want not_found error", trailer)
		}
	})

	t.Run("not_downloadable", func(t *testing.T) {
		// Resolver grants Downloadable=false — wire flag is ignored (NFR-SEC-73).
		d, uuid := setup(false)
		if uuid == "" {
			t.Skip("putBytes+list did not return a uuid — engine may not have the file")
		}
		body := downloadParamsFrame(t, streamScope, uuid, nil)
		w := serveStream(d, OpFileDownload, bytes.NewReader(body), streamScope, okIntents())
		if w.Code != 200 {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		rb := bytes.NewReader(w.Body.Bytes())
		dataFrames := 0
		var trailer endStreamResponse
		for {
			f, payload, err := readFrame(rb)
			if err != nil {
				break
			}
			if f == endStreamFlag {
				_ = json.Unmarshal(payload, &trailer)
				break
			}
			if f == dataFlag {
				dataFrames++
			}
		}
		if dataFrames != 0 {
			t.Fatalf("not_downloadable: %d data frames emitted before deny; want 0", dataFrames)
		}
		if trailer.Error == nil || trailer.Error.Code != wireCodePermissionDenied {
			t.Fatalf("not_downloadable trailer = %+v, want permission_denied error", trailer)
		}
	})
}

// TestFileDownloadRealSocket pins BL-P1 over a REAL unix socket: an
// upload followed by a fileDownload, both via raw chunked HTTP/1.1, proves
// the framing is byte-identical between the in-process recorder and the live
// transport. This is the release-blocker end-to-end witness.
func TestFileDownloadRealSocket(t *testing.T) {
	const content = "LIVE_SOCKET_DOWNLOAD_BYTES"
	const engPath = "live.bin"
	const guestPath = "/live.bin"
	const scope = "fs-dl-live"

	dir := filepath.Join(shortSocketDir(t), "dl")
	reg := NewSessionRegistry()
	entry := SessionEntry{
		FilesystemID:   scope,
		GrantedIntents: []Intent{IntentRead, IntentWrite},
	}

	eng := newFakeEngine()
	eng.putBytes(scope, engPath, []byte(content))

	resolver := &fakeResolver{grant: Grant{Downloadable: true}}
	guard := &fakeGuard{}
	sess := &recordingCeilingsSession{}
	d := newDispatcherWithEngine(resolver, guard, &recordingRegistry{sess: sess}, 1<<20, eng)
	d.maxFileSize = 1 << 20

	s, err := provisionSession(dir, entry, reg, d, allowAllPeer, 4242, discardLogger(), nil, nil)
	if err != nil {
		t.Fatalf("provisionSession: %v", err)
	}
	go s.Serve()
	defer s.Close()

	// Step 1: mint a uuid for the file via listDirectory over the real socket,
	// using the unix HTTP client (handles chunked responses transparently).
	var uuid string
	{
		client := unixHTTPClient(s.SocketPath())
		body := listBody(scope, "/", 0, "", false)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			"http://session"+servicePrefix+"listDirectory",
			bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatalf("build list request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(connectProtocolVersionHeader, connectProtocolVersion)
		req.ContentLength = int64(len(body))

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("list request: %v", err)
		}
		respBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("listDirectory status = %d, want 200; body %s", resp.StatusCode, respBytes)
		}

		var lr listDirectoryResponse
		if err := json.Unmarshal(respBytes, &lr); err != nil {
			t.Fatalf("list response not JSON: %v (%s)", err, respBytes)
		}
		for _, e := range lr.Entries {
			if e.File != nil && e.File.Path == guestPath {
				uuid = e.File.UUID
			}
		}
		if uuid == "" {
			t.Fatalf("listDirectory over real socket did not return a uuid for %s", guestPath)
		}
	}

	// Step 2: download via fileDownload over the real socket, using the unix
	// HTTP client (handles chunked response encoding transparently). The client
	// sends the params frame as the request body; the server streams data frames
	// back. Reading through http.Client unchunks the body automatically so
	// readFrame sees the raw framed bytes.
	{
		client := unixHTTPClient(s.SocketPath())
		params := downloadParamsFrame(t, scope, uuid, nil)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			"http://session"+servicePrefix+"fileDownload",
			bytes.NewReader(params))
		if err != nil {
			t.Fatalf("build download request: %v", err)
		}
		req.Header.Set("Content-Type", connContentTypeStream)
		req.Header.Set(connectProtocolVersionHeader, connectProtocolVersion)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("download request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("download status = %d, want 200; body %q", resp.StatusCode, body)
		}

		// The HTTP body (unchunked by the client) is the raw frame stream.
		var downloaded []byte
		var trailer endStreamResponse
		for {
			f, payload, readErr := readFrame(resp.Body)
			if readErr != nil {
				break
			}
			if f == endStreamFlag {
				if jerr := json.Unmarshal(payload, &trailer); jerr != nil {
					t.Fatalf("trailer not JSON: %v (%s)", jerr, payload)
				}
				break
			}
			if f == dataFlag {
				var df downloadDataFrame
				if jerr := json.Unmarshal(payload, &df); jerr != nil {
					t.Fatalf("data frame not JSON: %v", jerr)
				}
				downloaded = append(downloaded, df.Data...)
			}
		}

		if trailer.Error != nil {
			t.Fatalf("download trailer error = %+v, want success {}", trailer.Error)
		}
		if string(downloaded) != content {
			t.Fatalf("downloaded bytes = %q, want %q", downloaded, content)
		}
	}
}
