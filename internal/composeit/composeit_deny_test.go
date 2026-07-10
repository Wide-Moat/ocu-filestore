// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package composeit_test

// End-to-end DENY-PATH slice for the storage broker (component-04): the same
// refusals the in-package unit tests cover, but driven THROUGH the live TLS
// south face so the assertion is the real HTTP STATUS the assembled service
// returns over the wire. The HTTP STATUS is the authority; the BoundedReason
// body is diagnostic only and is NOT asserted on. The anti-enumeration 404
// degrade must leak NO truth header (x-deny-reason).
//
// It reuses the existing rig verbatim (composeUp/southClient/postJSON/authMeta/
// generateSouthCert) and gates every case on requireComposeIT (loud-skip
// without OCU_COMPOSE_IT=1). No mocks: the denies are the real south-face
// statuses, not a fake dispatcher's.

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// TestComponentDenyPathsOverTLS drives the end-to-end deny paths through the
// real south face. The HTTP STATUS is the authority; the BoundedReason body is
// diagnostic only and is NOT asserted on. The 404 anti-enumeration degrade must
// leak NO truth header (x-deny-reason).
func TestComponentDenyPathsOverTLS(t *testing.T) {
	requireComposeIT(t)

	certDir := t.TempDir()
	pool := generateSouthCert(t, certDir)
	composeUp(t, certDir)

	cl := southClient(pool)

	// --- 5. foreign filesystem_id -> 403 (scope_mismatch). The edge-injected
	// bearer binds to the daemon -filesystem-id (itScope); a body filesystem_id
	// that disagrees is the STAGE-1b channel-scope cross-check deny. The unary
	// path returns permission_denied (403) — scope_mismatch is an authorization
	// verdict, NOT the anti-enumeration uuid-degrade path that only the
	// fileDownload cross-scope-uuid leg takes. The STATUS is the authority.
	t.Run("foreign_filesystem_id_403", func(t *testing.T) {
		resp := postJSON(t, cl, "listDirectory", map[string]any{
			"filesystem_id":          "fs-some-other-scope",
			"path":                   downloadablePrefix,
			"authorization_metadata": authMeta("read"),
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("foreign filesystem_id status = %d, want 403; body %s", resp.StatusCode, b)
		}
	})

	// --- 6. missing credential -> 401. A POST with NO Authorization header. We
	// build the request directly (postJSON always injects the bearer) so the
	// header is genuinely absent; the credential-scope route layer cannot
	// attribute the request to any scope and returns unauthenticated (401).
	t.Run("missing_credential_401", func(t *testing.T) {
		body := []byte(`{"filesystem_id":"` + itScope + `","path":"` + downloadablePrefix +
			`","authorization_metadata":{"intent":"read","downloadable":false}}`)
		req, err := http.NewRequest(http.MethodPost,
			"https://"+southHostAddr+restBase+"listDirectory", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("new no-auth request: %v", err)
		}
		req.Header.Set("Content-Type", contentTypeJSON)
		// Deliberately NO Authorization header.
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("no-auth do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("missing-credential status = %d, want 401; body %s", resp.StatusCode, b)
		}
	})

	// --- 6b. empty Bearer -> 401. A present Authorization header whose token is
	// empty after the scheme is "missing credential" all the same.
	t.Run("empty_bearer_401", func(t *testing.T) {
		body := []byte(`{"filesystem_id":"` + itScope + `","path":"` + downloadablePrefix +
			`","authorization_metadata":{"intent":"read","downloadable":false}}`)
		req, err := http.NewRequest(http.MethodPost,
			"https://"+southHostAddr+restBase+"listDirectory", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("new empty-bearer request: %v", err)
		}
		req.Header.Set("Content-Type", contentTypeJSON)
		req.Header.Set("Authorization", "Bearer ")
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("empty-bearer do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("empty-bearer status = %d, want 401; body %s", resp.StatusCode, b)
		}
	})

	// --- 7. unknown path under a read-only (uploads) subtree -> 404 not_found,
	// header-less. readFile addresses by PATH; after the south-read-gate removal,
	// the downloadable axis is a NORTH egress control only. A read-intent op
	// joins under the "uploads" subtree (ADR-0029); an unknown path reaches the
	// engine (Stat), which returns not_found (404) — the same anti-enumeration
	// degrade as the unknown-uuid fileDownload (subtest 7b). No x-deny-reason
	// header on a not_found deny (the anti-enumeration degrade must not leak path
	// existence truth).
	t.Run("unknown_path_readFile_denied_before_enumeration", func(t *testing.T) {
		resp := postJSON(t, cl, "readFile", map[string]any{
			"filesystem_id":          itScope,
			"path":                   downloadablePrefix + "/does-not-exist.bin",
			"authorization_metadata": map[string]any{"intent": "read", "downloadable": true},
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("unknown-path readFile status = %d, want 404 not_found (engine Stat reaches here now; path does not exist); body %s", resp.StatusCode, b)
		}
		if hdr := resp.Header.Get("x-deny-reason"); hdr != "" {
			t.Fatalf("readFile not_found leaked x-deny-reason = %q, want NO truth header (anti-enumeration)", hdr)
		}
	})

	// --- 7b. unknown uuid fileDownload -> 404, header-less. fileDownload
	// addresses by UUID: a uuid unknown to this session resolves to not_found,
	// the same 404 anti-enumeration degrade with no truth header. (Confirmed
	// against download_octetstream.go: an unknown uuid is denyNotFound -> 404,
	// header=false.)
	t.Run("unknown_uuid_fileDownload_404_no_truth_header", func(t *testing.T) {
		resp := postJSON(t, cl, "fileDownload", map[string]any{
			"filesystem_id":          itScope,
			"uuid":                   "00000000-0000-0000-0000-000000000000",
			"authorization_metadata": map[string]any{"intent": "read", "downloadable": true},
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("unknown-uuid fileDownload status = %d, want 404; body %s", resp.StatusCode, b)
		}
		if hdr := resp.Header.Get("x-deny-reason"); hdr != "" {
			t.Fatalf("unknown-uuid 404 leaked x-deny-reason = %q, want NO truth header (anti-enumeration)", hdr)
		}
	})
}
