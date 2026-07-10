// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package composeit_test

// Mutating-ops component slice for the storage broker (component-04): it
// DEEPENS the single golden round-trip in composeit_test.go into a fuller
// exercise of the south-face mutation surface (copy/move/remove file, make/
// move/remove directory), still THROUGH the live TLS face and still asserted
// against the REAL MinIO bucket where it mutates state — an INDEPENDENT S3
// observer GetObject/HeadObjects every key the broker wrote or removed, never
// just the south-face status. It reuses the existing rig verbatim
// (composeUp/southClient/postJSON/uploadMultipart/minioClient/authMeta/uuidFor)
// and gates EVERY case on requireComposeIT (loud-skip without OCU_COMPOSE_IT=1).
//
// This file also hosts the shared helpers the sibling deny-path and multipart
// slices reuse (keyForGuestPath/getObjectBytes/assertObjectAbsent/uploadGolden)
// — one rig, one set of helpers, three slices. Under the ADR-0029 disjoint-subtree
// split a write object is undownloadable through the same mount (write->outputs/,
// read->uploads/), so the golden test's read leg seeds uploads/ directly and
// asserts the egress deny; write objects are verified by the independent MinIO
// observer under the write subtree.
//
// No mocks (owner rule): the bytes are asserted in real MinIO, the mutations
// are confirmed by an independent backend observer. Per-case keys/payloads keep
// cases isolated; compose teardown (down -v) cleans up.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// keyForGuestPath maps a WRITE guest path ("/pub/x.bin") to the real MinIO
// object key the s3 engine writes it under. Under the ADR-0029 default join a
// write-intent op joins the guest path beneath the write subtree ("outputs/"),
// so the backend key is "<scope>/outputs/<path-without-leading-slash>". Every
// caller of this helper verifies a WRITE object (upload/copy/move sources and
// destinations), so it keys on the write subtree. A read-plane object would key
// under "uploads/" instead (see the seeded read leg).
func keyForGuestPath(guestPath string) string {
	return itScope + "/outputs" + guestPath
}

// getObjectBytes reads an object straight from real MinIO via the independent S3
// observer and returns its bytes. A GetObject error fails the test — the caller
// asserts presence.
func getObjectBytes(t *testing.T, mc *s3.Client, key string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	obj, err := mc.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(minioBucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("independent MinIO GetObject %q: %v", key, err)
	}
	defer obj.Body.Close()
	got, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatalf("read MinIO object %q: %v", key, err)
	}
	return got
}

// assertObjectAbsent asserts the key is GONE from real MinIO: a HeadObject must
// surface a 404 / NoSuchKey, NOT a present object. This is the independent
// backend confirmation that a move/remove actually deleted the source.
func assertObjectAbsent(t *testing.T, mc *s3.Client, key string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := mc.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(minioBucket),
		Key:    aws.String(key),
	})
	if err == nil {
		t.Fatalf("MinIO key %q is still present, want it GONE from the bucket", key)
	}
	// A removed key surfaces as a 404 (NoSuchKey/NotFound). Any OTHER error
	// (auth, network) is a test-rig fault, not the expected absence — assert the
	// status is a 404 so a misconfigured client cannot masquerade as "absent".
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) {
		if re.HTTPStatusCode() != http.StatusNotFound {
			t.Fatalf("MinIO HeadObject %q: status = %d, want 404 (NoSuchKey)", key, re.HTTPStatusCode())
		}
		return
	}
	// Some MinIO/SDK paths surface NoSuchKey as a typed smithy API error without
	// a transport ResponseError; accept the not-found-shaped message rather than
	// fail a genuine absence on a missing transport wrapper.
	msg := err.Error()
	if strings.Contains(msg, "NotFound") || strings.Contains(msg, "NoSuchKey") || strings.Contains(msg, "status code: 404") {
		return
	}
	t.Fatalf("MinIO HeadObject %q error = %v, want a 404 NoSuchKey absence", key, err)
}

// uploadGolden uploads payload to guestPath under /pub through the live south
// face and asserts the 200, leaving a real object in MinIO. It is the common
// "arrange" step the mutation/multipart cases share. The caller must have already
// created the /pub working directory (which resolves to "outputs/pub" under the
// ADR-0029 write join and needs its parent chain via make_parents) — the s3
// engine's parentExists refuses a write whose prefix marker is absent.
func uploadGolden(t *testing.T, cl *http.Client, guestPath string, payload []byte) {
	t.Helper()
	up := uploadMultipart(t, cl, map[string]any{
		"filesystem_id":          itScope,
		"path":                   guestPath,
		"declared_size_bytes":    len(payload),
		"authorization_metadata": authMeta("write"),
	}, payload)
	defer up.Body.Close()
	if up.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(up.Body)
		t.Fatalf("fileUpload %s status = %d, want 200; body %s", guestPath, up.StatusCode, b)
	}
}

// TestComponentMutatingOpsAgainstMinIO drives the file-and-directory mutation
// ops through the live TLS south face, asserting each against the REAL MinIO
// bucket (independent GetObject/HeadObject), never merely the south-face status.
// Cases use distinct per-case keys so they do not collide; compose teardown
// cleans up.
func TestComponentMutatingOpsAgainstMinIO(t *testing.T) {
	requireComposeIT(t)

	certDir := t.TempDir()
	pool := generateSouthCert(t, certDir)
	composeUp(t, certDir)

	cl := southClient(pool)
	mc := minioClient()

	// makeDirectory /pub once — the directory ops below operate under it. Under the
	// ADR-0029 write join this resolves to "outputs/pub", whose parent "outputs/"
	// must also exist (the s3 engine's parentExists refuses a write with an absent
	// prefix), so make_parents lays down the whole chain.
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

	// --- 1. copyFile: source and destination BOTH present with identical bytes ---
	t.Run("copyFile_both_keys_identical", func(t *testing.T) {
		srcPath := downloadablePrefix + "/copy-src.bin"
		dstPath := downloadablePrefix + "/copy-dst.bin"
		payload := []byte("copyFile \x00\x01\x02 component payload — case 1")
		uploadGolden(t, cl, srcPath, payload)

		cp := postJSON(t, cl, "copyFile", map[string]any{
			"filesystem_id":          itScope,
			"source":                 srcPath,
			"destination":            dstPath,
			"authorization_metadata": authMeta("write"),
		})
		cp.Body.Close()
		if cp.StatusCode != http.StatusOK {
			t.Fatalf("copyFile status = %d, want 200", cp.StatusCode)
		}

		// Independent MinIO: BOTH keys present with the SAME bytes.
		srcKey, dstKey := keyForGuestPath(srcPath), keyForGuestPath(dstPath)
		if got := getObjectBytes(t, mc, srcKey); !bytes.Equal(got, payload) {
			t.Fatalf("MinIO source %q after copy = %q, want %q", srcKey, got, payload)
		}
		if got := getObjectBytes(t, mc, dstKey); !bytes.Equal(got, payload) {
			t.Fatalf("MinIO destination %q after copy = %q, want %q", dstKey, got, payload)
		}
	})

	// --- 2. moveFile: destination present, SOURCE gone from the bucket ---
	t.Run("moveFile_dest_present_source_gone", func(t *testing.T) {
		srcPath := downloadablePrefix + "/move-src.bin"
		dstPath := downloadablePrefix + "/move-dst.bin"
		payload := []byte("moveFile \x00\x10\x20 component payload — case 2")
		uploadGolden(t, cl, srcPath, payload)

		mv := postJSON(t, cl, "moveFile", map[string]any{
			"filesystem_id":          itScope,
			"source":                 srcPath,
			"destination":            dstPath,
			"authorization_metadata": authMeta("write"),
		})
		mv.Body.Close()
		if mv.StatusCode != http.StatusOK {
			t.Fatalf("moveFile status = %d, want 200", mv.StatusCode)
		}

		srcKey, dstKey := keyForGuestPath(srcPath), keyForGuestPath(dstPath)
		if got := getObjectBytes(t, mc, dstKey); !bytes.Equal(got, payload) {
			t.Fatalf("MinIO destination %q after move = %q, want %q", dstKey, got, payload)
		}
		assertObjectAbsent(t, mc, srcKey)
	})

	// --- 3. removeFile: key gone from the bucket ---
	t.Run("removeFile_key_gone", func(t *testing.T) {
		path := downloadablePrefix + "/remove-me.bin"
		payload := []byte("removeFile \x00\xff component payload — case 3")
		uploadGolden(t, cl, path, payload)

		key := keyForGuestPath(path)
		// Sanity: the object is present before the remove (independent observer).
		if got := getObjectBytes(t, mc, key); !bytes.Equal(got, payload) {
			t.Fatalf("MinIO %q before remove = %q, want %q", key, got, payload)
		}

		rm := postJSON(t, cl, "removeFile", map[string]any{
			"filesystem_id":          itScope,
			"path":                   path,
			"authorization_metadata": authMeta("write"),
		})
		rm.Body.Close()
		if rm.StatusCode != http.StatusOK {
			t.Fatalf("removeFile status = %d, want 200", rm.StatusCode)
		}
		assertObjectAbsent(t, mc, key)
	})

	// --- 4. directory ops: makeDirectory + moveDirectory with a real object
	// underneath, asserting the bucket reflects the rename. The s3 engine keys
	// directories as zero-byte markers and the objects beneath them as flat
	// "<scope>/<path>" keys; moveDirectory re-keys every object under the source
	// prefix to the destination prefix, so after the move the object lives under
	// the NEW prefix and the OLD object key is gone. We assert exactly that — the
	// real key-prefix re-mapping — not a fabricated POSIX expectation.
	t.Run("moveDirectory_reprefixes_objects", func(t *testing.T) {
		srcDir := downloadablePrefix + "/dir-src"
		dstDir := downloadablePrefix + "/dir-dst"
		filePath := srcDir + "/inside.bin"
		movedPath := dstDir + "/inside.bin"
		payload := []byte("moveDirectory \x00\x07 component payload — case 4")

		mkd := postJSON(t, cl, "makeDirectory", map[string]any{
			"filesystem_id":          itScope,
			"path":                   srcDir,
			"authorization_metadata": authMeta("write"),
		})
		mkd.Body.Close()
		if mkd.StatusCode != http.StatusOK {
			t.Fatalf("makeDirectory %s status = %d, want 200", srcDir, mkd.StatusCode)
		}
		uploadGolden(t, cl, filePath, payload)

		mvd := postJSON(t, cl, "moveDirectory", map[string]any{
			"filesystem_id":          itScope,
			"source":                 srcDir,
			"destination":            dstDir,
			"authorization_metadata": authMeta("write"),
		})
		mvd.Body.Close()
		if mvd.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(mvd.Body)
			t.Fatalf("moveDirectory status = %d, want 200; body %s", mvd.StatusCode, b)
		}

		// Independent MinIO: the object now lives under the destination prefix,
		// and the source object key is gone.
		movedKey := keyForGuestPath(movedPath)
		oldKey := keyForGuestPath(filePath)
		if got := getObjectBytes(t, mc, movedKey); !bytes.Equal(got, payload) {
			t.Fatalf("MinIO moved object %q = %q, want %q", movedKey, got, payload)
		}
		assertObjectAbsent(t, mc, oldKey)
	})

	// --- 4b. removeDirectory (recursive) sweeps the subtree from the bucket ---
	t.Run("removeDirectory_recursive_sweeps_subtree", func(t *testing.T) {
		dir := downloadablePrefix + "/rmdir-src"
		filePath := dir + "/inside.bin"
		payload := []byte("removeDirectory \x00\x09 component payload — case 4b")

		mkd := postJSON(t, cl, "makeDirectory", map[string]any{
			"filesystem_id":          itScope,
			"path":                   dir,
			"authorization_metadata": authMeta("write"),
		})
		mkd.Body.Close()
		if mkd.StatusCode != http.StatusOK {
			t.Fatalf("makeDirectory %s status = %d, want 200", dir, mkd.StatusCode)
		}
		uploadGolden(t, cl, filePath, payload)
		fileKey := keyForGuestPath(filePath)
		if got := getObjectBytes(t, mc, fileKey); !bytes.Equal(got, payload) {
			t.Fatalf("MinIO %q before rmdir = %q, want %q", fileKey, got, payload)
		}

		rmd := postJSON(t, cl, "removeDirectory", map[string]any{
			"filesystem_id":          itScope,
			"path":                   dir,
			"recursive":              true,
			"authorization_metadata": authMeta("write"),
		})
		rmd.Body.Close()
		if rmd.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(rmd.Body)
			t.Fatalf("removeDirectory status = %d, want 200; body %s", rmd.StatusCode, b)
		}
		// The object under the removed prefix is gone from the real bucket.
		assertObjectAbsent(t, mc, fileKey)
	})
}

// TestComponentScaffoldWriteSucceedsWithNoManualSeeding (N5) pins the compose
// scaffold guarantee: after a cold boot against a FRESH empty bucket, a
// write-intent mount write to the outputs/ subtree MUST succeed WITHOUT any
// prior manual makeDirectory call. The compose boot must seed the outputs/ and
// uploads/ dir-markers via the idempotent scaffold loop so the s3 engine's
// parentExists passes on the first real write.
//
// Without the scaffold loop the s3 engine refuses the write (parentExists on
// the outputs/ marker returns false), so this test is RED on the pre-fix
// binary. After the scaffold loop lands it turns GREEN.
func TestComponentScaffoldWriteSucceedsWithNoManualSeeding(t *testing.T) {
	requireComposeIT(t)

	certDir := t.TempDir()
	pool := generateSouthCert(t, certDir)
	composeUp(t, certDir)

	cl := southClient(pool)
	mc := minioClient()

	// Write-intent upload into the outputs/ subtree, NO prior makeDirectory.
	// The broker's scaffold loop must have already seeded the outputs/ marker.
	payload := []byte("scaffold-probe")
	up := uploadMultipart(t, cl, map[string]any{
		"filesystem_id":          itScope,
		"path":                   "/scaffold-probe.bin",
		"declared_size_bytes":    len(payload),
		"authorization_metadata": authMeta("write"),
	}, payload)
	defer up.Body.Close()
	if up.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(up.Body)
		t.Fatalf("fileUpload (no manual seeding) status = %d, want 200 — "+
			"scaffold loop did NOT seed outputs/ marker; body: %s", up.StatusCode, b)
	}
	// Confirm the object landed in MinIO under the write subtree.
	key := itScope + "/outputs/scaffold-probe.bin"
	if got := getObjectBytes(t, mc, key); !bytes.Equal(got, payload) {
		t.Fatalf("MinIO %q = %q, want %q", key, got, payload)
	}
}
