// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// liveSeedTagged PUTs a raw object carrying an explicit ocu-sha256 tag value —
// test arrangement only, used to drive verifyCopy's digest-comparison branches
// against the real backend without relying on a faithful copy reproducing the
// tag.
func liveSeedTagged(t *testing.T, e *s3Engine, key, digest string, body []byte) {
	t.Helper()
	if _, err := e.client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:  aws.String(e.bucket),
		Key:     aws.String(key),
		Body:    bytes.NewReader(body),
		Tagging: aws.String(digestTagKey + "=" + digest),
	}); err != nil {
		t.Fatalf("liveSeedTagged(%q): %v", key, err)
	}
}

// TestS3Live_VerifyCopy_Branches drives every decision inside verifyCopy
// against the live backend with directly-seeded source/destination pairs:
// size mismatch refuses; equal-size-no-digest passes (size-only verification);
// equal-size-matching-digest passes; equal-size-divergent-digest refuses. The
// HeadObject and GetObjectTagging calls are all real backend round-trips.
func TestS3Live_VerifyCopy_Branches(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	pfx := string(scope) + "/"

	digA := sha256.Sum256([]byte("alpha"))
	digB := sha256.Sum256([]byte("bravo"))
	hexA := hex.EncodeToString(digA[:])
	hexB := hex.EncodeToString(digB[:])

	// size mismatch: src 5 bytes, dst 3 bytes -> refuses, message names both.
	liveSeed(t, e, pfx+"sm-src", []byte("alpha"))
	liveSeed(t, e, pfx+"sm-dst", []byte("bra"))
	if err := e.verifyCopy(ctx, pfx+"sm-src", pfx+"sm-dst"); err == nil ||
		!strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("verifyCopy(size mismatch) = %v, want size-mismatch refusal", err)
	}

	// equal size, neither tagged: size-only verification passes (digest "").
	liveSeed(t, e, pfx+"nt-src", []byte("alpha"))
	liveSeed(t, e, pfx+"nt-dst", []byte("bravo"))
	if err := e.verifyCopy(ctx, pfx+"nt-src", pfx+"nt-dst"); err != nil {
		t.Fatalf("verifyCopy(equal size, no digest) = %v, want nil (size-only pass)", err)
	}

	// equal size, matching digest: passes.
	liveSeedTagged(t, e, pfx+"ok-src", hexA, []byte("alpha"))
	liveSeedTagged(t, e, pfx+"ok-dst", hexA, []byte("alpha"))
	if err := e.verifyCopy(ctx, pfx+"ok-src", pfx+"ok-dst"); err != nil {
		t.Fatalf("verifyCopy(equal size, matching digest) = %v, want nil", err)
	}

	// equal size, divergent digest: refuses with the digest-mismatch shape
	// (the bad-copy-deleted/source-intact invariant text).
	liveSeedTagged(t, e, pfx+"dm-src", hexA, []byte("alpha"))
	liveSeedTagged(t, e, pfx+"dm-dst", hexB, []byte("bravo"))
	err := e.verifyCopy(ctx, pfx+"dm-src", pfx+"dm-dst")
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("verifyCopy(divergent digest) = %v, want digest-mismatch refusal", err)
	}

	// src missing -> the first HeadObject maps to fs.ErrNotExist.
	if err := e.verifyCopy(ctx, pfx+"ghost-src", pfx+"ok-dst"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("verifyCopy(missing src) = %v, want fs.ErrNotExist", err)
	}
	// dst missing -> the second HeadObject maps to fs.ErrNotExist.
	if err := e.verifyCopy(ctx, pfx+"ok-src", pfx+"ghost-dst"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("verifyCopy(missing dst) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_DigestTagOf pins the tag reader against the live backend: a
// tagged object returns its ocu-sha256 value; an object with foreign tags but
// no ocu-sha256 returns ""; an untagged object returns ""; a missing key maps
// to fs.ErrNotExist.
func TestS3Live_DigestTagOf(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	pfx := string(scope) + "/"

	dig := sha256.Sum256([]byte("payload"))
	hexD := hex.EncodeToString(dig[:])
	liveSeedTagged(t, e, pfx+"tagged", hexD, []byte("payload"))
	if got, err := e.digestTagOf(ctx, pfx+"tagged"); err != nil || got != hexD {
		t.Fatalf("digestTagOf(tagged) = %q, %v; want %q, nil", got, err, hexD)
	}

	// Foreign tag, no ocu-sha256 -> "".
	if _, err := e.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(pfx + "foreign"),
		Body: bytes.NewReader([]byte("x")), Tagging: aws.String("other=value"),
	}); err != nil {
		t.Fatalf("seed foreign tag: %v", err)
	}
	if got, err := e.digestTagOf(ctx, pfx+"foreign"); err != nil || got != "" {
		t.Fatalf("digestTagOf(foreign tag only) = %q, %v; want \"\", nil", got, err)
	}

	liveSeed(t, e, pfx+"untagged", []byte("y"))
	if got, err := e.digestTagOf(ctx, pfx+"untagged"); err != nil || got != "" {
		t.Fatalf("digestTagOf(untagged) = %q, %v; want \"\", nil", got, err)
	}

	if _, err := e.digestTagOf(ctx, pfx+"missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("digestTagOf(missing) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_SrcTagging pins the copy-time tag carry: a tagged source encodes
// to "k=v" form (the digest tag travels with every copy); an untagged source
// encodes to ""; a missing source maps to fs.ErrNotExist.
func TestS3Live_SrcTagging(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	pfx := string(scope) + "/"

	dig := sha256.Sum256([]byte("body"))
	hexD := hex.EncodeToString(dig[:])
	liveSeedTagged(t, e, pfx+"src", hexD, []byte("body"))
	got, err := e.srcTagging(ctx, pfx+"src")
	if err != nil {
		t.Fatalf("srcTagging(tagged): %v", err)
	}
	if got != digestTagKey+"="+hexD {
		t.Fatalf("srcTagging(tagged) = %q, want %q", got, digestTagKey+"="+hexD)
	}

	liveSeed(t, e, pfx+"plain", []byte("body"))
	if got, err := e.srcTagging(ctx, pfx+"plain"); err != nil || got != "" {
		t.Fatalf("srcTagging(untagged) = %q, %v; want \"\", nil", got, err)
	}

	if _, err := e.srcTagging(ctx, pfx+"missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("srcTagging(missing) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_DeleteByPrefix_EmptyAndPopulated pins the plain (non-versioned)
// sweep helper directly: an empty prefix deletes nothing and returns (0,0,nil);
// a populated prefix returns the exact deleted count and erases every key,
// while a sibling prefix is untouched (the sweep is prefix-scoped, not bucket
// wide).
func TestS3Live_DeleteByPrefix_EmptyAndPopulated(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	pfx := string(scope) + "/"

	// Empty prefix: nothing listed, nothing deleted, no error.
	del, failed, err := e.deleteByPrefix(ctx, pfx+"empty/")
	if err != nil || del != 0 || failed != 0 {
		t.Fatalf("deleteByPrefix(empty) = (%d, %d, %v); want (0, 0, nil)", del, failed, err)
	}

	for _, k := range []string{"d/a", "d/b", "d/c"} {
		liveSeed(t, e, pfx+k, []byte("x"))
	}
	liveSeed(t, e, pfx+"sibling/keep", []byte("x")) // outside the swept prefix

	del, failed, err = e.deleteByPrefix(ctx, pfx+"d/")
	if err != nil || del != 3 || failed != 0 {
		t.Fatalf("deleteByPrefix(populated) = (%d, %d, %v); want (3, 0, nil)", del, failed, err)
	}
	if got := liveKeyCount(t, e, scope); got != 1 {
		t.Fatalf("after sweep, scope key count = %d, want 1 (the sibling survives)", got)
	}
	if ok, err := e.keyExists(ctx, pfx+"sibling/keep"); err != nil || !ok {
		t.Fatalf("sibling key after prefix sweep: ok=%v, err=%v; want survived", ok, err)
	}
}

// TestS3Live_DeleteAllVersions_Direct drives the versioned sweep helper
// directly on the versioned bucket: multiple versions and a delete-marker
// under the prefix are all erased and the function returns nil; an
// already-empty prefix is a clean no-op. The non-vacuity check confirms the
// history existed before the sweep.
func TestS3Live_DeleteAllVersions_Direct(t *testing.T) {
	e, scope := liveVersionedS3Engine(t)
	ctx := context.Background()
	pfx := string(scope) + "/"

	// empty prefix: no versions -> nil.
	if err := e.deleteAllVersions(ctx, pfx+"none/"); err != nil {
		t.Fatalf("deleteAllVersions(empty) = %v, want nil", err)
	}

	// Build history: two versions of one key plus a delete-marker, and a
	// second key with one version, so the batch carries Versions AND
	// DeleteMarkers together.
	if _, err := e.WriteStream(ctx, scope, "h.txt", bytes.NewReader([]byte("one")), false); err != nil {
		t.Fatalf("WriteStream(v1): %v", err)
	}
	if _, err := e.WriteStream(ctx, scope, "h.txt", bytes.NewReader([]byte("two")), true); err != nil {
		t.Fatalf("WriteStream(v2): %v", err)
	}
	if err := e.RemoveFile(ctx, scope, "h.txt"); err != nil {
		t.Fatalf("RemoveFile(h.txt): %v", err)
	}
	if _, err := e.WriteStream(ctx, scope, "k.txt", bytes.NewReader([]byte("k")), false); err != nil {
		t.Fatalf("WriteStream(k): %v", err)
	}

	before, err := e.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(e.bucket), Prefix: aws.String(pfx),
	})
	if err != nil {
		t.Fatalf("ListObjectVersions(before): %v", err)
	}
	if len(before.Versions) < 3 || len(before.DeleteMarkers) < 1 {
		t.Fatalf("pre-sweep history = %d versions, %d delete-markers; want >=3 and >=1 (arrangement broken)",
			len(before.Versions), len(before.DeleteMarkers))
	}

	if err := e.deleteAllVersions(ctx, pfx); err != nil {
		t.Fatalf("deleteAllVersions(populated) = %v, want nil", err)
	}

	after, err := e.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(e.bucket), Prefix: aws.String(pfx),
	})
	if err != nil {
		t.Fatalf("ListObjectVersions(after): %v", err)
	}
	if len(after.Versions) != 0 || len(after.DeleteMarkers) != 0 {
		t.Fatalf("post-sweep history = %d versions, %d delete-markers; want 0 and 0",
			len(after.Versions), len(after.DeleteMarkers))
	}
}

// TestS3Live_AbortScopeMPUs_PrefixFilter pins the client-side prefix filter
// inside abortScopeMPUs: an in-progress upload UNDER the scope prefix is
// aborted, while an upload under a foreign prefix is left untouched (the
// bucket-wide listing must not abort uploads outside the scope it is sweeping).
func TestS3Live_AbortScopeMPUs_PrefixFilter(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	inPrefix := string(scope) + "/"

	// An upload inside the scope, and one under a distinct foreign scope.
	foreign := ScopeID(string(scope) + "-foreign")
	foreignKey := string(foreign) + "/keep.bin"
	t.Cleanup(func() { liveSweepScope(t, e, foreign) })

	mkUpload := func(key string) *string {
		create, err := e.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket: aws.String(e.bucket), Key: aws.String(key),
		})
		if err != nil {
			t.Fatalf("CreateMultipartUpload(%q): %v", key, err)
		}
		if _, err := e.client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: aws.String(e.bucket), Key: aws.String(key), UploadId: create.UploadId,
			PartNumber: aws.Int32(1), Body: bytes.NewReader([]byte("part bytes")),
		}); err != nil {
			t.Fatalf("UploadPart(%q): %v", key, err)
		}
		return create.UploadId
	}
	mkUpload(inPrefix + "scoped.bin")
	foreignID := mkUpload(foreignKey)
	t.Cleanup(func() {
		_, _ = e.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket: aws.String(e.bucket), Key: aws.String(foreignKey), UploadId: foreignID,
		})
	})

	if got := liveMPUCount(t, e, scope); got != 1 {
		t.Fatalf("pre-sweep scoped MPU count = %d, want 1", got)
	}

	if err := e.abortScopeMPUs(ctx, inPrefix); err != nil {
		t.Fatalf("abortScopeMPUs: %v", err)
	}

	if got := liveMPUCount(t, e, scope); got != 0 {
		t.Fatalf("post-sweep scoped MPU count = %d, want 0 (scoped upload not aborted)", got)
	}
	// The foreign upload survived the prefix filter.
	if got := liveMPUCountPrefix(t, e, string(foreign)+"/"); got != 1 {
		t.Fatalf("foreign MPU count after scoped sweep = %d, want 1 (prefix filter aborted too much)", got)
	}
}

// liveMPUCountPrefix counts in-progress multipart uploads whose key carries
// the given prefix (bucket-wide listing + client-side filter) — the
// foreign-survival probe behind the prefix-filter assertion.
func liveMPUCountPrefix(t *testing.T, e *s3Engine, prefix string) int {
	t.Helper()
	out, err := e.client.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket: aws.String(e.bucket),
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads: %v", err)
	}
	n := 0
	for _, up := range out.Uploads {
		if strings.HasPrefix(aws.ToString(up.Key), prefix) {
			n++
		}
	}
	return n
}

// TestS3Live_ReadRange_NegativeGuard pins the negative-window refusal and the
// zero-length-on-existing path: a negative offset or length refuses without a
// GET; a zero-length window over an existing object asserts existence (HEAD)
// and writes nothing.
func TestS3Live_ReadRange_NegativeGuard(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	liveSeed(t, e, string(scope)+"/z.bin", []byte("0123456789"))

	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "z.bin", -1, 5, &buf); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("ReadRange(offset=-1) = %v, want ErrInvalidRange", err)
	}
	if err := e.ReadRange(ctx, scope, "z.bin", 0, -1, &buf); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("ReadRange(length=-1) = %v, want ErrInvalidRange", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("negative-window refusal wrote %d bytes, want 0", buf.Len())
	}

	// zero-length over an existing object: HEAD asserts existence, no bytes.
	if err := e.ReadRange(ctx, scope, "z.bin", 4, 0, &buf); err != nil {
		t.Fatalf("ReadRange(zero length, existing) = %v, want nil", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("zero-length read wrote %d bytes, want 0", buf.Len())
	}
}

// TestS3Live_KeyAndDirExists pins the two existence probes against the live
// backend: keyExists is true only for an exact object key (a directory prefix
// with no exact key is false); dirExists is true for a marker, true for a
// marker-less directory proven by children, and false for nothing.
func TestS3Live_KeyAndDirExists(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	pfx := string(scope) + "/"

	liveSeed(t, e, pfx+"file.txt", []byte("x"))
	if ok, err := e.keyExists(ctx, pfx+"file.txt"); err != nil || !ok {
		t.Fatalf("keyExists(file.txt) = %v, %v; want true", ok, err)
	}
	if ok, err := e.keyExists(ctx, pfx+"ghost.txt"); err != nil || ok {
		t.Fatalf("keyExists(ghost.txt) = %v, %v; want false", ok, err)
	}

	// Marker-backed directory.
	liveSeed(t, e, pfx+"withmarker/", nil)
	if ok, err := e.dirExists(ctx, pfx+"withmarker"); err != nil || !ok {
		t.Fatalf("dirExists(withmarker) = %v, %v; want true (marker present)", ok, err)
	}
	// Marker-less directory proven by a child key.
	liveSeed(t, e, pfx+"lostmarker/child.txt", []byte("c"))
	if ok, err := e.dirExists(ctx, pfx+"lostmarker"); err != nil || !ok {
		t.Fatalf("dirExists(lostmarker) = %v, %v; want true (child proves the dir)", ok, err)
	}
	// Nothing under the name.
	if ok, err := e.dirExists(ctx, pfx+"void"); err != nil || ok {
		t.Fatalf("dirExists(void) = %v, %v; want false", ok, err)
	}
}

// TestS3Live_ProvisionScaffold_ParentExists verifies that ProvisionScope is
// idempotent and does NOT erase existing dir-markers: after seeding subtree
// markers via MakeDir and then calling ProvisionScope a second time, the
// markers must still be visible via parentExists and WriteStream into the
// subtree must succeed. This pins the create-if-absent guarantee — a second
// provision must never wipe markers seeded by the first pass.
func TestS3Live_ProvisionScaffold_ParentExists(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	// First provision: ensures the scope's virtual prefix exists.
	if err := e.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope (first): %v", err)
	}
	// Seed the subtree dir-markers (the compose scaffold step plants these).
	if err := e.MakeDir(ctx, scope, "outputs"); err != nil {
		t.Fatalf("MakeDir(outputs): %v", err)
	}
	if err := e.MakeDir(ctx, scope, "uploads"); err != nil {
		t.Fatalf("MakeDir(uploads): %v", err)
	}

	// Second provision (restart simulation): MUST NOT erase the markers.
	if err := e.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope (second): %v", err)
	}

	// Markers must survive: parentExists returns true for children of each subtree.
	pfx := string(scope) + "/"
	if ok, err := e.parentExists(ctx, pfx+"outputs/x"); err != nil || !ok {
		t.Fatalf("parentExists(outputs/x) after re-provision = %v, %v; want true (marker survived)", ok, err)
	}
	if ok, err := e.parentExists(ctx, pfx+"uploads/x"); err != nil || !ok {
		t.Fatalf("parentExists(uploads/x) after re-provision = %v, %v; want true (marker survived)", ok, err)
	}

	// WriteStream into the outputs subtree must succeed without manual re-seeding.
	if _, err := e.WriteStream(ctx, scope, "outputs/probe.bin", bytes.NewReader([]byte("probe")), false); err != nil {
		t.Fatalf("WriteStream(outputs/probe.bin) after re-provision: %v", err)
	}
}

// TestS3Live_OwnerDataPreservedOnReProvision (N2-s3) pins that ProvisionScope
// is safe to call on an already-provisioned, live scope: owner bytes written
// via the engine API survive a second ProvisionScope call and remain readable.
// S3 prefixes are virtual so ProvisionScope is always a no-op; this test
// documents the contract and would catch any regression that re-introduces an
// erase on the provision path.
func TestS3Live_OwnerDataPreservedOnReProvision(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	if err := e.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope (first): %v", err)
	}
	if _, err := e.WriteStream(ctx, scope, "owner.bin", bytes.NewReader([]byte("OWNER")), false); err != nil {
		t.Fatalf("WriteStream (owner): %v", err)
	}

	// Re-provision must not touch owner data.
	if err := e.ProvisionScope(ctx, scope); err != nil {
		t.Fatalf("ProvisionScope (second): %v", err)
	}
	fi, err := e.Stat(ctx, scope, "owner.bin")
	if err != nil {
		t.Fatalf("Stat(owner.bin) after re-provision = %v, want still present", err)
	}
	if fi.Size != int64(len("OWNER")) {
		t.Fatalf("owner.bin size after re-provision = %d, want %d", fi.Size, len("OWNER"))
	}
}

// TestS3Live_EraseScope_PlainBucket drives the shared erase sweep on the plain
// (non-versioned) bucket directly: keys and an in-progress MPU under the scope
// are both gone after eraseScope, exercising the non-versioned branch
// (deleteByPrefix) followed by the MPU abort in one call.
func TestS3Live_EraseScope_PlainBucket(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	pfx := string(scope) + "/"

	for _, k := range []string{"a.txt", "sub/b.txt", "sub/c.txt"} {
		liveSeed(t, e, pfx+k, []byte("x"))
	}
	create, err := e.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(e.bucket), Key: aws.String(pfx + "inflight.bin"),
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if _, err := e.client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket: aws.String(e.bucket), Key: aws.String(pfx + "inflight.bin"), UploadId: create.UploadId,
		PartNumber: aws.Int32(1), Body: bytes.NewReader([]byte("inflight")),
	}); err != nil {
		t.Fatalf("UploadPart: %v", err)
	}

	if err := e.eraseScope(ctx, scope); err != nil {
		t.Fatalf("eraseScope(plain) = %v, want nil", err)
	}
	if got := liveKeyCount(t, e, scope); got != 0 {
		t.Fatalf("key count after eraseScope = %d, want 0", got)
	}
	if got := liveMPUCount(t, e, scope); got != 0 {
		t.Fatalf("MPU count after eraseScope = %d, want 0 (in-flight upload survived)", got)
	}
}

// TestS3Live_MoveFile_NonVacuousVerify proves the verify-then-delete order
// is genuinely exercised on the move path: a small overwrite=false move (which
// routes through the conditional multipart copy, not a plain CopyObject)
// preserves both content and the digest tag end-to-end, then the source is
// gone — a faithful copy whose verify passed.
func TestS3Live_MoveFile_NonVacuousVerify(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	body := []byte("verify-then-delete order matters")

	if _, err := e.WriteStream(ctx, scope, "src.bin", bytes.NewReader(body), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	srcDigest := liveDigestTag(t, e, string(scope)+"/src.bin")

	if err := e.MoveFile(ctx, scope, "src.bin", "dst.bin", false); err != nil {
		t.Fatalf("MoveFile: %v", err)
	}
	if got := liveDigestTag(t, e, string(scope)+"/dst.bin"); got != srcDigest {
		t.Fatalf("digest after move = %q, want carried %q", got, srcDigest)
	}
	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "dst.bin", 0, int64(len(body))+8, &buf); err != nil ||
		!bytes.Equal(buf.Bytes(), body) {
		t.Fatalf("dst content = %q, %v; want %q", buf.Bytes(), err, body)
	}
	if _, err := e.Stat(ctx, scope, "src.bin"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("source after verified move = %v, want fs.ErrNotExist", err)
	}
}
