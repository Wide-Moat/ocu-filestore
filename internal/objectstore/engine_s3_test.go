// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// testS3Config returns a minimal valid S3Config for constructor tests; no
// network I/O ever happens (the constructor only builds the client).
func testS3Config() S3Config {
	return S3Config{
		Endpoint:     "http://127.0.0.1:9000",
		Region:       "us-east-1",
		Bucket:       "ocu-test",
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""),
	}
}

// TestS3_Constructor_Refusals pins the constructor's fail-closed inputs: no
// bucket, no region, no credentials provider (the engine never falls back to
// ambient credential chains), and a part size below the backend's non-final
// part minimum.
func TestS3_Constructor_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*S3Config)
	}{
		{"no bucket", func(c *S3Config) { c.Bucket = "" }},
		{"no region", func(c *S3Config) { c.Region = "" }},
		{"no credentials", func(c *S3Config) { c.Credentials = nil }},
		{"part size below minimum", func(c *S3Config) { c.PartSize = s3MinPartSize - 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testS3Config()
			tc.mutate(&cfg)
			if _, err := NewS3Engine(cfg); err == nil {
				t.Fatal("NewS3Engine accepted an invalid config; want refusal")
			}
		})
	}
}

// TestS3_RetryModeConfigured pins the constructor's resilience posture at
// the client boundary: the retryer is the SDK's adaptive mode (client-rate
// pacing with jitter) with the capped attempt count, the custom endpoint
// sticks, path-style sticks, and both checksum modes are WhenRequired for a
// custom endpoint (the documented S3-compatible-backend setting).
func TestS3_RetryModeConfigured(t *testing.T) {
	eng, err := NewS3Engine(testS3Config())
	if err != nil {
		t.Fatalf("NewS3Engine: %v", err)
	}
	opts := eng.(*s3Engine).client.Options()

	if _, ok := opts.Retryer.(*retry.AdaptiveMode); !ok {
		t.Fatalf("Retryer is %T, want *retry.AdaptiveMode", opts.Retryer)
	}
	if got := opts.Retryer.MaxAttempts(); got != s3MaxRetryAttempts {
		t.Fatalf("Retryer.MaxAttempts() = %d, want %d", got, s3MaxRetryAttempts)
	}
	if opts.BaseEndpoint == nil || *opts.BaseEndpoint != "http://127.0.0.1:9000" {
		t.Fatalf("BaseEndpoint = %v, want the configured endpoint", opts.BaseEndpoint)
	}
	if !opts.UsePathStyle {
		t.Fatal("UsePathStyle = false, want true")
	}
	if opts.RequestChecksumCalculation != aws.RequestChecksumCalculationWhenRequired {
		t.Fatalf("RequestChecksumCalculation = %v, want WhenRequired on a custom endpoint", opts.RequestChecksumCalculation)
	}
	if opts.ResponseChecksumValidation != aws.ResponseChecksumValidationWhenRequired {
		t.Fatalf("ResponseChecksumValidation = %v, want WhenRequired on a custom endpoint", opts.ResponseChecksumValidation)
	}
}

// TestS3_Constructor_Defaults pins the default part size and single-PUT
// cutoff (16 MiB each) and the production multipart-copy threshold (5 GiB).
func TestS3_Constructor_Defaults(t *testing.T) {
	eng, err := NewS3Engine(testS3Config())
	if err != nil {
		t.Fatalf("NewS3Engine: %v", err)
	}
	e := eng.(*s3Engine)
	if e.partSize != s3DefaultPartSize {
		t.Fatalf("partSize = %d, want %d", e.partSize, int64(s3DefaultPartSize))
	}
	if e.singlePutCutoff != s3DefaultSinglePutCutoff {
		t.Fatalf("singlePutCutoff = %d, want %d", e.singlePutCutoff, int64(s3DefaultSinglePutCutoff))
	}
	if e.copyThreshold != s3MaxCopyObjectSize {
		t.Fatalf("copyThreshold = %d, want %d", e.copyThreshold, int64(s3MaxCopyObjectSize))
	}
}

// TestS3_KeyValidator_Rejections pins every rejection class of the S3 key
// layer: each hostile or malformed input refuses with ErrInvalidPath before
// any backend call (section-8 lexical stage; the S3 additions on top of
// ValidatePath).
func TestS3_KeyValidator_Rejections(t *testing.T) {
	e := &s3Engine{bucket: "b"}
	longSegment := strings.Repeat("a", s3MaxKeyBytes)

	for _, tc := range []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"dot (scope root is not an object)", "."},
		{"absolute", "/etc/passwd"},
		{"dot-dot escape", "../other-scope/file"},
		{"interior dot-dot", "a/../../b"},
		{"NUL byte", "a\x00b"},
		{"URL-shaped handle", "s3://bucket/key"},
		{"control character Cc", "a\x01b"},
		{"DEL control", "a\x7fb"},
		{"format character Cf (zero-width space)", "a\u200bb"},
		{"non-NFC (decomposed accent)", "cafe\u0301.txt"},
		{"invalid utf-8", "a\xff\xfeb"},
		{"joined key over 1024 bytes", longSegment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.objectKey("fs1", tc.path); !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("objectKey(%q) error = %v, want ErrInvalidPath", tc.path, err)
			}
		})
	}
}

// TestS3_KeyValidator_NFCCollision pins the normalization-collision rule
// (section 8): the composed (NFC) form of a name is a valid key; the
// decomposed variant — which would collide with it only after NFC
// normalization — is REJECTED at intake, never silently merged onto the
// existing object's key.
func TestS3_KeyValidator_NFCCollision(t *testing.T) {
	e := &s3Engine{bucket: "b"}

	composed := "caf\u00e9.txt" // NFC: precomposed U+00E9
	key, err := e.objectKey("fs1", composed)
	if err != nil {
		t.Fatalf("objectKey(composed NFC %q): %v", composed, err)
	}
	if key != "fs1/"+composed {
		t.Fatalf("objectKey(composed) = %q, want %q", key, "fs1/"+composed)
	}

	decomposed := "cafe\u0301.txt" // NFD: e + combining acute
	if _, err := e.objectKey("fs1", decomposed); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("objectKey(decomposed %q) error = %v, want ErrInvalidPath (reject, never merge)", decomposed, err)
	}
}

// TestS3_KeyValidator_ScopeShape pins the trusted-side shape guard on the
// prefix join: a malformed scope id refuses with ErrInvalidScopeID before
// any key is built (defense-in-depth — TeardownScope("..") must never sweep
// the whole bucket).
func TestS3_KeyValidator_ScopeShape(t *testing.T) {
	e := &s3Engine{bucket: "b"}
	for _, scope := range []ScopeID{"", ".", "..", "a/b", "a\\b", "a\x00b"} {
		if _, err := e.objectKey(scope, "f.txt"); !errors.Is(err, ErrInvalidScopeID) {
			t.Fatalf("objectKey(scope %q) error = %v, want ErrInvalidScopeID", scope, err)
		}
		if _, err := e.scopePrefix(scope); !errors.Is(err, ErrInvalidScopeID) {
			t.Fatalf("scopePrefix(scope %q) error = %v, want ErrInvalidScopeID", scope, err)
		}
	}
}

// TestS3_DirMarkerAndParentKey pins the single directory convention's two
// helpers: the marker is the key plus a trailing slash, and parentKey walks
// one level up, returning "" when the parent is the scope root.
func TestS3_DirMarkerAndParentKey(t *testing.T) {
	if got := dirMarkerKey("fs1/d"); got != "fs1/d/" {
		t.Fatalf("dirMarkerKey = %q, want %q", got, "fs1/d/")
	}
	for _, tc := range []struct{ key, want string }{
		{"fs1/leaf.txt", ""},
		{"fs1/d/leaf.txt", "fs1/d"},
		{"fs1/a/b/c.txt", "fs1/a/b"},
	} {
		if got := parentKey(tc.key); got != tc.want {
			t.Fatalf("parentKey(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

// opErr wraps an API error the way the SDK surfaces it (operation wrapper
// around the service error), so the table exercises the real errors.As
// digging the mapper relies on.
func opErr(inner error) error {
	return &smithy.OperationError{ServiceID: "S3", OperationName: "TestOp", Err: inner}
}

// httpRespErr builds the SDK's transport-level response error carrying an
// HTTP status code, wrapped like a real operation error.
func httpRespErr(status int) error {
	return opErr(&awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      errors.New("backend refused"),
		},
	})
}

// timeoutNetError is a net.Error whose Timeout() is true — the
// transport-level timeout class.
type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "dial timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

// TestS3_MapS3Err pins the complete decision-7 error taxonomy with real
// smithy/types error values — every backend code lands on exactly one
// sentinel, terminal classes are typed and never mapped retryable, and
// context cancellation survives the mapping errors.Is-matchable.
func TestS3_MapS3Err(t *testing.T) {
	var nilTarget error

	for _, tc := range []struct {
		name string
		in   error
		want error
	}{
		{"typed NoSuchKey -> fs.ErrNotExist", opErr(&types.NoSuchKey{}), fs.ErrNotExist},
		{"typed NoSuchBucket -> fs.ErrNotExist", opErr(&types.NoSuchBucket{}), fs.ErrNotExist},
		{"typed NotFound -> fs.ErrNotExist", opErr(&types.NotFound{}), fs.ErrNotExist},
		{"code PreconditionFailed -> ErrAlreadyExists", opErr(&smithy.GenericAPIError{Code: "PreconditionFailed"}), ErrAlreadyExists},
		{"code SlowDown -> ErrThrottled", opErr(&smithy.GenericAPIError{Code: "SlowDown"}), ErrThrottled},
		{"code ServiceUnavailable -> ErrThrottled", opErr(&smithy.GenericAPIError{Code: "ServiceUnavailable"}), ErrThrottled},
		{"code Throttling -> ErrThrottled", opErr(&smithy.GenericAPIError{Code: "Throttling"}), ErrThrottled},
		{"code RequestTimeout -> ErrTransient", opErr(&smithy.GenericAPIError{Code: "RequestTimeout"}), ErrTransient},
		{"code InternalError -> ErrTransient", opErr(&smithy.GenericAPIError{Code: "InternalError"}), ErrTransient},
		{"code AccessDenied -> terminal access denied", opErr(&smithy.GenericAPIError{Code: "AccessDenied"}), errS3AccessDenied},
		{"code RequestTimeTooSkewed -> terminal clock skew", opErr(&smithy.GenericAPIError{Code: "RequestTimeTooSkewed"}), errS3ClockSkew},
		{"bare HTTP 404 -> fs.ErrNotExist", httpRespErr(404), fs.ErrNotExist},
		{"bare HTTP 412 -> ErrAlreadyExists", httpRespErr(412), ErrAlreadyExists},
		{"bare HTTP 403 -> terminal access denied", httpRespErr(403), errS3AccessDenied},
		{"bare HTTP 503 -> ErrThrottled", httpRespErr(503), ErrThrottled},
		{"bare HTTP 429 -> ErrThrottled", httpRespErr(429), ErrThrottled},
		{"bare HTTP 500 -> ErrTransient", httpRespErr(500), ErrTransient},
		{"transport timeout -> ErrTransient", opErr(timeoutNetError{}), ErrTransient},
		{"net.OpError (conn reset) -> ErrTransient", opErr(&net.OpError{Op: "read", Err: errors.New("connection reset by peer")}), ErrTransient},
		{"ctx canceled passes through", opErr(context.Canceled), context.Canceled},
		{"ctx deadline passes through", opErr(context.DeadlineExceeded), context.DeadlineExceeded},
		{"nil -> nil", nil, nilTarget},
		{"unknown error wraps verbatim (non-vacuity)", opErr(errors.New("boom")), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapS3Err("test", tc.in)
			if tc.in == nil {
				if got != nil {
					t.Fatalf("mapS3Err(nil) = %v, want nil", got)
				}
				return
			}
			if tc.want == nil {
				// Non-vacuity: an unknown error maps onto NO sentinel.
				for _, sentinel := range []error{
					fs.ErrNotExist, ErrAlreadyExists, ErrThrottled, ErrTransient,
					errS3AccessDenied, errS3ClockSkew,
				} {
					if errors.Is(got, sentinel) {
						t.Fatalf("mapS3Err(unknown) = %v wrongly matches %v", got, sentinel)
					}
				}
				if got == nil {
					t.Fatal("mapS3Err(unknown) = nil, want the wrapped error")
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("mapS3Err(%v) = %v, want errors.Is(%v)", tc.in, got, tc.want)
			}
		})
	}
}

// TestS3_MapS3Err_TerminalNeverRetryable pins that the two terminal classes
// never co-classify as transient or throttled — a mapper regression that
// made AccessDenied retryable would spin against a policy misconfiguration.
func TestS3_MapS3Err_TerminalNeverRetryable(t *testing.T) {
	for _, in := range []error{
		opErr(&smithy.GenericAPIError{Code: "AccessDenied"}),
		opErr(&smithy.GenericAPIError{Code: "RequestTimeTooSkewed"}),
	} {
		got := mapS3Err("test", in)
		if errors.Is(got, ErrTransient) || errors.Is(got, ErrThrottled) {
			t.Fatalf("terminal error %v mapped retryable: %v", in, got)
		}
	}
}

// TestS3_EngineKindAndScaffold pins that the engine names the S3 kind and
// that un-landed verbs still refuse with ErrNotImplemented (the wave-by-wave
// scaffold; this test shrinks as verbs land).
func TestS3_EngineKindAndScaffold(t *testing.T) {
	eng, err := NewS3Engine(testS3Config())
	if err != nil {
		t.Fatalf("NewS3Engine: %v", err)
	}
	if eng.Kind() != S3 {
		t.Fatalf("Kind() = %q, want %q", eng.Kind(), S3)
	}
	if err := eng.ProvisionScope(context.Background(), "fs1"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ProvisionScope scaffold error = %v, want ErrNotImplemented until 13-09", err)
	}
}

// --- Live S3 leg (real MinIO; gated, never mocked) -------------------------

// liveSkipNotice names the exact local invocation, so a skip is always loud
// and actionable.
const liveSkipNotice = `OCU_S3_TEST_ENDPOINT not set - live S3 leg SKIPPED (it never runs against a mock).
Boot the rig and re-run:
  docker compose -f deploy/docker-compose.test.yml up -d --wait minio
  docker compose -f deploy/docker-compose.test.yml run --rm bucket-init
  OCU_S3_TEST_ENDPOINT=http://127.0.0.1:9000 OCU_S3_TEST_BUCKET=ocu-conformance \
  OCU_S3_TEST_ACCESS_KEY=ocu-test-root OCU_S3_TEST_SECRET_KEY=ocu-test-secret-key \
  go test ./internal/objectstore/ -run 'Conformance|S3Live' -count=1`

// liveS3Engine returns an engine bound to the real rig (skipping loudly when
// the env gate is unset) plus a unique scope; cleanup sweeps the scope's
// prefix with the raw client so test runs never bleed into each other.
func liveS3Engine(t *testing.T) (*s3Engine, ScopeID) {
	t.Helper()
	endpoint := os.Getenv("OCU_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip(liveSkipNotice)
	}
	bucket := os.Getenv("OCU_S3_TEST_BUCKET")
	if bucket == "" {
		bucket = "ocu-conformance"
	}
	eng, err := NewS3Engine(S3Config{
		Endpoint:     endpoint,
		Region:       "us-east-1",
		Bucket:       bucket,
		UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(
			os.Getenv("OCU_S3_TEST_ACCESS_KEY"), os.Getenv("OCU_S3_TEST_SECRET_KEY"), ""),
	})
	if err != nil {
		t.Fatalf("NewS3Engine(live): %v", err)
	}
	e := eng.(*s3Engine)

	scope := ScopeID(fmt.Sprintf("%s-%d",
		strings.ToLower(strings.NewReplacer("/", "-", "_", "-").Replace(t.Name())),
		time.Now().UnixNano()))
	t.Cleanup(func() { liveSweepScope(t, e, scope) })
	return e, scope
}

// liveSweepScope erases every key under the scope prefix with the raw
// client (paginated list + batched delete) — the test-side hygiene sweep
// until TeardownScope lands.
func liveSweepScope(t *testing.T, e *s3Engine, scope ScopeID) {
	t.Helper()
	ctx := context.Background()
	prefix := string(scope) + "/"
	var token *string
	for {
		out, err := e.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(e.bucket), Prefix: aws.String(prefix), ContinuationToken: token,
		})
		if err != nil {
			t.Logf("live sweep list: %v", err)
			return
		}
		if len(out.Contents) > 0 {
			ids := make([]types.ObjectIdentifier, 0, len(out.Contents))
			for _, obj := range out.Contents {
				ids = append(ids, types.ObjectIdentifier{Key: obj.Key})
			}
			if _, err := e.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(e.bucket), Delete: &types.Delete{Objects: ids},
			}); err != nil {
				t.Logf("live sweep delete: %v", err)
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return
		}
		token = out.NextContinuationToken
	}
}

// liveSeed PUTs a raw object with the raw client — test arrangement only;
// every assertion still runs through the engine against the real backend.
func liveSeed(t *testing.T, e *s3Engine, key string, body []byte) {
	t.Helper()
	if _, err := e.client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(key), Body: bytes.NewReader(body),
	}); err != nil {
		t.Fatalf("liveSeed(%q): %v", key, err)
	}
}

// --- 13-06: read verbs -----------------------------------------------------

// TestS3_RangeHeaderFormat pins the single-range header shape: half-open
// [offset, offset+length) becomes the inclusive "bytes=start-end" — exactly
// one range, never multi-range (which the backend ignores with a 200).
func TestS3_RangeHeaderFormat(t *testing.T) {
	for _, tc := range []struct {
		offset, length int64
		want           string
	}{
		{0, 1, "bytes=0-0"},
		{0, 10, "bytes=0-9"},
		{5, 100, "bytes=5-104"},
		{1 << 30, 1 << 20, "bytes=1073741824-1074790399"},
	} {
		if got := rangeHeader(tc.offset, tc.length); got != tc.want {
			t.Fatalf("rangeHeader(%d, %d) = %q, want %q", tc.offset, tc.length, got, tc.want)
		}
	}
}

// TestS3_ReopenOffsetArithmetic pins the mid-stream reopen window math: a
// reopen continues from the last good offset for the remaining bytes —
// never a whole-transfer restart, never a byte-discard seek.
func TestS3_ReopenOffsetArithmetic(t *testing.T) {
	for _, tc := range []struct {
		offset, length, delivered int64
		wantOffset, wantLength    int64
	}{
		{0, 100, 0, 0, 100},
		{0, 100, 40, 40, 60},
		{10, 100, 30, 40, 70},
		{10, 100, 100, 110, 0},
	} {
		gotOff, gotLen := reopenWindow(tc.offset, tc.length, tc.delivered)
		if gotOff != tc.wantOffset || gotLen != tc.wantLength {
			t.Fatalf("reopenWindow(%d, %d, %d) = (%d, %d), want (%d, %d)",
				tc.offset, tc.length, tc.delivered, gotOff, gotLen, tc.wantOffset, tc.wantLength)
		}
	}
	// The re-issued header continues exactly where delivery stopped.
	off, ln := reopenWindow(10, 100, 30)
	if got := rangeHeader(off, ln); got != "bytes=40-109" {
		t.Fatalf("reopened range header = %q, want bytes=40-109", got)
	}
}

// TestS3Live_Stat_FileDirMissing pins the three-step Stat resolution against
// the real backend: object key -> file; dir marker -> directory; lost marker
// with children -> still a directory; nothing -> fs.ErrNotExist.
func TestS3Live_Stat_FileDirMissing(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	prefix := string(scope) + "/"

	liveSeed(t, e, prefix+"f.txt", []byte("hello stat"))
	liveSeed(t, e, prefix+"d/", nil)             // marker directory
	liveSeed(t, e, prefix+"lost/child.txt", nil) // children, no marker

	fi, err := e.Stat(ctx, scope, "f.txt")
	if err != nil {
		t.Fatalf("Stat(file): %v", err)
	}
	if fi.IsDir || fi.Size != int64(len("hello stat")) || fi.Name != "f.txt" {
		t.Fatalf("Stat(file) = %+v, want file f.txt size %d", fi, len("hello stat"))
	}
	if fi.ModTime.IsZero() {
		t.Fatal("Stat(file).ModTime is zero")
	}

	di, err := e.Stat(ctx, scope, "d")
	if err != nil {
		t.Fatalf("Stat(marker dir): %v", err)
	}
	if !di.IsDir {
		t.Fatalf("Stat(marker dir) = %+v, want IsDir", di)
	}

	li, err := e.Stat(ctx, scope, "lost")
	if err != nil {
		t.Fatalf("Stat(lost-marker dir): %v", err)
	}
	if !li.IsDir {
		t.Fatalf("Stat(lost-marker dir) = %+v, want IsDir (children prove the dir)", li)
	}

	if _, err := e.Stat(ctx, scope, "missing.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(missing) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_List_OneLevel pins one-level listing semantics: files and
// subdirectories of the listed level only, nested entries invisible, the
// directory's own marker never an entry, and a missing directory refusing
// with fs.ErrNotExist.
func TestS3Live_List_OneLevel(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	prefix := string(scope) + "/"

	liveSeed(t, e, prefix+"top.txt", []byte("1"))
	liveSeed(t, e, prefix+"d/", nil)
	liveSeed(t, e, prefix+"d/inner.txt", []byte("22"))
	liveSeed(t, e, prefix+"d/sub/", nil)
	liveSeed(t, e, prefix+"d/sub/deep.txt", []byte("333"))
	liveSeed(t, e, prefix+"empty/", nil)

	root, err := e.List(ctx, scope, ".")
	if err != nil {
		t.Fatalf("List(.): %v", err)
	}
	got := map[string]bool{}
	for _, fi := range root {
		got[fi.Name] = fi.IsDir
	}
	want := map[string]bool{"top.txt": false, "d": true, "empty": true}
	if len(got) != len(want) {
		t.Fatalf("List(.) = %v, want exactly %v", got, want)
	}
	for name, isDir := range want {
		gotDir, ok := got[name]
		if !ok || gotDir != isDir {
			t.Fatalf("List(.) missing/wrong entry %q: got %v want isDir=%v", name, got, isDir)
		}
	}

	d, err := e.List(ctx, scope, "d")
	if err != nil {
		t.Fatalf("List(d): %v", err)
	}
	got = map[string]bool{}
	for _, fi := range d {
		got[fi.Name] = fi.IsDir
	}
	if len(got) != 2 || got["inner.txt"] != false || got["sub"] != true {
		t.Fatalf("List(d) = %v, want inner.txt(file) + sub(dir) only", got)
	}

	empty, err := e.List(ctx, scope, "empty")
	if err != nil {
		t.Fatalf("List(empty): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("List(empty) = %v, want no entries (marker excluded)", empty)
	}

	if _, err := e.List(ctx, scope, "no-such-dir"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("List(missing dir) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_List_Pagination proves the listing walks EVERY page: more than
// 1000 keys (the backend's page cap) under one directory all surface.
func TestS3Live_List_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: skipping the >1000-key pagination seed")
	}
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	prefix := string(scope) + "/"
	const n = 1100

	liveSeed(t, e, prefix+"big/", nil)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			key := fmt.Sprintf("%sbig/k-%04d", prefix, i)
			if _, err := e.client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: aws.String(e.bucket), Key: aws.String(key), Body: bytes.NewReader([]byte{byte(i)}),
			}); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("pagination seed: %v", err)
	}

	entries, err := e.List(ctx, scope, "big")
	if err != nil {
		t.Fatalf("List(big): %v", err)
	}
	if len(entries) != n {
		t.Fatalf("List(big) returned %d entries, want %d (pagination under-report)", len(entries), n)
	}
}

// TestS3Live_ReadRange_PastEOF pins the 416 contract: an offset exactly at
// EOF and an offset past EOF both yield ZERO bytes and nil error.
func TestS3Live_ReadRange_PastEOF(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	body := []byte("0123456789")
	liveSeed(t, e, string(scope)+"/r.bin", body)

	for _, offset := range []int64{int64(len(body)), int64(len(body)) + 7} {
		var buf bytes.Buffer
		if err := e.ReadRange(ctx, scope, "r.bin", offset, 5, &buf); err != nil {
			t.Fatalf("ReadRange(offset=%d past EOF): %v, want nil", offset, err)
		}
		if buf.Len() != 0 {
			t.Fatalf("ReadRange(offset=%d past EOF) wrote %d bytes, want 0", offset, buf.Len())
		}
	}

	// Missing object: fs.ErrNotExist, including the zero-length window.
	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "missing.bin", 0, 5, &buf); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadRange(missing) = %v, want fs.ErrNotExist", err)
	}
	if err := e.ReadRange(ctx, scope, "missing.bin", 0, 0, &buf); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadRange(missing, zero length) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_ReadRange_TailClamp pins the 206 clamp: a window extending past
// EOF short-reads to EOF without error; interior windows are byte-exact;
// zero-length windows return immediately with nil.
func TestS3Live_ReadRange_TailClamp(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	body := []byte("abcdefghij")
	liveSeed(t, e, string(scope)+"/r.bin", body)

	for _, tc := range []struct {
		name           string
		offset, length int64
		want           string
	}{
		{"tail clamped", 5, 100, "fghij"},
		{"interior window", 2, 5, "cdefg"},
		{"whole object", 0, 10, "abcdefghij"},
		{"zero length", 3, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := e.ReadRange(ctx, scope, "r.bin", tc.offset, tc.length, &buf); err != nil {
				t.Fatalf("ReadRange(%d, %d): %v", tc.offset, tc.length, err)
			}
			if buf.String() != tc.want {
				t.Fatalf("ReadRange(%d, %d) = %q, want %q", tc.offset, tc.length, buf.String(), tc.want)
			}
		})
	}
}

// --- 13-07: write verbs ----------------------------------------------------

// liveDigestTag fetches the ocu-sha256 tag of a key ("" when absent).
func liveDigestTag(t *testing.T, e *s3Engine, key string) string {
	t.Helper()
	out, err := e.client.GetObjectTagging(context.Background(), &s3.GetObjectTaggingInput{
		Bucket: aws.String(e.bucket), Key: aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObjectTagging(%q): %v", key, err)
	}
	for _, tag := range out.TagSet {
		if aws.ToString(tag.Key) == digestTagKey {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}

// liveMPUCount returns the number of in-progress multipart uploads under the
// scope prefix — the orphan detector.
func liveMPUCount(t *testing.T, e *s3Engine, scope ScopeID) int {
	t.Helper()
	out, err := e.client.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket: aws.String(e.bucket), Prefix: aws.String(string(scope) + "/"),
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads: %v", err)
	}
	return len(out.Uploads)
}

// failAfterReader serves `serve` pattern bytes then fails with err.
type failAfterReader struct {
	serve int
	err   error
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.serve <= 0 {
		return 0, r.err
	}
	if len(p) > r.serve {
		p = p[:r.serve]
	}
	for i := range p {
		p[i] = 'x'
	}
	r.serve -= len(p)
	return len(p), nil
}

// TestS3Live_WriteStream_SmallSinglePut pins the single-PUT path: byte-exact
// round trip, size HEAD-verified, and the streamed SHA-256 stored as the
// ocu-sha256 tag (never the ETag).
func TestS3Live_WriteStream_SmallSinglePut(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	body := []byte("small single put body")

	if err := e.WriteStream(ctx, scope, "small.txt", bytes.NewReader(body), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}

	fi, err := e.Stat(ctx, scope, "small.txt")
	if err != nil {
		t.Fatalf("Stat after write: %v", err)
	}
	if fi.Size != int64(len(body)) {
		t.Fatalf("Stat.Size = %d, want %d", fi.Size, len(body))
	}
	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "small.txt", 0, int64(len(body))+8, &buf); err != nil {
		t.Fatalf("ReadRange after write: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), body) {
		t.Fatalf("readback = %q, want %q", buf.Bytes(), body)
	}

	want := sha256.Sum256(body)
	if got := liveDigestTag(t, e, string(scope)+"/small.txt"); got != hex.EncodeToString(want[:]) {
		t.Fatalf("ocu-sha256 tag = %q, want %q", got, hex.EncodeToString(want[:]))
	}

	// Empty stream: a zero-byte object is a valid single PUT.
	if err := e.WriteStream(ctx, scope, "empty.bin", bytes.NewReader(nil), false); err != nil {
		t.Fatalf("WriteStream(empty): %v", err)
	}
	if fi, err := e.Stat(ctx, scope, "empty.bin"); err != nil || fi.Size != 0 {
		t.Fatalf("Stat(empty) = %+v, %v; want size 0", fi, err)
	}
}

// TestS3Live_WriteStream_LargeMPU pins the multipart path with a stream
// crossing several part boundaries: byte-exact spot windows, HEAD-verified
// size, and the single-pass digest tag matching the local SHA-256 — the
// multipart ETag (an MD5-of-MD5s "-N" composite) is never the content hash.
func TestS3Live_WriteStream_LargeMPU(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: skipping the 48 MiB multipart upload")
	}
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	// 48 MiB + 100 bytes -> parts of 16 MiB: 3 full + 1 short final part.
	const size = 48<<20 + 100
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i * 31 / 7)
	}

	if err := e.WriteStream(ctx, scope, "large.bin", bytes.NewReader(body), false); err != nil {
		t.Fatalf("WriteStream(48 MiB): %v", err)
	}

	fi, err := e.Stat(ctx, scope, "large.bin")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size != size {
		t.Fatalf("Stat.Size = %d, want %d", fi.Size, int64(size))
	}

	want := sha256.Sum256(body)
	if got := liveDigestTag(t, e, string(scope)+"/large.bin"); got != hex.EncodeToString(want[:]) {
		t.Fatalf("ocu-sha256 tag = %q, want %q (digest round-trip)", got, hex.EncodeToString(want[:]))
	}

	// Spot windows across part boundaries.
	for _, win := range []struct{ off, ln int64 }{
		{0, 64}, {16<<20 - 32, 64}, {32<<20 - 32, 64}, {size - 50, 100},
	} {
		var buf bytes.Buffer
		if err := e.ReadRange(ctx, scope, "large.bin", win.off, win.ln, &buf); err != nil {
			t.Fatalf("ReadRange(%d,%d): %v", win.off, win.ln, err)
		}
		end := win.off + int64(buf.Len())
		if !bytes.Equal(buf.Bytes(), body[win.off:end]) {
			t.Fatalf("window [%d,%d) differs from source", win.off, end)
		}
	}

	if n := liveMPUCount(t, e, scope); n != 0 {
		t.Fatalf("%d multipart uploads left in progress after success, want 0", n)
	}
}

// TestS3Live_WriteStream_NoReplace412 pins atomic no-replace on BOTH upload
// paths: overwrite=false against an existing key surfaces ErrAlreadyExists
// via the conditional write's 412 (single PUT) and via conditional Complete
// (multipart) — never a read-then-write check — and the loser never
// corrupts the existing content.
func TestS3Live_WriteStream_NoReplace412(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	first := []byte("the first writer wins")

	if err := e.WriteStream(ctx, scope, "f.txt", bytes.NewReader(first), false); err != nil {
		t.Fatalf("WriteStream(first): %v", err)
	}
	err := e.WriteStream(ctx, scope, "f.txt", bytes.NewReader([]byte("loser")), false)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("WriteStream(second, overwrite=false) = %v, want ErrAlreadyExists", err)
	}

	// The multipart no-replace: a >cutoff stream onto the same key. WARNING-5:
	// if the rig's backend rejects conditional Complete, this fails loudly
	// here — surface it, never silently degrade.
	big := make([]byte, 17<<20)
	err = e.WriteStream(ctx, scope, "f.txt", bytes.NewReader(big), false)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("WriteStream(multipart, overwrite=false onto existing) = %v, want ErrAlreadyExists (conditional Complete)", err)
	}
	if n := liveMPUCount(t, e, scope); n != 0 {
		t.Fatalf("%d multipart uploads left after refused conditional Complete, want 0 (aborted)", n)
	}

	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "f.txt", 0, int64(len(first))+8, &buf); err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), first) {
		t.Fatalf("content after refused overwrites = %q, want the first writer's %q", buf.Bytes(), first)
	}

	// overwrite=true replaces cleanly.
	second := []byte("replaced")
	if err := e.WriteStream(ctx, scope, "f.txt", bytes.NewReader(second), true); err != nil {
		t.Fatalf("WriteStream(overwrite=true): %v", err)
	}
	buf.Reset()
	if err := e.ReadRange(ctx, scope, "f.txt", 0, 64, &buf); err != nil || !bytes.Equal(buf.Bytes(), second) {
		t.Fatalf("readback after overwrite=true = %q, %v; want %q", buf.Bytes(), err, second)
	}
}

// TestS3Live_MPU_AbortOnError pins the abort discipline: a source failing
// mid-multipart aborts the upload — ListMultipartUploads shows ZERO
// in-progress uploads and the key never exists.
func TestS3Live_MPU_AbortOnError(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	src := &failAfterReader{serve: 20 << 20, err: errors.New("simulated source failure")}
	err := e.WriteStream(ctx, scope, "broken.bin", src, false)
	if err == nil {
		t.Fatal("WriteStream with failing source: got nil error")
	}
	if n := liveMPUCount(t, e, scope); n != 0 {
		t.Fatalf("%d multipart uploads left after failed stream, want 0 (abort-on-error)", n)
	}
	if _, serr := e.Stat(ctx, scope, "broken.bin"); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("Stat after aborted MPU = %v, want fs.ErrNotExist", serr)
	}
}

// TestS3Live_WriteStream_PartialNeverVisible pins section-9 invisibility:
// at no point does a failed stream leave readable bytes at the destination
// — a multipart object exists only after Complete.
func TestS3Live_WriteStream_PartialNeverVisible(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	src := &failAfterReader{serve: 33 << 20, err: errors.New("died mid-third-part")}
	if err := e.WriteStream(ctx, scope, "partial.bin", src, false); err == nil {
		t.Fatal("WriteStream with failing source: got nil error")
	}
	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "partial.bin", 0, 16, &buf); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadRange after failed stream = %v (read %d bytes), want fs.ErrNotExist", err, buf.Len())
	}
	entries, err := e.List(ctx, scope, ".")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, fi := range entries {
		if fi.Name == "partial.bin" {
			t.Fatal("partial.bin visible in listing after failed stream")
		}
	}
}

// TestS3Live_WriteStream_CancelCtx pins the context contract on the
// multipart path: cancellation mid-stream surfaces ctx.Err(), aborts the
// upload, and leaves no key.
func TestS3Live_WriteStream_CancelCtx(t *testing.T) {
	e, scope := liveS3Engine(t)

	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &cancelAtReader{cancel: cancel, at: 20 << 20}
	err := e.WriteStream(cctx, scope, "cancelled.bin", src, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WriteStream under cancel = %v, want errors.Is(context.Canceled)", err)
	}
	if n := liveMPUCount(t, e, scope); n != 0 {
		t.Fatalf("%d multipart uploads left after cancel, want 0 (aborted)", n)
	}
	if _, serr := e.Stat(context.Background(), scope, "cancelled.bin"); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("Stat after cancelled stream = %v, want fs.ErrNotExist", serr)
	}
}

// cancelAtReader serves pattern bytes and fires its cancel func once `at`
// bytes have been served; subsequent reads block on the (now cancelled)
// ctxReader wrapper upstream.
type cancelAtReader struct {
	cancel context.CancelFunc
	at     int
	served int
}

func (r *cancelAtReader) Read(p []byte) (int, error) {
	if r.served >= r.at {
		r.cancel()
	}
	for i := range p {
		p[i] = 'c'
	}
	r.served += len(p)
	return len(p), nil
}

// TestS3Live_MakeDir_MissingParent pins MakeDir's sentinel shapes: missing
// parent -> *fs.PathError wrapping fs.ErrNotExist; existing directory ->
// fs.ErrExist; a file at the same name -> fs.ErrExist; nested creation
// under an existing parent succeeds.
func TestS3Live_MakeDir_MissingParent(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	if err := e.MakeDir(ctx, scope, "no-parent/child"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("MakeDir(missing parent) = %v, want fs.ErrNotExist", err)
	}
	var pe *fs.PathError
	if err := e.MakeDir(ctx, scope, "no-parent/child"); !errors.As(err, &pe) {
		t.Fatalf("MakeDir(missing parent) = %T, want *fs.PathError (the local engine's shape)", err)
	}

	if err := e.MakeDir(ctx, scope, "d"); err != nil {
		t.Fatalf("MakeDir(d): %v", err)
	}
	if err := e.MakeDir(ctx, scope, "d"); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("MakeDir(existing dir) = %v, want fs.ErrExist", err)
	}
	if err := e.MakeDir(ctx, scope, "d/sub"); err != nil {
		t.Fatalf("MakeDir(d/sub) under existing parent: %v", err)
	}

	if err := e.WriteStream(ctx, scope, "f.txt", bytes.NewReader([]byte("x")), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := e.MakeDir(ctx, scope, "f.txt"); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("MakeDir(over file) = %v, want fs.ErrExist", err)
	}

	// WriteStream into a missing parent refuses too (decision 2 parity).
	if err := e.WriteStream(ctx, scope, "ghost/f.txt", bytes.NewReader([]byte("x")), false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("WriteStream(missing parent) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_RemoveFile_Parity pins the WARNING-4 remove(2) parity matrix:
// file removed; missing -> fs.ErrNotExist; EMPTY directory marker removed
// successfully; directory WITH children refuses ENOTEMPTY as *fs.PathError.
func TestS3Live_RemoveFile_Parity(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	if err := e.WriteStream(ctx, scope, "f.txt", bytes.NewReader([]byte("x")), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := e.RemoveFile(ctx, scope, "f.txt"); err != nil {
		t.Fatalf("RemoveFile(file): %v", err)
	}
	if _, err := e.Stat(ctx, scope, "f.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat after remove = %v, want fs.ErrNotExist", err)
	}

	if err := e.RemoveFile(ctx, scope, "missing.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("RemoveFile(missing) = %v, want fs.ErrNotExist", err)
	}

	if err := e.MakeDir(ctx, scope, "empty-d"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	if err := e.RemoveFile(ctx, scope, "empty-d"); err != nil {
		t.Fatalf("RemoveFile(empty dir) = %v, want success (local remove(2) parity)", err)
	}
	if _, err := e.Stat(ctx, scope, "empty-d"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(empty-d after remove) = %v, want fs.ErrNotExist", err)
	}

	if err := e.MakeDir(ctx, scope, "full-d"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	if err := e.WriteStream(ctx, scope, "full-d/child.txt", bytes.NewReader([]byte("y")), false); err != nil {
		t.Fatalf("WriteStream(child): %v", err)
	}
	err := e.RemoveFile(ctx, scope, "full-d")
	var pe *fs.PathError
	if !errors.As(err, &pe) || !errors.Is(err, syscall.ENOTEMPTY) {
		t.Fatalf("RemoveFile(non-empty dir) = %v, want *fs.PathError wrapping ENOTEMPTY", err)
	}
	if _, serr := e.Stat(ctx, scope, "full-d/child.txt"); serr != nil {
		t.Fatalf("child vanished after refused dir remove: %v", serr)
	}
}

// --- 13-08: copy/move/removedir ---------------------------------------------

// TestS3Live_CopyFile_MissingSource pins the missing-source refusal.
func TestS3Live_CopyFile_MissingSource(t *testing.T) {
	e, scope := liveS3Engine(t)
	if err := e.CopyFile(context.Background(), scope, "ghost.txt", "dst.txt", false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("CopyFile(missing source) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_CopyFile_NoReplace412 pins the atomic no-replace copy: the
// overwrite=false path is a multipart copy completed with If-None-Match, so
// an existing destination refuses ErrAlreadyExists without a read-then-write
// race, at any size; the destination's prior content survives.
func TestS3Live_CopyFile_NoReplace412(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	if err := e.WriteStream(ctx, scope, "src.txt", bytes.NewReader([]byte("source body")), false); err != nil {
		t.Fatalf("WriteStream(src): %v", err)
	}
	if err := e.WriteStream(ctx, scope, "dst.txt", bytes.NewReader([]byte("existing dst")), false); err != nil {
		t.Fatalf("WriteStream(dst): %v", err)
	}

	if err := e.CopyFile(ctx, scope, "src.txt", "dst.txt", false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("CopyFile(overwrite=false onto existing) = %v, want ErrAlreadyExists", err)
	}
	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "dst.txt", 0, 64, &buf); err != nil || buf.String() != "existing dst" {
		t.Fatalf("dst after refused copy = %q, %v; want untouched %q", buf.String(), err, "existing dst")
	}
	if n := liveMPUCount(t, e, scope); n != 0 {
		t.Fatalf("%d multipart uploads left after refused conditional copy, want 0", n)
	}

	// Fresh destination: the conditional multipart copy succeeds and the
	// digest tag travels with the copy.
	if err := e.CopyFile(ctx, scope, "src.txt", "fresh.txt", false); err != nil {
		t.Fatalf("CopyFile(fresh dst): %v", err)
	}
	want := sha256.Sum256([]byte("source body"))
	if got := liveDigestTag(t, e, string(scope)+"/fresh.txt"); got != hex.EncodeToString(want[:]) {
		t.Fatalf("copied digest tag = %q, want %q", got, hex.EncodeToString(want[:]))
	}

	// Zero-byte source with overwrite=false (the empty-MPU special case).
	if err := e.WriteStream(ctx, scope, "empty.bin", bytes.NewReader(nil), false); err != nil {
		t.Fatalf("WriteStream(empty): %v", err)
	}
	if err := e.CopyFile(ctx, scope, "empty.bin", "empty-copy.bin", false); err != nil {
		t.Fatalf("CopyFile(empty, no-replace): %v", err)
	}
	if fi, err := e.Stat(ctx, scope, "empty-copy.bin"); err != nil || fi.Size != 0 {
		t.Fatalf("Stat(empty-copy) = %+v, %v; want zero-byte file", fi, err)
	}
	if err := e.CopyFile(ctx, scope, "empty.bin", "empty-copy.bin", false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("CopyFile(empty onto existing) = %v, want ErrAlreadyExists", err)
	}
}

// TestS3Live_Copy_SameObjectGuard pins the same-object guard: src == dst
// never destroys the object — overwrite=false refuses, overwrite=true is
// the identity, and a same-key MoveFile leaves the source in place.
func TestS3Live_Copy_SameObjectGuard(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	body := []byte("survivor")

	if err := e.WriteStream(ctx, scope, "same.txt", bytes.NewReader(body), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := e.CopyFile(ctx, scope, "same.txt", "same.txt", false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("CopyFile(same, overwrite=false) = %v, want ErrAlreadyExists", err)
	}
	if err := e.CopyFile(ctx, scope, "same.txt", "same.txt", true); err != nil {
		t.Fatalf("CopyFile(same, overwrite=true) = %v, want nil identity", err)
	}
	if err := e.MoveFile(ctx, scope, "same.txt", "same.txt", true); err != nil {
		t.Fatalf("MoveFile(same) = %v, want nil with source intact", err)
	}
	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "same.txt", 0, 64, &buf); err != nil || !bytes.Equal(buf.Bytes(), body) {
		t.Fatalf("source after same-object ops = %q, %v; want %q intact", buf.Bytes(), err, body)
	}
}

// TestS3Live_Copy_SpecialCharKeys pins the x-amz-copy-source URL-encoding
// row: keys with spaces, '+', '%', and (NFC) unicode copy byte-exactly — an
// unencoded copy source would target the wrong object or 404.
func TestS3Live_Copy_SpecialCharKeys(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	for i, name := range []string{
		"with space.txt",
		"plus+sign.txt",
		"percent%41.txt",
		"café-ümläut.bin",
		"mixed +%& name.dat",
	} {
		body := []byte(fmt.Sprintf("special body %d", i))
		if err := e.WriteStream(ctx, scope, name, bytes.NewReader(body), false); err != nil {
			t.Fatalf("WriteStream(%q): %v", name, err)
		}
		dst := fmt.Sprintf("copies/c%d", i)
		if i == 0 {
			if err := e.MakeDir(ctx, scope, "copies"); err != nil {
				t.Fatalf("MakeDir(copies): %v", err)
			}
		}
		if err := e.CopyFile(ctx, scope, name, dst, false); err != nil {
			t.Fatalf("CopyFile(%q -> %q): %v", name, dst, err)
		}
		var buf bytes.Buffer
		if err := e.ReadRange(ctx, scope, dst, 0, 128, &buf); err != nil {
			t.Fatalf("ReadRange(%q): %v", dst, err)
		}
		if !bytes.Equal(buf.Bytes(), body) {
			t.Fatalf("copy of %q = %q, want %q (encoding corruption)", name, buf.Bytes(), body)
		}
	}
}

// TestS3Live_CopyThresholdSwitch drives the multipart-copy path end-to-end
// with a test-lowered threshold (the 5 GiB production switch is a
// constructor field, never exercised with a 5 GiB object): an
// overwrite=true copy above the threshold goes UploadPartCopy and lands
// byte-identical with its digest tag.
func TestS3Live_CopyThresholdSwitch(t *testing.T) {
	e, scope := liveS3Engine(t)
	e.copyThreshold = 1 << 20 // 1 MiB: force the multipart-copy path
	ctx := context.Background()

	body := make([]byte, 2<<20+17)
	for i := range body {
		body[i] = byte(i * 13 / 5)
	}
	if err := e.WriteStream(ctx, scope, "big-src.bin", bytes.NewReader(body), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := e.CopyFile(ctx, scope, "big-src.bin", "big-dst.bin", true); err != nil {
		t.Fatalf("CopyFile(above threshold, overwrite=true): %v", err)
	}

	fi, err := e.Stat(ctx, scope, "big-dst.bin")
	if err != nil || fi.Size != int64(len(body)) {
		t.Fatalf("Stat(big-dst) = %+v, %v; want size %d", fi, err, len(body))
	}
	want := sha256.Sum256(body)
	if got := liveDigestTag(t, e, string(scope)+"/big-dst.bin"); got != hex.EncodeToString(want[:]) {
		t.Fatalf("multipart-copy digest tag = %q, want %q", got, hex.EncodeToString(want[:]))
	}
	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "big-dst.bin", int64(len(body))-64, 128, &buf); err != nil {
		t.Fatalf("ReadRange(tail): %v", err)
	}
	if !bytes.Equal(buf.Bytes(), body[len(body)-64:]) {
		t.Fatal("multipart-copy tail bytes differ from source")
	}
}

// TestS3Live_MoveFile_VerifyThenDelete pins the copy -> verify -> delete
// ordering: after a move the destination carries the bytes AND the digest
// tag, the source is gone; a move of a zero-byte file works; a missing
// source refuses with the source side untouched.
func TestS3Live_MoveFile_VerifyThenDelete(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	body := []byte("movable bytes")

	if err := e.WriteStream(ctx, scope, "from.txt", bytes.NewReader(body), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := e.MoveFile(ctx, scope, "from.txt", "to.txt", false); err != nil {
		t.Fatalf("MoveFile: %v", err)
	}
	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "to.txt", 0, 64, &buf); err != nil || !bytes.Equal(buf.Bytes(), body) {
		t.Fatalf("dst after move = %q, %v; want %q", buf.Bytes(), err, body)
	}
	want := sha256.Sum256(body)
	if got := liveDigestTag(t, e, string(scope)+"/to.txt"); got != hex.EncodeToString(want[:]) {
		t.Fatalf("digest tag after move = %q, want %q", got, hex.EncodeToString(want[:]))
	}
	if _, err := e.Stat(ctx, scope, "from.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("source after move = %v, want fs.ErrNotExist", err)
	}

	if err := e.WriteStream(ctx, scope, "zero.bin", bytes.NewReader(nil), false); err != nil {
		t.Fatalf("WriteStream(zero): %v", err)
	}
	if err := e.MoveFile(ctx, scope, "zero.bin", "zero-moved.bin", false); err != nil {
		t.Fatalf("MoveFile(zero-byte): %v", err)
	}
	if fi, err := e.Stat(ctx, scope, "zero-moved.bin"); err != nil || fi.Size != 0 {
		t.Fatalf("Stat(zero-moved) = %+v, %v", fi, err)
	}

	if err := e.MoveFile(ctx, scope, "ghost.txt", "anywhere.txt", false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("MoveFile(missing source) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_MoveDest_PathContainment pins section 8 on move/copy
// destinations: dot-dot and absolute destinations refuse ErrInvalidPath and
// NOTHING is written — a move is not a containment hole.
func TestS3Live_MoveDest_PathContainment(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	if err := e.WriteStream(ctx, scope, "safe.txt", bytes.NewReader([]byte("contained")), false); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := e.MakeDir(ctx, scope, "d"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}

	for _, dst := range []string{"../escape.txt", "/abs.txt", "a/../../up.txt", "s3://bucket/key", "x\x00y"} {
		if err := e.CopyFile(ctx, scope, "safe.txt", dst, false); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("CopyFile(dst=%q) = %v, want ErrInvalidPath", dst, err)
		}
		if err := e.MoveFile(ctx, scope, "safe.txt", dst, false); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("MoveFile(dst=%q) = %v, want ErrInvalidPath", dst, err)
		}
		if err := e.MoveDir(ctx, scope, "d", dst, false); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("MoveDir(dst=%q) = %v, want ErrInvalidPath", dst, err)
		}
	}
	// The source survived every refused attempt.
	if _, err := e.Stat(ctx, scope, "safe.txt"); err != nil {
		t.Fatalf("source after refused moves: %v", err)
	}
}

// TestS3Live_MoveDir_Recursive pins the per-object subtree move: files,
// nested subdirectories, and empty-directory markers all relocate; the
// source prefix is left empty; overwrite=false refuses an existing
// destination directory.
func TestS3Live_MoveDir_Recursive(t *testing.T) {
	e, scope := liveS3Engine(t)
	ctx := context.Background()

	if err := e.MakeDir(ctx, scope, "tree"); err != nil {
		t.Fatalf("MakeDir(tree): %v", err)
	}
	if err := e.WriteStream(ctx, scope, "tree/f1.txt", bytes.NewReader([]byte("one")), false); err != nil {
		t.Fatalf("WriteStream(f1): %v", err)
	}
	if err := e.MakeDir(ctx, scope, "tree/sub"); err != nil {
		t.Fatalf("MakeDir(sub): %v", err)
	}
	if err := e.WriteStream(ctx, scope, "tree/sub/f2.txt", bytes.NewReader([]byte("two")), false); err != nil {
		t.Fatalf("WriteStream(f2): %v", err)
	}
	if err := e.MakeDir(ctx, scope, "tree/hollow"); err != nil {
		t.Fatalf("MakeDir(hollow): %v", err)
	}

	if err := e.MoveDir(ctx, scope, "tree", "moved", false); err != nil {
		t.Fatalf("MoveDir: %v", err)
	}

	var buf bytes.Buffer
	if err := e.ReadRange(ctx, scope, "moved/f1.txt", 0, 16, &buf); err != nil || buf.String() != "one" {
		t.Fatalf("moved/f1.txt = %q, %v", buf.String(), err)
	}
	buf.Reset()
	if err := e.ReadRange(ctx, scope, "moved/sub/f2.txt", 0, 16, &buf); err != nil || buf.String() != "two" {
		t.Fatalf("moved/sub/f2.txt = %q, %v", buf.String(), err)
	}
	if fi, err := e.Stat(ctx, scope, "moved/hollow"); err != nil || !fi.IsDir {
		t.Fatalf("Stat(moved/hollow) = %+v, %v; want empty dir moved", fi, err)
	}
	if _, err := e.Stat(ctx, scope, "tree"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(tree after move) = %v, want fs.ErrNotExist", err)
	}
	if _, err := e.List(ctx, scope, "tree"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("List(tree after move) = %v, want fs.ErrNotExist", err)
	}

	// overwrite=false onto an existing destination directory refuses.
	if err := e.MakeDir(ctx, scope, "tree2"); err != nil {
		t.Fatalf("MakeDir(tree2): %v", err)
	}
	if err := e.MoveDir(ctx, scope, "moved", "tree2", false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("MoveDir(onto existing, overwrite=false) = %v, want ErrAlreadyExists", err)
	}
	// Missing source refuses.
	if err := e.MoveDir(ctx, scope, "ghost-dir", "elsewhere", false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("MoveDir(missing source) = %v, want fs.ErrNotExist", err)
	}
}

// TestS3Live_RemoveDir_Over1000Keys exercises the batch cap: a directory
// with more keys than one DeleteObjects call allows is swept completely,
// and a missing directory is a silent no-op.
func TestS3Live_RemoveDir_Over1000Keys(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: skipping the >1000-key sweep seed")
	}
	e, scope := liveS3Engine(t)
	ctx := context.Background()
	prefix := string(scope) + "/"
	const n = 1100

	liveSeed(t, e, prefix+"sweep/", nil)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			key := fmt.Sprintf("%ssweep/k-%04d", prefix, i)
			if _, err := e.client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: aws.String(e.bucket), Key: aws.String(key), Body: bytes.NewReader([]byte{1}),
			}); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("sweep seed: %v", err)
	}

	if err := e.RemoveDir(ctx, scope, "sweep"); err != nil {
		t.Fatalf("RemoveDir(1100 keys): %v", err)
	}
	if _, err := e.Stat(ctx, scope, "sweep"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(sweep after remove) = %v, want fs.ErrNotExist", err)
	}
	if _, err := e.Stat(ctx, scope, "sweep/k-0500"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(swept key) = %v, want fs.ErrNotExist", err)
	}

	// Missing directory: silent no-op (the seam contract).
	if err := e.RemoveDir(ctx, scope, "never-existed"); err != nil {
		t.Fatalf("RemoveDir(missing) = %v, want nil no-op", err)
	}
}
