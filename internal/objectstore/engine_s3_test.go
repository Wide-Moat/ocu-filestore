// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
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
	if err := eng.MakeDir(context.Background(), "fs1", "d"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("MakeDir scaffold error = %v, want ErrNotImplemented until 13-07", err)
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
