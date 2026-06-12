// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
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
