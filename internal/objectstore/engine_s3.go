// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"golang.org/x/text/unicode/norm"
)

// S3 layer constants. The part size and single-PUT cutoff bound the engine's
// memory per stream (NFR-SEC-46): one reused part buffer, never a
// whole-object read.
const (
	// s3MinPartSize is the backend's minimum size for every non-final
	// multipart part.
	s3MinPartSize = 5 << 20 // 5 MiB
	// s3MaxParts is the backend's hard cap on parts per multipart upload.
	s3MaxParts = 10000
	// s3DefaultPartSize is the default reused part-buffer size.
	s3DefaultPartSize = 16 << 20 // 16 MiB
	// s3DefaultSinglePutCutoff is the default size at or under which a
	// stream goes up as one PutObject instead of a multipart upload.
	s3DefaultSinglePutCutoff = 16 << 20 // 16 MiB
	// s3MaxKeyBytes is the backend's maximum object-key length in BYTES
	// (UTF-8), enforced on the full joined key — never rune count.
	s3MaxKeyBytes = 1024
	// s3MaxCopyObjectSize is the size above which a server-side copy must
	// use multipart copy: a plain CopyObject above it is refused by the
	// backend.
	s3MaxCopyObjectSize = 5 << 30 // 5 GiB
	// s3MaxRetryAttempts caps the SDK retryer's attempts per request; the
	// adaptive pacer spaces them, the cap stops the spin.
	s3MaxRetryAttempts = 5
)

// Terminal S3-layer error classes (decision 7): neither retryable nor
// mappable onto an existing sentinel; each names its likely operational
// cause so the operator can act. Match them with errors.Is. No credential
// byte ever appears in these messages.
var (
	// errS3AccessDenied is the terminal authorization refusal from the
	// backend: never retried; usually a storage-lane or bucket-policy
	// misconfiguration, not a transient condition.
	errS3AccessDenied = errors.New("objectstore: backend access denied (check storage-lane and bucket policy; not retried)")
	// errS3ClockSkew is the terminal request-time refusal: the host clock
	// disagrees with the backend beyond tolerance; retrying cannot fix a
	// clock — never blind-retried.
	errS3ClockSkew = errors.New("objectstore: backend refused request time (host clock skew; fix the clock, not retried)")
)

// S3Config configures NewS3Engine. None of these fields carries a secret
// value directly: Credentials is an opaque provider whose secret material
// never leaves it (NFR-SEC-25).
type S3Config struct {
	// Endpoint is the backend URL; empty means the SDK's default resolution
	// (real AWS). Any non-empty value is a custom endpoint (MinIO, RGW) and
	// switches request/response checksums to WhenRequired — the documented
	// custom-endpoint mode where default checksum trailers can be handled
	// differently by S3-compatible backends and a mismatch masquerades as
	// data corruption.
	Endpoint string
	// Region is the signing region (custom endpoints still require one).
	Region string
	// Bucket is the single bucket all scopes live under.
	Bucket string
	// UsePathStyle selects path-style addressing (required by most
	// single-host S3-compatible backends).
	UsePathStyle bool
	// Credentials supplies the backend credential. REQUIRED — the engine
	// never falls back to ambient/environment credential chains; the intake
	// seam (CredentialSource) is the only feeder.
	Credentials aws.CredentialsProvider
	// HTTPClient is the injected dial path. When the storage lane is
	// composed (ADR-0011) this is the lane transport and the ONLY way the
	// engine reaches the network; nil selects the SDK default client and is
	// permitted for direct test rigs only.
	HTTPClient *http.Client
	// PartSize is the multipart part size in bytes; 0 selects the default
	// (16 MiB). Must be at least the backend's 5 MiB non-final-part minimum.
	PartSize int64
	// SinglePutCutoff is the size at or under which a stream is a single
	// PutObject; 0 selects the default (16 MiB).
	SinglePutCutoff int64
}

// s3Engine is the network backend engine (ADR-0010's second kind). It is the
// deployment's only backend-protocol speaker (NFR-SEC-25); every verb routes
// its backend error through mapS3Err and every key through objectKey — the
// sole join site.
type s3Engine struct {
	client          *s3.Client
	bucket          string
	partSize        int64
	singlePutCutoff int64
	// copyThreshold is the size above which CopyFile switches to multipart
	// copy. Production value is s3MaxCopyObjectSize; tests may lower it to
	// drive the multipart-copy path against small live objects.
	copyThreshold int64

	// versioningProbed/versioningOn cache the bucket-versioning probe for
	// the teardown sweep (filled in by the lifecycle verbs).
	versioningProbed bool
	versioningOn     bool
}

var _ Engine = (*s3Engine)(nil)

// NewS3Engine builds the S3 engine per S3Config. The constructor pins the
// resilience posture: adaptive retry mode (client-rate-limited backoff with
// jitter, honoring backend pacing) with a capped attempt count, and
// WhenRequired checksums whenever a custom endpoint is configured.
func NewS3Engine(cfg S3Config) (Engine, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("objectstore: s3 engine requires a bucket")
	}
	if cfg.Region == "" {
		return nil, errors.New("objectstore: s3 engine requires a region")
	}
	if cfg.Credentials == nil {
		return nil, errors.New("objectstore: s3 engine requires a credentials provider (no ambient fallback)")
	}
	partSize := cfg.PartSize
	if partSize == 0 {
		partSize = s3DefaultPartSize
	}
	if partSize < s3MinPartSize {
		return nil, fmt.Errorf("objectstore: s3 part size %d below the %d-byte non-final-part minimum", partSize, int64(s3MinPartSize))
	}
	cutoff := cfg.SinglePutCutoff
	if cutoff == 0 {
		cutoff = s3DefaultSinglePutCutoff
	}

	opts := s3.Options{
		Region:       cfg.Region,
		Credentials:  cfg.Credentials,
		UsePathStyle: cfg.UsePathStyle,
		Retryer: retry.NewAdaptiveMode(func(o *retry.AdaptiveModeOptions) {
			o.StandardOptions = append(o.StandardOptions, func(so *retry.StandardOptions) {
				so.MaxAttempts = s3MaxRetryAttempts
			})
		}),
	}
	if cfg.HTTPClient != nil {
		opts.HTTPClient = cfg.HTTPClient
	}
	if cfg.Endpoint != "" {
		opts.BaseEndpoint = aws.String(cfg.Endpoint)
		opts.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		opts.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	}

	return &s3Engine{
		client:          s3.New(opts),
		bucket:          cfg.Bucket,
		partSize:        partSize,
		singlePutCutoff: cutoff,
		copyThreshold:   s3MaxCopyObjectSize,
	}, nil
}

// --- Key mapping: the sole join site -------------------------------------

// s3ValidatePath layers the S3 key rules on top of the engine-neutral
// lexical stage. It REUSES ValidatePath (NUL, URL scheme, absolute, dot-dot,
// empty, depth bomb — never forked), then enforces the S3 layer on the
// cleaned form: valid UTF-8, no control (Cc) or format (Cf) characters, and
// NFC normalization REQUIRED. Rejecting non-NFC input is what makes
// normalization collisions impossible by construction: a key that would
// collide with an existing key only after NFC normalization is refused at
// intake — never silently merged onto the existing object.
//
// The returned form's separator is "/" (the engine targets POSIX hosts, so
// ValidatePath's cleaned form already uses it); a backslash is a literal
// name byte, never a separator — replacing it would silently merge two
// distinct names, the same merge class the NFC rule refuses. The 1024-byte
// cap binds on the full joined key and is enforced in objectKey, where the
// scope prefix is known.
func s3ValidatePath(p string) (string, error) {
	clean, err := ValidatePath(p)
	if err != nil {
		return "", err
	}
	if !utf8.ValidString(clean) {
		return "", fmt.Errorf("%w: invalid utf-8", ErrInvalidPath)
	}
	for _, r := range clean {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("%w: control or format character", ErrInvalidPath)
		}
	}
	if !norm.NFC.IsNormalString(clean) {
		return "", fmt.Errorf("%w: not NFC-normalized", ErrInvalidPath)
	}
	return clean, nil
}

// objectKey is the SOLE join site: every S3 key the engine ever sends is
// built here and nowhere else. The trusted scope id is validated for shape
// (defense-in-depth on the prefix join), the untrusted path goes through the
// full lexical + S3 validator, and the joined key is capped at the backend's
// 1024-byte limit. The result is always strictly inside the scope's "<id>/"
// prefix — the containment boundary on a flat keyspace.
//
// The relative path "." (the scope root) is NOT a valid object key; callers
// that operate on the scope root handle it before calling objectKey.
func (e *s3Engine) objectKey(scope ScopeID, p string) (string, error) {
	if err := validateScopeID(scope); err != nil {
		return "", err
	}
	clean, err := s3ValidatePath(p)
	if err != nil {
		return "", err
	}
	key := string(scope) + "/" + clean
	if len(key) > s3MaxKeyBytes {
		return "", fmt.Errorf("%w: joined key exceeds %d bytes", ErrInvalidPath, s3MaxKeyBytes)
	}
	return key, nil
}

// scopePrefix returns the scope's key prefix "<id>/" — the listing and sweep
// boundary. The scope id passes the same shape guard as in objectKey.
func (e *s3Engine) scopePrefix(scope ScopeID) (string, error) {
	if err := validateScopeID(scope); err != nil {
		return "", err
	}
	return string(scope) + "/", nil
}

// dirMarkerKey returns the zero-byte directory-marker key for an object key:
// the key with a trailing slash. ONE directory convention, never mixed:
// markers are written by MakeDir, excluded from listings and from the
// not-empty check, and swept with everything else at teardown.
func dirMarkerKey(key string) string {
	return key + "/"
}

// parentKey returns the object key of the parent directory of key within the
// scope, or "" when the parent is the scope root itself.
func parentKey(key string) string {
	dir := path.Dir(key)
	parts := strings.SplitN(key, "/", 2)
	if len(parts) < 2 || !strings.Contains(parts[1], "/") {
		// key is "<scope>/<leaf>" — the parent is the scope root.
		return ""
	}
	return dir
}

// --- Error taxonomy: one mapper ------------------------------------------

// mapS3Err is the single backend-error mapper (decision 7): every verb
// routes its SDK error through here before returning. Context cancellation
// passes through first so the Engine context contract (ctx.Err() is
// errors.Is-matchable) survives the SDK's wrapping. Backend codes map onto
// the package sentinels; transport-level timeouts and connection failures
// are transient; authorization and clock-skew refusals are terminal typed
// errors that are never retried. No credential material ever appears in the
// returned error.
func mapS3Err(verb string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("objectstore: s3 %s: %w", verb, err)
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NoSuchBucket", "NotFound", "404":
			return fmt.Errorf("objectstore: s3 %s: %w", verb, fs.ErrNotExist)
		case "PreconditionFailed":
			return fmt.Errorf("objectstore: s3 %s: %w", verb, ErrAlreadyExists)
		case "SlowDown", "ServiceUnavailable", "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequests":
			return fmt.Errorf("objectstore: s3 %s: %w", verb, ErrThrottled)
		case "RequestTimeout", "InternalError":
			return fmt.Errorf("objectstore: s3 %s: %w", verb, ErrTransient)
		case "AccessDenied":
			return fmt.Errorf("s3 %s: %w", verb, errS3AccessDenied)
		case "RequestTimeTooSkewed":
			return fmt.Errorf("s3 %s: %w", verb, errS3ClockSkew)
		}
	}

	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		switch sc := respErr.HTTPStatusCode(); {
		case sc == http.StatusNotFound:
			return fmt.Errorf("objectstore: s3 %s: %w", verb, fs.ErrNotExist)
		case sc == http.StatusPreconditionFailed:
			return fmt.Errorf("objectstore: s3 %s: %w", verb, ErrAlreadyExists)
		case sc == http.StatusForbidden:
			return fmt.Errorf("s3 %s: %w", verb, errS3AccessDenied)
		case sc == http.StatusServiceUnavailable, sc == http.StatusTooManyRequests:
			return fmt.Errorf("objectstore: s3 %s: %w", verb, ErrThrottled)
		case sc >= 500:
			return fmt.Errorf("objectstore: s3 %s: %w", verb, ErrTransient)
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("objectstore: s3 %s: %w (%v)", verb, ErrTransient, netErr)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Errorf("objectstore: s3 %s: %w (%v)", verb, ErrTransient, opErr.Op)
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("objectstore: s3 %s: %w (truncated response)", verb, ErrTransient)
	}

	return fmt.Errorf("objectstore: s3 %s: %w", verb, err)
}

// --- Engine verbs ----------------------------------------------------------
//
// The data and lifecycle verbs land wave by wave; until each lands it
// refuses with ErrNotImplemented. Nothing constructs s3Engine in production
// until the daemon composes it (the -engine s3 refusal stands meanwhile).

func (e *s3Engine) Kind() EngineKind { return S3 }

func (e *s3Engine) ProvisionScope(_ context.Context, _ ScopeID) error { return ErrNotImplemented }

func (e *s3Engine) TeardownScope(_ context.Context, _ ScopeID) error { return ErrNotImplemented }

func (e *s3Engine) List(_ context.Context, _ ScopeID, _ string) ([]FileInfo, error) {
	return nil, ErrNotImplemented
}

func (e *s3Engine) Stat(_ context.Context, _ ScopeID, _ string) (FileInfo, error) {
	return FileInfo{}, ErrNotImplemented
}

func (e *s3Engine) MakeDir(_ context.Context, _ ScopeID, _ string) error { return ErrNotImplemented }

func (e *s3Engine) MoveDir(_ context.Context, _ ScopeID, _, _ string, _ bool) error {
	return ErrNotImplemented
}

func (e *s3Engine) RemoveDir(_ context.Context, _ ScopeID, _ string) error {
	return ErrNotImplemented
}

func (e *s3Engine) CopyFile(_ context.Context, _ ScopeID, _, _ string, _ bool) error {
	return ErrNotImplemented
}

func (e *s3Engine) MoveFile(_ context.Context, _ ScopeID, _, _ string, _ bool) error {
	return ErrNotImplemented
}

func (e *s3Engine) RemoveFile(_ context.Context, _ ScopeID, _ string) error {
	return ErrNotImplemented
}

func (e *s3Engine) ReadRange(_ context.Context, _ ScopeID, _ string, _, _ int64, _ io.Writer) error {
	return ErrNotImplemented
}

func (e *s3Engine) WriteStream(_ context.Context, _ ScopeID, _ string, _ io.Reader, _ bool) error {
	return ErrNotImplemented
}
