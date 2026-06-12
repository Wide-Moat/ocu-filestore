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
	"io"
	"io/fs"
	"net"
	"net/http"
	"path"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
	// errS3TooManyParts is the typed stream-size refusal: the stream would
	// exceed the backend's part ceiling for the configured part size; the
	// multipart upload is aborted before refusing.
	errS3TooManyParts = errors.New("objectstore: stream exceeds the multipart part ceiling")
)

// digestTagKey is the object tag carrying the streamed SHA-256 (hex) of the
// object's content bytes. A TAG, not create-time metadata: the digest of a
// multipart stream is only known after the last part, while object metadata
// is immutable from CreateMultipartUpload on — and buffering the stream to
// learn the digest first would break the bounded-memory rule (SEC-46). The
// multipart ETag is an MD5-of-MD5s composite and is NEVER used as a content
// hash; this tag is the content digest for copy/move verification.
const digestTagKey = "ocu-sha256"

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
	if cutoff > partSize {
		// The single-PUT decision is made on the first part buffer; a cutoff
		// above the buffer size could never bind. Clamp, never grow memory.
		cutoff = partSize
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

// List returns ONE level of entries under path ("." = scope root):
// ListObjectsV2 with Prefix + Delimiter="/", FULLY paginated via
// ContinuationToken (a page-1-only listing is the classic under-report bug).
// CommonPrefixes are the subdirectories (an empty subdir appears through its
// marker rolling into a CommonPrefix), Contents are the files; the
// directory's OWN marker is excluded from the entries. A non-existent
// directory — no marker, no keys — refuses with fs.ErrNotExist, mirroring
// the local engine; the scope root always lists (possibly empty: prefixes
// are virtual and provisioning creates no key).
func (e *s3Engine) List(ctx context.Context, scope ScopeID, p string) ([]FileInfo, error) {
	var prefix string
	if p == "." {
		pref, err := e.scopePrefix(scope)
		if err != nil {
			return nil, err
		}
		prefix = pref
	} else {
		key, err := e.objectKey(scope, p)
		if err != nil {
			return nil, err
		}
		prefix = dirMarkerKey(key)
	}

	infos := make([]FileInfo, 0, 16)
	sawAny := false
	var token *string
	for {
		out, err := e.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(e.bucket),
			Prefix:            aws.String(prefix),
			Delimiter:         aws.String("/"),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, mapS3Err("list", err)
		}
		for _, cp := range out.CommonPrefixes {
			sawAny = true
			name := strings.TrimSuffix(strings.TrimPrefix(aws.ToString(cp.Prefix), prefix), "/")
			if name == "" {
				continue
			}
			infos = append(infos, FileInfo{Name: name, IsDir: true})
		}
		for _, obj := range out.Contents {
			sawAny = true
			k := aws.ToString(obj.Key)
			if k == prefix {
				continue // the directory's own marker is never an entry
			}
			infos = append(infos, FileInfo{
				Name:    path.Base(k),
				Size:    aws.ToInt64(obj.Size),
				ModTime: aws.ToTime(obj.LastModified),
			})
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		token = out.NextContinuationToken
	}

	if p != "." && !sawAny {
		return nil, fmt.Errorf("objectstore: s3 list %q: %w", p, fs.ErrNotExist)
	}
	return infos, nil
}

// Stat resolves the named path: the object key first; on 404, the directory
// marker; on 404 again, a one-key prefix probe (a directory with children
// but a lost marker is still a directory); otherwise fs.ErrNotExist.
func (e *s3Engine) Stat(ctx context.Context, scope ScopeID, p string) (FileInfo, error) {
	key, err := e.objectKey(scope, p)
	if err != nil {
		return FileInfo{}, err
	}

	head, err := e.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(key),
	})
	if err == nil {
		return FileInfo{
			Name:    path.Base(key),
			Size:    aws.ToInt64(head.ContentLength),
			ModTime: aws.ToTime(head.LastModified),
		}, nil
	}
	if mapped := mapS3Err("stat", err); !errors.Is(mapped, fs.ErrNotExist) {
		return FileInfo{}, mapped
	}

	marker := dirMarkerKey(key)
	mhead, merr := e.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(marker),
	})
	if merr == nil {
		return FileInfo{Name: path.Base(key), ModTime: aws.ToTime(mhead.LastModified), IsDir: true}, nil
	}
	if mapped := mapS3Err("stat", merr); !errors.Is(mapped, fs.ErrNotExist) {
		return FileInfo{}, mapped
	}

	probe, perr := e.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(e.bucket), Prefix: aws.String(marker), MaxKeys: aws.Int32(1),
	})
	if perr != nil {
		return FileInfo{}, mapS3Err("stat", perr)
	}
	if len(probe.Contents) > 0 {
		return FileInfo{Name: path.Base(key), IsDir: true}, nil
	}
	return FileInfo{}, fmt.Errorf("objectstore: s3 stat %q: %w", p, fs.ErrNotExist)
}

// dirExists reports whether the directory named by dirKey exists: marker
// present, or any key under its prefix (a directory with children but a
// lost marker is still a directory).
func (e *s3Engine) dirExists(ctx context.Context, dirKey string) (bool, error) {
	marker := dirMarkerKey(dirKey)
	_, err := e.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(marker),
	})
	if err == nil {
		return true, nil
	}
	if mapped := mapS3Err("stat", err); !errors.Is(mapped, fs.ErrNotExist) {
		return false, mapped
	}
	probe, perr := e.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(e.bucket), Prefix: aws.String(marker), MaxKeys: aws.Int32(1),
	})
	if perr != nil {
		return false, mapS3Err("stat", perr)
	}
	return len(probe.Contents) > 0, nil
}

// parentExists reports whether key's parent directory exists; the scope
// root always exists (prefixes are virtual).
func (e *s3Engine) parentExists(ctx context.Context, key string) (bool, error) {
	parent := parentKey(key)
	if parent == "" {
		return true, nil
	}
	return e.dirExists(ctx, parent)
}

// keyExists reports whether an object exists at exactly key.
func (e *s3Engine) keyExists(ctx context.Context, key string) (bool, error) {
	_, err := e.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(key),
	})
	if err == nil {
		return true, nil
	}
	if mapped := mapS3Err("stat", err); !errors.Is(mapped, fs.ErrNotExist) {
		return false, mapped
	}
	return false, nil
}

// MakeDir creates a single directory level: parent must exist; an existing
// directory (or a file at the same name) surfaces as a *fs.PathError
// wrapping fs.ErrExist — the same EEXIST shape the local engine produces,
// which the deny spine's classification ordering depends on. The marker PUT
// is conditional (If-None-Match), so two concurrent MakeDirs race to
// exactly one winner.
func (e *s3Engine) MakeDir(ctx context.Context, scope ScopeID, p string) error {
	key, err := e.objectKey(scope, p)
	if err != nil {
		return err
	}
	ok, err := e.parentExists(ctx, key)
	if err != nil {
		return err
	}
	if !ok {
		return &fs.PathError{Op: "mkdir", Path: p, Err: fs.ErrNotExist}
	}
	// A file at the same name refuses EEXIST (parity with mkdir(2)).
	if exists, err := e.keyExists(ctx, key); err != nil {
		return err
	} else if exists {
		return &fs.PathError{Op: "mkdir", Path: p, Err: fs.ErrExist}
	}

	marker := dirMarkerKey(key)
	_, perr := e.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(e.bucket),
		Key:           aws.String(marker),
		Body:          bytes.NewReader(nil),
		ContentLength: aws.Int64(0),
		IfNoneMatch:   aws.String("*"),
	})
	if perr != nil {
		if mapped := mapS3Err("mkdir", perr); errors.Is(mapped, ErrAlreadyExists) {
			return &fs.PathError{Op: "mkdir", Path: p, Err: fs.ErrExist}
		} else {
			return mapped
		}
	}
	return nil
}

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

// RemoveFile removes a single object. A directory target mirrors the local
// engine's remove(2) semantics exactly: an EMPTY directory's marker is
// removed successfully; a directory WITH children refuses with a
// *fs.PathError wrapping ENOTEMPTY (the local engine's non-empty refusal
// shape). A missing path refuses fs.ErrNotExist.
func (e *s3Engine) RemoveFile(ctx context.Context, scope ScopeID, p string) error {
	key, err := e.objectKey(scope, p)
	if err != nil {
		return err
	}

	if exists, err := e.keyExists(ctx, key); err != nil {
		return err
	} else if exists {
		if _, derr := e.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(e.bucket), Key: aws.String(key),
		}); derr != nil {
			return mapS3Err("removefile", derr)
		}
		return nil
	}

	// Directory probe: marker and/or children under the prefix.
	marker := dirMarkerKey(key)
	probe, perr := e.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(e.bucket), Prefix: aws.String(marker), MaxKeys: aws.Int32(2),
	})
	if perr != nil {
		return mapS3Err("removefile", perr)
	}
	hasMarker := false
	hasChildren := false
	for _, obj := range probe.Contents {
		if aws.ToString(obj.Key) == marker {
			hasMarker = true
		} else {
			hasChildren = true
		}
	}
	switch {
	case hasChildren:
		return &fs.PathError{Op: "remove", Path: p, Err: syscall.ENOTEMPTY}
	case hasMarker:
		// Empty directory: the marker delete IS the empty-dir remove —
		// parity with the local engine's remove(2) succeeding on an empty
		// directory.
		if _, derr := e.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(e.bucket), Key: aws.String(marker),
		}); derr != nil {
			return mapS3Err("removefile", derr)
		}
		return nil
	default:
		return fmt.Errorf("objectstore: s3 removefile %q: %w", p, fs.ErrNotExist)
	}
}

// s3ReadReopenAttempts bounds the mid-stream reopen retries in ReadRange: a
// failed body read re-issues the range from the last good offset (never a
// whole-transfer restart, never byte-discard seek emulation) at most this
// many times before surfacing ErrTransient.
const s3ReadReopenAttempts = 3

// rangeHeader formats the single half-open window [offset, offset+length)
// as the inclusive byte-range header "bytes=start-end". Exactly ONE range
// per GET — the backend ignores multi-range and would return the whole
// object with a 200.
func rangeHeader(offset, length int64) string {
	return fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)
}

// reopenWindow returns the remaining window after `delivered` bytes of
// [offset, offset+length) reached the writer — the arithmetic a mid-stream
// reopen re-issues.
func reopenWindow(offset, length, delivered int64) (nextOffset, nextLength int64) {
	return offset + delivered, length - delivered
}

// isInvalidRange reports whether err is the backend's 416 range refusal —
// the start-past-EOF case the Engine contract maps to a zero-byte success.
func isInvalidRange(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidRange" {
		return true
	}
	var respErr *awshttp.ResponseError
	return errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusRequestedRangeNotSatisfiable
}

// ReadRange streams the half-open window [offset, offset+length) into w
// with exactly one bytes=start-end range per GET. An offset at or past EOF
// surfaces as the backend's 416 and returns zero bytes with nil error (the
// contract's past-EOF short read); a window merely extending past EOF is
// clamped by the backend and the short 206 streams through unchanged. A
// mid-stream body failure re-opens the range from the last good offset with
// bounded attempts. The body copy is cancellation-aware.
func (e *s3Engine) ReadRange(ctx context.Context, scope ScopeID, p string, offset, length int64, w io.Writer) error {
	key, err := e.objectKey(scope, p)
	if err != nil {
		return err
	}
	if offset < 0 || length < 0 {
		return fmt.Errorf("objectstore: s3 readrange: negative offset or length")
	}
	if length == 0 {
		// Zero-length window: no GET, but existence still asserted — the
		// local engine opens the file before copying zero bytes, and the
		// missing-object refusal must agree across engines.
		_, herr := e.client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(e.bucket), Key: aws.String(key),
		})
		if herr != nil {
			return mapS3Err("readrange", herr)
		}
		return nil
	}

	cur, remaining := offset, length
	for attempt := 1; ; attempt++ {
		rng := rangeHeader(cur, remaining)
		out, gerr := e.client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(e.bucket), Key: aws.String(key), Range: aws.String(rng),
		})
		if gerr != nil {
			if isInvalidRange(gerr) {
				if cur != offset {
					// A reopen mid-transfer hit 416: the object shrank under
					// the read (replaced) — the delivered bytes are torn.
					return fmt.Errorf("objectstore: s3 readrange: %w (object changed mid-read)", ErrTransient)
				}
				return nil // start at/past EOF -> zero bytes, no error
			}
			return mapS3Err("readrange", gerr)
		}
		n, copyErr := io.Copy(w, ctxReader{ctx: ctx, r: out.Body})
		out.Body.Close()
		cur, remaining = reopenWindow(cur, remaining, n)
		if copyErr == nil {
			// Clean EOF: the backend delivered its full response — the whole
			// window, or the tail-clamped remainder. Done either way.
			return nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("objectstore: s3 readrange: %w", cerr)
		}
		if remaining <= 0 {
			return nil
		}
		if attempt >= s3ReadReopenAttempts {
			return fmt.Errorf("objectstore: s3 readrange: %w after %d reopen attempts (%v)", ErrTransient, attempt, copyErr)
		}
		// Mid-stream failure: loop re-opens [cur, cur+remaining).
	}
}

// fillBuffer reads from r until buf is full or the stream ends, returning
// the byte count and whether the stream ended. A non-nil error is a real
// source failure — never io.EOF (stream end is the bool).
func fillBuffer(r io.Reader, buf []byte) (int, bool, error) {
	n, err := io.ReadFull(r, buf)
	switch {
	case err == nil:
		return n, false, nil
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return n, true, nil
	default:
		return n, false, err
	}
}

// noCancelCtx returns a context detached from ctx's cancellation but
// bounded by its own timeout — the cleanup contexts (multipart abort,
// delete-on-mismatch) must run even when the operation's own ctx is the
// thing that was cancelled.
func noCancelCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
}

// WriteStream consumes r into the named object with ONE reused part buffer
// (SEC-46: bounded memory, never a whole-object read). A stream that ends
// inside the first buffer at or under the cutoff goes up as a single
// PutObject with a known Content-Length; anything larger streams as a
// multipart upload whose every part except the last is the full part size
// by construction. SHA-256 is computed in the same single pass and stored
// as the ocu-sha256 object tag. overwrite=false is atomic: If-None-Match on
// PutObject AND on CompleteMultipartUpload — never a read-then-write check.
// Every error and cancellation path aborts the multipart upload; a partial
// write is never visible (a multipart object only exists after Complete).
// After upload, a HEAD verifies the size; a mismatch deletes the object and
// errors.
func (e *s3Engine) WriteStream(ctx context.Context, scope ScopeID, p string, r io.Reader, overwrite bool) error {
	key, err := e.objectKey(scope, p)
	if err != nil {
		return err
	}
	ok, err := e.parentExists(ctx, key)
	if err != nil {
		return err
	}
	if !ok {
		return &fs.PathError{Op: "write", Path: p, Err: fs.ErrNotExist}
	}

	hasher := sha256.New()
	src := io.TeeReader(ctxReader{ctx: ctx, r: r}, hasher)
	buf := make([]byte, e.partSize) // the ONE buffer this stream ever holds

	n, ended, rerr := fillBuffer(src, buf)
	if rerr != nil {
		return fmt.Errorf("objectstore: s3 writestream: read source: %w", rerr)
	}

	var total int64
	if ended && int64(n) <= e.singlePutCutoff {
		total = int64(n)
		digest := hex.EncodeToString(hasher.Sum(nil))
		in := &s3.PutObjectInput{
			Bucket:        aws.String(e.bucket),
			Key:           aws.String(key),
			Body:          bytes.NewReader(buf[:n]),
			ContentLength: aws.Int64(total),
			Tagging:       aws.String(digestTagKey + "=" + digest),
		}
		if !overwrite {
			in.IfNoneMatch = aws.String("*")
		}
		if _, perr := e.client.PutObject(ctx, in); perr != nil {
			return mapS3Err("writestream", perr)
		}
	} else {
		var werr error
		total, werr = e.writeMultipart(ctx, key, src, buf, n, ended, overwrite)
		if werr != nil {
			return werr
		}
		// The digest tag lands after Complete (multipart metadata is fixed
		// at Create, before a single-pass digest can exist).
		digest := hex.EncodeToString(hasher.Sum(nil))
		if _, terr := e.client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket: aws.String(e.bucket),
			Key:    aws.String(key),
			Tagging: &types.Tagging{TagSet: []types.Tag{
				{Key: aws.String(digestTagKey), Value: aws.String(digest)},
			}},
		}); terr != nil {
			return mapS3Err("writestream tag", terr)
		}
	}

	// Post-upload verification (section-9 discipline): the backend's view
	// of the size must equal what was streamed; a mismatch deletes the
	// object — a torn write is never left visible.
	head, herr := e.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(key),
	})
	if herr != nil {
		return mapS3Err("writestream verify", herr)
	}
	if got := aws.ToInt64(head.ContentLength); got != total {
		cctx, cancel := noCancelCtx(ctx)
		defer cancel()
		_, _ = e.client.DeleteObject(cctx, &s3.DeleteObjectInput{
			Bucket: aws.String(e.bucket), Key: aws.String(key),
		})
		return fmt.Errorf("objectstore: s3 writestream: size verification failed (streamed %d, backend reports %d); object deleted", total, got)
	}
	return nil
}

// writeMultipart streams the remainder of src as a multipart upload whose
// first part is already in buf[:n]. Every part except the final one is the
// full buffer by construction (>= the backend's 5 MiB minimum, enforced at
// the constructor); crossing the part ceiling aborts and refuses typed. The
// deferred abort fires on EVERY error and cancellation path — an
// un-completed multipart upload never outlives the call.
func (e *s3Engine) writeMultipart(ctx context.Context, key string, src io.Reader, buf []byte, n int, ended bool, overwrite bool) (int64, error) {
	create, cerr := e.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(e.bucket), Key: aws.String(key),
	})
	if cerr != nil {
		return 0, mapS3Err("writestream", cerr)
	}
	uploadID := create.UploadId
	completed := false
	defer func() {
		if completed {
			return
		}
		actx, cancel := noCancelCtx(ctx)
		defer cancel()
		_, _ = e.client.AbortMultipartUpload(actx, &s3.AbortMultipartUploadInput{
			Bucket: aws.String(e.bucket), Key: aws.String(key), UploadId: uploadID,
		})
	}()

	var (
		parts   []types.CompletedPart
		partNum int32
		total   int64
	)
	for {
		if n > 0 || partNum == 0 {
			partNum++
			if partNum > s3MaxParts {
				return 0, fmt.Errorf("objectstore: s3 writestream: %w (%d parts of %d bytes)", errS3TooManyParts, partNum, len(buf))
			}
			up, uerr := e.client.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:        aws.String(e.bucket),
				Key:           aws.String(key),
				UploadId:      uploadID,
				PartNumber:    aws.Int32(partNum),
				Body:          bytes.NewReader(buf[:n]),
				ContentLength: aws.Int64(int64(n)),
			})
			if uerr != nil {
				return 0, mapS3Err("writestream", uerr)
			}
			// Strict part-number-ordered aggregation: parts are appended in
			// upload order and numbered monotonically — the Complete body
			// is ordered by construction.
			parts = append(parts, types.CompletedPart{ETag: up.ETag, PartNumber: aws.Int32(partNum)})
			total += int64(n)
		}
		if ended {
			break
		}
		var rerr error
		n, ended, rerr = fillBuffer(src, buf)
		if rerr != nil {
			return 0, fmt.Errorf("objectstore: s3 writestream: read source: %w", rerr)
		}
	}

	in := &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(e.bucket),
		Key:             aws.String(key),
		UploadId:        uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	}
	if !overwrite {
		in.IfNoneMatch = aws.String("*")
	}
	if _, cerr := e.client.CompleteMultipartUpload(ctx, in); cerr != nil {
		return 0, mapS3Err("writestream", cerr)
	}
	completed = true
	return total, nil
}
