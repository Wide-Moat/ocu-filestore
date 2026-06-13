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
	"net/url"
	"path"
	"strings"
	"sync"
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
	// s3DeleteBatchMax is the backend's per-call DeleteObjects key cap.
	s3DeleteBatchMax = 1000
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
	// errS3VersionSweepDenied is the typed teardown refusal for a versioned
	// bucket whose version listing is denied: a plain delete would leave
	// every version's bytes readable and billing — the sweep REFUSES rather
	// than report clean while bytes remain (SEC-54 fail-closed).
	errS3VersionSweepDenied = errors.New("objectstore: bucket is versioned but version listing is denied; erase refused (bytes would remain)")
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

	// versMu guards the cached bucket-versioning probe: the erase sweep's
	// versioned-vs-plain split is decided once per engine, never re-probed
	// per call. A failed probe is NOT cached — the next sweep re-probes.
	versMu           sync.Mutex
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
// All 13 Engine verbs are implemented; the daemon composes this engine for
// `-engine s3` (lane transport + CredentialSource per ADR-0011/T1-7).

func (e *s3Engine) Kind() EngineKind { return S3 }

// ProvisionScope is erase-at-provision: a dirty prefix left by a crashed
// prior session is erased before serving (the provision-side analogue of
// erase-before-reuse, SEC-54). Prefixes are virtual — after the sweep there
// is nothing to create.
func (e *s3Engine) ProvisionScope(ctx context.Context, scope ScopeID) error {
	return e.eraseScope(ctx, scope)
}

// TeardownScope erases EVERY byte under the scope prefix (SEC-54): on a
// versioned (or suspended) bucket every version and delete-marker is
// deleted by VersionId — a plain delete writes only a delete-marker and the
// bytes remain readable via version requests and keep billing; on an
// unversioned bucket the plain paginated sweep suffices. The same teardown
// aborts every orphaned in-progress multipart upload under the prefix. A
// versioned bucket whose version listing is denied REFUSES with a typed
// error — never a clean report while bytes remain.
func (e *s3Engine) TeardownScope(ctx context.Context, scope ScopeID) error {
	return e.eraseScope(ctx, scope)
}

// bucketVersioned reports (cached) whether the bucket has versioning
// enabled or suspended — both keep historical versions that a true erase
// must sweep.
func (e *s3Engine) bucketVersioned(ctx context.Context) (bool, error) {
	e.versMu.Lock()
	defer e.versMu.Unlock()
	if e.versioningProbed {
		return e.versioningOn, nil
	}
	out, err := e.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(e.bucket),
	})
	if err != nil {
		return false, mapS3Err("versioning probe", err)
	}
	e.versioningOn = out.Status == types.BucketVersioningStatusEnabled ||
		out.Status == types.BucketVersioningStatusSuspended
	e.versioningProbed = true
	return e.versioningOn, nil
}

// eraseScope is the shared SEC-54 sweep behind both lifecycle verbs.
func (e *s3Engine) eraseScope(ctx context.Context, scope ScopeID) error {
	prefix, err := e.scopePrefix(scope)
	if err != nil {
		return err
	}
	versioned, verr := e.bucketVersioned(ctx)
	if verr != nil {
		return verr
	}
	if versioned {
		if err := e.deleteAllVersions(ctx, prefix); err != nil {
			return err
		}
	} else {
		if _, _, err := e.deleteByPrefix(ctx, prefix); err != nil {
			return err
		}
	}
	return e.abortScopeMPUs(ctx, prefix)
}

// deleteAllVersions erases every version AND delete-marker under prefix:
// fully paginated ListObjectVersions, <=1000-key DeleteObjects batches with
// explicit VersionIds, per-key Errors aggregated — never abort-on-first. A
// denied version listing refuses typed (errS3VersionSweepDenied).
func (e *s3Engine) deleteAllVersions(ctx context.Context, prefix string) error {
	var (
		keyMarker, versionMarker *string
		deleted, failed          int
		firstErr                 error
	)
	for {
		page, lerr := e.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:          aws.String(e.bucket),
			Prefix:          aws.String(prefix),
			KeyMarker:       keyMarker,
			VersionIdMarker: versionMarker,
		})
		if lerr != nil {
			if mapped := mapS3Err("version sweep", lerr); errors.Is(mapped, errS3AccessDenied) {
				return fmt.Errorf("%w (%v)", errS3VersionSweepDenied, mapped)
			} else {
				return mapped
			}
		}

		ids := make([]types.ObjectIdentifier, 0, len(page.Versions)+len(page.DeleteMarkers))
		for _, v := range page.Versions {
			ids = append(ids, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
		}
		for _, dm := range page.DeleteMarkers {
			ids = append(ids, types.ObjectIdentifier{Key: dm.Key, VersionId: dm.VersionId})
		}
		for start := 0; start < len(ids); start += s3DeleteBatchMax {
			end := start + s3DeleteBatchMax
			if end > len(ids) {
				end = len(ids)
			}
			out, derr := e.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(e.bucket),
				Delete: &types.Delete{Objects: ids[start:end], Quiet: aws.Bool(true)},
			})
			if derr != nil {
				failed += end - start
				if firstErr == nil {
					firstErr = mapS3Err("version sweep", derr)
				}
				continue
			}
			failed += len(out.Errors)
			deleted += (end - start) - len(out.Errors)
		}

		if !aws.ToBool(page.IsTruncated) {
			break
		}
		keyMarker = page.NextKeyMarker
		versionMarker = page.NextVersionIdMarker
	}
	if failed > 0 {
		if firstErr != nil {
			return fmt.Errorf("objectstore: s3 version sweep under %q: %d of %d deletions failed: %w", prefix, failed, failed+deleted, firstErr)
		}
		return fmt.Errorf("objectstore: s3 version sweep under %q: %d of %d deletions failed", prefix, failed, failed+deleted)
	}
	return firstErr
}

// abortScopeMPUs aborts every in-progress multipart upload under prefix
// (paginated) — orphaned parts never show in listings, bill silently, and
// would survive a key-only sweep. The listing is bucket-wide with a
// client-side prefix filter: some S3-compatible backends return an upload
// for a directory-style Prefix only when it equals the full object key, so
// a prefix-scoped listing silently under-reports and the sweep would lie.
//
// Abort failures are aggregated (first-error kept, count tracked, loop
// continues) so that a single failing abort never strands every remaining
// in-progress upload as a silently-billing orphan — the same best-effort
// sweep contract as deleteByPrefix / deleteAllVersions (SEC-54).
func (e *s3Engine) abortScopeMPUs(ctx context.Context, prefix string) error {
	var (
		keyMarker, uploadMarker *string
		aborted, failed         int
		firstErr                error
	)
	for {
		page, lerr := e.client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         aws.String(e.bucket),
			KeyMarker:      keyMarker,
			UploadIdMarker: uploadMarker,
		})
		if lerr != nil {
			return mapS3Err("mpu sweep", lerr)
		}
		for _, up := range page.Uploads {
			if !strings.HasPrefix(aws.ToString(up.Key), prefix) {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if _, aerr := e.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(e.bucket),
				Key:      up.Key,
				UploadId: up.UploadId,
			}); aerr != nil {
				failed++
				if firstErr == nil {
					firstErr = mapS3Err("mpu sweep", aerr)
				}
				continue
			}
			aborted++
		}
		if !aws.ToBool(page.IsTruncated) {
			break
		}
		keyMarker = page.NextKeyMarker
		uploadMarker = page.NextUploadIdMarker
	}
	if failed > 0 {
		return fmt.Errorf("objectstore: s3 mpu sweep under %q: %d of %d aborts failed: %w",
			prefix, failed, failed+aborted, firstErr)
	}
	return nil
}

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
		// Nothing lived under the "<key>/" prefix. Distinguish a path that is a
		// FILE from one that is truly absent: if the plain object key exists,
		// the caller listed a file, which the local engine refuses with ENOTDIR
		// (classified internal), NOT not-found. HeadObject the plain key and
		// return ErrNotADirectory in that case so both engines agree on the wire
		// class and the audited truth for the same edge; only a genuinely absent
		// key returns fs.ErrNotExist.
		key, err := e.objectKey(scope, p)
		if err != nil {
			return nil, err
		}
		exists, err := e.keyExists(ctx, key)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("objectstore: s3 list %q: %w", p, ErrNotADirectory)
		}
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

// completeMultipart issues CompleteMultipartUpload with decision-8 retry
// hardening: Complete is NOT safely retryable after success — a retry of a
// Complete whose first response was lost surfaces NoSuchUpload. That
// NoSuchUpload is verified via HEAD: when the key exists with the expected
// size, the Complete already succeeded and this is success, not failure.
// CreateMultipartUpload is never blindly retried by engine code (each call
// mints a new uploadId); the teardown MPU sweep is the orphan backstop.
func (e *s3Engine) completeMultipart(ctx context.Context, in *s3.CompleteMultipartUploadInput, wantSize int64) error {
	_, err := e.client.CompleteMultipartUpload(ctx, in)
	if err == nil {
		return nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchUpload" {
		head, herr := e.client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: in.Bucket, Key: in.Key,
		})
		if herr == nil && aws.ToInt64(head.ContentLength) == wantSize {
			return nil // the earlier Complete landed; the retry saw its wake
		}
	}
	return mapS3Err("complete multipart", err)
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

// copySourceFor URL-encodes the x-amz-copy-source value for a key: an
// unencoded key with spaces or special characters silently targets the
// wrong object or 404s. Path segments are escaped, separators preserved.
func (e *s3Engine) copySourceFor(key string) string {
	u := url.URL{Path: "/" + e.bucket + "/" + key}
	return strings.TrimPrefix(u.EscapedPath(), "/")
}

// srcTagging returns the source object's tag set in the URL-encoded
// "k=v&k=v" form for write-time Tagging fields — the digest tag travels
// with a copy on every path.
func (e *s3Engine) srcTagging(ctx context.Context, key string) (string, error) {
	out, err := e.client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(e.bucket), Key: aws.String(key),
	})
	if err != nil {
		return "", mapS3Err("copy tags", err)
	}
	vals := url.Values{}
	for _, tag := range out.TagSet {
		vals.Set(aws.ToString(tag.Key), aws.ToString(tag.Value))
	}
	return vals.Encode(), nil
}

// copyObjectKeys performs the server-side copy of srcKey onto dstKey for a
// source of size bytes. overwrite=true under the threshold is a plain
// CopyObject (tags travel via the COPY directive default); anything else —
// every overwrite=false copy (atomic no-replace via conditional Complete at
// any size, live-proven) and any copy above the threshold (a plain
// CopyObject over 5 GiB is refused by the backend) — is a multipart copy
// via UploadPartCopy. A zero-byte source with overwrite=false is the one
// special case (an empty multipart copy cannot exist): an empty conditional
// PutObject carrying the source's tags.
func (e *s3Engine) copyObjectKeys(ctx context.Context, srcKey, dstKey string, size int64, overwrite bool) error {
	if overwrite && size <= e.copyThreshold {
		_, err := e.client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     aws.String(e.bucket),
			Key:        aws.String(dstKey),
			CopySource: aws.String(e.copySourceFor(srcKey)),
		})
		return mapS3Err("copyfile", err)
	}

	tagging, terr := e.srcTagging(ctx, srcKey)
	if terr != nil {
		return terr
	}

	if size == 0 {
		in := &s3.PutObjectInput{
			Bucket:        aws.String(e.bucket),
			Key:           aws.String(dstKey),
			Body:          bytes.NewReader(nil),
			ContentLength: aws.Int64(0),
		}
		if tagging != "" {
			in.Tagging = aws.String(tagging)
		}
		if !overwrite {
			in.IfNoneMatch = aws.String("*")
		}
		_, err := e.client.PutObject(ctx, in)
		return mapS3Err("copyfile", err)
	}

	// Part size: the configured part size, grown only when the object would
	// otherwise exceed the part ceiling.
	partSize := e.partSize
	if minPart := (size + s3MaxParts - 1) / s3MaxParts; partSize < minPart {
		partSize = minPart
	}

	createIn := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(e.bucket), Key: aws.String(dstKey),
	}
	if tagging != "" {
		createIn.Tagging = aws.String(tagging)
	}
	create, cerr := e.client.CreateMultipartUpload(ctx, createIn)
	if cerr != nil {
		return mapS3Err("copyfile", cerr)
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
			Bucket: aws.String(e.bucket), Key: aws.String(dstKey), UploadId: uploadID,
		})
	}()

	var parts []types.CompletedPart
	var partNum int32
	for off := int64(0); off < size; off += partSize {
		end := off + partSize - 1
		if end > size-1 {
			end = size - 1
		}
		partNum++
		up, uerr := e.client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          aws.String(e.bucket),
			Key:             aws.String(dstKey),
			UploadId:        uploadID,
			PartNumber:      aws.Int32(partNum),
			CopySource:      aws.String(e.copySourceFor(srcKey)),
			CopySourceRange: aws.String(fmt.Sprintf("bytes=%d-%d", off, end)),
		})
		if uerr != nil {
			return mapS3Err("copyfile", uerr)
		}
		parts = append(parts, types.CompletedPart{ETag: up.CopyPartResult.ETag, PartNumber: aws.Int32(partNum)})
	}

	completeIn := &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(e.bucket),
		Key:             aws.String(dstKey),
		UploadId:        uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	}
	if !overwrite {
		completeIn.IfNoneMatch = aws.String("*")
	}
	if cerr := e.completeMultipart(ctx, completeIn, size); cerr != nil {
		return cerr
	}
	completed = true
	return nil
}

// CopyFile duplicates a file within the scope. Same-object guard first
// (src and dst resolving to one key must never proceed — a move built on
// this copy would otherwise delete its own source); the destination key
// re-runs the FULL validator and the parent-directory check (a copy
// destination is not a containment hole). The source's size decides plain
// CopyObject vs multipart copy.
func (e *s3Engine) CopyFile(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	srcKey, err := e.objectKey(scope, src)
	if err != nil {
		return err
	}
	dstKey, err := e.objectKey(scope, dst)
	if err != nil {
		return err
	}

	head, herr := e.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(srcKey),
	})
	if herr != nil {
		return mapS3Err("copyfile", herr)
	}
	size := aws.ToInt64(head.ContentLength)

	if srcKey == dstKey {
		// Same object: with overwrite the copy is the identity (a no-op);
		// without it the destination trivially exists. The source is never
		// deleted on this path.
		if overwrite {
			return nil
		}
		return fmt.Errorf("objectstore: s3 copyfile: %w", ErrAlreadyExists)
	}

	ok, perr := e.parentExists(ctx, dstKey)
	if perr != nil {
		return perr
	}
	if !ok {
		return &fs.PathError{Op: "copy", Path: dst, Err: fs.ErrNotExist}
	}

	return e.copyObjectKeys(ctx, srcKey, dstKey, size, overwrite)
}

// MoveFile is copy -> verify -> delete-source, in that order: a crash at
// any point never loses bytes (a surviving duplicate is the acceptable
// failure mode). The verification compares size and — when the source
// carries one — the ocu-sha256 digest tag; a failed verification deletes
// the bad copy and leaves the source untouched.
func (e *s3Engine) MoveFile(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	if err := e.CopyFile(ctx, scope, src, dst, overwrite); err != nil {
		return err
	}
	srcKey, err := e.objectKey(scope, src)
	if err != nil {
		return err
	}
	dstKey, err := e.objectKey(scope, dst)
	if err != nil {
		return err
	}
	if srcKey == dstKey {
		return nil // same-object guard already handled by CopyFile
	}

	verifyErr := e.verifyCopy(ctx, srcKey, dstKey)
	if verifyErr != nil {
		cctx, cancel := noCancelCtx(ctx)
		defer cancel()
		_, delErr := e.client.DeleteObject(cctx, &s3.DeleteObjectInput{
			Bucket: aws.String(e.bucket), Key: aws.String(dstKey),
		})
		if delErr != nil {
			return errors.Join(verifyErr, fmt.Errorf("objectstore: s3 movefile: cleanup delete of bad copy also failed: %w", mapS3Err("movefile cleanup", delErr)))
		}
		return verifyErr
	}

	if _, derr := e.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(srcKey),
	}); derr != nil {
		return mapS3Err("movefile", derr)
	}
	return nil
}

// verifyCopy asserts dstKey carries the same size as srcKey and — when the
// source has an ocu-sha256 tag — the same digest.
func (e *s3Engine) verifyCopy(ctx context.Context, srcKey, dstKey string) error {
	srcHead, err := e.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(srcKey),
	})
	if err != nil {
		return mapS3Err("movefile verify", err)
	}
	dstHead, err := e.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(dstKey),
	})
	if err != nil {
		return mapS3Err("movefile verify", err)
	}
	if aws.ToInt64(srcHead.ContentLength) != aws.ToInt64(dstHead.ContentLength) {
		return fmt.Errorf("objectstore: s3 movefile: size mismatch after copy (src %d, dst %d); attempted to delete bad copy, source intact",
			aws.ToInt64(srcHead.ContentLength), aws.ToInt64(dstHead.ContentLength))
	}
	srcDigest, serr := e.digestTagOf(ctx, srcKey)
	if serr != nil {
		return serr
	}
	if srcDigest == "" {
		return nil // size-only verification when no digest exists; stated.
	}
	dstDigest, derr := e.digestTagOf(ctx, dstKey)
	if derr != nil {
		return derr
	}
	if dstDigest != srcDigest {
		return fmt.Errorf("objectstore: s3 movefile: digest mismatch after copy; attempted to delete bad copy, source intact")
	}
	return nil
}

// digestTagOf returns the key's ocu-sha256 tag value, "" when absent.
func (e *s3Engine) digestTagOf(ctx context.Context, key string) (string, error) {
	out, err := e.client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(e.bucket), Key: aws.String(key),
	})
	if err != nil {
		return "", mapS3Err("digest tag", err)
	}
	for _, tag := range out.TagSet {
		if aws.ToString(tag.Key) == digestTagKey {
			return aws.ToString(tag.Value), nil
		}
	}
	return "", nil
}

// MoveDir relocates a directory subtree: a paginated walk of the source
// prefix with per-object copy-then-delete (markers included), so a crash
// mid-move leaves duplicates, never losses. NOT atomic — an observer can
// see both trees mid-move; this is a documented divergence from the local
// engine's rename. Every destination key re-runs the FULL validator via
// the joined relative path — a move is not a containment hole. A move of a
// directory into its OWN SUBTREE is refused with syscall.EINVAL before any
// destructive step, exactly as the local engine's rename(2) refuses it.
func (e *s3Engine) MoveDir(ctx context.Context, scope ScopeID, src, dst string, overwrite bool) error {
	srcKey, err := e.objectKey(scope, src)
	if err != nil {
		return err
	}
	dstKey, err := e.objectKey(scope, dst)
	if err != nil {
		return err
	}
	if srcKey == dstKey {
		return fmt.Errorf("objectstore: s3 movedir: %w", ErrAlreadyExists)
	}

	srcExists, err := e.dirExists(ctx, srcKey)
	if err != nil {
		return err
	}
	if !srcExists {
		return fmt.Errorf("objectstore: s3 movedir %q: %w", src, fs.ErrNotExist)
	}
	if !overwrite {
		dstExists, derr := e.dirExists(ctx, dstKey)
		if derr != nil {
			return derr
		}
		if dstExists {
			return fmt.Errorf("objectstore: s3 movedir: %w", ErrAlreadyExists)
		}
	}
	// Refuse moving a directory INTO ITS OWN SUBTREE before any destructive
	// step. The walk below copies-then-deletes per object; if the destination
	// were inside the source prefix, keys moved in on one page would reappear
	// under the still-matching source prefix on later listing pages, an
	// unbounded re-copy/re-delete sweep on attacker-influenced names. The
	// local engine's rename(2) refuses this same case with EINVAL; surface the
	// identical sentinel so both engines present one semantics to the broker.
	// The trailing-slash join makes "a/b" inside "a" match while "ab" does
	// not. The src==dst and dst-exists rows are decided above first, mirroring
	// the local engine's refusal ordering exactly.
	if strings.HasPrefix(dstKey+"/", srcKey+"/") {
		return &fs.PathError{Op: "movedir", Path: dst, Err: syscall.EINVAL}
	}
	if ok, perr := e.parentExists(ctx, dstKey); perr != nil {
		return perr
	} else if !ok {
		return &fs.PathError{Op: "movedir", Path: dst, Err: fs.ErrNotExist}
	}

	srcPrefix := dirMarkerKey(srcKey)
	var token *string
	for {
		page, lerr := e.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(e.bucket), Prefix: aws.String(srcPrefix), ContinuationToken: token,
		})
		if lerr != nil {
			return mapS3Err("movedir", lerr)
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			rel := strings.TrimPrefix(key, srcPrefix)
			isMarker := rel == "" || strings.HasSuffix(rel, "/")

			// Re-run the FULL validator on the destination path (section 8):
			// the destination of every moved object must still be a valid,
			// contained key.
			relPath := strings.TrimSuffix(rel, "/")
			dstObjPath := dst
			if relPath != "" {
				dstObjPath = dst + "/" + relPath
			}
			newKey, verr := e.objectKey(scope, dstObjPath)
			if verr != nil {
				return verr
			}
			if isMarker {
				newKey = dirMarkerKey(newKey)
			}

			if cerr := e.copyObjectKeys(ctx, key, newKey, aws.ToInt64(obj.Size), true); cerr != nil {
				return cerr
			}
			if _, derr := e.client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(e.bucket), Key: aws.String(key),
			}); derr != nil {
				return mapS3Err("movedir", derr)
			}
		}
		if !aws.ToBool(page.IsTruncated) {
			break
		}
		token = page.NextContinuationToken
	}
	return nil
}

// deleteByPrefix erases every object under prefix: fully paginated listing,
// DeleteObjects in <=1000-key batches, and the per-key Errors array of
// every batch inspected — a 200 can carry partial failures. Failures
// aggregate to a count and the sweep continues; it never aborts on the
// first error. Returns the deleted and failed counts.
func (e *s3Engine) deleteByPrefix(ctx context.Context, prefix string) (deleted, failed int, err error) {
	var token *string
	for {
		page, lerr := e.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(e.bucket), Prefix: aws.String(prefix), ContinuationToken: token,
		})
		if lerr != nil {
			return deleted, failed, mapS3Err("delete sweep", lerr)
		}
		for start := 0; start < len(page.Contents); start += s3DeleteBatchMax {
			end := start + s3DeleteBatchMax
			if end > len(page.Contents) {
				end = len(page.Contents)
			}
			ids := make([]types.ObjectIdentifier, 0, end-start)
			for _, obj := range page.Contents[start:end] {
				ids = append(ids, types.ObjectIdentifier{Key: obj.Key})
			}
			out, derr := e.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
				Bucket: aws.String(e.bucket),
				Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)},
			})
			if derr != nil {
				failed += len(ids)
				if err == nil {
					err = mapS3Err("delete sweep", derr)
				}
				continue
			}
			failed += len(out.Errors)
			deleted += len(ids) - len(out.Errors)
		}
		if !aws.ToBool(page.IsTruncated) {
			break
		}
		token = page.NextContinuationToken
	}
	if failed > 0 && err == nil {
		err = fmt.Errorf("objectstore: s3 delete sweep under %q: %d of %d deletions failed", prefix, failed, failed+deleted)
	}
	return deleted, failed, err
}

// RemoveDir removes the named directory and its contents recursively: the
// paginated batch-delete sweep over the prefix, marker included. A missing
// directory is a NO-OP (the seam contract: removeDirectory of an absent
// path converges silently).
func (e *s3Engine) RemoveDir(ctx context.Context, scope ScopeID, p string) error {
	key, err := e.objectKey(scope, p)
	if err != nil {
		return err
	}
	_, _, serr := e.deleteByPrefix(ctx, dirMarkerKey(key))
	return serr
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
		return fmt.Errorf("%w: negative offset or length", ErrInvalidRange)
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
		sizeErr := fmt.Errorf("objectstore: s3 writestream: size verification failed (streamed %d, backend reports %d); attempted to delete torn object", total, got)
		_, delErr := e.client.DeleteObject(cctx, &s3.DeleteObjectInput{
			Bucket: aws.String(e.bucket), Key: aws.String(key),
		})
		if delErr != nil {
			return errors.Join(sizeErr, fmt.Errorf("objectstore: s3 writestream: cleanup delete of torn object also failed: %w", mapS3Err("writestream cleanup", delErr)))
		}
		return sizeErr
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
	if cerr := e.completeMultipart(ctx, in, total); cerr != nil {
		return 0, cerr
	}
	completed = true
	return total, nil
}
