// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/Wide-Moat/ocu-filestore/internal/admission"
)

// Backend credential intake (T1-7). The credential NEVER arrives as a flag
// VALUE — a flag-carried secret leaks through the process argument list.
// Two sources, in precedence order:
//
//  1. A credential FILE named by the -s3-credential-file flag (the path is
//     not a secret). The file must be mode exactly 0600 and owned by the
//     daemon's uid, holding `access_key_id=` and `secret_access_key=`
//     lines. Any defect refuses with a typed error — never a fall-through
//     to another source.
//  2. Environment: OCU_S3_ACCESS_KEY_ID / OCU_S3_SECRET_ACCESS_KEY.
//
// The secret value lives ONLY inside the provider; the carrying types
// redact themselves under every fmt verb, and no error in this file ever
// interpolates a credential byte (a malformed line is reported by NUMBER,
// never by content).

// Environment variable names for the static backend credential.
const (
	EnvS3AccessKeyID     = "OCU_S3_ACCESS_KEY_ID"
	EnvS3SecretAccessKey = "OCU_S3_SECRET_ACCESS_KEY"
)

var (
	// ErrCredentialMissing refuses startup when neither the credential file
	// nor the environment pair provides a complete credential. Match it
	// with errors.Is.
	ErrCredentialMissing = errors.New("objectstore: no backend credential (provide -s3-credential-file or " + EnvS3AccessKeyID + "/" + EnvS3SecretAccessKey + ")")
	// ErrCredentialFileUnsafe refuses a credential file whose mode is not
	// exactly 0600, whose owner is not the daemon uid, or which is a
	// symbolic link. Match it with errors.Is.
	ErrCredentialFileUnsafe = errors.New("objectstore: credential file refused (require a regular file, mode exactly 0600, owned by the daemon uid)")
	// ErrCredentialMalformed refuses a credential file whose contents do
	// not parse. The message carries the line NUMBER only — never the line.
	// Match it with errors.Is.
	ErrCredentialMalformed = errors.New("objectstore: credential file malformed")
)

// CredentialSource is the seam the daemon composes a backend credential
// through: one Provider for the SDK client, one Kind for the admission
// gate. STS-per-session drops into the same seam.
type CredentialSource interface {
	// Provider returns the aws.CredentialsProvider the s3 client is built
	// with. The secret never leaves the returned provider.
	Provider(ctx context.Context) (aws.CredentialsProvider, error)
	// Kind names the credential kind admission admits.
	Kind() admission.CredentialKind
}

// staticCredential carries the ingested static pair. Every fmt verb on the
// value (or a pointer to it) prints "[redacted]" — the type can never leak
// through logging, error wrapping, or %#v dumps.
type staticCredential struct {
	accessKeyID     string
	secretAccessKey string
}

func (staticCredential) String() string   { return "[redacted]" }
func (staticCredential) GoString() string { return "[redacted]" }
func (staticCredential) Format(f fmt.State, _ rune) {
	io.WriteString(f, "[redacted]")
}

// StaticCredentialSource is the host-local long-lived static credential
// source (admission kind host_local_long_lived) — the minimal-shelf cell.
type StaticCredentialSource struct {
	cred staticCredential
}

func (*StaticCredentialSource) String() string { return "objectstore.StaticCredentialSource[redacted]" }
func (*StaticCredentialSource) GoString() string {
	return "objectstore.StaticCredentialSource[redacted]"
}
func (*StaticCredentialSource) Format(f fmt.State, _ rune) {
	io.WriteString(f, "objectstore.StaticCredentialSource[redacted]")
}

// NewStaticCredentialSource ingests the static backend credential.
// credentialFile, when non-empty, is AUTHORITATIVE: any defect in the file
// refuses — there is no silent fall-through to the environment. With no
// file, the environment pair is read; with neither, ErrCredentialMissing.
func NewStaticCredentialSource(credentialFile string) (*StaticCredentialSource, error) {
	if credentialFile != "" {
		cred, err := readCredentialFile(credentialFile)
		if err != nil {
			return nil, err
		}
		return &StaticCredentialSource{cred: cred}, nil
	}

	akid := os.Getenv(EnvS3AccessKeyID)
	secret := os.Getenv(EnvS3SecretAccessKey)
	if akid == "" || secret == "" {
		return nil, ErrCredentialMissing
	}
	return &StaticCredentialSource{cred: staticCredential{accessKeyID: akid, secretAccessKey: secret}}, nil
}

// Provider wraps the ingested pair in the SDK's static provider. The secret
// value exists only here and inside the returned provider.
func (s *StaticCredentialSource) Provider(_ context.Context) (aws.CredentialsProvider, error) {
	return credentials.NewStaticCredentialsProvider(s.cred.accessKeyID, s.cred.secretAccessKey, ""), nil
}

// Kind names the host-local long-lived cell — the only long-lived kind the
// admission table admits (single-tenant trusted_operator, NFR-SEC-60).
func (s *StaticCredentialSource) Kind() admission.CredentialKind {
	return admission.CredHostLocalLongLived
}

// readCredentialFile loads and validates the 0600 credential file. Every
// refusal is typed; no error carries file CONTENT (a malformed line is
// named by number only — the line may hold a mistyped secret).
func readCredentialFile(path string) (staticCredential, error) {
	var zero staticCredential

	fi, err := os.Lstat(path)
	if err != nil {
		// The wrapped stat error carries the PATH (not a secret), never
		// content.
		return zero, fmt.Errorf("%w: %v", ErrCredentialFileUnsafe, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return zero, fmt.Errorf("%w: %q is a symbolic link", ErrCredentialFileUnsafe, path)
	}
	if !fi.Mode().IsRegular() {
		return zero, fmt.Errorf("%w: %q is not a regular file", ErrCredentialFileUnsafe, path)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		return zero, fmt.Errorf("%w: %q has mode %04o, require exactly 0600", ErrCredentialFileUnsafe, path, perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != os.Getuid() {
			return zero, fmt.Errorf("%w: %q owned by uid %d, daemon runs as uid %d", ErrCredentialFileUnsafe, path, st.Uid, os.Getuid())
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrCredentialFileUnsafe, err)
	}

	var cred staticCredential
	var haveKey, haveSecret bool
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(v) == "" {
			return zero, fmt.Errorf("%w: %q line %d", ErrCredentialMalformed, path, i+1)
		}
		switch strings.TrimSpace(k) {
		case "access_key_id":
			cred.accessKeyID = strings.TrimSpace(v)
			haveKey = true
		case "secret_access_key":
			cred.secretAccessKey = strings.TrimSpace(v)
			haveSecret = true
		default:
			// The unknown KEY name is content-adjacent; report the line
			// number only.
			return zero, fmt.Errorf("%w: %q line %d: unknown key", ErrCredentialMalformed, path, i+1)
		}
	}
	if !haveKey || !haveSecret {
		return zero, fmt.Errorf("%w: %q must hold access_key_id= and secret_access_key= lines", ErrCredentialMalformed, path)
	}
	return cred, nil
}

// --- STS-per-session source (T1-7, the second admitted credential kind) ----

// errSTSConfig refuses an incomplete STS source configuration. Match it
// with errors.Is.
var errSTSConfig = errors.New("objectstore: sts credential source misconfigured")

// STSConfig configures the per-session AssumeRole source. RoleARN and an
// ARN are deployment identifiers, never secrets; the PARENT credential
// (used to sign the AssumeRole call) arrives through the same intake
// discipline as the static source.
type STSConfig struct {
	// RoleARN is the role assumed per session.
	RoleARN string
	// Endpoint optionally overrides the STS endpoint (an S3-compatible
	// rig's STS). Empty = the SDK's regional default.
	Endpoint string
	// Region is the signing region.
	Region string
	// Bucket is the backend bucket the inline session policy is scoped to.
	Bucket string
	// Scope is the host-attested session scope: it becomes BOTH the role
	// session name and the policy's prefix cell. It is validated before
	// any policy text is built.
	Scope ScopeID
	// Parent signs the AssumeRole call.
	Parent CredentialSource
	// HTTPClient optionally pins the transport (the storage lane drops in
	// here). Nil = the SDK default client.
	HTTPClient *http.Client
}

// STSCredentialSource mints a short-lived, scope-prefix-confined session
// credential per session via AssumeRole with an INLINE session policy: even
// a leaked session credential can touch nothing outside the scope's prefix
// cell. Kind = sts_per_session (already in the admission table for every
// admitted profile row; this wires SELECTION, not new rows).
type STSCredentialSource struct {
	cfg STSConfig
}

func (*STSCredentialSource) String() string { return "objectstore.STSCredentialSource[redacted]" }
func (*STSCredentialSource) GoString() string {
	return "objectstore.STSCredentialSource[redacted]"
}
func (*STSCredentialSource) Format(f fmt.State, _ rune) {
	io.WriteString(f, "objectstore.STSCredentialSource[redacted]")
}

// NewSTSCredentialSource validates the configuration. The scope id is
// validated HERE — before any policy text exists — so a hostile scope can
// never reach the policy builder.
func NewSTSCredentialSource(cfg STSConfig) (*STSCredentialSource, error) {
	if err := validateScopeID(cfg.Scope); err != nil {
		return nil, err
	}
	if cfg.RoleARN == "" {
		return nil, fmt.Errorf("%w: role ARN is required", errSTSConfig)
	}
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("%w: bucket is required for the scope-prefix policy", errSTSConfig)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("%w: region is required", errSTSConfig)
	}
	if cfg.Parent == nil {
		return nil, fmt.Errorf("%w: a parent credential source is required to sign AssumeRole", errSTSConfig)
	}
	return &STSCredentialSource{cfg: cfg}, nil
}

// Provider builds the AssumeRole provider: role session name = the scope
// id, inline policy = the scope-prefix least-privilege cell, credentials
// cached and auto-refreshed by the SDK cache.
func (s *STSCredentialSource) Provider(ctx context.Context) (aws.CredentialsProvider, error) {
	parent, err := s.cfg.Parent.Provider(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := scopePrefixPolicy(s.cfg.Bucket, s.cfg.Scope)
	if err != nil {
		return nil, err
	}

	opts := sts.Options{
		Region:      s.cfg.Region,
		Credentials: parent,
	}
	if s.cfg.Endpoint != "" {
		opts.BaseEndpoint = aws.String(s.cfg.Endpoint)
	}
	if s.cfg.HTTPClient != nil {
		opts.HTTPClient = s.cfg.HTTPClient
	}
	client := sts.New(opts)

	prov := stscreds.NewAssumeRoleProvider(client, s.cfg.RoleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = string(s.cfg.Scope)
		o.Policy = aws.String(policy)
	})
	return aws.NewCredentialsCache(prov), nil
}

// Kind names the short-lived session-scoped cell.
func (s *STSCredentialSource) Kind() admission.CredentialKind {
	return admission.CredSTSPerSession
}

// stsPolicyDocument is the inline session-policy JSON shape.
type stsPolicyDocument struct {
	Version   string               `json:"Version"`
	Statement []stsPolicyStatement `json:"Statement"`
}

type stsPolicyStatement struct {
	Sid       string                       `json:"Sid"`
	Effect    string                       `json:"Effect"`
	Action    []string                     `json:"Action"`
	Resource  string                       `json:"Resource"`
	Condition map[string]map[string]string `json:"Condition,omitempty"`
}

// scopePrefixPolicy builds the least-privilege inline session policy for
// one scope: object verbs confined to the scope's key prefix, bucket-level
// listing confined by an s3:prefix condition. No statement ever names a
// wildcard bucket or an unconditioned bucket-wide read.
//
// One deliberate exception: ListBucketMultipartUploads carries NO prefix
// condition — the engine's orphan-MPU sweep lists bucket-wide and filters
// client-side (a directory-style Prefix on that call is not honored by
// every S3-compatible backend), so a prefix condition would deny the SEC-54
// sweep. The exposure is upload-key METADATA only; every mutating MPU verb
// stays prefix-confined.
func scopePrefixPolicy(bucket string, scope ScopeID) (string, error) {
	if err := validateScopeID(scope); err != nil {
		return "", err
	}
	if bucket == "" {
		return "", fmt.Errorf("%w: bucket is required for the scope-prefix policy", errSTSConfig)
	}
	prefix := string(scope) + "/"
	doc := stsPolicyDocument{
		Version: "2012-10-17",
		Statement: []stsPolicyStatement{
			{
				Sid:    "ScopeObjects",
				Effect: "Allow",
				Action: []string{
					"s3:GetObject",
					"s3:GetObjectVersion",
					"s3:GetObjectTagging",
					"s3:PutObject",
					"s3:PutObjectTagging",
					"s3:DeleteObject",
					"s3:DeleteObjectVersion",
					"s3:AbortMultipartUpload",
					"s3:ListMultipartUploadParts",
				},
				Resource: "arn:aws:s3:::" + bucket + "/" + prefix + "*",
			},
			{
				Sid:    "ScopeList",
				Effect: "Allow",
				Action: []string{
					"s3:ListBucket",
					"s3:ListBucketVersions",
				},
				Resource: "arn:aws:s3:::" + bucket,
				Condition: map[string]map[string]string{
					"StringLike": {"s3:prefix": prefix + "*"},
				},
			},
			{
				Sid:    "ScopeMPUSweep",
				Effect: "Allow",
				Action: []string{
					"s3:ListBucketMultipartUploads",
				},
				Resource: "arn:aws:s3:::" + bucket,
			},
			{
				Sid:    "BucketVersioningProbe",
				Effect: "Allow",
				Action: []string{
					"s3:GetBucketVersioning",
				},
				Resource: "arn:aws:s3:::" + bucket,
			},
		},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("objectstore: marshal scope policy: %w", err)
	}
	return string(out), nil
}
