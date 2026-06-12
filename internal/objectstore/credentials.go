// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

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
