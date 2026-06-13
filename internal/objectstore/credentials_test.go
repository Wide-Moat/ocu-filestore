// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/admission"
)

// testSecret is the canary every redaction assertion greps for. It never
// appears in any error, fmt verb, or provider string surface.
const testSecret = "REDACTION-CANARY-vN9xQ2pT7wL4"

// writeCredFile writes a credential file with the given mode and returns
// its path.
func writeCredFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s3.cred")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Chmod separately: WriteFile's mode is masked by umask.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return path
}

func clearCredEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvS3AccessKeyID, "")
	t.Setenv(EnvS3SecretAccessKey, "")
}

// TestCredentialFile_ModeGate pins the 0600 admission: exactly 0600 is
// accepted; anything more open (or more closed) refuses typed, and a
// symbolic link refuses even at 0600.
func TestCredentialFile_ModeGate(t *testing.T) {
	clearCredEnv(t)
	content := "access_key_id=AKIDTEST\nsecret_access_key=" + testSecret + "\n"

	t.Run("0600 accepted", func(t *testing.T) {
		src, err := NewStaticCredentialSource(writeCredFile(t, content, 0o600))
		if err != nil {
			t.Fatalf("NewStaticCredentialSource(0600) = %v, want nil", err)
		}
		prov, err := src.Provider(context.Background())
		if err != nil {
			t.Fatalf("Provider: %v", err)
		}
		got, err := prov.Retrieve(context.Background())
		if err != nil {
			t.Fatalf("Retrieve: %v", err)
		}
		if got.AccessKeyID != "AKIDTEST" || got.SecretAccessKey != testSecret {
			t.Fatal("ingested credential does not round-trip through the provider")
		}
	})

	for _, mode := range []os.FileMode{0o644, 0o640, 0o660, 0o400, 0o700} {
		t.Run(fmt.Sprintf("%04o refused", mode), func(t *testing.T) {
			_, err := NewStaticCredentialSource(writeCredFile(t, content, mode))
			if !errors.Is(err, ErrCredentialFileUnsafe) {
				t.Fatalf("NewStaticCredentialSource(%04o) = %v, want ErrCredentialFileUnsafe", mode, err)
			}
		})
	}

	t.Run("symlink refused", func(t *testing.T) {
		real := writeCredFile(t, content, 0o600)
		link := filepath.Join(t.TempDir(), "link.cred")
		if err := os.Symlink(real, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if _, err := NewStaticCredentialSource(link); !errors.Is(err, ErrCredentialFileUnsafe) {
			t.Fatalf("NewStaticCredentialSource(symlink) = %v, want ErrCredentialFileUnsafe", err)
		}
	})

	t.Run("missing file refused, never env fall-through", func(t *testing.T) {
		t.Setenv(EnvS3AccessKeyID, "AKIDENV")
		t.Setenv(EnvS3SecretAccessKey, testSecret)
		_, err := NewStaticCredentialSource(filepath.Join(t.TempDir(), "absent.cred"))
		if !errors.Is(err, ErrCredentialFileUnsafe) {
			t.Fatalf("NewStaticCredentialSource(missing file with env set) = %v, want ErrCredentialFileUnsafe (no fall-through)", err)
		}
	})

	t.Run("unsafe file refused even with env set", func(t *testing.T) {
		t.Setenv(EnvS3AccessKeyID, "AKIDENV")
		t.Setenv(EnvS3SecretAccessKey, testSecret)
		_, err := NewStaticCredentialSource(writeCredFile(t, content, 0o644))
		if !errors.Is(err, ErrCredentialFileUnsafe) {
			t.Fatalf("defective file with env set = %v, want ErrCredentialFileUnsafe (no fall-through)", err)
		}
	})
}

// TestCredentialFile_Malformed pins the parse refusals: no separator, empty
// value, unknown key, a missing required line — each ErrCredentialMalformed,
// and the error NEVER carries line content.
func TestCredentialFile_Malformed(t *testing.T) {
	clearCredEnv(t)
	for _, tc := range []struct {
		name, content string
	}{
		{"no separator", "access_key_id=AKID\n" + testSecret + "\n"},
		{"empty value", "access_key_id=AKID\nsecret_access_key=\n"},
		{"unknown key", "access_key_id=AKID\npassword=" + testSecret + "\n"},
		{"missing secret line", "access_key_id=AKID\n"},
		{"missing key line", "secret_access_key=" + testSecret + "\n"},
		{"empty file", ""},
		{"comments only", "# just a comment\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewStaticCredentialSource(writeCredFile(t, tc.content, 0o600))
			if !errors.Is(err, ErrCredentialMalformed) {
				t.Fatalf("NewStaticCredentialSource(%s) = %v, want ErrCredentialMalformed", tc.name, err)
			}
			if strings.Contains(fmt.Sprintf("%v %+v %s", err, err, err), testSecret) {
				t.Fatal("malformed-file error carries credential content")
			}
		})
	}
}

// TestCredentialEnv_Intake pins the environment source: both variables set
// ingests; either missing refuses ErrCredentialMissing.
func TestCredentialEnv_Intake(t *testing.T) {
	t.Run("both set", func(t *testing.T) {
		t.Setenv(EnvS3AccessKeyID, "AKIDENV")
		t.Setenv(EnvS3SecretAccessKey, testSecret)
		src, err := NewStaticCredentialSource("")
		if err != nil {
			t.Fatalf("NewStaticCredentialSource(env) = %v, want nil", err)
		}
		prov, err := src.Provider(context.Background())
		if err != nil {
			t.Fatalf("Provider: %v", err)
		}
		got, err := prov.Retrieve(context.Background())
		if err != nil {
			t.Fatalf("Retrieve: %v", err)
		}
		if got.AccessKeyID != "AKIDENV" || got.SecretAccessKey != testSecret {
			t.Fatal("env credential does not round-trip through the provider")
		}
	})
	t.Run("key only", func(t *testing.T) {
		t.Setenv(EnvS3AccessKeyID, "AKIDENV")
		t.Setenv(EnvS3SecretAccessKey, "")
		if _, err := NewStaticCredentialSource(""); !errors.Is(err, ErrCredentialMissing) {
			t.Fatalf("key-only env = %v, want ErrCredentialMissing", err)
		}
	})
	t.Run("secret only", func(t *testing.T) {
		t.Setenv(EnvS3AccessKeyID, "")
		t.Setenv(EnvS3SecretAccessKey, testSecret)
		if _, err := NewStaticCredentialSource(""); !errors.Is(err, ErrCredentialMissing) {
			t.Fatalf("secret-only env = %v, want ErrCredentialMissing", err)
		}
	})
	t.Run("neither", func(t *testing.T) {
		clearCredEnv(t)
		if _, err := NewStaticCredentialSource(""); !errors.Is(err, ErrCredentialMissing) {
			t.Fatalf("no source = %v, want ErrCredentialMissing", err)
		}
	})
}

// TestCredentialFile_PrecedenceOverEnv pins source precedence: a valid file
// wins over a populated environment.
func TestCredentialFile_PrecedenceOverEnv(t *testing.T) {
	t.Setenv(EnvS3AccessKeyID, "AKIDENV")
	t.Setenv(EnvS3SecretAccessKey, "env-secret-never-used")
	path := writeCredFile(t, "access_key_id=AKIDFILE\nsecret_access_key="+testSecret+"\n", 0o600)
	src, err := NewStaticCredentialSource(path)
	if err != nil {
		t.Fatalf("NewStaticCredentialSource: %v", err)
	}
	prov, _ := src.Provider(context.Background())
	got, err := prov.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got.AccessKeyID != "AKIDFILE" || got.SecretAccessKey != testSecret {
		t.Fatal("file source did not take precedence over env")
	}
}

// TestCredentialKind pins the admission wiring: the static source is the
// host-local long-lived cell.
func TestCredentialKind(t *testing.T) {
	t.Setenv(EnvS3AccessKeyID, "AKIDENV")
	t.Setenv(EnvS3SecretAccessKey, testSecret)
	src, err := NewStaticCredentialSource("")
	if err != nil {
		t.Fatalf("NewStaticCredentialSource: %v", err)
	}
	if got := src.Kind(); got != admission.CredHostLocalLongLived {
		t.Fatalf("Kind() = %q, want %q", got, admission.CredHostLocalLongLived)
	}
	var _ CredentialSource = src // the seam compiles
}

// TestCredentialRedaction is the load-bearing leak gate: every fmt verb over
// the credential value, the source, and EVERY constructor error path must
// never reproduce the secret byte-string.
func TestCredentialRedaction(t *testing.T) {
	t.Setenv(EnvS3AccessKeyID, "AKIDENV")
	t.Setenv(EnvS3SecretAccessKey, testSecret)

	src, err := NewStaticCredentialSource("")
	if err != nil {
		t.Fatalf("NewStaticCredentialSource: %v", err)
	}

	cred := src.cred
	for _, rendered := range []string{
		fmt.Sprintf("%v", cred), fmt.Sprintf("%+v", cred), fmt.Sprintf("%s", cred),
		fmt.Sprintf("%#v", cred), fmt.Sprintf("%q", cred),
		fmt.Sprintf("%v", &cred), fmt.Sprintf("%+v", &cred),
		fmt.Sprintf("%v", src), fmt.Sprintf("%+v", src), fmt.Sprintf("%s", src),
		fmt.Sprintf("%#v", src),
	} {
		if strings.Contains(rendered, testSecret) {
			t.Fatalf("credential rendering leaked the secret: %q", rendered)
		}
		if strings.Contains(rendered, "AKIDENV") {
			t.Fatalf("credential rendering leaked the access key id: %q", rendered)
		}
	}

	// Every error path, rendered under every common verb: the secret is in
	// the FILE CONTENT for these cases, so a leak would mean the error
	// echoed the file.
	clearCredEnv(t)
	errPaths := []error{}
	if _, err := NewStaticCredentialSource(filepath.Join(t.TempDir(), "absent")); err != nil {
		errPaths = append(errPaths, err)
	}
	if _, err := NewStaticCredentialSource(writeCredFile(t, "access_key_id=AKID\nsecret_access_key="+testSecret+"\n", 0o644)); err != nil {
		errPaths = append(errPaths, err)
	}
	if _, err := NewStaticCredentialSource(writeCredFile(t, "garbage "+testSecret+"\n", 0o600)); err != nil {
		errPaths = append(errPaths, err)
	}
	if _, err := NewStaticCredentialSource(writeCredFile(t, "token="+testSecret+"\n", 0o600)); err != nil {
		errPaths = append(errPaths, err)
	}
	if _, err := NewStaticCredentialSource(""); err != nil {
		errPaths = append(errPaths, err)
	}
	if len(errPaths) != 5 {
		t.Fatalf("expected 5 constructor error paths, got %d", len(errPaths))
	}
	for i, err := range errPaths {
		rendered := fmt.Sprintf("%v | %+v | %s | %#v", err, err, err, err)
		if strings.Contains(rendered, testSecret) {
			t.Fatalf("error path %d leaked the secret: %q", i, rendered)
		}
	}
}

// TestStaticCredential_StringGoString pins that the staticCredential and
// StaticCredentialSource String/GoString methods — the %v and %#v paths —
// return a redaction marker and NEVER expose the access key id or the secret
// key bytes. These methods were 0% covered; they are security-load-bearing:
// a bug here lets a credential leak through any log or error that formats the
// type.
func TestStaticCredential_StringGoString(t *testing.T) {
	t.Setenv(EnvS3AccessKeyID, "AKIDTEST-SGS")
	t.Setenv(EnvS3SecretAccessKey, testSecret)

	src, err := NewStaticCredentialSource("")
	if err != nil {
		t.Fatalf("NewStaticCredentialSource: %v", err)
	}

	// staticCredential (inner type, accessed as src.cred).
	cred := src.cred
	strVal := cred.String()
	goStrVal := cred.GoString()
	for _, rendered := range []string{strVal, goStrVal} {
		if strings.Contains(rendered, testSecret) {
			t.Fatalf("staticCredential rendering leaked the secret: %q", rendered)
		}
		if strings.Contains(rendered, "AKIDTEST-SGS") {
			t.Fatalf("staticCredential rendering leaked the access key id: %q", rendered)
		}
		if rendered == "" {
			t.Fatalf("staticCredential rendering returned empty string — must return a non-empty redaction marker")
		}
	}

	// StaticCredentialSource (outer type).
	srcStr := src.String()
	srcGoStr := src.GoString()
	for _, rendered := range []string{srcStr, srcGoStr} {
		if strings.Contains(rendered, testSecret) {
			t.Fatalf("StaticCredentialSource rendering leaked the secret: %q", rendered)
		}
		if strings.Contains(rendered, "AKIDTEST-SGS") {
			t.Fatalf("StaticCredentialSource rendering leaked the access key id: %q", rendered)
		}
		if rendered == "" {
			t.Fatalf("StaticCredentialSource rendering returned empty string — must return a non-empty redaction marker")
		}
	}
}

// TestSTSCredentialSource_StringGoString pins that STSCredentialSource
// String/GoString never expose the parent credential's secret (the redaction
// property for the STS wrapper, mirroring TestStaticCredential_StringGoString
// for the same coverage gap on the STS side).
func TestSTSCredentialSource_StringGoString(t *testing.T) {
	src, err := NewSTSCredentialSource(stsTestConfig(t))
	if err != nil {
		t.Fatalf("NewSTSCredentialSource: %v", err)
	}

	strVal := src.String()
	goStrVal := src.GoString()
	for _, rendered := range []string{strVal, goStrVal} {
		if strings.Contains(rendered, testSecret) {
			t.Fatalf("STSCredentialSource rendering leaked the parent secret: %q", rendered)
		}
		if rendered == "" {
			t.Fatalf("STSCredentialSource rendering returned empty string — must return a non-empty redaction marker")
		}
	}
}

// --- 13-14: STS-per-session source -----------------------------------------

// stsTestConfig returns a valid STSConfig backed by an env static parent.
func stsTestConfig(t *testing.T) STSConfig {
	t.Helper()
	t.Setenv(EnvS3AccessKeyID, "AKIDPARENT")
	t.Setenv(EnvS3SecretAccessKey, testSecret)
	parent, err := NewStaticCredentialSource("")
	if err != nil {
		t.Fatalf("parent source: %v", err)
	}
	return STSConfig{
		RoleARN: "arn:aws:iam::000000000000:role/ocu-session",
		Region:  "us-east-1",
		Bucket:  "ocu-bucket",
		Scope:   "fs-sts-01",
		Parent:  parent,
	}
}

// TestSTSPolicyDocument table-asserts the inline session policy: every
// object action confined to the scope prefix resource, bucket-level listing
// confined by the s3:prefix condition, no wildcard bucket, no
// unconditioned ListBucket — the least-privilege cell. The single
// documented exception is ListBucketMultipartUploads (the SEC-54 orphan
// sweep lists bucket-wide and filters client-side).
func TestSTSPolicyDocument(t *testing.T) {
	raw, err := scopePrefixPolicy("ocu-bucket", "fs-sts-01")
	if err != nil {
		t.Fatalf("scopePrefixPolicy: %v", err)
	}
	var doc stsPolicyDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("policy is not valid JSON: %v", err)
	}
	if doc.Version != "2012-10-17" {
		t.Fatalf("policy version = %q", doc.Version)
	}

	byID := map[string]stsPolicyStatement{}
	for _, st := range doc.Statement {
		if st.Effect != "Allow" {
			t.Fatalf("statement %q effect = %q, want Allow only", st.Sid, st.Effect)
		}
		if st.Resource == "*" || strings.Contains(st.Resource, ":::*") {
			t.Fatalf("statement %q names a wildcard resource: %q", st.Sid, st.Resource)
		}
		for _, a := range st.Action {
			if a == "*" || a == "s3:*" {
				t.Fatalf("statement %q carries a wildcard action", st.Sid)
			}
		}
		byID[st.Sid] = st
	}

	obj, ok := byID["ScopeObjects"]
	if !ok {
		t.Fatal("ScopeObjects statement missing")
	}
	if obj.Resource != "arn:aws:s3:::ocu-bucket/fs-sts-01/*" {
		t.Fatalf("ScopeObjects resource = %q, want the scope-prefix cell", obj.Resource)
	}
	for _, want := range []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject",
		"s3:DeleteObjectVersion", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"} {
		found := false
		for _, a := range obj.Action {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("ScopeObjects missing action %q", want)
		}
	}

	list, ok := byID["ScopeList"]
	if !ok {
		t.Fatal("ScopeList statement missing")
	}
	if list.Resource != "arn:aws:s3:::ocu-bucket" {
		t.Fatalf("ScopeList resource = %q, want the bucket ARN", list.Resource)
	}
	cond, ok := list.Condition["StringLike"]
	if !ok || cond["s3:prefix"] != "fs-sts-01/*" {
		t.Fatalf("ScopeList condition = %v, want StringLike s3:prefix fs-sts-01/*", list.Condition)
	}

	// The documented exception: the MPU sweep statement is bucket-level
	// list-only — it must never carry mutating actions.
	mpu, ok := byID["ScopeMPUSweep"]
	if !ok {
		t.Fatal("ScopeMPUSweep statement missing")
	}
	if len(mpu.Action) != 1 || mpu.Action[0] != "s3:ListBucketMultipartUploads" {
		t.Fatalf("ScopeMPUSweep actions = %v, want exactly ListBucketMultipartUploads", mpu.Action)
	}
}

// TestSTSHostileScopeNeverBuildsPolicy pins the validation order: a hostile
// scope id refuses at the constructor AND at the policy builder — policy
// text for a hostile scope is never constructed.
func TestSTSHostileScopeNeverBuildsPolicy(t *testing.T) {
	for _, hostile := range []ScopeID{"", ".", "..", "a/b", `a\b`, "x\x00y", "../escape"} {
		cfg := stsTestConfig(t)
		cfg.Scope = hostile
		if _, err := NewSTSCredentialSource(cfg); !errors.Is(err, ErrInvalidScopeID) {
			t.Fatalf("NewSTSCredentialSource(scope=%q) = %v, want ErrInvalidScopeID", hostile, err)
		}
		if raw, err := scopePrefixPolicy("ocu-bucket", hostile); !errors.Is(err, ErrInvalidScopeID) {
			t.Fatalf("scopePrefixPolicy(scope=%q) = %q, %v, want ErrInvalidScopeID", hostile, raw, err)
		}
	}
}

// TestSTSConstructorRefusals pins the config gate: every missing field is a
// typed refusal.
func TestSTSConstructorRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*STSConfig)
	}{
		{"no role arn", func(c *STSConfig) { c.RoleARN = "" }},
		{"no bucket", func(c *STSConfig) { c.Bucket = "" }},
		{"no region", func(c *STSConfig) { c.Region = "" }},
		{"no parent", func(c *STSConfig) { c.Parent = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stsTestConfig(t)
			tc.mutate(&cfg)
			if _, err := NewSTSCredentialSource(cfg); !errors.Is(err, errSTSConfig) {
				t.Fatalf("NewSTSCredentialSource(%s) = %v, want errSTSConfig", tc.name, err)
			}
		})
	}
}

// TestSTSKindAndRedaction pins the seam: Kind = sts_per_session, the seam
// interface compiles, and the source never renders its parent's secret.
func TestSTSKindAndRedaction(t *testing.T) {
	src, err := NewSTSCredentialSource(stsTestConfig(t))
	if err != nil {
		t.Fatalf("NewSTSCredentialSource: %v", err)
	}
	if got := src.Kind(); got != admission.CredSTSPerSession {
		t.Fatalf("Kind() = %q, want %q", got, admission.CredSTSPerSession)
	}
	var _ CredentialSource = src

	for _, rendered := range []string{
		fmt.Sprintf("%v", src), fmt.Sprintf("%+v", src),
		fmt.Sprintf("%s", src), fmt.Sprintf("%#v", src),
	} {
		if strings.Contains(rendered, testSecret) {
			t.Fatalf("STS source rendering leaked the parent secret: %q", rendered)
		}
	}

	// The provider constructs without any network call (AssumeRole is lazy
	// — it fires on first Retrieve).
	prov, err := src.Provider(context.Background())
	if err != nil {
		t.Fatalf("Provider: %v", err)
	}
	if prov == nil {
		t.Fatal("Provider returned nil")
	}
}

// TestS3Live_STSAssumeRole exercises the real AssumeRole flow against an
// STS endpoint when the rig exposes one. The MinIO rig's root credential
// cannot assume roles, so this leg gates on an EXPLICIT
// OCU_S3_TEST_STS_ENDPOINT (+OCU_S3_TEST_STS_ROLE_ARN) and skips loudly
// otherwise — the honest gate until the rig grows an STS principal; there
// is NO mock STS server.
func TestS3Live_STSAssumeRole(t *testing.T) {
	endpoint := os.Getenv("OCU_S3_TEST_STS_ENDPOINT")
	roleARN := os.Getenv("OCU_S3_TEST_STS_ROLE_ARN")
	if endpoint == "" || roleARN == "" {
		t.Skip(`OCU_S3_TEST_STS_ENDPOINT / OCU_S3_TEST_STS_ROLE_ARN not set - live STS leg SKIPPED.
The MinIO rig's root credential cannot AssumeRole; point these at an STS
endpoint with an assumable role to run the live AssumeRole flow. The call
shape is covered un-gated by the policy-document and constructor tests.`)
	}
	cfg := stsTestConfig(t)
	cfg.Endpoint = endpoint
	cfg.RoleARN = roleARN
	if b := os.Getenv("OCU_S3_TEST_BUCKET"); b != "" {
		cfg.Bucket = b
	}
	src, err := NewSTSCredentialSource(cfg)
	if err != nil {
		t.Fatalf("NewSTSCredentialSource: %v", err)
	}
	prov, err := src.Provider(context.Background())
	if err != nil {
		t.Fatalf("Provider: %v", err)
	}
	creds, err := prov.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("AssumeRole Retrieve: %v", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		t.Fatal("AssumeRole returned an incomplete session credential")
	}
}
