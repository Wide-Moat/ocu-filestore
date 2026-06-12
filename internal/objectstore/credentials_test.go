// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"context"
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
