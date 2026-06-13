// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/text/unicode/norm"
)

// TestDepsSmoke_ChecksumWhenRequired is a compile-touch pin at the dependency
// boundary: it constructs an s3.Client from a static aws.Config with the
// checksum calculation and validation modes both set to WhenRequired — the
// setting the s3 engine relies on for custom (non-AWS) endpoints, where the
// SDK's default checksum trailers can be handled differently by
// S3-compatible backends and a mismatch masquerades as data corruption — and
// asserts the options stick on the constructed client. No network I/O: an
// SDK upgrade that renames or drops either option breaks this test loudly
// instead of silently reverting the engine to the default mode.
func TestDepsSmoke_ChecksumWhenRequired(t *testing.T) {
	cfg := aws.Config{
		Region:                     "us-east-1",
		Credentials:                credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}

	client := s3.NewFromConfig(cfg)
	opts := client.Options()

	if opts.RequestChecksumCalculation != aws.RequestChecksumCalculationWhenRequired {
		t.Fatalf("RequestChecksumCalculation = %v, want WhenRequired", opts.RequestChecksumCalculation)
	}
	if opts.ResponseChecksumValidation != aws.ResponseChecksumValidationWhenRequired {
		t.Fatalf("ResponseChecksumValidation = %v, want WhenRequired", opts.ResponseChecksumValidation)
	}
}

// TestDepsSmoke_STSAndNorm compile-touches the two remaining pinned modules
// so a single go.mod churn carries the whole dependency set: the sts client
// (the STS-per-session credential source's transport) constructs from a
// static config with no network I/O, and x/text's NFC form (the key
// validator's normalization check) classifies a decomposed sequence as
// non-NFC.
func TestDepsSmoke_STSAndNorm(t *testing.T) {
	stsClient := sts.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""),
	})
	if stsClient == nil {
		t.Fatal("sts.NewFromConfig returned nil")
	}

	// "e" + COMBINING ACUTE ACCENT (U+0301) is NFD, not NFC; its NFC form is
	// the precomposed U+00E9.
	decomposed := "e\u0301"
	composed := "\u00e9"
	if norm.NFC.IsNormalString(decomposed) {
		t.Fatalf("norm.NFC.IsNormalString(%q) = true, want false", decomposed)
	}
	if got := norm.NFC.String(decomposed); got != composed {
		t.Fatalf("norm.NFC.String(%q) = %q, want %q", decomposed, got, composed)
	}
}
