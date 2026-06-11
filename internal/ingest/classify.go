// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"bytes"
	"net/http"
)

// supplementalMagic fills the gap http.DetectContentType leaves for the
// threat model: the WHATWG sniff resolves media, markup, ZIP, and PDF, but
// reports every executable format as application/octet-stream. These eight
// prefixes cover the executable and script shapes the per-scope policy
// needs to be able to name (ARC-03, NFR-SEC-81).
var supplementalMagic = []struct {
	prefix []byte
	mime   string
}{
	{[]byte{0x7f, 'E', 'L', 'F'}, "application/x-elf"},            // ELF
	{[]byte{'M', 'Z'}, "application/x-msdownload"},                // PE/MZ
	{[]byte{0xcf, 0xfa, 0xed, 0xfe}, "application/x-mach-binary"}, // Mach-O 64-bit LE
	{[]byte{0xce, 0xfa, 0xed, 0xfe}, "application/x-mach-binary"}, // Mach-O 32-bit LE
	{[]byte{0xfe, 0xed, 0xfa, 0xcf}, "application/x-mach-binary"}, // Mach-O 64-bit BE
	{[]byte{0xfe, 0xed, 0xfa, 0xce}, "application/x-mach-binary"}, // Mach-O 32-bit BE
	// 0xcafebabe is BOTH the Mach-O universal (fat) magic and the Java
	// .class magic; the four bytes alone are ambiguous (byte five would
	// disambiguate: Java's minor/major version vs the fat header's
	// architecture count). Day-one both classify as
	// application/x-mach-binary: both are executable, high-risk shapes,
	// so the policy outcome is the same either way.
	{[]byte{0xca, 0xfe, 0xba, 0xbe}, "application/x-mach-binary"}, // Mach-O universal / Java .class
	{[]byte{'#', '!'}, "text/x-script"},                           // shebang
}

// supplementalSniff returns the supplemental MIME type for the first bytes
// of an entry, or ok=false when no supplemental prefix matches.
func supplementalSniff(b []byte) (string, bool) {
	for _, m := range supplementalMagic {
		if bytes.HasPrefix(b, m.prefix) {
			return m.mime, true
		}
	}
	return "", false
}

// detect classifies the first <=512 bytes of a regular-file entry:
// http.DetectContentType is the baseline, and the supplemental table is
// consulted only when the baseline reports application/octet-stream — the
// stdlib's positive identifications are never overridden. Resolved is
// never empty; Mismatch is recorded, never enforced here — enforcement is
// the caller's policy gate (ARC-03).
func detect(firstBytes []byte, declared string) ClassificationResult {
	resolved := http.DetectContentType(firstBytes)
	if resolved == "application/octet-stream" {
		if supp, ok := supplementalSniff(firstBytes); ok {
			resolved = supp
		}
	}
	return ClassificationResult{
		Declared: declared,
		Resolved: resolved,
		Mismatch: declared != "" && declared != resolved,
	}
}
