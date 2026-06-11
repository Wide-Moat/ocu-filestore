// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Entry-name and symlink-target lexical validation. validateEntryName is
// the twin of internal/objectstore.ValidatePath, re-implemented here (not
// imported) because this package builds off main independently of the
// engine branches and imports no internal package. It ADDS two checks the
// twin does not need on its wire: backslash-separator normalization and an
// explicit drive-letter reject, because archive entry names arrive from
// arbitrary zippers, including Windows ones.

package ingest

import (
	"path/filepath"
	"strings"
)

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// hasURLScheme reports whether s begins with an RFC-3986 scheme followed by
// "://" (scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )). It is purely
// lexical — it does not validate the rest of the string as a URL. It must
// run on the input BEFORE filepath.Clean, because Clean deduplicates "//"
// to "/" and hides the scheme shape.
func hasURLScheme(s string) bool {
	i := 0
	if i >= len(s) || !isAlpha(s[i]) {
		return false
	}
	i++
	for i < len(s) && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '+' || s[i] == '-' || s[i] == '.') {
		i++
	}
	return i+2 < len(s) && s[i] == ':' && s[i+1] == '/' && s[i+2] == '/'
}

// validateEntryName returns the cleaned, lexically safe form of a zip
// entry name, or ErrInvalidEntry. It is a pure function — no filesystem
// access — so every rejection happens before the sink sees the name
// (ARC-02, NFR-SEC-80).
//
// Rejection classes, checked in this exact order:
//
//  1. NUL byte — first: filepath.Clean and filepath.IsLocal both pass NUL
//     through, so relying on them would defer the rejection to the
//     syscall layer.
//  2. Backslash normalization — Windows zippers write "\"-separated
//     names; normalized to "/" BEFORE the drive-letter and URL checks so
//     neither shape can be smuggled behind a backslash.
//  3. Drive letter — explicit reject: filepath.IsLocal is OS-dependent
//     and returns true for "C:/foo" on linux/darwin.
//  4. URL scheme — before filepath.Clean, which deduplicates "//" and
//     would hide the scheme shape.
//  5. filepath.Clean, then reject "." (the empty name, ".", "a/.." ...)
//     and anything not filepath.IsLocal (absolute paths, ".." escapes):
//     an entry must name an object inside the destination, never the
//     destination root itself.
func validateEntryName(raw string) (string, error) {
	if strings.ContainsRune(raw, '\x00') {
		return "", ErrInvalidEntry
	}
	name := strings.ReplaceAll(raw, "\\", "/")
	if len(name) >= 2 && name[1] == ':' && isAlpha(name[0]) {
		return "", ErrInvalidEntry
	}
	if hasURLScheme(name) {
		return "", ErrInvalidEntry
	}
	clean := filepath.Clean(name)
	if clean == "." || !filepath.IsLocal(clean) {
		return "", ErrInvalidEntry
	}
	return clean, nil
}

// validateSymlinkTarget rejects a symlink entry at destDir/entryCleanName
// whose target would resolve outside destDir. destDir is a lexical anchor
// only — it is never opened; runtime containment is the engine's job.
//
// Absolute targets are rejected FIRST and unconditionally: filepath.Rel
// arithmetic on an absolute target can produce a ".."-free result for
// shallow destinations, so the relative check alone cannot be trusted to
// flag them. Every reject returns ErrSymlinkEscape — deliberately distinct
// from ErrInvalidEntry, so a symlink reject is distinguishable from a
// traversal reject (ARC-02).
func validateSymlinkTarget(entryCleanName, target, destDir string) error {
	if filepath.IsAbs(target) {
		return ErrSymlinkEscape
	}
	if strings.ContainsRune(target, '\x00') {
		return ErrSymlinkEscape
	}
	symlinkDir := filepath.Dir(filepath.Join(destDir, entryCleanName))
	resolved := filepath.Clean(filepath.Join(symlinkDir, target))
	rel, err := filepath.Rel(destDir, resolved)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ErrSymlinkEscape
	}
	return nil
}
