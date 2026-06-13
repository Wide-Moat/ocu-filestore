// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package observ

import "log/slog"

// PathAttr returns a slog.Attr for the given key/path pair, subject to the
// redaction rule:
//
//   - At DEBUG level (level <= slog.LevelDebug): the actual path value is
//     included. Operators running at debug can see paths in the log stream.
//   - At any higher level (INFO and above): the attribute value is replaced
//     with the fixed placeholder "[path-elided]". File paths must not appear
//     in production log streams — a path may carry workspace structure that an
//     external aggregator should not receive.
//
// Use PathAttr for every log attribute that carries a file or directory path.
// Never log a raw path string at INFO or above — this function is the sole
// sanctioned path-logging seam.
//
// REDACTION RULE (enforced by design):
//
//   - Credential values (access keys, secret tokens, bearer tokens) MUST
//     NEVER be logged at any level. This package provides NO helper that
//     accepts a credential value or a raw payload []byte, so the absence of
//     such helpers is the enforcement. If a call site needs to log "a
//     credential was used" it logs the credential kind/source only, never the
//     value.
//   - Payload bytes (file contents, upload/download body slices) MUST NEVER
//     be logged at any level, for the same reason.
//
// These rules make the JSON log stream safe to forward to any log aggregator
// without a secondary scrubbing pass.
func PathAttr(level slog.Level, key, path string) slog.Attr {
	if level <= slog.LevelDebug {
		return slog.String(key, path)
	}
	return slog.String(key, "[path-elided]")
}
