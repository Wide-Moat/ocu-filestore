// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package observ

import (
	"context"
	"log/slog"
)

// pathElided is the fixed placeholder substituted for a real path when the
// destination logger would not emit at DEBUG.
const pathElided = "[path-elided]"

// PathAttr returns a slog.Attr for the given key/path pair, with the redaction
// decision derived from the destination logger itself rather than from a
// caller-supplied level:
//
//   - If l would emit at DEBUG (l.Handler().Enabled(ctx, slog.LevelDebug) is
//     true), the actual path value is included. Operators running at debug can
//     see paths in the log stream.
//   - Otherwise the attribute value is replaced with the fixed placeholder
//     "[path-elided]". File paths must not appear in production log streams — a
//     path may carry workspace structure that an external aggregator should not
//     receive.
//
// Because the gate reads the logger's own enablement, the placeholder choice
// cannot disagree with the level the record is actually emitted at: a call such
// as l.Info("op", PathAttr(ctx, l, key, realPath)) on an INFO-or-higher logger
// elides the path, and the only way to surface the real path is to log through
// a logger whose handler is enabled at DEBUG. Pass the SAME *slog.Logger the
// attribute is attached to.
//
// Use PathAttr for every log attribute that carries a file or directory path.
// Never log a raw path string through a plain slog.String — this function is
// the sole sanctioned path-logging seam.
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
func PathAttr(ctx context.Context, l *slog.Logger, key, path string) slog.Attr {
	if l != nil && l.Handler().Enabled(ctx, slog.LevelDebug) {
		return slog.String(key, path)
	}
	return slog.String(key, pathElided)
}
