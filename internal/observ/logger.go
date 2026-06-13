// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package observ provides the structured-logging plumbing shared across all
// broker packages: a stdlib log/slog JSON logger, a level parser, an
// http.Server ErrorLog bridge, redaction discipline, and a set of reserved
// attribute-key constants.
//
// Import policy: observ imports stdlib only (log/slog, log, io, os, fmt,
// errors). It MUST NOT import any internal/* package so that southface,
// telemetry, and cmd can all depend on it cycle-free.
//
// Redaction rule (see also redact.go): no log line at any level carries a
// credential value or payload bytes. File paths appear ONLY when the
// destination logger is enabled at DEBUG; use PathAttr for any path attribute
// so the gate reads the logger's own enablement and a caller cannot leak a
// path by mismatching a level argument.
package observ

import (
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
)

// Attribute key constants. Every log call that emits a structured attribute
// MUST use these constants — never a raw string — so key names are stable
// across refactors and the request-id threading stays uniform across call
// sites.
//
// KeyRequestID is the request-correlation key: the dispatch layer derives a
// per-request child logger at STAGE 0 (With(KeyRequestID, id)), so every log
// line emitted while handling that request carries the same request_id. Use
// the constant rather than the raw string anywhere a request id is logged.
const (
	// KeyRequestID is the request-correlation key set by the dispatch layer
	// at STAGE 0; every per-request log line carries it.
	KeyRequestID = "request_id"
	// KeyDenyClass names the broker deny class in a deny WARN.
	KeyDenyClass = "deny_class"
	// KeyPeerUID is the kernel-attested peer uid at the accept gate.
	KeyPeerUID = "peer_uid"
	// KeyPeerPID is the kernel-attested peer pid at the accept gate.
	KeyPeerPID = "peer_pid"
	// KeyScope is the filesystem scope identifier for a session.
	KeyScope = "filesystem_id"
	// KeyOp is the broker operation name.
	KeyOp = "op"
	// KeyReason is a human-readable reason string (non-secret).
	KeyReason = "reason"
)

// errBadLogLevel is the typed error ParseLevel wraps when given an
// unrecognised level string. Match it with errors.Is.
var errBadLogLevel = errors.New("observ: unknown log level")

// ParseLevel maps the four lowercase level tokens to slog.Level values.
// Any other input — including the empty string and the uppercase forms —
// returns errBadLogLevel wrapping the offending token. This is called
// during flag validation BEFORE any socket is bound.
func ParseLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("%w: %q", errBadLogLevel, s)
	}
}

// NewLogger returns a *slog.Logger writing JSON to w at the given level.
// The handler uses slog.NewJSONHandler so every record is a valid JSON
// object with the standard time/level/msg keys. Callers derive child
// loggers via Logger.With so the T2-18 request-id drops in without
// rewriting call sites.
func NewLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
	}))
}

// ErrorLog returns a *log.Logger that routes every log.Print* call through
// the given slog.Logger at WARN level. Wire it into http.Server.ErrorLog so
// the http.Server's internal chatter enters the JSON stream rather than
// landing as bare text on a raw writer.
//
// The bridge is deliberately WARN, not ERROR: http.Server emits log.Print for
// benign, recoverable conditions (peer connection resets, superfluous
// WriteHeader calls, request-line read timeouts) as well as genuine faults,
// and it gives no way to tell them apart at this seam. Classifying all of it
// as ERROR would inflate the error rate and risk false pages, so it lands at
// WARN; real broker faults are logged at ERROR by the broker's own call sites.
func ErrorLog(l *slog.Logger) *log.Logger {
	return slog.NewLogLogger(l.Handler(), slog.LevelWarn)
}

// IsBadLogLevel reports whether err is (or wraps) errBadLogLevel. Exported
// so the cmd layer can match validate's error without importing the unexported
// sentinel — the same pattern the rest of validate uses with errors.Is on
// typed sentinels.
func IsBadLogLevel(err error) bool {
	return errors.Is(err, errBadLogLevel)
}
