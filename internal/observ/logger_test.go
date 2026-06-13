// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package observ

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TestParseLevel verifies all four valid tokens and a representative set of
// invalid ones, including the empty string and upper-case variants.
func TestParseLevel(t *testing.T) {
	valid := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
	}
	for _, tc := range valid {
		got, err := ParseLevel(tc.in)
		if err != nil {
			t.Errorf("ParseLevel(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	invalid := []string{"", "DEBUG", "INFO", "WARN", "ERROR", "loud", "verbose", "trace"}
	for _, s := range invalid {
		_, err := ParseLevel(s)
		if err == nil {
			t.Errorf("ParseLevel(%q) = nil error, want errBadLogLevel", s)
			continue
		}
		if !IsBadLogLevel(err) {
			t.Errorf("ParseLevel(%q) error %v does not wrap errBadLogLevel", s, err)
		}
	}
}

// TestNewLogger checks that NewLogger emits per-line valid JSON objects:
// - lines below the configured threshold are absent
// - lines at/above the threshold are present
// - each line is a valid JSON object with time/level/msg keys
func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelWarn)

	l.Debug("should be absent")
	l.Info("also absent")
	l.Warn("present warn")
	l.Error("present error")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (warn+error), got %d:\n%s", len(lines), buf.String())
	}

	wantMsgs := []string{"present warn", "present error"}
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d not valid JSON: %v\n%s", i, err, line)
		}
		for _, key := range []string{"time", "level", "msg"} {
			if _, ok := obj[key]; !ok {
				t.Errorf("line %d: missing key %q in %s", i, key, line)
			}
		}
		if obj["msg"] != wantMsgs[i] {
			t.Errorf("line %d: msg = %q, want %q", i, obj["msg"], wantMsgs[i])
		}
	}

	// Also check that at debug level all four appear.
	var buf2 bytes.Buffer
	l2 := NewLogger(&buf2, slog.LevelDebug)
	l2.Debug("d")
	l2.Info("i")
	l2.Warn("w")
	l2.Error("e")
	lines2 := strings.Split(strings.TrimSpace(buf2.String()), "\n")
	if len(lines2) != 4 {
		t.Fatalf("at debug expected 4 lines, got %d:\n%s", len(lines2), buf2.String())
	}
}

// TestErrorLog verifies that a plain log.Print call through the bridge
// becomes exactly one WARN JSON line and that the printed text is preserved
// in the msg field. The bridge is WARN, not ERROR: http.Server chatter is
// largely benign and must not inflate the error rate or page operators.
func TestErrorLog(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelDebug)
	bridge := ErrorLog(l)

	bridge.Print("http server error: dial refused")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 line, got %d:\n%s", len(lines), buf.String())
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &obj); err != nil {
		t.Fatalf("ErrorLog output not valid JSON: %v\n%s", err, lines[0])
	}
	if obj["level"] != "WARN" {
		t.Errorf("level = %q, want WARN", obj["level"])
	}
	msg, _ := obj["msg"].(string)
	if !strings.Contains(msg, "http server error: dial refused") {
		t.Errorf("msg %q does not contain the printed text", msg)
	}
}

// TestAttrKeyConstants checks that the exported attribute key constants exist
// and that KeyRequestID in particular is the exact string "request_id" (the
// T2-18 seam value the rest of the system will use).
func TestAttrKeyConstants(t *testing.T) {
	if KeyRequestID != "request_id" {
		t.Errorf("KeyRequestID = %q, want %q", KeyRequestID, "request_id")
	}
	// Verify a freshly built logger emits no "request_id" key at the
	// message level — it must be reserved, never auto-set.
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelInfo)
	l.Info("startup")
	if strings.Contains(buf.String(), "request_id") {
		t.Errorf("NewLogger emitted request_id key on first log — it must be RESERVED, never auto-set:\n%s", buf.String())
	}
}
