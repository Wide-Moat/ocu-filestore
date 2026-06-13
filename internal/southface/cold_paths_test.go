// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
)

// TestDenyWithNonRequestScoped pins the non-request-scoped deny choke point
// (denyWith, as distinct from the request-scoped denyWithLog): it writes the
// Connect error from the verdict AND emits a WARN carrying the broker-resolved
// AUDIT truth (never the degraded wire reason). denyWith is the path a
// connect-level refusal takes before a request_id-bearing logger exists, so it
// uses the dispatcher base logger. The test captures that base logger's output
// and asserts both the wire response and the truth-carrying log line.
func TestDenyWithNonRequestScoped(t *testing.T) {
	var logBuf bytes.Buffer
	d := newDispatcherWithEngine(&fakeResolver{}, &fakeGuard{}, okCeilings(), 1<<20, newFakeEngine())
	// Replace the discard logger with a capturing one so the WARN line is
	// observable. denyWith reads d.logger directly (no request scope).
	d.logger = slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// A degraded verdict: the audited TRUTH is scope_mismatch, the WIRE
	// degrades to not_found (anti-enumeration). denyWith must log the truth,
	// not the degraded wire reason.
	v := mapDenyDegraded(denyScopeMismatch, denyNotFound)
	w := httptest.NewRecorder()
	d.denyWith(w, v, "connect-level refusal")

	// Wire side: the degraded not_found mapping (404, no x-deny-reason header).
	if w.Code != http.StatusNotFound {
		t.Fatalf("denyWith status = %d, want 404 (degraded not_found)", w.Code)
	}
	if h := w.Header().Get("x-deny-reason"); h != "" {
		t.Fatalf("x-deny-reason = %q on a degraded not_found wire, want none", h)
	}
	var ce connectError
	if err := json.Unmarshal(w.Body.Bytes(), &ce); err != nil {
		t.Fatalf("denyWith body not Connect JSON: %v (%q)", err, w.Body.String())
	}
	if ce.Code != wireCodeNotFound {
		t.Fatalf("denyWith wire code = %q, want %q", ce.Code, wireCodeNotFound)
	}

	// Log side: a WARN line carrying the AUDIT TRUTH (scope_mismatch) under
	// deny_class, never the degraded wire reason.
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logBuf.Bytes()), &line); err != nil {
		t.Fatalf("denyWith did not emit a parseable WARN line: %v (%q)", err, logBuf.String())
	}
	if line["level"] != "WARN" {
		t.Fatalf("denyWith log level = %v, want WARN", line["level"])
	}
	if line[observ.KeyDenyClass] != denyScopeMismatch {
		t.Fatalf("denyWith logged deny_class = %v, want the audited truth %q (never the degraded wire reason)",
			line[observ.KeyDenyClass], denyScopeMismatch)
	}
	if line[observ.KeyReason] != "connect-level refusal" {
		t.Fatalf("denyWith logged reason = %v, want the supplied message", line[observ.KeyReason])
	}
}

// TestMimeForPathTable pins the coarse extension->mime map the listing emitter
// uses (mimeForPath): every recognised extension, case-insensitivity, the
// no-extension fallback, the trailing-dot fallback, and the unknown-extension
// fallback all resolve to the documented value. The south face does not sniff
// content; this map is the only mime source on the mount surface.
func TestMimeForPathTable(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{"notes.txt", "text/plain"},
		{"data.json", "application/json"},
		{"page.html", "text/html"},
		{"page.htm", "text/html"},
		{"pic.png", "image/png"},
		{"photo.jpg", "image/jpeg"},
		{"photo.jpeg", "image/jpeg"},
		// Case-insensitive: the extension is lowercased before lookup.
		{"SHOUT.TXT", "text/plain"},
		{"Capture.PNG", "image/png"},
		// Unknown extension -> octet-stream.
		{"archive.tar", "application/octet-stream"},
		{"binary.xyz", "application/octet-stream"},
		// No extension at all -> octet-stream.
		{"README", "application/octet-stream"},
		{"nested/path/noext", "application/octet-stream"},
		// Trailing dot (extension empty) -> octet-stream.
		{"weird.", "application/octet-stream"},
		// Dot only in a parent directory, leaf has no extension.
		{"a.dir/leaf", "application/octet-stream"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			if got := mimeForPath(tc.path); got != tc.want {
				t.Fatalf("mimeForPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestInternalPanicErrorString pins the stringer on the engine-goroutine panic
// sentinel (internalPanicError.Error). The recover wrappers that SEND this
// sentinel are exercised by the panic-containment tests; this asserts the
// message the sentinel carries when an operator inspects a wrapped error.
func TestInternalPanicErrorString(t *testing.T) {
	if got := errInternalPanic.Error(); got != "southface: internal panic in engine goroutine" {
		t.Fatalf("errInternalPanic.Error() = %q, want the engine-goroutine panic message", got)
	}
	// errors.Is over the sentinel value still matches itself (the download /
	// upload handlers route it through denyClassForEngineErr by identity).
	if !errors.Is(errInternalPanic, errInternalPanic) {
		t.Fatal("errInternalPanic does not match itself under errors.Is")
	}
}

// TestMoveMissingSourceNotFound pins the missing-source deny arm of the move
// handlers (handleMoveFile / handleMoveDirectory): a move whose source does not
// exist surfaces not_found/404 from the engine ENOENT, no x-deny-reason header,
// and the destination is never created (no mutation recorded). This is the
// denyEngine arm the happy-path move tests do not reach.
func TestMoveMissingSourceNotFound(t *testing.T) {
	t.Run("moveFile", func(t *testing.T) {
		eng := newFakeEngine()
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
		body := fmt.Sprintf(`{"filesystem_id":%q,"source":"/ghost.txt","destination":"/dest.txt","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		w := serveOp(d, OpMoveFile, body, opScope, okIntents())
		if w.Code != http.StatusNotFound {
			t.Fatalf("moveFile(missing source) status = %d, want 404; body %s", w.Code, w.Body.String())
		}
		if h := w.Header().Get("x-deny-reason"); h != "" {
			t.Fatalf("x-deny-reason = %q on not_found, want none", h)
		}
		if got := eng.mutations(); len(got) != 0 {
			t.Fatalf("moveFile of a missing source mutated %v, want none (no destination created)", got)
		}
	})

	t.Run("moveDirectory", func(t *testing.T) {
		eng := newFakeEngine()
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
		body := fmt.Sprintf(`{"filesystem_id":%q,"source":"/no-such-dir","destination":"/dest-dir","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		w := serveOp(d, OpMoveDirectory, body, opScope, okIntents())
		if w.Code != http.StatusNotFound {
			t.Fatalf("moveDirectory(missing source) status = %d, want 404; body %s", w.Code, w.Body.String())
		}
		if got := eng.mutations(); len(got) != 0 {
			t.Fatalf("moveDirectory of a missing source mutated %v, want none", got)
		}
	})
}

// TestRemoveDirectoryMissingListError pins the List-error deny arm of
// handleRemoveDirectory (recursive=false): when the non-empty guard's
// engine.List call fails (a missing directory ENOENT), the handler surfaces the
// engine error through denyEngine WITHOUT ever calling RemoveDir. This is the
// "List error before the emptiness check" arm the rmdir-guard happy/non-empty
// tests do not reach.
func TestRemoveDirectoryMissingListError(t *testing.T) {
	eng := newFakeEngine()
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
	body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/never-made","recursive":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
	w := serveOp(d, OpRemoveDirectory, body, opScope, okIntents())
	if w.Code != http.StatusNotFound {
		t.Fatalf("removeDirectory(missing, recursive=false) status = %d, want 404 (List ENOENT); body %s", w.Code, w.Body.String())
	}
	// The non-empty guard's List failed, so RemoveDir must never have run.
	if calls := eng.removeDirCalls(); len(calls) != 0 {
		t.Fatalf("RemoveDir called %v after a List error, want none (the guard List fails first)", calls)
	}
}

// TestListDirectoryRootListError pins the listOneLevel error-return arm reached
// through handleListDirectory: listing a path whose engine root does not exist
// surfaces the engine ENOENT through denyEngine (not an empty 200). This drives
// the walk's first listOneLevel call to its error branch.
func TestListDirectoryRootListError(t *testing.T) {
	eng := newFakeEngine()
	// Seed only the scope root; the requested subdir is absent.
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
	w := serveOp(d, OpListDirectory, listBody(opScope, "/absent-subdir", 0, "", false), opScope, okIntents())
	if w.Code != http.StatusNotFound {
		t.Fatalf("listDirectory(absent subdir) status = %d, want 404 (List ENOENT); body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"entries"`) {
		t.Fatalf("listDirectory of a missing root returned an entries body, want a deny: %s", w.Body.String())
	}
}
