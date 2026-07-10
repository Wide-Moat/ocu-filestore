// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
)

// newEngineDispatcher builds a dispatcher with the seven phase-9 handlers
// wired over the given engine fake and the supplied seams.
func newEngineDispatcher(res Resolver, g Guard, c CeilingsRegistry, eng Engine) *dispatcher {
	return newDispatcherWithEngine(res, g, c, 1<<20, eng)
}

// serveOp drives a single op end-to-end through the real dispatcher and
// returns the recorder. body is the full op JSON body.
func serveOp(d *dispatcher, op Op, body string, scope string, intents []Intent) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	d.ServeHTTP(w, scopedRequest(op, body, scope, intents))
	return w
}

// listBody builds a listDirectory request body.
func listBody(scope, path string, limit int, cursor string, recursive bool) string {
	return fmt.Sprintf(
		`{"filesystem_id":%q,"path":%q,"limit":%d,"cursor":%q,"recursive":%t,"authorization_metadata":{"intent":"read","downloadable":false}}`,
		scope, path, limit, cursor, recursive)
}

func decodeList(t *testing.T, w *httptest.ResponseRecorder) listDirectoryResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("listDirectory status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	var resp listDirectoryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("listDirectory body not JSON: %v (%s)", err, w.Body.String())
	}
	return resp
}

// assertBareAck asserts the response is 200 with a parsed-equal bare ack {}.
func assertBareAck(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (bare ack); body %s", w.Code, w.Body.String())
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("ack body not JSON object: %v (%s)", err, w.Body.String())
	}
	if len(m) != 0 {
		t.Fatalf("ack body = %s, want bare {}", w.Body.String())
	}
}

const opScope = "fs-ops"

func okIntents() []Intent { return []Intent{IntentRead, IntentWrite} }

// TestHandlerListDirectory pins OPS-01: the Entry union with guest-read field
// names and guest-convention paths, and uuid reuse across listings.
func TestHandlerListDirectory(t *testing.T) {
	eng := newFakeEngine()
	eng.mkdirSeed(opScope, "sub")
	eng.putFile(opScope, "a.txt", 11)
	eng.putFile(opScope, "sub/b.json", 22)

	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	w := serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents())
	resp := decodeList(t, w)

	var sawFile, sawDir bool
	var fileUUID string
	for _, e := range resp.Entries {
		switch {
		case e.File != nil:
			sawFile = true
			if e.File.Path != "/a.txt" {
				t.Fatalf("file path = %q, want guest-convention /a.txt", e.File.Path)
			}
			if e.File.Size != 11 {
				t.Fatalf("file size = %d, want 11", e.File.Size)
			}
			if e.File.MTime == "" || e.File.MIME == "" || e.File.UUID == "" {
				t.Fatalf("file entry missing guest-read field: %+v", e.File)
			}
			fileUUID = e.File.UUID
		case e.Directory != nil:
			sawDir = true
			if e.Directory.Path != "/sub" {
				t.Fatalf("dir path = %q, want guest-convention /sub", e.Directory.Path)
			}
			if e.Directory.MTime == "" {
				t.Fatalf("dir entry missing mtime: %+v", e.Directory)
			}
		}
	}
	if !sawFile || !sawDir {
		t.Fatalf("listing missing a file or directory branch: %+v", resp.Entries)
	}

	// uuid reuse: a second listing of the same tree reuses the file uuid.
	w2 := serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents())
	resp2 := decodeList(t, w2)
	for _, e := range resp2.Entries {
		if e.File != nil && e.File.Path == "/a.txt" {
			if e.File.UUID != fileUUID {
				t.Fatalf("uuid not reused: %q vs %q", e.File.UUID, fileUUID)
			}
		}
	}
}

// TestHandlerListDirectoryRecursiveCursor pins OPS-01 + P2: a multi-page
// recursive walk visits each entry exactly once with strictly-advancing
// cursors and an empty cursor on the last page.
func TestHandlerListDirectoryRecursiveCursor(t *testing.T) {
	eng := newFakeEngine()
	// Build a tree spanning >2 pages at limit=2.
	eng.mkdirSeed(opScope, "d1")
	eng.mkdirSeed(opScope, "d2")
	eng.putFile(opScope, "d1/f1", 1)
	eng.putFile(opScope, "d1/f2", 2)
	eng.putFile(opScope, "d2/f3", 3)
	eng.putFile(opScope, "top", 4)

	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	seen := map[string]int{}
	cursor := ""
	prevCursor := ""
	pages := 0
	for {
		w := serveOp(d, OpListDirectory, listBody(opScope, "/", 2, cursor, true), opScope, okIntents())
		resp := decodeList(t, w)
		pages++
		for _, e := range resp.Entries {
			var p string
			if e.File != nil {
				p = e.File.Path
			} else if e.Directory != nil {
				p = e.Directory.Path
			}
			seen[p]++
		}
		if resp.Cursor == "" {
			break
		}
		if resp.Cursor == prevCursor {
			t.Fatalf("cursor did not advance: %q (guest progress guard would abort)", resp.Cursor)
		}
		prevCursor = cursor
		cursor = resp.Cursor
		if pages > 20 {
			t.Fatal("pagination did not terminate")
		}
	}

	if pages < 2 {
		t.Fatalf("walk spanned %d pages, want >= 2 (cursor actually exercised)", pages)
	}
	// d1, d1/f1, d1/f2, d2, d2/f3, top -> 6 entries, each exactly once.
	want := []string{"/d1", "/d1/f1", "/d1/f2", "/d2", "/d2/f3", "/top"}
	if len(seen) != len(want) {
		t.Fatalf("visited %d distinct entries, want %d: %v", len(seen), len(want), seen)
	}
	for _, p := range want {
		if seen[p] != 1 {
			t.Fatalf("entry %q visited %d times, want exactly 1", p, seen[p])
		}
	}
}

// TestHandlerDir pins OPS-02: make/move/removeDirectory effects visible in a
// subsequent listing; all responses parse-equal bare {}.
func TestHandlerDir(t *testing.T) {
	eng := newFakeEngine()
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	mkBody := fmt.Sprintf(`{"filesystem_id":%q,"path":"/alpha","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
	assertBareAck(t, serveOp(d, OpMakeDirectory, mkBody, opScope, okIntents()))

	// Visible in a later listing.
	resp := decodeList(t, serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents()))
	if !hasDir(resp, "/alpha") {
		t.Fatalf("after makeDirectory, /alpha not in listing: %+v", resp.Entries)
	}

	// Move it to /beta.
	mvBody := fmt.Sprintf(`{"filesystem_id":%q,"source":"/alpha","destination":"/beta","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
	assertBareAck(t, serveOp(d, OpMoveDirectory, mvBody, opScope, okIntents()))
	resp = decodeList(t, serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents()))
	if hasDir(resp, "/alpha") {
		t.Fatalf("after moveDirectory, /alpha still present: %+v", resp.Entries)
	}
	if !hasDir(resp, "/beta") {
		t.Fatalf("after moveDirectory, /beta absent: %+v", resp.Entries)
	}

	// Remove the (empty) /beta.
	rmBody := fmt.Sprintf(`{"filesystem_id":%q,"path":"/beta","recursive":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
	assertBareAck(t, serveOp(d, OpRemoveDirectory, rmBody, opScope, okIntents()))
	resp = decodeList(t, serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents()))
	if hasDir(resp, "/beta") {
		t.Fatalf("after removeDirectory, /beta still present: %+v", resp.Entries)
	}
}

func hasDir(resp listDirectoryResponse, path string) bool {
	for _, e := range resp.Entries {
		if e.Directory != nil && e.Directory.Path == path {
			return true
		}
	}
	return false
}

// TestHandlerMakeParents pins OPS-02 make_parents composition.
func TestHandlerMakeParents(t *testing.T) {
	eng := newFakeEngine()
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	mp := func(path string, parents bool) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":%q,"make_parents":%t,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope, path, parents)
		return serveOp(d, OpMakeDirectory, body, opScope, okIntents())
	}

	t.Run("make_parents true creates each level", func(t *testing.T) {
		assertBareAck(t, mp("/a/b/c", true))
		resp := decodeList(t, serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", true), opScope, okIntents()))
		for _, want := range []string{"/a", "/a/b", "/a/b/c"} {
			if !hasDir(resp, want) {
				t.Fatalf("make_parents did not create %q: %+v", want, resp.Entries)
			}
		}
	})

	t.Run("final EEXIST surfaces already_exists/409", func(t *testing.T) {
		w := mp("/a/b/c", true)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (final EEXIST already_exists); body %s", w.Code, w.Body.String())
		}
		if h := w.Header().Get("x-deny-reason"); h != "" {
			t.Fatalf("x-deny-reason = %q on already_exists, want none", h)
		}
	})

	t.Run("make_parents false on missing parent surfaces not_found/404", func(t *testing.T) {
		w := mp("/no/such/parent", false)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (missing parent not_found); body %s", w.Code, w.Body.String())
		}
	})
}

// TestHandlerRmdirGuard pins OPS-02 T-09-03: recursive=false on a non-empty
// dir refuses invalid_argument WITHOUT a RemoveDir call; recursive=true
// deletes the subtree.
func TestHandlerRmdirGuard(t *testing.T) {
	eng := newFakeEngine()
	eng.mkdirSeed(opScope, "full")
	eng.putFile(opScope, "full/child", 1)
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)

	rm := func(recursive bool) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/full","recursive":%t,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope, recursive)
		return serveOp(d, OpRemoveDirectory, body, opScope, okIntents())
	}

	t.Run("recursive=false non-empty refuses invalid_argument, no delete", func(t *testing.T) {
		w := rm(false)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (invalid_argument); body %s", w.Code, w.Body.String())
		}
		if h := w.Header().Get("x-deny-reason"); h != "" {
			t.Fatalf("x-deny-reason = %q on invalid_argument, want none", h)
		}
		if calls := eng.removeDirCalls(); len(calls) != 0 {
			t.Fatalf("RemoveDir was called %v on a non-empty-rmdir refusal, want none", calls)
		}
		// Still present.
		resp := decodeList(t, serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents()))
		if !hasDir(resp, "/full") {
			t.Fatal("/full deleted despite the refusal")
		}
	})

	t.Run("recursive=true deletes the subtree", func(t *testing.T) {
		assertBareAck(t, rm(true))
		resp := decodeList(t, serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents()))
		if hasDir(resp, "/full") {
			t.Fatal("/full still present after recursive remove")
		}
	})
}

// TestHandlerFile pins OPS-03: copy/move/removeFile bare ack, audited before
// ack, and the overwrite=false collision -> already_exists.
func TestHandlerFile(t *testing.T) {
	t.Run("copyFile bare ack, mandate precedes ack", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(opScope, "src.txt", 5)
		rec := &callRecorder{}
		g := &fakeGuard{rec: rec}
		d := newEngineDispatcher(&fakeResolver{rec: rec}, g, &fakeCeilingsRegistry{session: &fakeCeilingsSession{rec: rec}}, eng)

		body := fmt.Sprintf(`{"filesystem_id":%q,"source":"/src.txt","destination":"/copy.txt","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		assertBareAck(t, serveOp(d, OpCopyFile, body, opScope, okIntents()))

		calls := rec.snapshot()
		if len(calls) == 0 || calls[len(calls)-1] != "mandate" {
			t.Fatalf("call order = %v, want ...mandate before the ack", calls)
		}
		// Exactly one event on the clean path.
		if got := len(g.events); got != 1 {
			t.Fatalf("clean copy emitted %d audit events, want exactly 1", got)
		}
	})

	t.Run("moveFile then source gone, dest present", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(opScope, "m.txt", 5)
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
		body := fmt.Sprintf(`{"filesystem_id":%q,"source":"/m.txt","destination":"/moved.txt","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		assertBareAck(t, serveOp(d, OpMoveFile, body, opScope, okIntents()))
		resp := decodeList(t, serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents()))
		if hasFile(resp, "/m.txt") {
			t.Fatal("source /m.txt still present after move")
		}
		if !hasFile(resp, "/moved.txt") {
			t.Fatal("dest /moved.txt absent after move")
		}
	})

	t.Run("removeFile bare ack then gone", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(opScope, "r.txt", 5)
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/r.txt","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		assertBareAck(t, serveOp(d, OpRemoveFile, body, opScope, okIntents()))
		resp := decodeList(t, serveOp(d, OpListDirectory, listBody(opScope, "/", 0, "", false), opScope, okIntents()))
		if hasFile(resp, "/r.txt") {
			t.Fatal("/r.txt still present after remove")
		}
	})

	t.Run("copy to existing dst overwrite=false -> already_exists/409", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(opScope, "src.txt", 5)
		eng.putFile(opScope, "dst.txt", 9)
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
		body := fmt.Sprintf(`{"filesystem_id":%q,"source":"/src.txt","destination":"/dst.txt","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		w := serveOp(d, OpCopyFile, body, opScope, okIntents())
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (already_exists); body %s", w.Code, w.Body.String())
		}
	})
}

func hasFile(resp listDirectoryResponse, path string) bool {
	for _, e := range resp.Entries {
		if e.File != nil && e.File.Path == path {
			return true
		}
	}
	return false
}

// TestHandlerDenyMatrix pins that every phase-9 op short-circuits in the spine
// BEFORE the handler on scope_mismatch / intent_denied / audit_down: the
// engine fake is NEVER called and the wire code/header match D4/n3.
func TestHandlerDenyMatrix(t *testing.T) {
	ops := []struct {
		op   Op
		body func(scope string) string
	}{
		{OpListDirectory, func(s string) string { return listBody(s, "/", 0, "", false) }},
		{OpMakeDirectory, func(s string) string {
			return fmt.Sprintf(`{"filesystem_id":%q,"path":"/x","authorization_metadata":{"intent":"write","downloadable":false}}`, s)
		}},
		{OpMoveDirectory, func(s string) string {
			return fmt.Sprintf(`{"filesystem_id":%q,"source":"/a","destination":"/b","authorization_metadata":{"intent":"write","downloadable":false}}`, s)
		}},
		{OpRemoveDirectory, func(s string) string {
			return fmt.Sprintf(`{"filesystem_id":%q,"path":"/x","recursive":true,"authorization_metadata":{"intent":"write","downloadable":false}}`, s)
		}},
		{OpCopyFile, func(s string) string {
			return fmt.Sprintf(`{"filesystem_id":%q,"source":"/a","destination":"/b","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, s)
		}},
		{OpMoveFile, func(s string) string {
			return fmt.Sprintf(`{"filesystem_id":%q,"source":"/a","destination":"/b","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, s)
		}},
		{OpRemoveFile, func(s string) string {
			return fmt.Sprintf(`{"filesystem_id":%q,"path":"/x","authorization_metadata":{"intent":"write","downloadable":false}}`, s)
		}},
	}

	for _, o := range ops {
		t.Run(string(o.op)+"/scope_mismatch", func(t *testing.T) {
			eng := newFakeEngine()
			d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
			// Body claims a different scope than the channel.
			w := serveOp(d, o.op, o.body("fs-evil"), opScope, okIntents())
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (scope_mismatch)", w.Code)
			}
			if w.Header().Get("x-deny-reason") != denyScopeMismatch {
				t.Fatalf("x-deny-reason = %q, want scope_mismatch", w.Header().Get("x-deny-reason"))
			}
			if len(eng.mutations()) != 0 {
				t.Fatalf("engine mutated on a scope_mismatch short-circuit: %v", eng.mutations())
			}
		})

		t.Run(string(o.op)+"/intent_denied", func(t *testing.T) {
			eng := newFakeEngine()
			d := newEngineDispatcher(&fakeResolver{err: ErrIntentDenied}, &fakeGuard{}, okCeilings(), eng)
			w := serveOp(d, o.op, o.body(opScope), opScope, okIntents())
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (intent_denied)", w.Code)
			}
			if w.Header().Get("x-deny-reason") != denyIntentDenied {
				t.Fatalf("x-deny-reason = %q, want intent_denied", w.Header().Get("x-deny-reason"))
			}
			if len(eng.mutations()) != 0 {
				t.Fatalf("engine mutated on an intent_denied short-circuit: %v", eng.mutations())
			}
		})

		t.Run(string(o.op)+"/audit_down", func(t *testing.T) {
			eng := newFakeEngine()
			d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{err: ErrAuditUnavailable}, okCeilings(), eng)
			w := serveOp(d, o.op, o.body(opScope), opScope, okIntents())
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 (audit_down)", w.Code)
			}
			if w.Header().Get("x-deny-reason") != "" {
				t.Fatalf("x-deny-reason = %q on audit_down, want none (n3)", w.Header().Get("x-deny-reason"))
			}
			if len(eng.mutations()) != 0 {
				t.Fatalf("engine mutated on an audit_down short-circuit: %v", eng.mutations())
			}
		})
	}
}

// TestHandlerSecondDenyEvent pins T-09-04 / Q7-A2: a handler-stage operational
// refusal emits a SECOND deny audit event after the spine's pre-handler allow
// Mandate (allow first), and a clean success emits exactly one.
func TestHandlerSecondDenyEvent(t *testing.T) {
	t.Run("EEXIST refusal -> two events, allow first", func(t *testing.T) {
		eng := newFakeEngine()
		eng.mkdirSeed(opScope, "dup")
		rec := &callRecorder{}
		g := &fakeGuard{rec: rec}
		d := newEngineDispatcher(&fakeResolver{rec: rec}, g, &fakeCeilingsRegistry{session: &fakeCeilingsSession{rec: rec}}, eng)

		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/dup","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		w := serveOp(d, OpMakeDirectory, body, opScope, okIntents())
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (already_exists)", w.Code)
		}
		if got := len(g.events); got != 2 {
			t.Fatalf("emitted %d audit events, want 2 (allow + handler deny)", got)
		}
		// The allow event came first (allow disposition, no x_deny_reason),
		// then the deny event. The spine adopts auditgate.FileActivityEvent
		// (W1.2), so the captured event is the mapped OCSF record.
		first, ok := g.events[0].(auditgate.FileActivityEvent)
		if !ok || first.Outcome.DispositionID != auditgate.DispositionAllow || first.Outcome.XDenyReason != "" {
			t.Fatalf("first event = %+v, want the allow event (allow disposition, empty x_deny_reason)", g.events[0])
		}
		second, ok := g.events[1].(auditgate.FileActivityEvent)
		if !ok || second.Outcome.DispositionID != auditgate.DispositionDeny || second.Outcome.XDenyReason != denyAlreadyExists {
			t.Fatalf("second event = %+v, want a deny event with x_deny_reason already_exists", g.events[1])
		}
	})

	t.Run("non-empty-rmdir refusal audits directory_not_empty", func(t *testing.T) {
		eng := newFakeEngine()
		eng.mkdirSeed(opScope, "ne")
		eng.putFile(opScope, "ne/kid", 1)
		g := &fakeGuard{}
		d := newEngineDispatcher(&fakeResolver{}, g, okCeilings(), eng)
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/ne","recursive":false,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		serveOp(d, OpRemoveDirectory, body, opScope, okIntents())
		if len(g.events) != 2 {
			t.Fatalf("emitted %d events, want 2", len(g.events))
		}
		second := g.events[1].(auditgate.FileActivityEvent)
		if second.Outcome.XDenyReason != denyDirNotEmpty {
			t.Fatalf("deny reason = %q, want directory_not_empty (not malformed_envelope)", second.Outcome.XDenyReason)
		}
	})

	t.Run("clean success emits exactly one event", func(t *testing.T) {
		eng := newFakeEngine()
		g := &fakeGuard{}
		d := newEngineDispatcher(&fakeResolver{}, g, okCeilings(), eng)
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/clean","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		assertBareAck(t, serveOp(d, OpMakeDirectory, body, opScope, okIntents()))
		if len(g.events) != 1 {
			t.Fatalf("clean success emitted %d events, want exactly 1", len(g.events))
		}
	})
}

// TestEngineDenyMap pins the engine-sentinel D4 rows end-to-end through the
// handler: EEXIST->409, ENOENT->404, escape->404(degraded) with audited
// truth, non-empty-rmdir->400.
func TestEngineDenyMap(t *testing.T) {
	t.Run("ENOENT removeFile -> not_found/404 no header", func(t *testing.T) {
		eng := newFakeEngine()
		g := &fakeGuard{}
		d := newEngineDispatcher(&fakeResolver{}, g, okCeilings(), eng)
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/ghost.txt","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		w := serveOp(d, OpRemoveFile, body, opScope, okIntents())
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
		if w.Header().Get("x-deny-reason") != "" {
			t.Fatalf("x-deny-reason set on not_found, want none")
		}
		second := g.events[1].(auditgate.FileActivityEvent)
		if second.Outcome.XDenyReason != denyNotFound {
			t.Fatalf("audit reason = %q, want not_found", second.Outcome.XDenyReason)
		}
	})

	t.Run("redundant-slash path is canonicalized before the engine, resolves not_found", func(t *testing.T) {
		eng := newFakeEngine()
		g := &fakeGuard{}
		d := newEngineDispatcher(&fakeResolver{}, g, okCeilings(), eng)
		// Pre-fix, "/a//b" reached the engine raw and drove its errInvalidPath
		// (degraded to not_found, audited as the escape truth). Post-fix
		// (bypass-01/03), the spine canonicalizes the path ONCE at the boundary,
		// so the redundant "//" is collapsed to the in-scope "/a/b" BEFORE the
		// engine — a redundant-slash path is no longer treated as an escape; it
		// resolves like any other absent object (not_found), and the engine sees
		// the SINGLE canonical form, never the raw "a//b".
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/a//b","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		w := serveOp(d, OpRemoveFile, body, opScope, okIntents())
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body %s", w.Code, w.Body.String())
		}
		second := g.events[1].(auditgate.FileActivityEvent)
		// not_found, NOT scope_mismatch: the audited path is the canonical
		// in-scope "/a/b", proving the spine cleaned the redundant "//" before
		// the engine (raw "a//b" would have driven the engine's errInvalidPath
		// and audited the escape truth scope_mismatch).
		if second.Outcome.XDenyReason != denyNotFound {
			t.Fatalf("audit reason = %q, want not_found (a canonicalized in-scope path, not an escape)", second.Outcome.XDenyReason)
		}
		if second.ObjectHandle != opScope+":/a/b" {
			t.Fatalf("audit ObjectHandle = %q, want the canonical %q", second.ObjectHandle, opScope+":/a/b")
		}
	})
}

// TestHandlerStrictBody pins that the per-op handler — now the owner of the
// SEC-51 unknown-field guard for phase-9 bodies — rejects an unknown top-level
// field and a malformed body with invalid_argument (no header), and that the
// engine is never touched.
func TestHandlerStrictBody(t *testing.T) {
	t.Run("unknown op field rejected by the handler strict decode", func(t *testing.T) {
		eng := newFakeEngine()
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
		// A field the spine envelope tolerates but the makeDirectory body does
		// not declare.
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/x","bogus_field":true,"authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
		w := serveOp(d, OpMakeDirectory, body, opScope, okIntents())
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (unknown field); body %s", w.Code, w.Body.String())
		}
		if len(eng.mutations()) != 0 {
			t.Fatalf("engine mutated on a malformed body: %v", eng.mutations())
		}
	})

	t.Run("malformed JSON rejected by the spine envelope decode", func(t *testing.T) {
		eng := newFakeEngine()
		d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
		w := serveOp(d, OpMakeDirectory, `{not json`, opScope, okIntents())
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (malformed JSON)", w.Code)
		}
	})
}

// TestHandlerUnimplementedStillRejects pins that a non-phase-9 op (createFile)
// still returns unimplemented/501 even when an engine is wired.
func TestHandlerUnimplementedStillRejects(t *testing.T) {
	eng := newFakeEngine()
	d := newEngineDispatcher(&fakeResolver{}, &fakeGuard{}, okCeilings(), eng)
	body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/x","authorization_metadata":{"intent":"write","downloadable":false}}`, opScope)
	w := serveOp(d, OpCreateFile, body, opScope, okIntents())
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("createFile status = %d, want 501 (still unimplemented)", w.Code)
	}
}

// readBody builds a readFile request body with an explicit range.
func readBody(scope, path string, offset, length int64, wireDownloadable bool) string {
	return fmt.Sprintf(
		`{"filesystem_id":%q,"path":%q,"range":{"offset":%d,"length":%d},"authorization_metadata":{"intent":"read","downloadable":%t}}`,
		scope, path, offset, length, wireDownloadable)
}

// readBodyNoRange builds a readFile request body omitting the range (full read).
func readBodyNoRange(scope, path string, wireDownloadable bool) string {
	return fmt.Sprintf(
		`{"filesystem_id":%q,"path":%q,"authorization_metadata":{"intent":"read","downloadable":%t}}`,
		scope, path, wireDownloadable)
}

// decodeReadFile parses a 200 readFile response into its metadata body.
func decodeReadFile(t *testing.T, w *httptest.ResponseRecorder) readFileResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("readFile status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	var resp readFileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("readFile body not JSON: %v (%s)", err, w.Body.String())
	}
	return resp
}

// TestReadFileRangedRead pins OPS-04: a ranged readFile validates the window
// through engine.ReadRange and emits the metadata-only {file} body with the
// FULL object size and NO content bytes. The grant is downloadable.
func TestReadFileRangedRead(t *testing.T) {
	eng := newFakeEngine()
	eng.putBytes(opScope, "golden.bin", make([]byte, 42))
	d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)

	cases := []struct {
		name string
		body string
	}{
		{"in_bounds", readBody(opScope, "/golden.bin", 2, 3, false)},
		{"past_eof_short_read", readBody(opScope, "/golden.bin", 40, 100, false)},
		{"absent_range_full", readBodyNoRange(opScope, "/golden.bin", false)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := serveOp(d, OpReadFile, c.body, opScope, okIntents())
			resp := decodeReadFile(t, w)
			if resp.File.Path != "/golden.bin" {
				t.Fatalf("file path = %q, want /golden.bin", resp.File.Path)
			}
			if resp.File.Size != 42 {
				t.Fatalf("file size = %d, want full object size 42", resp.File.Size)
			}
			if resp.File.MTime == "" || resp.File.MIME == "" || resp.File.UUID == "" {
				t.Fatalf("metadata missing a guest-read field: %+v", resp.File)
			}
		})
	}
}

// TestReadFileMetadataOnly pins that the readFile response carries NO
// content/data/bytes key (D6 TBD content body stays TBD).
func TestReadFileMetadataOnly(t *testing.T) {
	eng := newFakeEngine()
	eng.putBytes(opScope, "golden.bin", []byte("ABCDEFGH"))
	d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)
	w := serveOp(d, OpReadFile, readBody(opScope, "/golden.bin", 0, 4, false), opScope, okIntents())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	// The body is {"file":{...}} with the file object carrying only metadata
	// keys. Assert no content/data/bytes anywhere.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &top); err != nil {
		t.Fatalf("body not JSON object: %v", err)
	}
	fileRaw, ok := top["file"]
	if !ok {
		t.Fatalf("response missing the file body: %s", w.Body.String())
	}
	var fileObj map[string]json.RawMessage
	if err := json.Unmarshal(fileRaw, &fileObj); err != nil {
		t.Fatalf("file not JSON object: %v", err)
	}
	for _, forbidden := range []string{"content", "data", "bytes"} {
		if _, present := fileObj[forbidden]; present {
			t.Fatalf("readFile body carries a forbidden %q key (D6): %s", forbidden, w.Body.String())
		}
	}
}

// TestReadFileNonDownloadableIsReadable pins the corrected SEC-73 scope: the
// downloadable axis is a NORTH egress control (the /content egress endpoint).
// The SOUTH readFile is an in-session metadata read — it is governed by
// intent/subtree (read-intent → uploads RO, ADR-0029), NOT the egress axis.
// A non-downloadable object MUST be accessible to the south readFile plane so
// the guest cat path (ocufs resolve → readFile → fileDownload) can service
// in-session reads regardless of north egress eligibility.
//
// Asserts: Grant{Downloadable:false} + read-intent + existing object →
//   - 200 with metadata body (path, size, uuid present)
//   - ReadRange call count is 0 (Stat-only; readFile emits NO content bytes)
//   - engine.Stat WAS called (the object was looked up)
func TestReadFileNonDownloadableIsReadable(t *testing.T) {
	for _, wireFlag := range []bool{false, true} {
		t.Run(fmt.Sprintf("wire_downloadable_%t", wireFlag), func(t *testing.T) {
			eng := newFakeEngine()
			eng.putBytes(opScope, "golden.bin", []byte("ABCDEFGH"))
			g := &fakeGuard{}
			// Grant marks not-downloadable (north egress axis). South readFile
			// must serve the metadata regardless.
			d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: false}}, g, okCeilings(), eng)
			w := serveOp(d, OpReadFile, readBody(opScope, "/golden.bin", 0, 4, wireFlag), opScope, okIntents())

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (non-downloadable south read must succeed); body %s", w.Code, w.Body.String())
			}
			resp := decodeReadFile(t, w)
			if resp.File.Path == "" || resp.File.Size == 0 || resp.File.UUID == "" {
				t.Fatalf("readFile metadata incomplete: %+v", resp.File)
			}
			// ReadRange must NOT be called — readFile is Stat-only (NFR-SEC-46/78).
			if calls := eng.readRangeCalls(); len(calls) != 0 {
				t.Fatalf("ReadRange was called on a metadata-only south read: %v", calls)
			}
			// engine.Stat must have been called (the path was resolved).
			if len(eng.statCalls()) == 0 {
				t.Fatalf("engine.Stat was never called for the south readFile")
			}
		})
	}
}

// TestNonDownloadableObjectSouthReadSplit pins the invariant the fix restores:
// a non-downloadable object (Grant{Downloadable:false}) is south-readable
// in-session on both the metadata and the byte-stream plane, but NOT eligible
// for north egress (the north /content tests are the authority for that half).
//
// (a) OpReadFile → 200 + metadata body (path/size/uuid present, no content).
// (b) OpFileDownload (south byte-stream) → 200 + exact raw bytes.
//
// The north egress half is covered by the untouched filesapi content/archive
// tests; this test does NOT duplicate north assertions.
func TestNonDownloadableObjectSouthReadSplit(t *testing.T) {
	const scope = "fs-split"
	content := []byte("in-session payload delta")

	// (a) South readFile — metadata-only, no content bytes.
	t.Run("readFile_200_metadata", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putBytes(scope, "secret.bin", content)
		d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: false}}, &fakeGuard{}, okCeilings(), eng)

		w := serveOp(d, OpReadFile, readBodyNoRange(scope, "/secret.bin", false), scope, okIntents())
		resp := decodeReadFile(t, w)
		if resp.File.Path == "" || resp.File.Size == 0 || resp.File.UUID == "" {
			t.Fatalf("readFile metadata incomplete for non-downloadable object: %+v", resp.File)
		}
		if calls := eng.readRangeCalls(); len(calls) != 0 {
			t.Fatalf("readFile called ReadRange on a metadata-only op: %v", calls)
		}
	})

	// (b) South fileDownload byte-stream — exact bytes, in-session.
	t.Run("fileDownload_200_bytes", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putBytes(scope, "secret.bin", content)
		sess := &recordingCeilingsSession{}
		d := newDownloadDispatcher(eng, &fakeGuard{}, sess, false)
		uuid := d.ids.idFor(scope, "/secret.bin")

		w := serveDownload(t, d, scope, uuid, nil, scope, okIntents())
		assertDownloadOK(t, w, content)
		if len(eng.readRangeCalls()) == 0 {
			t.Fatalf("fileDownload never called ReadRange for a non-downloadable in-session read")
		}
	})
}

// TestReadFileNoContentRead pins CONC-01 (NFR-SEC-46/78): readFile validates
// through engine.Stat ONLY — the engine's ReadRange is NEVER called, so no
// content byte is read or buffered regardless of object size or the guest
// range. The object here nominally spans 1 TiB (a size-only fake node with no
// backing bytes): a content-buffering implementation could not answer it.
// With zero content bytes in flight, the in-flight byte ceiling is satisfied
// structurally for ANY number of concurrent readFile calls.
func TestReadFileNoContentRead(t *testing.T) {
	eng := newFakeEngine()
	eng.putFile(opScope, "huge.bin", 1<<40) // 1 TiB nominal, no backing bytes
	d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)

	for _, body := range []string{
		readBody(opScope, "/huge.bin", 0, 1<<40, false), // full-window range
		readBodyNoRange(opScope, "/huge.bin", false),    // absent range
	} {
		w := serveOp(d, OpReadFile, body, opScope, okIntents())
		resp := decodeReadFile(t, w)
		if resp.File.Size != 1<<40 {
			t.Fatalf("size = %d, want the full 1 TiB nominal size", resp.File.Size)
		}
	}
	if calls := eng.readRangeCalls(); len(calls) != 0 {
		t.Fatalf("readFile called engine.ReadRange %v — content must never be read (Stat-only validation)", calls)
	}
}

// TestReadFileBoundedAllocation is the O(size) heap pin for CONC-01: a
// readFile of a 32 MiB object allocates far less than the object size (the
// pre-fix implementation buffered the full window into a bytes.Buffer).
func TestReadFileBoundedAllocation(t *testing.T) {
	const objSize = 32 << 20
	eng := newFakeEngine()
	eng.putBytes(opScope, "big.bin", make([]byte, objSize))
	d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)

	body := readBodyNoRange(opScope, "/big.bin", false)
	allocs := testing.AllocsPerRun(3, func() {
		w := serveOp(d, OpReadFile, body, opScope, okIntents())
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
		}
	})
	// The request path allocates request/response plumbing (well under a
	// hundred small allocations); a full-window buffer of a 32 MiB object
	// would show up as orders of magnitude more allocated bytes. Pin the
	// allocation COUNT — buffering 32 MiB through bytes.Buffer growth adds
	// many large grow allocations per run.
	if allocs > 500 {
		t.Fatalf("readFile of a 32 MiB object made %v allocations per run — content is being buffered", allocs)
	}
}

// TestReadFileDirectoryTarget pins that readFile of a directory refuses
// not_found (readFile names a file; the directory listing surface is
// listDirectory).
func TestReadFileDirectoryTarget(t *testing.T) {
	eng := newFakeEngine()
	eng.mkdirSeed(opScope, "adir")
	d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)
	w := serveOp(d, OpReadFile, readBodyNoRange(opScope, "/adir", false), opScope, okIntents())
	if w.Code != http.StatusNotFound {
		t.Fatalf("readFile(directory) status = %d, want 404; body %s", w.Code, w.Body.String())
	}
}

// TestReadFileEngineErrors pins the engine-error deny paths: a missing object
// maps not_found/404, and an escape-shaped path degrades to not_found (the
// audited truth differs — D8 — but the wire is not_found).
func TestReadFileEngineErrors(t *testing.T) {
	t.Run("missing_object", func(t *testing.T) {
		eng := newFakeEngine()
		d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)
		w := serveOp(d, OpReadFile, readBody(opScope, "/missing.bin", 0, 1, false), opScope, okIntents())
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (not found); body %s", w.Code, w.Body.String())
		}
	})
}

// TestReadFileDeferredOpsUnimplemented pins that the deferred uuid-axis read
// ops stay unimplemented even with an engine wired.
func TestReadFileDeferredOpsUnimplemented(t *testing.T) {
	eng := newFakeEngine()
	d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)
	for _, op := range []Op{OpGetFileMetadata, OpListFiles} {
		body := fmt.Sprintf(`{"filesystem_id":%q,"path":"/x","authorization_metadata":{"intent":"read","downloadable":false}}`, opScope)
		w := serveOp(d, op, body, opScope, okIntents())
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("%s status = %d, want 501 (deferred)", op, w.Code)
		}
	}
}

// TestAuditHandleCanonicalForCopyMove pins bypass-02b + crutch-04 (audit-truth,
// NFR-SEC-79): a copy or move whose Destination (or Source on a move) carries
// traversal segments ("/pub/../priv/stolen") must record the BROKER-RESOLVED
// canonical path ("/priv/stolen") in the audit ObjectHandle — the same
// canonicalization the spine applies to the primary path at STAGE 1b/2 — AND
// the engine must receive that SAME canonical leg. Before crutch-04 the engine
// saw the raw wire path while authz/audit saw the canonical one; the spine now
// canonicalizes source/destination once before authz, so the audited leg and
// the engine leg are identical.
func TestAuditHandleCanonicalForCopyMove(t *testing.T) {
	// copyFile: non-canonical destination. The destination "/pub/../dst.txt"
	// canonicalizes to the in-scope "/dst.txt" (engine-relative "dst.txt"). After
	// crutch-04 the spine cleans it BEFORE the engine call, so the engine receives
	// the canonical leg and the copy SUCCEEDS (200) — the source exists and the
	// canonical destination is a valid in-scope path. The STAGE-3 allow event
	// (events[0]) records the canonical "/dst.txt" in ObjectHandle, and the engine
	// records the mutation at the canonical engine path "dst.txt" (never the raw
	// "pub/../dst.txt" form), proving the audited leg and the engine leg agree.
	t.Run("copyFile_non_canonical_destination_is_cleaned_for_engine_and_audit", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(opScope, "src.txt", 10)
		g := &fakeGuard{}
		d := newEngineDispatcher(&fakeResolver{}, g, okCeilings(), eng)

		body := fmt.Sprintf(
			`{"filesystem_id":%q,"source":"/src.txt","destination":"/pub/../dst.txt","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`,
			opScope)
		w := serveOp(d, OpCopyFile, body, opScope, okIntents())
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (canonical destination is a valid in-scope path); body %s", w.Code, w.Body.String())
		}

		if len(g.events) < 1 {
			t.Fatalf("copyFile emitted %d audit events, want at least 1 (the STAGE-3 allow)", len(g.events))
		}
		ev, ok := g.events[0].(auditgate.FileActivityEvent)
		if !ok {
			t.Fatalf("first audit event type = %T, want auditgate.FileActivityEvent", g.events[0])
		}
		// STAGE-3 allow event: ObjectHandle must name the canonical destination,
		// not the raw "/pub/../dst.txt" traversal form.
		wantHandle := opScope + ":/dst.txt"
		if ev.ObjectHandle != wantHandle {
			t.Fatalf("copyFile STAGE-3 audit ObjectHandle = %q, want the canonical %q", ev.ObjectHandle, wantHandle)
		}
		// The engine received the CANONICAL destination leg "dst.txt" (crutch-04),
		// not the raw "pub/../dst.txt" — the audited leg and the engine leg agree.
		if got := eng.mutations(); len(got) != 1 || got[0] != "dst.txt" {
			t.Fatalf("engine mutation targets = %v, want exactly [\"dst.txt\"] (the canonical leg, not the raw traversal form)", got)
		}
	})

	// moveFile: non-canonical destination
	t.Run("moveFile_non_canonical_destination_is_cleaned_in_audit_handle", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(opScope, "mv-src.txt", 7)
		g := &fakeGuard{}
		d := newEngineDispatcher(&fakeResolver{}, g, okCeilings(), eng)

		body := fmt.Sprintf(
			`{"filesystem_id":%q,"source":"/mv-src.txt","destination":"/a/b/../moved.txt","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`,
			opScope)
		// The destination parent "a" does not exist, so the engine returns not_found
		// and the handler emits a deny event. We assert the ALLOW event (events[0])
		// which is the STAGE-3 pre-handler record: ObjectHandle is built from the
		// parsed body destination BEFORE the engine is called.
		w := serveOp(d, OpMoveFile, body, opScope, okIntents())
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (dst parent missing); body %s", w.Code, w.Body.String())
		}

		if len(g.events) < 1 {
			t.Fatalf("moveFile emitted %d audit events, want at least 1 (the STAGE-3 allow)", len(g.events))
		}
		ev, ok := g.events[0].(auditgate.FileActivityEvent)
		if !ok {
			t.Fatalf("first audit event type = %T, want auditgate.FileActivityEvent", g.events[0])
		}
		// STAGE-3 allow event: ObjectHandle must name the canonical destination
		// "/a/moved.txt", not the raw "/a/b/../moved.txt".
		wantHandle := opScope + ":/a/moved.txt"
		if ev.ObjectHandle != wantHandle {
			t.Fatalf("moveFile STAGE-3 audit ObjectHandle = %q, want the canonical %q", ev.ObjectHandle, wantHandle)
		}
	})

	// moveDirectory: non-canonical destination
	t.Run("moveDirectory_non_canonical_destination_is_cleaned_in_audit_handle", func(t *testing.T) {
		eng := newFakeEngine()
		eng.mkdirSeed(opScope, "srcdir")
		g := &fakeGuard{}
		d := newEngineDispatcher(&fakeResolver{}, g, okCeilings(), eng)

		// Destination "/x/y/../dstdir" canonicalizes to "/x/dstdir".
		// The destination parent "x" does not exist, so the engine returns
		// not_found and we assert the STAGE-3 allow event.
		body := fmt.Sprintf(
			`{"filesystem_id":%q,"source":"/srcdir","destination":"/x/y/../dstdir","authorization_metadata":{"intent":"write","downloadable":false}}`,
			opScope)
		w := serveOp(d, OpMoveDirectory, body, opScope, okIntents())
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (dst parent missing); body %s", w.Code, w.Body.String())
		}

		if len(g.events) < 1 {
			t.Fatalf("moveDirectory emitted %d audit events, want at least 1", len(g.events))
		}
		ev, ok := g.events[0].(auditgate.FileActivityEvent)
		if !ok {
			t.Fatalf("first audit event type = %T, want auditgate.FileActivityEvent", g.events[0])
		}
		wantHandle := opScope + ":/x/dstdir"
		if ev.ObjectHandle != wantHandle {
			t.Fatalf("moveDirectory STAGE-3 audit ObjectHandle = %q, want the canonical %q", ev.ObjectHandle, wantHandle)
		}
	})
}

// TestMoveCopySourceDestCanonicalizedAtSpine pins crutch-04: the spine runs the
// SAME canonicalizePath over the SECOND-LEG paths (source/destination) of the
// two-path ops that it runs over the primary path at the STAGE 1b->2 boundary,
// BEFORE authz and audit. A source or destination the canonicalizer REJECTS (a
// scheme-shaped backend handle — one of the lexical classes canonicalizePath
// refuses regardless of which engine is bound) is denied denyMalformed /
// invalid_argument (400) at the spine, the resolver and audit guard are NEVER
// consulted, and the engine is NEVER touched — symmetric with the primary path.
// A clean source/destination still succeeds and the engine receives the
// canonical leg.
func TestMoveCopySourceDestCanonicalizedAtSpine(t *testing.T) {
	// Each case names the op, the JSON body (one of source/destination carries a
	// canonicalizer-rejected value), and whether the rejected leg is the source.
	rejected := []struct {
		name string
		op   Op
		body string
	}{
		{
			name: "copyFile_url_scheme_destination",
			op:   OpCopyFile,
			body: `{"filesystem_id":%q,"source":"/src.txt","destination":"s3://bucket/key","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`,
		},
		{
			name: "copyFile_url_scheme_source",
			op:   OpCopyFile,
			body: `{"filesystem_id":%q,"source":"s3://bucket/src","destination":"/dst.txt","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`,
		},
		{
			name: "moveFile_url_scheme_destination",
			op:   OpMoveFile,
			body: `{"filesystem_id":%q,"source":"/src.txt","destination":"https://evil/key","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`,
		},
		{
			name: "moveDirectory_url_scheme_destination",
			op:   OpMoveDirectory,
			body: `{"filesystem_id":%q,"source":"/srcdir","destination":"file:///etc/dstdir","authorization_metadata":{"intent":"write","downloadable":false}}`,
		},
	}
	for _, c := range rejected {
		t.Run(c.name, func(t *testing.T) {
			eng := newFakeEngine()
			eng.putFile(opScope, "src.txt", 10)
			eng.mkdirSeed(opScope, "srcdir")
			rec := &callRecorder{}
			res := &fakeResolver{rec: rec, grant: Grant{Downloadable: true}}
			g := &fakeGuard{rec: rec}
			d := newEngineDispatcher(res, g, okCeilings(), eng)

			w := serveOp(d, c.op, fmt.Sprintf(c.body, opScope), opScope, okIntents())
			// invalid_argument / 400, the SAME class the primary path's
			// canonicalize reject produces.
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (invalid_argument: rejected source/dest at the canonicalizer); body %s", w.Code, w.Body.String())
			}
			// A canonicalize reject on the second leg degrades to invalid_argument
			// with NO x-deny-reason header (denyMalformed), like the primary path.
			if h := w.Header().Get("x-deny-reason"); h != "" {
				t.Fatalf("x-deny-reason = %q on a malformed-path deny, want none", h)
			}
			// The deny precedes STAGE-2 authz and STAGE-3 audit: neither the
			// resolver nor the audit guard was consulted.
			for _, call := range rec.snapshot() {
				if call == "resolve" {
					t.Fatalf("resolver consulted on a rejected-path request; the deny must precede STAGE-2 authz")
				}
				if call == "mandate" {
					t.Fatalf("audit guard consulted on a rejected-path request; the deny must precede STAGE-3 audit")
				}
			}
			// The engine was NEVER touched: defense-in-depth is not the boundary
			// — the spine refuses before any engine verb runs.
			if got := eng.mutations(); len(got) != 0 {
				t.Fatalf("engine recorded mutations %v on a rejected-path request, want none (deny precedes the engine)", got)
			}
		})
	}

	// Clean source/destination still succeeds, and the engine receives the
	// canonical engine-relative leg.
	t.Run("clean_source_dest_succeeds_engine_sees_canonical_leg", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putFile(opScope, "src.txt", 10)
		d := newEngineDispatcher(&fakeResolver{grant: Grant{Downloadable: true}}, &fakeGuard{}, okCeilings(), eng)

		// Redundant-but-clean segments on both legs: "/./src.txt" -> "/src.txt"
		// (engine "src.txt"); "/sub/../dst.txt" -> "/dst.txt" (engine "dst.txt").
		body := fmt.Sprintf(
			`{"filesystem_id":%q,"source":"/./src.txt","destination":"/sub/../dst.txt","overwrite_existing":false,"authorization_metadata":{"intent":"write","downloadable":false}}`,
			opScope)
		assertBareAck(t, serveOp(d, OpCopyFile, body, opScope, okIntents()))

		// The engine received the CANONICAL destination leg "dst.txt", proving the
		// spine cleaned the second leg before the engine call (crutch-04).
		if got := eng.mutations(); len(got) != 1 || got[0] != "dst.txt" {
			t.Fatalf("engine mutation targets = %v, want exactly [\"dst.txt\"] (the canonical leg)", got)
		}
	})
}
