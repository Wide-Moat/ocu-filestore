// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// prefixDownloadableResolver models the broker prefix downloadable policy
// (broker.NewPrefixDownloadablePolicy) at the resolver seam: a read grant is
// Downloadable IFF the request path lies under a configured downloadable prefix
// (path-boundary match). It always ALLOWS the read (no error); only the
// Downloadable axis varies — exactly the invariant-5 posture (the read is
// permitted, the egress-eligible artifact withheld). This lets the whole-tree
// bridge test prove outputs/ downloads 200 while uploads/ downloads 403 through
// the SAME handler, against the SAME reconciled list.
type prefixDownloadableResolver struct {
	downloadablePrefixes []string
}

func (r *prefixDownloadableResolver) Resolve(_ context.Context, _ any, req southface.ResolveRequest) (southface.Grant, error) {
	p := strings.TrimPrefix(req.Path, "/")
	dl := false
	for _, prefix := range r.downloadablePrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			dl = true
			break
		}
	}
	return southface.Grant{Downloadable: dl}, nil
}

// TestList_WholeTreeBridge is the whole-tree bridge keystone (ADR-0029:46). An
// engine object the agent wrote through the SOUTH FUSE mount ("outputs/report.pdf")
// carries NO north handle; a browser File-Pane list must still surface it. It
// proves, through the real handler:
//
//  1. GET /v1/files surfaces the engine object with SOME file_id F (the reconcile
//     minted a handle on first sight).
//  2. GET /v1/files/{F}/content resolves and returns the bytes (the minted handle
//     is a working read handle; outputs/ is downloadable -> 200).
//  3. list AGAIN returns the SAME file_id F — the ANTI-DUP keystone: a naive
//     per-list random mint reddens here (the red-probe below proves it).
//  4. NEGATIVE leg: an engine object under "uploads/seed.bin" ALSO surfaces in the
//     list (whole tree), but its content download is 403 not_downloadable — the
//     bridge surfaces the object without reopening exfil (the broker prefix
//     policy: outputs downloadable, uploads not).
func TestList_WholeTreeBridge(t *testing.T) {
	const scope = "fs-fleet"

	eng := newFakeEngine()
	// Two engine objects with NO north handle: an agent deliverable under outputs/
	// (downloadable) and an input under uploads/ (NOT downloadable).
	eng.seedObject("outputs/report.pdf", []byte("PDF-REPORT-BYTES"))
	eng.seedObject("uploads/seed.bin", []byte("SEED-INPUT-BYTES"))

	store := newFakeStore()
	h := newTestHandler(Deps{
		Engine:   eng,
		Store:    store,
		Resolver: &prefixDownloadableResolver{downloadablePrefixes: []string{"outputs"}},
		Scope:    fakeScope{ps: southface.PeerScope{FilesystemID: scope, GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	// (1) FIRST LIST: the reconcile mints handles for both engine objects.
	list1 := listFiles(t, h)
	reportID := findByFilename(t, list1, "report.pdf")
	seedID := findByFilename(t, list1, "seed.bin")
	if reportID == "" {
		t.Fatal("outputs/report.pdf did not surface in the north list — the whole-tree bridge is not reconciling the engine namespace")
	}
	if seedID == "" {
		t.Fatal("uploads/seed.bin did not surface in the north list — the whole-tree bridge must surface the whole tree, not just downloadable objects")
	}

	// (2) POSITIVE: the outputs/ object downloads 200 with the real bytes through
	// the minted handle.
	cw := doReq(h, http.MethodGet, "/v1/files/"+reportID+"/content")
	if cw.Code != http.StatusOK {
		t.Fatalf("content of outputs/report.pdf = %d, want 200 (the minted handle must be a working read handle)", cw.Code)
	}
	if got := cw.Body.String(); got != "PDF-REPORT-BYTES" {
		t.Fatalf("content bytes = %q, want the seeded engine bytes", got)
	}

	// (3) ANTI-DUP KEYSTONE: list AGAIN -> the SAME file_id for report.pdf. A naive
	// per-list random mint returns a different id here.
	list2 := listFiles(t, h)
	reportID2 := findByFilename(t, list2, "report.pdf")
	if reportID2 != reportID {
		t.Fatalf("ANTI-DUP: outputs/report.pdf minted a new file_id on the second list (%q != %q) — the reconcile is not idempotent", reportID2, reportID)
	}
	if len(list2) != len(list1) {
		t.Fatalf("second list has %d entries, first had %d — a duplicate handle was minted", len(list2), len(list1))
	}

	// (4) NEGATIVE leg: uploads/seed.bin surfaced (proven above) but its download is
	// 403 not_downloadable — the bridge surfaces the object without reopening exfil.
	dw := doReq(h, http.MethodGet, "/v1/files/"+seedID+"/content")
	if dw.Code != http.StatusForbidden {
		t.Fatalf("content of uploads/seed.bin = %d, want 403 not_downloadable (the bridge must not reopen exfil)", dw.Code)
	}
}

// TestList_NorthCreateThenList_ExactlyOneEntry pins that a north-CREATED object
// (via the REAL create path, which stores an engine-relative ObjectRef joined
// under the read subtree) appears EXACTLY ONCE after a reconcile — proving the
// refIndex key byte-matches the create path's joined ObjectRef (the inv-5
// normalization is correct). If the reconcile keyed on a mismatched convention,
// the created handle and its engine-visible twin would both appear (two entries
// for one object).
//
// It wires a REAL handlestore.DiskStore so the create's Put and the reconcile's
// EnsureObject share ONE ref index — the byte-match is proven end to end, not
// against a fake that could paper over a convention drift. The record-keeping
// createEngine both persists the write (so List sees it) and satisfies the
// create's parent-marker EnsureDir.
func TestList_NorthCreateThenList_ExactlyOneEntry(t *testing.T) {
	const scope = "fs-fleet"
	const subtree = "uploads"

	eng := newFakeEngine()
	store, err := handlestore.NewDiskStore(t.TempDir() + "/handles.jsonl")
	if err != nil {
		t.Fatalf("NewDiskStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// A record-keeping WriteStream so a north create lands the object in the same
	// engine namespace the reconcile walks (the default fakeEngine WriteStream is a
	// no-op). The create joins "/doc.txt" under CreateSubtree -> "uploads/doc.txt",
	// the SAME engine-relative ObjectRef it stores.
	recEng := &recordingEngine{fakeEngine: eng}

	h := newTestHandler(Deps{
		Engine:        recEng,
		Store:         store,
		CreateSubtree: subtree,
		Resolver:      &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Scope:         fakeScope{ps: southface.PeerScope{FilesystemID: scope, GrantedIntents: []southface.Intent{southface.IntentRead, southface.IntentWrite}}, ok: true},
	})

	payload := []byte("north-created body")
	createdID := createDoc(t, h, "/doc.txt", payload)

	// List: the reconcile walks the engine (sees uploads/doc.txt) and the store
	// already has a handle for that (scope, ref) from the create — so the object
	// appears EXACTLY ONCE (the refIndex key matched the create's joined ObjectRef).
	list := listFiles(t, h)
	count := 0
	var listedID string
	for _, fo := range list {
		if fo.Filename == "doc.txt" {
			count++
			listedID = fo.ID
		}
	}
	if count != 1 {
		t.Fatalf("north-created object appears %d times after reconcile, want EXACTLY 1 (refIndex key must byte-match the create's joined ObjectRef)", count)
	}
	if listedID != createdID {
		t.Fatalf("the listed object has file_id %q, want the created handle %q (the reconcile re-minted instead of dedup'ing)", listedID, createdID)
	}
}

// TestList_ReconcileHonestDegradeOnEngineError pins the honest degrade: when the
// engine namespace walk errors, the list does NOT 503 — it falls through to the
// plain Store.List so the pane still sees every north-created handle.
func TestList_ReconcileHonestDegradeOnEngineError(t *testing.T) {
	const scope = "fs-fleet"
	eng := newFakeEngine()
	eng.listErr = southface.ErrBackendTransient // the engine namespace is unavailable

	store := newFakeStore()
	// A pre-existing north-created handle the plain List must still return.
	store.put("north-1", scope, handlestore.Record{Filename: "created.txt", ObjectRef: "uploads/created.txt", CreatedAt: "2026-01-01T00:00:00Z"})

	h := newTestHandler(Deps{
		Engine: eng,
		Store:  store,
		Scope:  fakeScope{ps: southface.PeerScope{FilesystemID: scope, GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusOK {
		t.Fatalf("list under an engine walk error = %d, want 200 (honest degrade, not 503)", w.Code)
	}
	list := decodeList(t, w.Body.Bytes())
	if findByFilename(t, list, "created.txt") == "" {
		t.Fatal("the north-created handle vanished under the engine-error degrade — the plain List must still run")
	}
}

// TestList_ReconcileSkippedOnLatchedStore pins that a latched store skips the
// reconcile (EnsureObject is a mutation) yet still serves the reads-from-memory
// List. The fakeEngine's List would surface the object if reconcile ran; with the
// store latched it must NOT be minted.
func TestList_ReconcileSkippedOnLatchedStore(t *testing.T) {
	const scope = "fs-fleet"
	eng := newFakeEngine()
	eng.seedObject("outputs/report.pdf", []byte("x"))

	store := newFakeStore()
	store.latched = true

	h := newTestHandler(Deps{
		Engine: eng,
		Store:  store,
		Scope:  fakeScope{ps: southface.PeerScope{FilesystemID: scope, GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusOK {
		t.Fatalf("list on a latched store = %d, want 200", w.Code)
	}
	if store.ensureMints != 0 {
		t.Fatalf("EnsureObject minted %d records on a latched store, want 0 (the reconcile must be skipped)", store.ensureMints)
	}
	if eng.listCalls != 0 {
		t.Fatalf("the engine was walked %d times on a latched store, want 0 (reconcile skipped before any engine call)", eng.listCalls)
	}
}

// TestList_ReconcileGatedToFirstPage pins that a paged request (?after=...) does
// NOT re-walk the engine — the reconcile is gated to the cursorless first page.
func TestList_ReconcileGatedToFirstPage(t *testing.T) {
	const scope = "fs-fleet"
	eng := newFakeEngine()
	eng.seedObject("outputs/report.pdf", []byte("x"))

	// A store that returns a valid page for any cursor (so ?after does not 400/503).
	store := newFakeStore()
	store.listPage = handlestore.ListPage{Records: []handlestore.Record{{FileID: "f1", Scope: scope, Filename: "a"}}}

	h := newTestHandler(Deps{
		Engine: eng,
		Store:  store,
		Scope:  fakeScope{ps: southface.PeerScope{FilesystemID: scope, GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})

	w := doReq(h, http.MethodGet, "/v1/files?after=some-cursor")
	if w.Code != http.StatusOK {
		t.Fatalf("paged list = %d, want 200", w.Code)
	}
	if eng.listCalls != 0 {
		t.Fatalf("the engine was walked %d times on a PAGED request, want 0 (reconcile is first-page only)", eng.listCalls)
	}
}

// --- test helpers ---

// listFiles drives GET /v1/files and returns the decoded FileObjects (fails on a
// non-200).
func listFiles(t *testing.T, h *Handler) []FileObject {
	t.Helper()
	w := doReq(h, http.MethodGet, "/v1/files")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /v1/files = %d, want 200; body %s", w.Code, w.Body.String())
	}
	return decodeList(t, w.Body.Bytes())
}

func decodeList(t *testing.T, body []byte) []FileObject {
	t.Helper()
	var env ListResponse
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode list envelope: %v", err)
	}
	return env.Data
}

// findByFilename returns the id of the first FileObject with the given filename,
// or "" when absent.
func findByFilename(t *testing.T, list []FileObject, filename string) string {
	t.Helper()
	for _, fo := range list {
		if fo.Filename == filename {
			return fo.ID
		}
	}
	return ""
}

// recordingEngine is a fakeEngine whose WriteStream PERSISTS the written bytes at
// the engine path, so a north create lands an object the reconcile walk then sees
// (the base fakeEngine WriteStream is a no-op). MakeDir stays a no-op success (the
// create's EnsureDir tolerates it). It is the minimal record-keeping engine the
// create+reconcile byte-match test needs — not a mock, a real in-memory namespace.
type recordingEngine struct {
	*fakeEngine
}

func (e *recordingEngine) WriteStream(_ context.Context, _ string, path string, r io.Reader, _ bool) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	e.fakeEngine.seedObject(path, b)
	return nil
}

// createDoc drives POST /v1/files with a real multipart body and returns the
// minted file_id (fails on a non-201).
func createDoc(t *testing.T, h *Handler, wirePath string, body []byte) string {
	t.Helper()
	params := map[string]any{
		"path":                wirePath,
		"declared_size_bytes": len(body),
		"media_type":          "text/plain",
		"filename":            "doc.txt",
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal create params: %v", err)
	}
	w := doCreate(h, string(paramsJSON), body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201; body %s", w.Code, w.Body.String())
	}
	var fo FileObject
	if err := json.Unmarshal(w.Body.Bytes(), &fo); err != nil {
		t.Fatalf("decode create FileObject: %v", err)
	}
	return fo.ID
}
