// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
)

// TestRecordToFileObjectCarriesTheADR0028Shape pins the projection onto the
// frozen six-field read shape. The dialect is shared with the north face, so a
// field renamed or dropped here makes one record answer in two dialects — the
// drift ADR-0036 exists to prevent.
//
// It asserts the ON-WIRE JSON keys, not the Go field names: the contract pins
// the wire, and a struct-field assertion would pass through a renamed tag.
func TestRecordToFileObjectCarriesTheADR0028Shape(t *testing.T) {
	rec := handlestore.Record{
		FileID:    "abc123",
		Scope:     "fs-a",
		Filename:  "report.pdf",
		Mime:      "application/pdf",
		Size:      4096,
		CreatedAt: "2026-08-06T10:00:00Z",
	}

	blob, err := json.Marshal(recordToFileObject(rec))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var onWire map[string]any
	if err := json.Unmarshal(blob, &onWire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := map[string]any{
		"id":         "abc123",
		"type":       "file",
		"filename":   "report.pdf",
		"mime_type":  "application/pdf",
		"size_bytes": float64(4096),
		"created_at": "2026-08-06T10:00:00Z",
	}
	for k, v := range want {
		got, present := onWire[k]
		if !present {
			t.Errorf("the frozen FileObject requires %q; the wire carries %v", k, keysOfWire(onWire))
			continue
		}
		if got != v {
			t.Errorf("%q = %v, want %v", k, got, v)
		}
	}
	// downloadable is a read-time authorization output (NFR-SEC-73), never a
	// stored or transported field. Emitting it would publish a decision the
	// record does not hold.
	if _, leaked := onWire["downloadable"]; leaked {
		t.Error("the FileObject carries downloadable: it resolves at read from the " +
			"prefix grant and is never stamped onto the record")
	}
	if len(onWire) != len(want) {
		t.Errorf("the wire carries %d fields, the frozen shape has %d: %v",
			len(onWire), len(want), keysOfWire(onWire))
	}
}

// TestListOrderFromWireIsTolerant pins the ADR-0037 selector semantics: only
// the literal "desc" selects the descending walk, and everything else — an
// unknown value, a case variant, an empty string — is the ascending default.
//
// Tolerance is the decision, not an accident. A direction is a rendering
// preference rather than an authorization input, so a typo must render
// ascending instead of refusing the listing.
func TestListOrderFromWireIsTolerant(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want handlestore.ListOrder
	}{
		{"desc", handlestore.ListOrderDesc},
		{"", handlestore.ListOrderAsc},
		{"asc", handlestore.ListOrderAsc},
		{"DESC", handlestore.ListOrderAsc}, // exact match only, mirroring north
		{"descending", handlestore.ListOrderAsc},
		{"garbage", handlestore.ListOrderAsc},
	} {
		if got := listOrderFromWire(tc.in); got != tc.want {
			t.Errorf("listOrderFromWire(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestDenyHandleStoreErrCollapsesAbsentAndForeign pins the anti-enumeration
// keystone. The store answers ErrNotFound for BOTH an absent id and one bound
// to another scope; the handler must not re-distinguish them, or a caller could
// probe scope membership with a valid id minted in another session.
//
// It asserts the deny CLASS each error maps to, because that class is what
// reaches the wire and the audit record.
func TestDenyHandleStoreErrCollapsesAbsentAndForeign(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"absent-or-foreign", handlestore.ErrNotFound, denyNotFound},
		{"store-unavailable", handlestore.ErrStoreUnavailable, denyBackendUnavailable},
		{"unclassified", errSentinelForTest, denyBackendUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingDenyCtx{}
			denyHandleStoreErr(rec.ctx(), tc.err)
			if rec.class != tc.want {
				t.Fatalf("deny class = %q, want %q", rec.class, tc.want)
			}
		})
	}
}

// TestRequireHandlesDeniesUnavailableNotUnimplemented pins the nil-store
// answer. ADR-0036 makes the 501 set exactly the set with no frozen body, so a
// deployment-dependent 501 would misreport the build: the verb IS implemented
// and its body IS pinned — the backing resource is what is missing, which is
// unavailability.
func TestRequireHandlesDeniesUnavailableNotUnimplemented(t *testing.T) {
	rec := &recordingDenyCtx{}
	if requireHandles(&handlerDeps{}, rec.ctx()) {
		t.Fatal("requireHandles admitted a nil store: the handler would nil-dereference")
	}
	if rec.class != denyBackendUnavailable {
		t.Fatalf("nil-store deny class = %q, want %q (never denyUnimplemented)",
			rec.class, denyBackendUnavailable)
	}

	// The positive control: a configured store admits, or every by-handle verb
	// would answer 503 forever and the test above would pass vacuously.
	rec2 := &recordingDenyCtx{}
	if !requireHandles(&handlerDeps{handles: stubHandleStore{}}, rec2.ctx()) {
		t.Fatal("requireHandles refused a configured store")
	}
	if rec2.class != "" {
		t.Fatalf("a configured store recorded deny %q", rec2.class)
	}
}

// recordingDenyCtx captures what a handler denied. mandateDeny is a func field
// on handlerCtx, so the recorder is a closure over the real seam rather than a
// substitute type — the test observes the exact hook production uses.
type recordingDenyCtx struct {
	class   string
	wire    string
	message string
	calls   int
}

func (r *recordingDenyCtx) ctx() handlerCtx {
	return handlerCtx{
		mandateDeny: func(auditReason, wireClass, message string) {
			r.class, r.wire, r.message = auditReason, wireClass, message
			r.calls++
		},
	}
}

// stubHandleStore satisfies the port without a durable store behind it. It is
// only ever used where the test asserts the CONFIGURED branch is taken; a call
// reaching a method is a test bug, so each fails loudly rather than returning a
// zero value that would read as success.
type stubHandleStore struct{}

func (stubHandleStore) Get(context.Context, string, string) (handlestore.Record, error) {
	panic("stubHandleStore.Get called: this stub exists to be non-nil, not to serve")
}

func (stubHandleStore) List(context.Context, handlestore.ListInput) (handlestore.ListPage, error) {
	panic("stubHandleStore.List called: this stub exists to be non-nil, not to serve")
}

func (stubHandleStore) Delete(context.Context, string, string) error {
	panic("stubHandleStore.Delete called: this stub exists to be non-nil, not to serve")
}

func (stubHandleStore) Put(context.Context, handlestore.PutInput) (handlestore.Record, error) {
	panic("stubHandleStore.Put called: this stub exists to be non-nil, not to serve")
}

// errSentinelForTest stands in for a store error outside the classified set, so
// the default branch is exercised by something that is not a known sentinel.
var errSentinelForTest = errors.New("southface: unclassified store fault")

func keysOfWire(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestCreateFilenameFromParamsUsesThePathLeaf pins the display name the record
// carries. The south params frame has no filename field, so the leaf is the
// only source — and it must match the fallback the north create applies, or one
// record reads under two names depending on which door minted it.
func TestCreateFilenameFromParamsUsesThePathLeaf(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/outputs/report.pdf", "report.pdf"},
		{"outputs/nested/deep/a.txt", "a.txt"},
		{"/single.bin", "single.bin"},
	} {
		if got := createFilenameFromParams(uploadParamsFrame{Path: tc.in}); got != tc.want {
			t.Errorf("createFilenameFromParams(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCreateFileIsAMultipartRoute pins the transport class. ADR-0036 makes south
// createFile the ADR-0028 create whole — params then file — and a create's bytes
// cannot ride the unary JSON envelope under the RPC message ceiling. A
// createFile that fell through to the unary registry would try to decode a
// multipart body as JSON and refuse every real create.
func TestCreateFileIsAMultipartRoute(t *testing.T) {
	multipartReq := httptest.NewRequest(http.MethodPost, restBase+"createFile", nil)
	multipartReq.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	if got := negotiatedRequestClass(OpCreateFile, multipartReq); got != multipartContentType {
		t.Fatalf("createFile with a multipart body classified as %q, want the multipart class", got)
	}

	// A non-multipart createFile stays on the JSON class, where the dispatcher's
	// own media-type gate refuses it — the route boundary stays a classifier and
	// never becomes a second place that decides media types.
	jsonReq := httptest.NewRequest(http.MethodPost, restBase+"createFile", nil)
	jsonReq.Header.Set("Content-Type", contentTypeJSON)
	if got := negotiatedRequestClass(OpCreateFile, jsonReq); got != contentTypeJSON {
		t.Fatalf("createFile with a JSON body classified as %q, want the JSON class", got)
	}
}

// TestCreateFileObjectRefIsTheEnginePath pins the coherence rule between the
// two faces. The north list's reconcile keys on (Scope, ObjectRef), so a south
// create recording anything other than the canonical engine-relative path makes
// that reconcile mint a SECOND handle for the same object — one file, two
// file_ids, and a list that shows a duplicate the caller cannot delete.
//
// The rule is invisible on this face: the south create succeeds and returns a
// valid FileObject either way, and the damage only surfaces on the north list.
// A build-time constant match is what pins it, since no south-side response
// distinguishes the two.
func TestCreateFileObjectRefIsTheEnginePath(t *testing.T) {
	params := uploadParamsFrame{Path: "/outputs/deliverable.bin"}

	// enginePath is the exact expression the streaming write passes to
	// Engine.WriteStream, so it is the value the object is stored under.
	wantRef := enginePath(params.Path)
	if wantRef == params.Path {
		t.Fatalf("enginePath is an identity on %q, so this test cannot tell the "+
			"engine-relative form from the wire form", params.Path)
	}
	if strings.HasPrefix(wantRef, "/") {
		t.Errorf("the engine-relative ObjectRef %q carries a leading slash; the "+
			"north records it without one, so the reconcile would not match", wantRef)
	}
	// The binding assertion: what the handler RECORDS must equal what the engine
	// WROTE UNDER. Recording the wire path instead reds here.
	if got := createObjectRef(params); got != wantRef {
		t.Fatalf("createFile records ObjectRef %q but the engine wrote under %q: "+
			"the north reconcile keys on (Scope, ObjectRef) and would mint a "+
			"second handle for this object", got, wantRef)
	}
}
