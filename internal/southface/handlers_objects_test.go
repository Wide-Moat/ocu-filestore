// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"encoding/json"
	"errors"
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
