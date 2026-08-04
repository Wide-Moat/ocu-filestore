// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// contentCeilingSetup wires a content handler over a single 5-byte object with
// the given whole-object ceiling.
func contentCeilingSetup(maxFileSize int64) (*Handler, *fakeEngine) {
	store := newFakeStore()
	store.put("fid-known", "fs-alpha", handlestore.Record{
		Filename: "doc", ObjectRef: "obj/doc", Size: 5,
	})
	eng := newFakeEngine()
	eng.bytesByPath["obj/doc"] = []byte("hello")
	h := newTestHandler(Deps{
		Store:       store,
		Engine:      eng,
		Resolver:    &fakeResolver{grant: southface.Grant{Downloadable: true}},
		Guard:       &fakeGuard{},
		MaxFileSize: maxFileSize,
		Scope:       fakeScope{ps: southface.PeerScope{FilesystemID: "fs-alpha", GrantedIntents: []southface.Intent{southface.IntentRead}}, ok: true},
	})
	return h, eng
}

// TestContentSizeCeiling is the north mirror of the south download ceiling
// (SEC-46 egress symmetry): the resolved read window is bounded by the SAME
// whole-object ceiling create's pre-assembly reject enforces, BEFORE the
// ALLOW Mandate and the 200 commit. Only a window no door-written object can
// satisfy is refused -- an out-of-band oversized backend object or a runaway
// explicit length.
func TestContentSizeCeiling(t *testing.T) {
	t.Run("whole_object_over_ceiling_denies_pre_byte", func(t *testing.T) {
		h, eng := contentCeilingSetup(4) // object size 5 > ceiling 4
		w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for an over-ceiling whole-object read", w.Code)
		}
		if eng.readRangeCalls != 0 {
			t.Fatalf("ReadRange called %d times on an over-ceiling read; want 0", eng.readRangeCalls)
		}
	})

	t.Run("explicit_length_over_ceiling_denies", func(t *testing.T) {
		h, eng := contentCeilingSetup(4)
		w := doReq(h, http.MethodGet, "/v1/files/fid-known/content?offset=0&length=5")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for an over-ceiling explicit window", w.Code)
		}
		if eng.readRangeCalls != 0 {
			t.Fatalf("ReadRange called %d times on an over-ceiling explicit window; want 0", eng.readRangeCalls)
		}
	})

	t.Run("exactly_at_ceiling_serves", func(t *testing.T) {
		// Strict `>` boundary, mirroring create's pre-assembly reject.
		h, _ := contentCeilingSetup(5)
		w := doReq(h, http.MethodGet, "/v1/files/fid-known/content")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for a window exactly at the ceiling", w.Code)
		}
		if got := w.Body.String(); got != "hello" {
			t.Fatalf("body = %q, want hello", got)
		}
	})
}
