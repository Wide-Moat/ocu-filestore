// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"net/http"
	"testing"
)

// TestDownloadOctetStreamSizeCeiling pins the egress half of the SEC-46 size
// symmetry: the download's resolved read window is bounded by the SAME
// whole-object ceiling the upload's pre-assembly reject enforces, BEFORE the
// ALLOW audit and the 200 commit. Door-written objects sit at or under the
// ceiling, so the refusal only fires for a window no legitimate object can
// satisfy -- an out-of-band oversized backend object or a runaway explicit
// range. Without it a single op token buys an unbounded response stream.
func TestDownloadOctetStreamSizeCeiling(t *testing.T) {
	overCap := []byte("123456789") // 9 bytes against an 8-byte ceiling

	newRig := func(ceiling int64) (*dispatcher, *fakeEngine, *fakeGuard) {
		eng := newFakeEngine()
		eng.putBytes(downloadScope, "big.bin", overCap)
		g := &fakeGuard{}
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, g, sess, ceiling)
		d.resolver = &fakeResolver{grant: Grant{Downloadable: true}}
		return d, eng, g
	}

	t.Run("whole_object_over_ceiling_denies_pre_byte", func(t *testing.T) {
		d, eng, _ := newRig(8)
		uuid := d.ids.idFor(downloadScope, "/big.bin")
		// Nil range: the handler Stats the whole-object size (9) and must
		// refuse it against the ceiling (8) BEFORE any byte or 200 header.
		w := serveDownload(t, d, downloadScope, uuid, nil, downloadScope, okIntents())
		assertDownloadDenied(t, w, http.StatusBadRequest)
		if n := len(eng.readRangeCalls()); n != 0 {
			t.Fatalf("ReadRange called %d times on an over-ceiling whole-object download; want 0", n)
		}
	})

	t.Run("explicit_range_over_ceiling_denies", func(t *testing.T) {
		d, eng, _ := newRig(8)
		uuid := d.ids.idFor(downloadScope, "/big.bin")
		// An explicit window wider than the ceiling is refused the same way:
		// the bound is on the REQUESTED window, so a caller cannot evade the
		// whole-object arm by naming the huge range explicitly.
		w := serveDownload(t, d, downloadScope, uuid, &rangeFixture{Offset: 0, Length: 9}, downloadScope, okIntents())
		assertDownloadDenied(t, w, http.StatusBadRequest)
		if n := len(eng.readRangeCalls()); n != 0 {
			t.Fatalf("ReadRange called %d times on an over-ceiling ranged download; want 0", n)
		}
	})

	t.Run("exactly_at_ceiling_serves", func(t *testing.T) {
		// Strict `>` boundary, mirroring the upload reject: a window exactly
		// at the ceiling is admitted.
		d, _, _ := newRig(9)
		uuid := d.ids.idFor(downloadScope, "/big.bin")
		w := serveDownload(t, d, downloadScope, uuid, nil, downloadScope, okIntents())
		assertDownloadOK(t, w, overCap)
	})
}
