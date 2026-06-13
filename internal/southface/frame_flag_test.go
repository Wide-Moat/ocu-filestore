// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
)

// flagFrame encodes a frame with an ARBITRARY flag byte carrying payload —
// the adversarial framer the WIRE-01 fix refuses.
func flagFrame(t *testing.T, flag byte, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := writeFrame(&buf, flag, payload); err != nil {
		t.Fatalf("flagFrame: %v", err)
	}
	return buf.Bytes()
}

// TestFileUploadUnknownFrameFlagHardAborts pins WIRE-01: a mid-stream frame
// whose flag is neither dataFlag (0x00) nor endStreamFlag (0x02) — 0x01, an
// arbitrary 0x37, 0xFF — HARD-ABORTS the upload with invalid_argument, emits
// a deny Mandate, and stages nothing. Pre-fix, such frames fell through the
// end-stream check and were unmarshalled as chunk data.
func TestFileUploadUnknownFrameFlagHardAborts(t *testing.T) {
	chunkPayload, err := json.Marshal(uploadChunkFrame{Chunk: []byte("ABCD")})
	if err != nil {
		t.Fatalf("marshal chunk payload: %v", err)
	}

	for _, flag := range []byte{0x01, 0x37, 0xFF} {
		t.Run(fmt.Sprintf("flag_0x%02x", flag), func(t *testing.T) {
			eng := newFakeEngine()
			sess := &recordingCeilingsSession{}
			g := &fakeGuard{}
			d := newDispatcherWithEngine(&fakeResolver{}, g, &recordingRegistry{sess: sess}, 1<<20, eng)
			d.maxFileSize = 1 << 20

			// A well-formed chunk payload under a non-data flag: only the
			// flag is wrong, so a pass would have been silently accepted as
			// data pre-fix.
			body := concat(
				paramsFrame(t, streamScope, "/up.bin", 8),
				flagFrame(t, flag, chunkPayload),
				chunkFrame(t, []byte("ABCDEFGH")),
				endFrame(t),
			)
			w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
			assertErrorTrailer(t, w, wireCodeInvalidArgument)

			// Nothing staged.
			var sink bytes.Buffer
			if err := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 1, &sink); err == nil {
				t.Fatalf("unknown-flag frame staged an object")
			}
			// A deny Mandate was emitted after the allow (the abort is
			// audited, not silent).
			g.mu.Lock()
			events := append([]any(nil), g.events...)
			g.mu.Unlock()
			if len(events) < 2 {
				t.Fatalf("want an allow then a deny audit event, got %d", len(events))
			}
			last, ok := events[len(events)-1].(auditgate.FileActivityEvent)
			if !ok || last.Outcome.DispositionID != auditgate.DispositionDeny {
				t.Fatalf("last audit event = %+v, want a deny", events[len(events)-1])
			}
			if !sess.balanced() {
				t.Fatalf("ceilings gauge unbalanced after an unknown-flag abort")
			}
		})
	}
}
