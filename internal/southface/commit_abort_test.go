// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"testing"
)

// TestUploadAbortAfterAllBytesStagesNothing is the WR-P3 reproduction test.
// It sends params + all declared bytes in chunk frames + a MALFORMED/unknown-
// flag frame instead of the 0x02 end-stream, then asserts two invariants:
//
//	(a) the trailer carries the abort verdict (not success),
//	(b) the object is NOT visible afterward (engine.ReadRange/Stat → not_found).
//
// This covers the case the guest reported: a stream that delivers all declared
// bytes and then a malformed terminal frame must be treated as aborted — no
// committed object, no visible bytes.
//
// Each abort path variant is exercised: unknown frame flag (non-data,
// non-end-stream) and a data frame with undecodable JSON.
func TestUploadAbortAfterAllBytesStagesNothing(t *testing.T) {
	const (
		scope   = streamScope
		path    = "/abort-after-bytes.bin"
		engPath = "abort-after-bytes.bin"
	)
	content := []byte("COMPLETE_PAYLOAD_ABCDEFGH") // 24 bytes
	declared := int64(len(content))

	// unknownFlagFrame builds a frame with flag 0x05 (not 0x00 data, not 0x02
	// end-stream), which the handler must hard-abort as unsupported.
	unknownFlagFrame := func(t *testing.T) []byte {
		t.Helper()
		var buf bytes.Buffer
		if err := writeFrame(&buf, 0x05, []byte(`{"chunk":"dGVzdA=="}`)); err != nil {
			t.Fatalf("unknownFlagFrame: %v", err)
		}
		return buf.Bytes()
	}

	// malformedDataFrame builds a 0x00 data frame whose payload is not a
	// valid uploadChunkFrame JSON (an array instead of an object).
	malformedDataFrame := func(t *testing.T) []byte {
		t.Helper()
		return frameBytes(t, []byte(`["not","a","chunk","frame"]`))
	}

	cases := []struct {
		name      string
		termFrame func(*testing.T) []byte
		wantCode  string
	}{
		{
			// The guest's primary report: unknown flag frame after all bytes.
			// The handler must detect the unsupported flag and abort; the
			// object is NOT committed.
			name:      "unknown_flag_after_full_payload",
			termFrame: unknownFlagFrame,
			wantCode:  wireCodeInvalidArgument,
		},
		{
			// Malformed JSON in a data frame after all declared bytes.
			// Equivalent abort path.
			name:      "malformed_json_frame_after_full_payload",
			termFrame: malformedDataFrame,
			wantCode:  wireCodeInvalidArgument,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eng := newFakeEngine()
			sess := &recordingCeilingsSession{}
			d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)

			// Build the stream: params + full content chunk + malformed terminal.
			body := concat(
				paramsFrame(t, scope, path, declared),
				chunkFrame(t, content),
				c.termFrame(t),
			)
			w := serveStream(d, OpFileUpload, bytes.NewReader(body), scope, okIntents())

			// (a) Trailer must be the abort/error verdict.
			assertErrorTrailer(t, w, c.wantCode)

			// (b) No object must be visible — ReadRange must error (not_found).
			var sink bytes.Buffer
			if readErr := eng.ReadRange(t.Context(), scope, engPath, 0, declared, &sink); readErr == nil {
				t.Fatalf(
					"%s: object was committed despite abort — ReadRange succeeded with %q; "+
						"a refused stream MUST stage nothing",
					c.name, sink.String(),
				)
			}

			// Ceilings gauge must balance on every abort path.
			if !sess.balanced() {
				t.Fatalf("%s: ceilings gauge unbalanced after abort: acquired=%d released=%d fd_acq=%d fd_rel=%d",
					c.name, sess.acquired, sess.released, sess.fdAcquired, sess.fdReleased)
			}
		})
	}
}
