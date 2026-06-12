// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"testing"
)

// TestDecodeChunkFrameStrict pins WIRE-02 at the decoder: the chunk frame is
// the strictest inbound decode in the package — unknown fields, trailing
// values, and an absent/null chunk all reject; the contract-named numChunks
// is accepted (declared, unused); a present empty chunk is a legal 0-byte
// chunk.
func TestDecodeChunkFrameStrict(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		wantErr bool
		want    []byte // expected chunk bytes when wantErr is false
	}{
		{"empty_object", `{}`, true, nil},
		{"null_chunk", `{"chunk":null}`, true, nil},
		{"unknown_field", `{"chunk":"QQ==","bogus":1}`, true, nil},
		{"trailing_value", `{"chunk":"QQ=="}{"chunk":"Qg=="}`, true, nil},
		{"not_an_object", `["QQ=="]`, true, nil},
		{"bad_base64", `{"chunk":"@@@"}`, true, nil},
		{"valid_chunk", `{"chunk":"QUJDREVGR0g="}`, false, []byte("ABCDEFGH")},
		{"empty_chunk_is_zero_bytes", `{"chunk":""}`, false, []byte{}},
		{"contract_numChunks_accepted_unused", `{"chunk":"QUJDREVGR0g=","numChunks":1}`, false, []byte("ABCDEFGH")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cf, err := decodeChunkFrame([]byte(tc.payload))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("decodeChunkFrame(%s): got nil error, want a strict reject", tc.payload)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeChunkFrame(%s): got %v, want nil", tc.payload, err)
			}
			if !bytes.Equal(cf.Chunk, tc.want) {
				t.Fatalf("chunk = %q, want %q", cf.Chunk, tc.want)
			}
		})
	}
}

// TestFileUploadStrictChunkFramesOnWire pins WIRE-02 end-to-end: {} and
// unknown-field chunk frames hard-abort the stream with invalid_argument and
// stage nothing, while a contract-conformant frame carrying numChunks
// uploads successfully (parity with a stricter future guest preserved).
func TestFileUploadStrictChunkFramesOnWire(t *testing.T) {
	reject := []struct {
		name    string
		payload string
	}{
		{"empty_object_frame", `{}`},
		{"null_chunk_frame", `{"chunk":null}`},
		{"unknown_field_frame", `{"chunk":"QUJDREVGR0g=","metadata_retention_days":7}`},
	}
	for _, c := range reject {
		t.Run(c.name, func(t *testing.T) {
			eng := newFakeEngine()
			sess := &recordingCeilingsSession{}
			d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)
			body := concat(
				paramsFrame(t, streamScope, "/up.bin", 8),
				frameBytes(t, []byte(c.payload)),
				endFrame(t),
			)
			w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
			assertErrorTrailer(t, w, wireCodeInvalidArgument)
			var sink bytes.Buffer
			if err := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 1, &sink); err == nil {
				t.Fatalf("%s staged an object", c.name)
			}
			if !sess.balanced() {
				t.Fatalf("gauge unbalanced after %s", c.name)
			}
		})
	}

	t.Run("numChunks_frame_uploads", func(t *testing.T) {
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)
		body := concat(
			paramsFrame(t, streamScope, "/up.bin", 8),
			frameBytes(t, []byte(`{"chunk":"QUJDREVGR0g=","numChunks":1}`)),
			endFrame(t),
		)
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertSuccessTrailer(t, w)
		var buf bytes.Buffer
		if err := eng.ReadRange(t.Context(), streamScope, "up.bin", 0, 8, &buf); err != nil || buf.String() != "ABCDEFGH" {
			t.Fatalf("stored object = %q,%v want ABCDEFGH,nil", buf.String(), err)
		}
	})
}
