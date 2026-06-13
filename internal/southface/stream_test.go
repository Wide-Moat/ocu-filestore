// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

// mustHex decodes a hex literal from GOLDEN-FIXTURES into raw bytes.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// jsonEqual reports whether two JSON byte slices are parsed-equal (key order
// independent).
func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		t.Fatalf("left not JSON: %v (%s)", err, string(a))
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		t.Fatalf("right not JSON: %v (%s)", err, string(b))
	}
	return reflect.DeepEqual(va, vb)
}

// TestFrameGolden pins the codec byte-for-byte against GOLDEN-FIXTURES: the
// frame HEADER (flag + 4-byte BE length) is compared as raw bytes; the JSON
// payload is compared parsed-equal (the encoder's key order may differ).
func TestFrameGolden(t *testing.T) {
	cases := []struct {
		name    string
		flag    byte
		payload []byte
		hdrHex  string // the 5-byte header, hex
	}{
		{
			name:    "params_frame_len143",
			flag:    dataFlag,
			payload: []byte(`{"filesystem_id":"fs-golden-01","path":"/golden.bin","declared_size_bytes":42,"authorization_metadata":{"intent":"write","downloadable":false}}`),
			hdrHex:  "000000008f",
		},
		{
			name:    "chunk_frame_len24",
			flag:    dataFlag,
			payload: []byte(`{"chunk":"QUJDREVGR0g="}`),
			hdrHex:  "0000000018",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeFrame(&buf, c.flag, c.payload); err != nil {
				t.Fatalf("writeFrame: %v", err)
			}
			got := buf.Bytes()
			wantHdr := mustHex(t, c.hdrHex)
			if !bytes.Equal(got[:frameHeaderLen], wantHdr) {
				t.Fatalf("header = %x, want %x", got[:frameHeaderLen], wantHdr)
			}
			if !jsonEqual(t, got[frameHeaderLen:], c.payload) {
				t.Fatalf("payload = %s, not parsed-equal to %s", got[frameHeaderLen:], c.payload)
			}
		})
	}
}

// TestFrameGoldenChunkExact pins the FULL chunk frame bytes (header + body)
// against the golden hex — the chunk body is compact and field-order-stable so
// the whole frame is byte-identical.
func TestFrameGoldenChunkExact(t *testing.T) {
	want := mustHex(t, "00000000187b226368756e6b223a2251554a44524556475230673d227d")
	cf := uploadChunkFrame{Chunk: []byte("ABCDEFGH")}
	payload, err := json.Marshal(cf)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}
	var buf bytes.Buffer
	if err := writeFrame(&buf, dataFlag, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("chunk frame = %x, want %x", buf.Bytes(), want)
	}
}

// TestEndStreamGolden pins the success trailer (02000000027b7d) byte-for-byte
// and the error trailer header (flag 0x02, len 57) with a parsed-equal body.
func TestEndStreamGolden(t *testing.T) {
	t.Run("success_exact", func(t *testing.T) {
		var buf bytes.Buffer
		if err := writeEndStream(&buf, nil); err != nil {
			t.Fatalf("writeEndStream(nil): %v", err)
		}
		want := mustHex(t, "02000000027b7d")
		if !bytes.Equal(buf.Bytes(), want) {
			t.Fatalf("success trailer = %x, want %x", buf.Bytes(), want)
		}
	})
	t.Run("error_header_and_body", func(t *testing.T) {
		var buf bytes.Buffer
		if err := writeEndStream(&buf, &connectError{Code: "not_found", Message: "object missing"}); err != nil {
			t.Fatalf("writeEndStream(err): %v", err)
		}
		golden := mustHex(t, "02000000397b226572726f72223a7b22636f6465223a226e6f745f666f756e64222c226d657373616765223a226f626a656374206d697373696e67227d7d")
		got := buf.Bytes()
		// Header byte-for-byte: flag 0x02 + len 57.
		if !bytes.Equal(got[:frameHeaderLen], golden[:frameHeaderLen]) {
			t.Fatalf("error trailer header = %x, want %x", got[:frameHeaderLen], golden[:frameHeaderLen])
		}
		if got[0] != endStreamFlag {
			t.Fatalf("error trailer flag = %#x, want %#x", got[0], endStreamFlag)
		}
		// Body parsed-equal to the golden error body.
		if !jsonEqual(t, got[frameHeaderLen:], golden[frameHeaderLen:]) {
			t.Fatalf("error trailer body = %s, not parsed-equal to golden", got[frameHeaderLen:])
		}
		// The golden error body declares len=57 — confirm the wire length.
		if n := len(got) - frameHeaderLen; n != 57 {
			t.Fatalf("error trailer payload len = %d, want 57", n)
		}
	})
}

// TestChunkBase64Parity proves Go's []byte<->std-base64 matches the guest:
// raw "ABCDEFGH" marshals to {"chunk":"QUJDREVGR0g="} and unmarshals back.
func TestChunkBase64Parity(t *testing.T) {
	cf := uploadChunkFrame{Chunk: []byte("ABCDEFGH")}
	b, err := json.Marshal(cf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"chunk":"QUJDREVGR0g="}` {
		t.Fatalf("marshalled chunk = %s, want {\"chunk\":\"QUJDREVGR0g=\"}", b)
	}
	var back uploadChunkFrame
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(back.Chunk) != "ABCDEFGH" {
		t.Fatalf("round-trip chunk = %q, want ABCDEFGH", back.Chunk)
	}
}

// TestFrameRoundTrip pins writeFrame->readFrame fidelity across flags and
// sizes including 0, 1, the golden 143, and a few KiB.
func TestFrameRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 143, 4096}
	flags := []byte{dataFlag, endStreamFlag}
	for _, flag := range flags {
		for _, sz := range sizes {
			payload := bytes.Repeat([]byte{'x'}, sz)
			var buf bytes.Buffer
			if err := writeFrame(&buf, flag, payload); err != nil {
				t.Fatalf("writeFrame(flag=%#x,sz=%d): %v", flag, sz, err)
			}
			gotFlag, gotPayload, err := readFrame(&buf)
			if err != nil {
				t.Fatalf("readFrame(flag=%#x,sz=%d): %v", flag, sz, err)
			}
			if gotFlag != flag {
				t.Fatalf("flag = %#x, want %#x", gotFlag, flag)
			}
			if !bytes.Equal(gotPayload, payload) {
				t.Fatalf("payload len = %d, want %d", len(gotPayload), sz)
			}
		}
	}
}

// boundedReader caps total bytes it will produce, so the maxInboundFrame test
// proves readFrame rejects an oversize length BEFORE allocating/reading the
// payload (a reader that would refuse to supply gigabytes).
type boundedReader struct {
	r       io.Reader
	max     int
	read    int
	tripped bool
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.read >= b.max {
		b.tripped = true
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > b.max-b.read {
		p = p[:b.max-b.read]
	}
	n, err := b.r.Read(p)
	b.read += n
	return n, err
}

// TestFrameMaxInbound rejects an oversize length before allocation and accepts
// a length exactly at the cap.
func TestFrameMaxInbound(t *testing.T) {
	t.Run("over_cap_rejected_before_alloc", func(t *testing.T) {
		// A header declaring maxInboundFrame+1, then NOTHING. A bounded reader
		// lets only the 5-byte header through; if readFrame tried to allocate
		// and read the payload it would block/trip on the bound.
		var hdr [frameHeaderLen]byte
		hdr[0] = dataFlag
		binary.BigEndian.PutUint32(hdr[1:frameHeaderLen], uint32(maxInboundFrame+1))
		br := &boundedReader{r: bytes.NewReader(hdr[:]), max: frameHeaderLen}
		_, _, err := readFrame(br)
		if !errors.Is(err, errFrameTooLarge) {
			t.Fatalf("err = %v, want errFrameTooLarge", err)
		}
		if br.tripped {
			t.Fatalf("readFrame read past the header — it allocated/read the oversize payload")
		}
	})
	t.Run("at_cap_accepted", func(t *testing.T) {
		// A frame exactly at the cap: header declares maxInboundFrame, payload
		// is that many bytes.
		payload := bytes.Repeat([]byte{'y'}, maxInboundFrame)
		var buf bytes.Buffer
		if err := writeFrame(&buf, dataFlag, payload); err != nil {
			t.Fatalf("writeFrame: %v", err)
		}
		flag, got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("readFrame at cap: %v", err)
		}
		if flag != dataFlag || len(got) != maxInboundFrame {
			t.Fatalf("at-cap frame = flag %#x len %d, want %#x len %d", flag, len(got), dataFlag, maxInboundFrame)
		}
	})
}

// TestFrameTruncated covers the WIRE-LESSONS #1 hard-abort inputs: a short
// header and a header with a short payload both error (non-nil).
func TestFrameTruncated(t *testing.T) {
	t.Run("short_header", func(t *testing.T) {
		_, _, err := readFrame(bytes.NewReader([]byte{0x00, 0x00, 0x00}))
		if err == nil {
			t.Fatalf("short header: err = nil, want non-nil")
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("short header err = %v, want ErrUnexpectedEOF class", err)
		}
	})
	t.Run("short_payload", func(t *testing.T) {
		// Header declares len=8, but only 3 payload bytes follow.
		var hdr [frameHeaderLen]byte
		hdr[0] = dataFlag
		hdr[4] = 8
		input := append(hdr[:], 'a', 'b', 'c')
		_, _, err := readFrame(bytes.NewReader(input))
		if err == nil {
			t.Fatalf("short payload: err = nil, want non-nil")
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("short payload err = %v, want ErrUnexpectedEOF class", err)
		}
	})
}

// TestFakeReadRange pins the in-memory engine fake's half-open + past-EOF
// short-read semantics (the contract the handler relies on).
func TestFakeReadRange(t *testing.T) {
	eng := newFakeEngine()
	eng.putBytes("fs", "f", []byte("ABCDEFGH"))

	read := func(off, length int64) (string, error) {
		var buf bytes.Buffer
		err := eng.ReadRange(context.Background(), "fs", "f", off, length, &buf)
		return buf.String(), err
	}

	if got, err := read(0, 8); err != nil || got != "ABCDEFGH" {
		t.Fatalf("[0,8) = %q,%v want ABCDEFGH,nil", got, err)
	}
	if got, err := read(2, 3); err != nil || got != "CDE" {
		t.Fatalf("[2,3) = %q,%v want CDE,nil (half-open)", got, err)
	}
	if got, err := read(6, 10); err != nil || got != "GH" {
		t.Fatalf("[6,10) = %q,%v want GH,nil (past-EOF short-read)", got, err)
	}
	if got, err := read(0, 0); err != nil || got != "ABCDEFGH" {
		t.Fatalf("[0,0) = %q,%v want full read ABCDEFGH,nil (length<=0 = full)", got, err)
	}
	if got, err := read(20, 5); err != nil || got != "" {
		t.Fatalf("[20,5) = %q,%v want empty,nil (offset past EOF)", got, err)
	}
	// Missing path -> ErrNotExist.
	var sink bytes.Buffer
	if err := eng.ReadRange(context.Background(), "fs", "missing", 0, 1, &sink); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing path err = %v, want fs.ErrNotExist", err)
	}
}

// TestFakeWriteStream pins the fake's WriteStream semantics: clean reassembly,
// overwrite=false collision without changing bytes, and partial invisibility.
func TestFakeWriteStream(t *testing.T) {
	t.Run("clean_write_then_read", func(t *testing.T) {
		eng := newFakeEngine()
		if err := eng.WriteStream(context.Background(), "fs", "f", strings.NewReader("ABCDEFGH"), false); err != nil {
			t.Fatalf("WriteStream: %v", err)
		}
		var buf bytes.Buffer
		if err := eng.ReadRange(context.Background(), "fs", "f", 0, 8, &buf); err != nil || buf.String() != "ABCDEFGH" {
			t.Fatalf("read-back = %q,%v want ABCDEFGH,nil", buf.String(), err)
		}
	})
	t.Run("overwrite_false_collision", func(t *testing.T) {
		eng := newFakeEngine()
		if err := eng.WriteStream(context.Background(), "fs", "f", strings.NewReader("AAAA"), false); err != nil {
			t.Fatalf("first WriteStream: %v", err)
		}
		// A second reader that, if read, would change the stored bytes.
		err := eng.WriteStream(context.Background(), "fs", "f", strings.NewReader("ZZZZZZ"), false)
		if !errors.Is(err, errAlreadyExists) {
			t.Fatalf("collision err = %v, want errAlreadyExists", err)
		}
		var buf bytes.Buffer
		_ = eng.ReadRange(context.Background(), "fs", "f", 0, 0, &buf)
		if buf.String() != "AAAA" {
			t.Fatalf("stored bytes after refused overwrite = %q, want AAAA", buf.String())
		}
	})
	t.Run("partial_aborted_leaves_no_node", func(t *testing.T) {
		eng := newFakeEngine()
		pr, pw := io.Pipe()
		errCh := make(chan error, 1)
		go func() { errCh <- eng.WriteStream(context.Background(), "fs", "f", pr, false) }()
		_, _ = pw.Write([]byte("partial"))
		pw.CloseWithError(errors.New("aborted mid-stream"))
		if err := <-errCh; err == nil {
			t.Fatalf("WriteStream after CloseWithError: err = nil, want the abort error")
		}
		// No node linked: a read of the path is ErrNotExist.
		var sink bytes.Buffer
		if err := eng.ReadRange(context.Background(), "fs", "f", 0, 1, &sink); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("aborted upload left a node: read err = %v, want fs.ErrNotExist", err)
		}
	})
}
