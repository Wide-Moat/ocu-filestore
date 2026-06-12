// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// The 5-byte Connect stream envelope. Both south-face streaming ops (the
// deferred fileDownload and this phase's fileUpload) frame their wire bytes
// with this codec, byte-identical to the guest framer it must interoperate
// with: byte0 is the frame flag, bytes 1..4 are the payload length as a
// big-endian uint32, and the payload is compact JSON. Streams are always
// HTTP 200; the verdict rides only in the trailing end-stream frame.
const (
	// frameHeaderLen is the fixed 5-byte header: 1 flag byte + a 4-byte
	// big-endian uint32 length.
	frameHeaderLen = 5
	// dataFlag marks a data frame (params or chunk on intake; content on a
	// download response).
	dataFlag byte = 0x00
	// endStreamFlag marks the terminal end-stream frame carrying the verdict
	// ({} success / {"error":{code,message}}). The trailer writer is just the
	// frame writer with this flag.
	endStreamFlag byte = 0x02
	// maxInboundFrame is the transport cap on a single inbound frame's
	// declared length (4 MiB, matching the guest's per-frame ceiling). A
	// header whose length field exceeds this is a TRANSPORT reject mapping to
	// resource_exhausted — distinct from the policy size deny
	// (invalid_argument/size_exceeded) applied to declared_size_bytes. The cap
	// is enforced before any payload buffer is allocated so a corrupt or
	// desynced length cannot drive a multi-GiB allocation.
	maxInboundFrame = 4 * 1024 * 1024
)

// Frame codec sentinels. Each is matched with errors.Is by the streaming
// handler to choose the wire verdict.
var (
	// errFrameTooLarge is returned by readFrame when a header's length field
	// exceeds maxInboundFrame, before any allocation. The handler maps it to a
	// resource_exhausted trailer (transport).
	errFrameTooLarge = errors.New("southface: inbound frame exceeds transport ceiling")

	// errExpectedParams is returned by readParamsFrame when the first frame is
	// not a data frame (e.g. a leading end-stream frame). The handler maps it
	// to an invalid_argument trailer.
	errExpectedParams = errors.New("southface: first frame must be the params data frame")

	// errMalformedFrame is the hard-abort sentinel for an undecodable inbound
	// data frame payload (WIRE-LESSONS #1: never skip a malformed frame).
	errMalformedFrame = errors.New("southface: malformed inbound frame")
)

// endStreamResponse is the JSON body of an end-stream error trailer:
// {"error":{"code":...,"message":...}}. A nil Error marshals as {} only via
// the success path in writeEndStream, which writes the literal "{}" so the
// success trailer bytes match the golden fixture exactly.
type endStreamResponse struct {
	Error *connectError `json:"error"`
}

// writeFrame writes one frame: the 5-byte header (flag + big-endian uint32
// payload length) followed by the payload. A zero-length payload writes only
// the header. It returns the first write error encountered.
func writeFrame(w io.Writer, flag byte, payload []byte) error {
	var hdr [frameHeaderLen]byte
	hdr[0] = flag
	binary.BigEndian.PutUint32(hdr[1:frameHeaderLen], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one frame from r: the 5-byte header, then the payload. The
// declared length is checked against maxInboundFrame BEFORE the payload buffer
// is allocated (errFrameTooLarge on breach). A short header or short payload
// returns the io.ReadFull error (io.ErrUnexpectedEOF / io.EOF), which the
// handler treats as a hard abort (WIRE-LESSONS #1).
func readFrame(r io.Reader) (flag byte, payload []byte, err error) {
	var hdr [frameHeaderLen]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	flag = hdr[0]
	n := binary.BigEndian.Uint32(hdr[1:frameHeaderLen])
	if n > maxInboundFrame {
		return 0, nil, errFrameTooLarge
	}
	if n == 0 {
		return flag, []byte{}, nil
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return flag, payload, nil
}

// writeEndStream writes the terminal end-stream (0x02) trailer. A nil connErr
// writes the success trailer with the literal body {} (byte-identical to the
// golden success trailer 02000000027b7d). A non-nil connErr marshals
// {"error":{"code":...,"message":...}} so the bytes match the golden error
// trailer shape. The trailer writer IS the frame writer — it is the single
// path every reject and the success path use, and it is written BEFORE intake
// is closed on a mid-stream reject (WIRE-LESSONS #2).
func writeEndStream(w io.Writer, connErr *connectError) error {
	if connErr == nil {
		return writeFrame(w, endStreamFlag, []byte("{}"))
	}
	payload, err := json.Marshal(endStreamResponse{Error: connErr})
	if err != nil {
		// A connectError is two strings; marshalling cannot fail in practice.
		// Fail closed to a minimal error trailer rather than an empty success.
		payload = []byte(`{"error":{"code":"internal","message":"trailer encode failed"}}`)
	}
	return writeFrame(w, endStreamFlag, payload)
}
