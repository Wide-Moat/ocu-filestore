// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"pgregory.net/rapid"
)

var (
	propActivities  = []ActivityID{ActivityCreate, ActivityRead, ActivityDelete, ActivityOpen}
	propIntents     = []string{"read", "write", "preview"}
	propDenyReasons = []string{"scope_mismatch", "intent_denied", "not_downloadable", "lease_expired", "size_exceeded", "not_found"}
)

// arbitraryEvent draws a structurally valid FileActivityEvent: pinned class
// constants, sampled activity/intent/outcome, arbitrary short identifiers.
func arbitraryEvent(rt *rapid.T) FileActivityEvent {
	outcome := Outcome{DispositionID: DispositionAllow}
	if rapid.Bool().Draw(rt, "deny") {
		outcome = Outcome{
			DispositionID: DispositionDeny,
			XDenyReason:   rapid.SampledFrom(propDenyReasons).Draw(rt, "reason"),
		}
	}
	return FileActivityEvent{
		ClassUID:    1001,
		CategoryUID: 1,
		ActivityID:  rapid.SampledFrom(propActivities).Draw(rt, "activity"),
		Actor: ActorSubject{
			UserUID:    rapid.String().Draw(rt, "user_uid"),
			SessionUID: rapid.String().Draw(rt, "session_uid"),
		},
		FilesystemID: rapid.String().Draw(rt, "filesystem_id"),
		ObjectHandle: rapid.String().Draw(rt, "object_handle"),
		ByteCount:    rapid.Int64Range(0, 1<<40).Draw(rt, "byte_count"),
		Intent:       rapid.SampledFrom(propIntents).Draw(rt, "intent"),
		Downloadable: rapid.Bool().Draw(rt, "downloadable"),
		Outcome:      outcome,
	}
}

// writeChain writes the events through a fresh sink and returns the path.
func writeChain(rt *rapid.T, t *testing.T, events []FileActivityEvent) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		rt.Fatalf("NewFileSink: %v", err)
	}
	for i, ev := range events {
		if err := s.Mandate(context.Background(), ev); err != nil {
			rt.Fatalf("Mandate #%d: %v", i, err)
		}
	}
	if err := s.f.Close(); err != nil {
		rt.Fatalf("close sink: %v", err)
	}
	return path
}

// lineSpans returns the [start, end) byte spans of each newline-terminated
// line in data, end inclusive of the newline.
func lineSpans(data []byte) [][2]int {
	var spans [][2]int
	start := 0
	for {
		i := bytes.IndexByte(data[start:], '\n')
		if i < 0 {
			return spans
		}
		spans = append(spans, [2]int{start, start + i + 1})
		start += i + 1
	}
}

// TestPropChainAcceptsHonest asserts that every honestly written event
// sequence produces a chain Verify accepts (AUD-02).
func TestPropChainAcceptsHonest(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		events := rapid.SliceOfN(rapid.Custom(arbitraryEvent), 1, 8).Draw(rt, "events")
		path := writeChain(rt, t, events)
		if err := Verify(path); err != nil {
			rt.Fatalf("Verify honest chain of %d events: %v", len(events), err)
		}
	})
}

// TestPropChainTamperDetected asserts that flipping an arbitrary byte at an
// arbitrary position of any line that has a successor makes Verify reject
// the chain (AUD-02). The final line's body is outside what an offline
// verifier can pin — equivalent to truncate-then-append, the same class as
// trailing-line removal; external anchoring is deferred to the full shelf.
func TestPropChainTamperDetected(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		events := rapid.SliceOfN(rapid.Custom(arbitraryEvent), 2, 8).Draw(rt, "events")
		path := writeChain(rt, t, events)

		data, err := os.ReadFile(path)
		if err != nil {
			rt.Fatalf("ReadFile: %v", err)
		}
		spans := lineSpans(data)
		if len(spans) != len(events) {
			rt.Fatalf("line count: got %d, want %d", len(spans), len(events))
		}

		// Any line with a successor, any byte in it (newline included).
		lineIdx := rapid.IntRange(0, len(spans)-2).Draw(rt, "line")
		span := spans[lineIdx]
		byteIdx := rapid.IntRange(span[0], span[1]-1).Draw(rt, "byte")

		mutated := append([]byte{}, data...)
		mutated[byteIdx] ^= 0xFF // always changes the byte
		if err := os.WriteFile(path, mutated, 0o600); err != nil {
			rt.Fatalf("rewrite: %v", err)
		}

		if err := Verify(path); err == nil {
			rt.Fatalf("Verify accepted a chain with line %d byte %d flipped", lineIdx, byteIdx-span[0])
		}
	})
}
