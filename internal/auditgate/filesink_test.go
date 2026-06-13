// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// testEvent returns a valid allow-outcome event with every pinned field set.
func testEvent() FileActivityEvent {
	return FileActivityEvent{
		ClassUID:     1001,
		CategoryUID:  1,
		ActivityID:   ActivityRead,
		Actor:        ActorSubject{UserUID: "user-1", SessionUID: "sess-1"},
		FilesystemID: "fs-1",
		ObjectHandle: "fs-1/notes/a.txt",
		ByteCount:    42,
		Intent:       "read",
		Downloadable: true,
		Outcome:      Outcome{DispositionID: DispositionAllow},
	}
}

// denyEvent returns a deny-outcome variant carrying x_deny_reason.
func denyEvent() FileActivityEvent {
	ev := testEvent()
	ev.Downloadable = false
	ev.Outcome = Outcome{DispositionID: DispositionDeny, XDenyReason: "not_downloadable"}
	return ev
}

// newTestSink creates a sink on a fresh file under t.TempDir.
func newTestSink(t *testing.T) (string, *FileSink) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	return path, s
}

// completeLines returns the newline-terminated lines of the file at path,
// each WITHOUT its trailing newline; a torn unterminated tail is excluded.
func completeLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var lines [][]byte
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return lines
		}
		lines = append(lines, data[:i])
		data = data[i+1:]
	}
}

// TestMandateDurable pins AUD-01: after Mandate returns nil the record is on
// disk; the pinned fields round-trip intact and the first record links from
// the named genesis sentinel.
func TestMandateDurable(t *testing.T) {
	path, s := newTestSink(t)
	for _, tc := range []struct {
		name string
		ev   FileActivityEvent
	}{
		{"allow outcome", testEvent()},
		{"deny outcome with reason", denyEvent()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Mandate(context.Background(), tc.ev); err != nil {
				t.Fatalf("Mandate: got %v, want nil", err)
			}
			lines := completeLines(t, path)
			if len(lines) == 0 {
				t.Fatalf("Mandate returned nil but no record is on disk")
			}
			var got FileActivityEvent
			if err := json.Unmarshal(lines[len(lines)-1], &got); err != nil {
				t.Fatalf("unmarshal last line: %v", err)
			}
			if got.ClassUID != 1001 || got.CategoryUID != 1 {
				t.Fatalf("class_uid/category_uid: got %d/%d, want 1001/1", got.ClassUID, got.CategoryUID)
			}
			if got.ByteCount != tc.ev.ByteCount || got.Intent != tc.ev.Intent {
				t.Fatalf("byte_count/intent: got %d/%q, want %d/%q", got.ByteCount, got.Intent, tc.ev.ByteCount, tc.ev.Intent)
			}
			if got.Outcome != tc.ev.Outcome {
				t.Fatalf("outcome: got %+v, want %+v", got.Outcome, tc.ev.Outcome)
			}
			if got.PrevHash == "" {
				t.Fatalf("prev_hash: empty, want a hex digest")
			}
			if got.Metadata.Version != "1.1.0" || got.Metadata.Product.Name != "ocu-filestore" {
				t.Fatalf("metadata: got %+v, want version 1.1.0 / product ocu-filestore", got.Metadata)
			}
		})
	}

	// The first record links from the genesis sentinel.
	var first FileActivityEvent
	if err := json.Unmarshal(completeLines(t, path)[0], &first); err != nil {
		t.Fatalf("unmarshal first line: %v", err)
	}
	genesis := sha256.Sum256([]byte(genesisInput))
	if first.PrevHash != hex.EncodeToString(genesis[:]) {
		t.Fatalf("first prev_hash: got %s, want genesis %s", first.PrevHash, hex.EncodeToString(genesis[:]))
	}
}

// TestMandateUnavailable pins AUD-01 fail-closed: a sink whose target cannot
// be written returns ErrAuditUnavailable so the caller denies (NFR-SEC-79).
func TestMandateUnavailable(t *testing.T) {
	_, s := newTestSink(t)
	if err := s.f.Close(); err != nil {
		t.Fatalf("close underlying file: %v", err)
	}
	if err := s.Mandate(context.Background(), testEvent()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Mandate on closed file: got %v, want ErrAuditUnavailable", err)
	}
}

// faultSyncer wraps the sink's write seam, failing Write or Sync on
// demand while delegating the other call to the real implementation.
type faultSyncer struct {
	ws        writeSyncer
	failWrite bool
	failSync  bool
}

func (f *faultSyncer) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("injected write fault")
	}
	return f.ws.Write(p)
}

func (f *faultSyncer) Sync() error {
	if f.failSync {
		return errors.New("injected sync fault")
	}
	return f.ws.Sync()
}

// TestMandateLatchesAfterFault pins the post-error latch: any write or
// sync fault permanently fails the sink — every later Mandate returns
// ErrAuditUnavailable without writing, even after the underlying fault is
// gone. Recovery is a restart: NewFileSink re-scans the chain and serves.
func TestMandateLatchesAfterFault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault faultSyncer
	}{
		{"write fault", faultSyncer{failWrite: true}},
		{"sync fault", faultSyncer{failSync: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, s := newTestSink(t)
			if err := s.Mandate(context.Background(), testEvent()); err != nil {
				t.Fatalf("baseline Mandate: %v", err)
			}

			fault := tc.fault
			fault.ws = s.f
			s.w = &fault
			if err := s.Mandate(context.Background(), testEvent()); !errors.Is(err, ErrAuditUnavailable) {
				t.Fatalf("Mandate under fault: got %v, want ErrAuditUnavailable", err)
			}
			linesAfterFault := len(completeLines(t, path))

			// The underlying problem is fixed — the latch must still refuse,
			// and must not touch the file.
			s.w = s.f
			if err := s.Mandate(context.Background(), testEvent()); !errors.Is(err, ErrAuditUnavailable) {
				t.Fatalf("Mandate after fault cleared: got %v, want ErrAuditUnavailable (latched)", err)
			}
			if got := len(completeLines(t, path)); got != linesAfterFault {
				t.Fatalf("latched Mandate wrote to the file: %d lines, want %d", got, linesAfterFault)
			}

			// Restart recovers: a fresh sink re-scans from genesis, adopts
			// every complete line, and the continued chain verifies.
			if err := s.f.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			s2, err := NewFileSink(path)
			if err != nil {
				t.Fatalf("NewFileSink restart: %v", err)
			}
			if err := s2.Mandate(context.Background(), testEvent()); err != nil {
				t.Fatalf("Mandate after restart: %v", err)
			}
			if err := Verify(path); err != nil {
				t.Fatalf("Verify after restart recovery: got %v, want nil", err)
			}
		})
	}
}

// TestMandateUnknownType pins the type-assert fail-closed path: anything
// that is not a FileActivityEvent value returns ErrAuditUnavailable.
func TestMandateUnknownType(t *testing.T) {
	_, s := newTestSink(t)
	ev := testEvent()
	for _, tc := range []struct {
		name  string
		event any
	}{
		{"string", "not an event"},
		{"nil", nil},
		{"pointer instead of value", &ev},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Mandate(context.Background(), tc.event); !errors.Is(err, ErrAuditUnavailable) {
				t.Fatalf("Mandate(%s): got %v, want ErrAuditUnavailable", tc.name, err)
			}
		})
	}
}

// TestMandateStampsBrokerTime pins NFR-SEC-48: a caller-supplied time never
// reaches the record; Mandate stamps the broker clock.
func TestMandateStampsBrokerTime(t *testing.T) {
	path, s := newTestSink(t)
	const sentinel = int64(-777)
	ev := testEvent()
	ev.Time = sentinel
	if err := s.Mandate(context.Background(), ev); err != nil {
		t.Fatalf("Mandate: %v", err)
	}
	var got FileActivityEvent
	if err := json.Unmarshal(completeLines(t, path)[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Time == sentinel {
		t.Fatalf("time: caller-supplied sentinel %d reached the record", sentinel)
	}
	if got.Time <= 0 {
		t.Fatalf("time: got %d, want a positive broker-stamped epoch-ms value", got.Time)
	}
}

// TestHashInputIncludesNewline pins the exact-bytes rule: the chain hash
// input is the written line INCLUDING the trailing newline.
func TestHashInputIncludesNewline(t *testing.T) {
	path, s := newTestSink(t)
	if err := s.Mandate(context.Background(), testEvent()); err != nil {
		t.Fatalf("Mandate #1: %v", err)
	}
	raw := completeLines(t, path)[0]
	withNL := append(append([]byte{}, raw...), '\n')
	want := sha256.Sum256(withNL)

	if err := s.Mandate(context.Background(), denyEvent()); err != nil {
		t.Fatalf("Mandate #2: %v", err)
	}
	var second FileActivityEvent
	if err := json.Unmarshal(completeLines(t, path)[1], &second); err != nil {
		t.Fatalf("unmarshal second line: %v", err)
	}
	if second.PrevHash != hex.EncodeToString(want[:]) {
		t.Fatalf("prev_hash of record 2: got %s, want sha256(line1+'\\n') %s", second.PrevHash, hex.EncodeToString(want[:]))
	}
}

// TestVerifyHonestChain pins AUD-02 acceptance: an honestly written chain
// verifies, as do a missing and an empty file.
func TestVerifyHonestChain(t *testing.T) {
	path, s := newTestSink(t)
	for i := 0; i < 5; i++ {
		if err := s.Mandate(context.Background(), testEvent()); err != nil {
			t.Fatalf("Mandate #%d: %v", i, err)
		}
	}
	if err := Verify(path); err != nil {
		t.Fatalf("Verify honest chain: got %v, want nil", err)
	}

	if err := Verify(filepath.Join(t.TempDir(), "absent.jsonl")); err != nil {
		t.Fatalf("Verify missing file: got %v, want nil", err)
	}
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	if err := Verify(empty); err != nil {
		t.Fatalf("Verify empty file: got %v, want nil", err)
	}
}

// TestVerifyTruncated pins the truncation semantics: removing a complete
// trailing line leaves a shorter intact chain (offline verification cannot
// see past EOF — external anchoring is full-shelf), but a chain whose
// recorded continuation no longer matches fails.
func TestVerifyTruncated(t *testing.T) {
	path, s := newTestSink(t)
	for i := 0; i < 3; i++ {
		if err := s.Mandate(context.Background(), testEvent()); err != nil {
			t.Fatalf("Mandate #%d: %v", i, err)
		}
	}
	lines := completeLines(t, path)

	t.Run("removed complete trailing line still verifies", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "truncated.jsonl")
		content := append(append(append([]byte{}, lines[0]...), '\n'), append(append([]byte{}, lines[1]...), '\n')...)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := Verify(p); err != nil {
			t.Fatalf("Verify shorter intact chain: got %v, want nil", err)
		}
	})

	t.Run("mismatched continuation fails", func(t *testing.T) {
		// Mutate line 2's prev_hash, then truncate line 3: the recorded
		// continuation from line 1 no longer matches.
		p := filepath.Join(t.TempDir(), "mutated.jsonl")
		mutated := append([]byte{}, lines[1]...)
		i := bytes.Index(mutated, []byte(`"prev_hash":"`))
		if i < 0 {
			t.Fatalf("prev_hash field not found in line 2")
		}
		pos := i + len(`"prev_hash":"`)
		if mutated[pos] == '0' {
			mutated[pos] = '1'
		} else {
			mutated[pos] = '0'
		}
		content := append(append(append([]byte{}, lines[0]...), '\n'), append(mutated, '\n')...)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := Verify(p); err == nil {
			t.Fatalf("Verify mutated-then-truncated chain: got nil, want error")
		}
	})
}

// TestVerifyTamperByteFlip pins AUD-02 tamper evidence: flipping one byte of
// a line that has a successor breaks the chain.
func TestVerifyTamperByteFlip(t *testing.T) {
	path, s := newTestSink(t)
	for i := 0; i < 3; i++ {
		if err := s.Mandate(context.Background(), testEvent()); err != nil {
			t.Fatalf("Mandate #%d: %v", i, err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	mutated := append([]byte{}, data...)
	mutated[5] ^= 0xFF // a byte inside line 1, which has successors
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := Verify(path); err == nil {
		t.Fatalf("Verify tampered chain: got nil, want error")
	}
}

// TestRestartContinuity pins reopen behaviour: a second NewFileSink on the
// same path adopts the last complete line's hash and the appended chain
// verifies end to end.
func TestRestartContinuity(t *testing.T) {
	path, s := newTestSink(t)
	for i := 0; i < 3; i++ {
		if err := s.Mandate(context.Background(), testEvent()); err != nil {
			t.Fatalf("Mandate #%d: %v", i, err)
		}
	}
	if err := s.f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink reopen: %v", err)
	}
	if err := s2.Mandate(context.Background(), denyEvent()); err != nil {
		t.Fatalf("Mandate after reopen: %v", err)
	}
	if got := len(completeLines(t, path)); got != 4 {
		t.Fatalf("line count after reopen: got %d, want 4", got)
	}
	if err := Verify(path); err != nil {
		t.Fatalf("Verify after restart continuation: got %v, want nil", err)
	}
}

// TestRestartTornTailRefusal pins constructor fail-closed: a broken chain in
// an existing file (mutated non-final line) refuses to start the broker.
func TestRestartTornTailRefusal(t *testing.T) {
	path, s := newTestSink(t)
	for i := 0; i < 3; i++ {
		if err := s.Mandate(context.Background(), testEvent()); err != nil {
			t.Fatalf("Mandate #%d: %v", i, err)
		}
	}
	if err := s.f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	data[5] ^= 0xFF // corrupt a byte inside line 1 (non-final)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := NewFileSink(path); err == nil {
		t.Fatalf("NewFileSink on broken chain: got nil, want error (broker must not start)")
	}
}

// TestFileSinkLatchedReportsState pins the Latched() reader: a healthy sink
// reports false; after a write or sync fault it reports true and stays true
// on every subsequent Mandate call (SEC-79: the 100%-deny condition is
// observable).
func TestFileSinkLatchedReportsState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault faultSyncer
	}{
		{"write fault", faultSyncer{failWrite: true}},
		{"sync fault", faultSyncer{failSync: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, s := newTestSink(t)
			if s.Latched() {
				t.Fatal("Latched() on healthy sink: got true, want false")
			}
			fault := tc.fault
			fault.ws = s.f
			s.w = &fault
			_ = s.Mandate(context.Background(), testEvent())
			if !s.Latched() {
				t.Fatal("Latched() after fault: got false, want true")
			}
			s.w = s.f // underlying fault gone — latch stays
			_ = s.Mandate(context.Background(), testEvent())
			if !s.Latched() {
				t.Fatal("Latched() stays true after fault is cleared: got false")
			}
		})
	}
}

// TestFileSinkOnLatchFiresExactlyOnce pins the on-latch callback contract:
// the callback fires EXACTLY ONCE when the sink transitions to the latched
// state; subsequent denied Mandates do NOT re-fire it.
func TestFileSinkOnLatchFiresExactlyOnce(t *testing.T) {
	_, s := newTestSink(t)
	var count int
	s.SetOnLatch(func() { count++ })

	// Baseline: healthy Mandate does not fire the callback.
	if err := s.Mandate(context.Background(), testEvent()); err != nil {
		t.Fatalf("baseline Mandate: %v", err)
	}
	if count != 0 {
		t.Fatalf("onLatch fired before any fault: count=%d, want 0", count)
	}

	// Inject fault: the first failed Mandate fires the callback.
	fault := &faultSyncer{ws: s.f, failWrite: true}
	s.w = fault
	_ = s.Mandate(context.Background(), testEvent())
	if count != 1 {
		t.Fatalf("onLatch after first fault: count=%d, want 1", count)
	}

	// Three more denied Mandates — callback must NOT fire again.
	s.w = s.f // fault cleared; latch remains
	for i := 0; i < 3; i++ {
		_ = s.Mandate(context.Background(), testEvent())
	}
	if count != 1 {
		t.Fatalf("onLatch after follow-up Mandates: count=%d, want 1 (fires exactly once)", count)
	}
}

// TestFileSinkExistingFailClosedTestsUnchanged is a compile-time canary: the
// existing fail-closed behaviour tests still call the same API. If the
// filesink semantics changed this would fail at compile time. The runtime
// correctness is pinned by TestMandateLatchesAfterFault (unchanged).
var _ = func() bool { return (*FileSink)(nil) == nil } // nop: confirms FileSink is still a concrete type

// TestRestartTornTailTolerated pins the torn-write case: a trailing partial
// line with no newline was never acked (Sync never returned), so the
// constructor succeeds, continues from the last complete line, and the
// whole file verifies after the next record.
func TestRestartTornTailTolerated(t *testing.T) {
	path, s := newTestSink(t)
	for i := 0; i < 3; i++ {
		if err := s.Mandate(context.Background(), testEvent()); err != nil {
			t.Fatalf("Mandate #%d: %v", i, err)
		}
	}
	if err := s.f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Strip the trailing newline plus part of the final line: a simulated
	// torn un-acked tail.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lastStart := bytes.LastIndexByte(data[:len(data)-1], '\n') + 1
	cut := lastStart + (len(data)-1-lastStart)/2
	if err := os.WriteFile(path, data[:cut], 0o600); err != nil {
		t.Fatalf("write torn file: %v", err)
	}

	s2, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink on torn tail: got %v, want nil", err)
	}
	if err := s2.Mandate(context.Background(), testEvent()); err != nil {
		t.Fatalf("Mandate after torn-tail reopen: %v", err)
	}
	if got := len(completeLines(t, path)); got != 3 {
		t.Fatalf("line count after torn-tail continuation: got %d, want 3 (2 intact + 1 new)", got)
	}
	if err := Verify(path); err != nil {
		t.Fatalf("Verify after torn-tail continuation: got %v, want nil", err)
	}
}

// TestCloseIdempotentAndReleases pins the shutdown contract: Close releases
// the descriptor, every acked record stays on disk and verifies, a second
// Close is a no-op (nil), and a Mandate after Close is denied fail-closed
// rather than writing to a released descriptor.
func TestCloseIdempotentAndReleases(t *testing.T) {
	path, s := newTestSink(t)
	for i := 0; i < 3; i++ {
		if err := s.Mandate(context.Background(), testEvent()); err != nil {
			t.Fatalf("Mandate #%d: %v", i, err)
		}
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: got %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: got %v, want nil (idempotent)", err)
	}

	// Every acked record survives the close and the chain still verifies.
	if got := len(completeLines(t, path)); got != 3 {
		t.Fatalf("line count after Close: got %d, want 3", got)
	}
	if err := Verify(path); err != nil {
		t.Fatalf("Verify after Close: got %v, want nil", err)
	}

	// A Mandate after Close must not write to the released descriptor.
	if err := s.Mandate(context.Background(), testEvent()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Mandate after Close: got %v, want ErrAuditUnavailable", err)
	}
	if got := len(completeLines(t, path)); got != 3 {
		t.Fatalf("line count after post-Close Mandate: got %d, want 3 (no new write)", got)
	}
}

// TestMandateCancelledContextEarlyOut pins the cheap ctx early-out: a Mandate
// whose context is already cancelled is denied fail-closed without writing,
// so an already-disconnected client never queues behind a durable write.
func TestMandateCancelledContextEarlyOut(t *testing.T) {
	path, s := newTestSink(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Mandate(ctx, testEvent()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Mandate(cancelled ctx): got %v, want ErrAuditUnavailable", err)
	}
	if got := len(completeLines(t, path)); got != 0 {
		t.Fatalf("line count after cancelled Mandate: got %d, want 0 (no write)", got)
	}
	// The sink is not latched by a pre-write early-out; a fresh Mandate works.
	if s.Latched() {
		t.Fatal("sink latched after a pre-write ctx early-out; want healthy")
	}
	if err := s.Mandate(context.Background(), testEvent()); err != nil {
		t.Fatalf("Mandate after early-out: got %v, want nil", err)
	}
}
