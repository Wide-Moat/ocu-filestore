// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"pgregory.net/rapid"
)

// reassemble joins newline-terminated lines back into a file body, each line
// followed by its newline, in the given order. It is the inverse of
// completeLines for a clean (untorn) chain.
func reassemble(lines [][]byte) []byte {
	var buf bytes.Buffer
	for _, ln := range lines {
		buf.Write(ln)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// TestVerifyReorderDetected pins AUD-02 against an event-reorder attack — a
// class distinct from the in-place byte-flip TestVerifyTamperByteFlip and
// TestPropChainTamperDetected already cover. Two COMPLETE acked lines are
// swapped, preserving every byte and changing only their order; because each
// record's prev_hash links to the exact bytes of its predecessor, a reorder
// breaks the linkage at the first swapped position even though no byte was
// altered. The property draws arbitrary honest chains of >=3 events and swaps
// an arbitrary pair of non-final lines.
//
// Non-vacuity per draw: the two swapped lines are asserted byte-distinct (so
// the swap is a real reorder, not a no-op on two identical lines), and the
// unswapped control reassembly is asserted to Verify nil in the same draw —
// proving the harness reassembly is faithful and the rejection is caused by
// the reorder alone, not by reassembly corruption.
func TestVerifyReorderDetected(t *testing.T) {
	reorders := 0
	rapid.Check(t, func(rt *rapid.T) {
		events := rapid.SliceOfN(rapid.Custom(arbitraryEvent), 3, 8).Draw(rt, "events")
		path := writeChain(rt, t, events)

		data, err := os.ReadFile(path)
		if err != nil {
			rt.Fatalf("ReadFile: %v", err)
		}
		var lines [][]byte
		rest := data
		for {
			k := bytes.IndexByte(rest, '\n')
			if k < 0 {
				break
			}
			lines = append(lines, append([]byte{}, rest[:k]...))
			rest = rest[k+1:]
		}
		if len(lines) != len(events) {
			rt.Fatalf("line count: got %d, want %d", len(lines), len(events))
		}

		// Control: the faithful reassembly of the unswapped lines verifies.
		ctrl := filepath.Join(t.TempDir(), "control.jsonl")
		if err := os.WriteFile(ctrl, reassemble(lines), 0o600); err != nil {
			rt.Fatalf("write control: %v", err)
		}
		if err := Verify(ctrl); err != nil {
			rt.Fatalf("control reassembly failed to verify (harness bug, not a reorder): %v", err)
		}

		// Pick two distinct non-final indices to swap. The final line is the
		// unanchored chain head no successor records, so swapping it out of the
		// tail would be the truncate-then-append class, not a detectable
		// reorder; keep both swapped lines strictly before the last.
		i := rapid.IntRange(0, len(lines)-2).Draw(rt, "i")
		j := rapid.IntRange(0, len(lines)-2).Draw(rt, "j")
		if i == j || bytes.Equal(lines[i], lines[j]) {
			// Either not a swap, or the two lines are byte-identical so the
			// swap is a genuine no-op; skip — the next draw retries. This is
			// not a vacuous pass: the reorders counter only increments on a
			// real, byte-distinct swap below.
			return
		}

		swapped := make([][]byte, len(lines))
		copy(swapped, lines)
		swapped[i], swapped[j] = swapped[j], swapped[i]

		p := filepath.Join(t.TempDir(), "reordered.jsonl")
		if err := os.WriteFile(p, reassemble(swapped), 0o600); err != nil {
			rt.Fatalf("write reordered: %v", err)
		}
		if err := Verify(p); err == nil {
			rt.Fatalf("Verify accepted a chain with lines %d and %d swapped", i, j)
		}
		reorders++
	})
	if reorders == 0 {
		t.Fatal("vacuous run: no real (byte-distinct, distinct-index) reorder was ever exercised")
	}
}

// TestVerifyReorderDetectedExplicit is a deterministic companion to the
// property: a hand-built 3-record chain with its first two lines swapped is
// rejected, and the unswapped control verifies. It guarantees at least one
// byte-distinct reorder is always exercised even if the property's draws were
// unlucky, and names a broken line in the rejection.
func TestVerifyReorderDetectedExplicit(t *testing.T) {
	path, s := newTestSink(t)
	// Two distinct event shapes so adjacent lines differ byte-for-byte.
	for i := 0; i < 3; i++ {
		ev := testEvent()
		if i == 1 {
			ev = denyEvent()
		}
		if err := s.Mandate(context.Background(), ev); err != nil {
			t.Fatalf("Mandate #%d: %v", i, err)
		}
	}
	lines := completeLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("line count: got %d, want 3", len(lines))
	}
	if bytes.Equal(lines[0], lines[1]) {
		t.Fatal("setup: lines 0 and 1 are byte-identical; the swap would be a no-op")
	}

	// Control: faithful reassembly verifies.
	ctrl := filepath.Join(t.TempDir(), "control.jsonl")
	if err := os.WriteFile(ctrl, reassemble(lines), 0o600); err != nil {
		t.Fatalf("write control: %v", err)
	}
	if err := Verify(ctrl); err != nil {
		t.Fatalf("control reassembly failed to verify: %v", err)
	}

	// Swap the first two complete lines (both non-final).
	swapped := [][]byte{lines[1], lines[0], lines[2]}
	p := filepath.Join(t.TempDir(), "reordered.jsonl")
	if err := os.WriteFile(p, reassemble(swapped), 0o600); err != nil {
		t.Fatalf("write reordered: %v", err)
	}
	err := Verify(p)
	if err == nil {
		t.Fatal("Verify accepted a reordered chain")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("line")) {
		t.Fatalf("reorder rejection must name a broken line: %v", err)
	}
}

// TestConcurrentAppendUnderRace exercises the FileSink locking surface the
// race detector has never seen: Mandate, Latched, and Close all serialize on
// s.mu, and Mandate drops and re-acquires the lock around the onLatch callback
// — a non-trivial hand-off where a data race or a lost prevLineHash update
// could hide. N goroutines append to one shared sink concurrently; after they
// join, EXACTLY N complete lines must exist and the chain must verify, proving
// prevLineHash advanced atomically under contention with no torn or duplicated
// link. A Latched() reader races the writers to exercise the read-lock path.
//
// Non-vacuity: N > 1 and the post-run line count is asserted == N (not <= N),
// so a lost write or an interleaved torn line fails rather than passing
// silently. Meaningful only under -race; run via `go test -race`.
func TestConcurrentAppendUnderRace(t *testing.T) {
	const n = 16
	path, s := newTestSink(t)

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = s.Mandate(context.Background(), testEvent())
		}(i)
	}
	// A concurrent reader to exercise the Latched() read-lock against the
	// writers; its result is not asserted (the sink is healthy), only that the
	// race detector sees the read/write interleave.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			_ = s.Latched()
		}
	}()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Mandate #%d: got %v, want nil", i, err)
		}
	}
	if got := len(completeLines(t, path)); got != n {
		t.Fatalf("line count after %d concurrent appends: got %d, want exactly %d (a lost or torn write)", n, got, n)
	}
	if err := Verify(path); err != nil {
		t.Fatalf("Verify after concurrent appends: got %v, want nil (chain link torn under contention)", err)
	}
}
