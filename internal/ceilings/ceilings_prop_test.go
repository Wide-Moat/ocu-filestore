// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ceilings

import (
	"errors"
	"io"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// instrumentedReader fails the property on any Read: it stands in for the
// inbound body on the reject path, where not a single byte may be read.
type instrumentedReader struct {
	rt *rapid.T
}

func (r *instrumentedReader) Read(p []byte) (int, error) {
	r.rt.Fatal("Read called on instrumentedReader — body was not rejected pre-buffer")
	return 0, io.EOF
}

// gatedRead mimics the phase-8 consumer protocol: the pre-buffer check
// gates every body read. A reject returns before the reader is touched.
func gatedRead(r io.Reader, declared, ceiling int64) error {
	if err := CheckDeclaredSize(declared, ceiling); err != nil {
		return err
	}
	var buf [1]byte
	_, _ = r.Read(buf[:])
	return nil
}

// TestPropPreBuffer asserts that any declared size strictly above the
// ceiling is rejected with ErrSizeExceeded and zero Read calls — the
// instrumented reader fails the property if a single body byte is read
// (LIM-02, NFR-SEC-78).
func TestPropPreBuffer(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		ceiling := rapid.Int64Range(1, 1<<40).Draw(rt, "ceiling")
		declared := ceiling + rapid.Int64Range(1, 1<<20).Draw(rt, "excess")
		if declared < ceiling {
			// int64 wrap guard — unreachable at these ranges, kept so the
			// generator bounds can widen without re-deriving safety.
			return
		}

		err := gatedRead(&instrumentedReader{rt: rt}, declared, ceiling)
		if !errors.Is(err, ErrSizeExceeded) {
			rt.Fatalf("gatedRead(declared=%d, ceiling=%d): got %v, want ErrSizeExceeded", declared, ceiling, err)
		}
	})
}

// TestPropIsolation asserts that fully exhausting session A's ops, bytes,
// and fd budgets leaves a fresh session B at full capacity on all three
// limiters. Exhaustion is proven non-vacuous: each of A's limiters is
// driven to an actual over-ceiling refusal before B is consulted
// (LIM-01, NFR-SEC-46).
func TestPropIsolation(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		opsBurst := rapid.IntRange(1, 16).Draw(rt, "ops_burst")
		bytesCeiling := rapid.Int64Range(1, 1<<20).Draw(rt, "bytes_ceiling")
		fdCeiling := rapid.IntRange(1, 16).Draw(rt, "fd_ceiling")

		// Frozen clock: the bucket never refills, so exhaustion sticks.
		frozen := func() time.Time { return time.Unix(0, 0) }
		reg := NewRegistry(Config{
			OpsPerSecond:         rapid.Float64Range(0.1, 100).Draw(rt, "rate"),
			OpsBurst:             float64(opsBurst),
			InFlightBytesCeiling: bytesCeiling,
			FDCeiling:            int32(fdCeiling),
			Clock:                frozen,
		})

		keyA := SessionKey(rapid.String().Draw(rt, "key_a"))
		keyB := keyA + "/peer" // distinct by construction

		sA := reg.Session(keyA)

		// Exhaust A's ops bucket and prove it refuses.
		for i := 0; i < opsBurst; i++ {
			if err := sA.TryConsumeOp(); err != nil {
				rt.Fatalf("TryConsumeOp #%d on A: got %v, want nil", i+1, err)
			}
		}
		if err := sA.TryConsumeOp(); !errors.Is(err, ErrThrottleExceeded) {
			rt.Fatalf("TryConsumeOp on drained A: got %v, want ErrThrottleExceeded", err)
		}

		// Fill A's byte gauge and prove it refuses.
		if err := sA.AcquireBytes(bytesCeiling); err != nil {
			rt.Fatalf("AcquireBytes(ceiling) on A: got %v, want nil", err)
		}
		if err := sA.AcquireBytes(1); !errors.Is(err, ErrBytesExceeded) {
			rt.Fatalf("AcquireBytes(1) on full A: got %v, want ErrBytesExceeded", err)
		}

		// Fill A's fd ceiling and prove it refuses.
		for i := 0; i < fdCeiling; i++ {
			if err := sA.TryAcquireFD(); err != nil {
				rt.Fatalf("TryAcquireFD #%d on A: got %v, want nil", i+1, err)
			}
		}
		if err := sA.TryAcquireFD(); !errors.Is(err, ErrFDExceeded) {
			rt.Fatalf("TryAcquireFD on full A: got %v, want ErrFDExceeded", err)
		}

		// Session B must hold its full capacity on all three limiters.
		sB := reg.Session(keyB)
		if err := sB.TryConsumeOp(); err != nil {
			rt.Fatalf("TryConsumeOp on B after A exhausted: got %v, want nil", err)
		}
		if err := sB.AcquireBytes(1); err != nil {
			rt.Fatalf("AcquireBytes(1) on B after A exhausted: got %v, want nil", err)
		}
		if err := sB.TryAcquireFD(); err != nil {
			rt.Fatalf("TryAcquireFD on B after A exhausted: got %v, want nil", err)
		}
	})
}

// TestPropBucketNeverOverAdmits drives a session's ops bucket through an
// arbitrary sequence of non-negative fake-clock advances and consume
// attempts, mirroring every step in a reference counter that starts full,
// refills elapsed*rate capped at burst, and consumes when at least one
// token is present. The bucket must never admit more operations than the
// reference — i.e. never more than burst + rate*elapsed in any window
// (LIM-01, NFR-SEC-46). No sleeps, no goroutines: the clock is a closure.
func TestPropBucketNeverOverAdmits(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		rate := rapid.Float64Range(0.1, 1000).Draw(rt, "rate")
		burst := rapid.Float64Range(1, 100).Draw(rt, "burst")

		var fakeNow int64 // nanoseconds; never decreases
		clock := func() time.Time { return time.Unix(0, fakeNow) }

		reg := NewRegistry(Config{
			OpsPerSecond:         rate,
			OpsBurst:             burst,
			InFlightBytesCeiling: 1,
			FDCeiling:            1,
			Clock:                clock,
		})
		sess := reg.Session("bucket-session")

		refTokens := burst // reference starts full, like the bucket
		refSuccesses := 0
		actualSuccesses := 0

		steps := rapid.IntRange(1, 200).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			advanceNs := rapid.Int64Range(0, int64(1e9/rate*2)).Draw(rt, "adv")
			fakeNow += advanceNs

			// Reference refill: elapsed*rate, capped at burst.
			elapsed := float64(advanceNs) / 1e9
			refTokens += elapsed * rate
			if refTokens > burst {
				refTokens = burst
			}
			// Reference consume.
			if refTokens >= 1 {
				refTokens--
				refSuccesses++
			}

			if err := sess.TryConsumeOp(); err == nil {
				actualSuccesses++
			} else if !errors.Is(err, ErrThrottleExceeded) {
				rt.Fatalf("TryConsumeOp step %d: got %v, want nil or ErrThrottleExceeded", i, err)
			}
		}

		if actualSuccesses > refSuccesses {
			rt.Fatalf("bucket over-admitted: actual=%d ref=%d (rate=%g burst=%g steps=%d)",
				actualSuccesses, refSuccesses, rate, burst, steps)
		}
	})
}
