// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ceilings

import (
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"sync"
	"testing"
	"time"
)

// frozenClock returns a ClockFunc pinned to a fixed instant so the ops
// bucket never refills during accounting tests (no sleeps, no goroutines).
func frozenClock() ClockFunc {
	at := time.Unix(0, 0)
	return func() time.Time { return at }
}

// mustPanic asserts fn panics — the fail-loud contract for broken
// acquire/release pairing (never a silent negative counter).
func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: want panic on broken pairing, got none", name)
		}
	}()
	fn()
}

// TestFDAccounting pins the per-session open-fd ceiling: every acquire up
// to the ceiling succeeds, the next is refused with ErrFDExceeded, one
// release restores exactly one slot, and a release at zero panics
// (LIM-01, NFR-SEC-46).
func TestFDAccounting(t *testing.T) {
	const ceiling = 3
	reg := NewRegistry(Config{
		OpsPerSecond:         1,
		OpsBurst:             1,
		InFlightBytesCeiling: 1,
		FDCeiling:            ceiling,
		Clock:                frozenClock(),
	})
	sess := reg.Session("fd-session")

	for i := 0; i < ceiling; i++ {
		if err := sess.TryAcquireFD(); err != nil {
			t.Fatalf("TryAcquireFD #%d: got %v, want nil", i+1, err)
		}
	}
	if err := sess.TryAcquireFD(); !errors.Is(err, ErrFDExceeded) {
		t.Fatalf("TryAcquireFD over ceiling: got %v, want ErrFDExceeded", err)
	}

	// One release frees exactly one slot.
	sess.ReleaseFD()
	if err := sess.TryAcquireFD(); err != nil {
		t.Fatalf("TryAcquireFD after ReleaseFD: got %v, want nil", err)
	}
	if err := sess.TryAcquireFD(); !errors.Is(err, ErrFDExceeded) {
		t.Fatalf("TryAcquireFD refilled slot: got %v, want ErrFDExceeded", err)
	}

	// Drain to zero, then a further release is a broken pairing — panic.
	for i := 0; i < ceiling; i++ {
		sess.ReleaseFD()
	}
	mustPanic(t, "ReleaseFD at zero", func() { sess.ReleaseFD() })
}

// TestGaugeRoundTrip pins the in-flight bytes gauge: acquire+release
// returns full capacity, an over-ceiling acquire is refused with
// ErrBytesExceeded and reserves nothing, negative sizes are refused, the
// overflow guard holds for values near math.MaxInt64, and a release beyond
// current panics (LIM-01, NFR-SEC-46).
func TestGaugeRoundTrip(t *testing.T) {
	const ceiling = int64(1024)
	reg := NewRegistry(Config{
		OpsPerSecond:         1,
		OpsBurst:             1,
		InFlightBytesCeiling: ceiling,
		FDCeiling:            1,
		Clock:                frozenClock(),
	})
	sess := reg.Session("gauge-session")

	// Round trip: acquire then release restores full capacity.
	if err := sess.AcquireBytes(512); err != nil {
		t.Fatalf("AcquireBytes(512): got %v, want nil", err)
	}
	sess.ReleaseBytes(512)
	if err := sess.AcquireBytes(ceiling); err != nil {
		t.Fatalf("AcquireBytes(ceiling) after round trip: got %v, want nil", err)
	}

	// Full gauge: one more byte is refused, and the refusal reserves nothing.
	if err := sess.AcquireBytes(1); !errors.Is(err, ErrBytesExceeded) {
		t.Fatalf("AcquireBytes(1) on full gauge: got %v, want ErrBytesExceeded", err)
	}
	sess.ReleaseBytes(ceiling)
	if err := sess.AcquireBytes(ceiling); err != nil {
		t.Fatalf("AcquireBytes(ceiling) after failed acquire: got %v, want nil", err)
	}
	sess.ReleaseBytes(ceiling)

	// Negative size is a protocol error, refused with the same sentinel.
	if err := sess.AcquireBytes(-1); !errors.Is(err, ErrBytesExceeded) {
		t.Fatalf("AcquireBytes(-1): got %v, want ErrBytesExceeded", err)
	}

	// Overflow guard: with one byte in flight, a MaxInt64 request must be
	// refused, not wrapped into an accept (T-06-03).
	if err := sess.AcquireBytes(1); err != nil {
		t.Fatalf("AcquireBytes(1): got %v, want nil", err)
	}
	if err := sess.AcquireBytes(math.MaxInt64); !errors.Is(err, ErrBytesExceeded) {
		t.Fatalf("AcquireBytes(MaxInt64) with bytes in flight: got %v, want ErrBytesExceeded", err)
	}
	sess.ReleaseBytes(1)

	// Release beyond current is a broken pairing — panic.
	mustPanic(t, "ReleaseBytes beyond current", func() { sess.ReleaseBytes(1) })
}

// TestTinyBucketThrottlesAndRefills pins the smallest operator-tunable
// bucket (1 ops/s, 1-token burst) deterministically: the first immediate op
// is admitted, the second is refused with ErrThrottleExceeded, and a
// one-second clock advance re-admits exactly one op — then refuses again
// (LIM-01, NFR-SEC-46). No sleeps: the clock is an injected closure.
func TestTinyBucketThrottlesAndRefills(t *testing.T) {
	now := time.Unix(0, 0)
	reg := NewRegistry(Config{
		OpsPerSecond:         1,
		OpsBurst:             1,
		InFlightBytesCeiling: 1,
		FDCeiling:            1,
		Clock:                func() time.Time { return now },
	})
	sess := reg.Session("tiny-bucket")

	if err := sess.TryConsumeOp(); err != nil {
		t.Fatalf("first TryConsumeOp on full 1/1 bucket: got %v, want nil", err)
	}
	if err := sess.TryConsumeOp(); !errors.Is(err, ErrThrottleExceeded) {
		t.Fatalf("second immediate TryConsumeOp: got %v, want ErrThrottleExceeded", err)
	}

	// One second at 1 ops/s refills exactly one token.
	now = now.Add(time.Second)
	if err := sess.TryConsumeOp(); err != nil {
		t.Fatalf("TryConsumeOp after 1s refill: got %v, want nil", err)
	}
	if err := sess.TryConsumeOp(); !errors.Is(err, ErrThrottleExceeded) {
		t.Fatalf("TryConsumeOp after refill token spent: got %v, want ErrThrottleExceeded", err)
	}
}

// TestNilClockPanics pins the clock-seam purity contract: this package
// never reads the wall clock itself, so a Registry constructed without an
// injected clock is a wiring error and fails loud, never a silent fallback.
func TestNilClockPanics(t *testing.T) {
	mustPanic(t, "NewRegistry with nil Clock", func() {
		NewRegistry(Config{
			OpsPerSecond:         1,
			OpsBurst:             1,
			InFlightBytesCeiling: 1,
			FDCeiling:            1,
		})
	})
}

// TestNewRegistryFailLoudOnBadCeilings pins the single-place "callers
// validate" contract: a real (enforcing) Registry refuses a non-positive
// rate, a sub-one burst, or a negative byte/fd ceiling with a panic, so a
// misconfigured limiter is a loud wiring failure rather than a silent
// permanent throttle (rate=0 would drain once then deny forever).
func TestNewRegistryFailLoudOnBadCeilings(t *testing.T) {
	base := func() Config {
		return Config{
			OpsPerSecond:         1,
			OpsBurst:             1,
			InFlightBytesCeiling: 1,
			FDCeiling:            1,
			Clock:                frozenClock(),
		}
	}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"zero_rate", func(c *Config) { c.OpsPerSecond = 0 }},
		{"negative_rate", func(c *Config) { c.OpsPerSecond = -1 }},
		{"zero_burst", func(c *Config) { c.OpsBurst = 0 }},
		{"fractional_burst", func(c *Config) { c.OpsBurst = 0.5 }},
		{"negative_bytes_ceiling", func(c *Config) { c.InFlightBytesCeiling = -1 }},
		{"negative_fd_ceiling", func(c *Config) { c.FDCeiling = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			mustPanic(t, "NewRegistry "+tc.name, func() {
				NewRegistry(cfg)
			})
		})
	}

	// A fully valid enforcing config must NOT panic.
	if reg := NewRegistry(base()); reg == nil {
		t.Fatal("NewRegistry with a valid config returned nil")
	}
}

// TestFixedCeilingDefaults pins the fixed-this-phase byte and fd ceiling
// defaults to their documented values and confirms a Registry built from
// them passes the fail-loud validation (the defaults are servable, never a
// silent permanent throttle).
func TestFixedCeilingDefaults(t *testing.T) {
	if DefaultInFlightBytesCeiling != 1<<31 {
		t.Errorf("DefaultInFlightBytesCeiling: got %d, want %d (2 GiB)", DefaultInFlightBytesCeiling, int64(1)<<31)
	}
	if DefaultFDCeiling != 256 {
		t.Errorf("DefaultFDCeiling: got %d, want 256", DefaultFDCeiling)
	}
	reg := NewRegistry(Config{
		OpsPerSecond:         1,
		OpsBurst:             1,
		InFlightBytesCeiling: DefaultInFlightBytesCeiling,
		FDCeiling:            DefaultFDCeiling,
		Clock:                frozenClock(),
	})
	if reg == nil {
		t.Fatal("NewRegistry with the fixed defaults returned nil")
	}
}

// TestNopRegistryAdmitsEverything pins the non-enforcing constructor for
// downstream wiring: ops, bytes, and fd admission all succeed repeatedly —
// it must never throttle a phase 8-11 test harness.
func TestNopRegistryAdmitsEverything(t *testing.T) {
	sess := NewNopRegistry().Session("nop-session")
	for i := 0; i < 1000; i++ {
		if err := sess.TryConsumeOp(); err != nil {
			t.Fatalf("nop TryConsumeOp #%d: got %v, want nil", i+1, err)
		}
		if err := sess.AcquireBytes(1 << 30); err != nil {
			t.Fatalf("nop AcquireBytes #%d: got %v, want nil", i+1, err)
		}
		sess.ReleaseBytes(1 << 30)
		if err := sess.TryAcquireFD(); err != nil {
			t.Fatalf("nop TryAcquireFD #%d: got %v, want nil", i+1, err)
		}
		sess.ReleaseFD()
	}
}

// TestSizeLimitsParity asserts DefaultSizeLimits matches the vendored
// file-ops contract defaults byte-for-byte, and that the broker file-size
// ceiling has no constant default (deployment policy, zero means unset).
// When the vendored contract is absent on this branch the test skips
// LOUDLY — never a silent pass (LIM-02, NFR-SEC-46).
func TestSizeLimitsParity(t *testing.T) {
	const contractPath = "../../contracts/storage/file-ops.schema.json"
	data, err := os.ReadFile(contractPath)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("SKIPPING PARITY GATE: vendored contract %s not on this branch; "+
			"parity gate becomes live when the CI-gates PR merges", contractPath)
	}
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}

	var schema struct {
		Defs struct {
			SizeLimits struct {
				Properties struct {
					RPCMessageCeiling struct {
						Default int64 `json:"default"`
					} `json:"rpc_message_ceiling_bytes"`
					ReadChunkDefault struct {
						Default int64 `json:"default"`
					} `json:"read_chunk_default_bytes"`
					VFSCacheMax struct {
						Default int64 `json:"default"`
					} `json:"vfs_cache_max_size_bytes"`
				} `json:"properties"`
			} `json:"SizeLimits"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("unmarshal %s: %v", contractPath, err)
	}

	got := DefaultSizeLimits()
	props := schema.Defs.SizeLimits.Properties
	if got.RPCMessageCeilingBytes != props.RPCMessageCeiling.Default {
		t.Errorf("RPCMessageCeilingBytes: got %d, want %d", got.RPCMessageCeilingBytes, props.RPCMessageCeiling.Default)
	}
	if got.ReadChunkDefaultBytes != props.ReadChunkDefault.Default {
		t.Errorf("ReadChunkDefaultBytes: got %d, want %d", got.ReadChunkDefaultBytes, props.ReadChunkDefault.Default)
	}
	if got.VFSCacheMaxSizeBytes != props.VFSCacheMax.Default {
		t.Errorf("VFSCacheMaxSizeBytes: got %d, want %d", got.VFSCacheMaxSizeBytes, props.VFSCacheMax.Default)
	}
	// No contract default for the broker file-size ceiling — zero means
	// unset, a deployment must configure it explicitly.
	if got.BrokerMaxFileSizeBytes != 0 {
		t.Errorf("BrokerMaxFileSizeBytes: got %d, want 0 (unset policy)", got.BrokerMaxFileSizeBytes)
	}
}

// TestCheckDeclaredSize pins the pre-buffer size gate (NFR-SEC-78): a declared
// size strictly above the ceiling is rejected with ErrSizeExceeded before any
// body byte is read; a declared size AT the ceiling and one strictly UNDER pass
// (nil); and a declared 0 (unknown length) is accepted on purpose — the
// in-flight gauge bounds unknown-length bodies per chunk. The comparison is a
// direct >, never a subtraction, so a near-MaxInt64 declared size against a
// modest ceiling still rejects without wrapping.
func TestCheckDeclaredSize(t *testing.T) {
	const ceiling int64 = 1 << 20 // 1 MiB
	for _, tc := range []struct {
		name     string
		declared int64
		ceiling  int64
		wantErr  bool
	}{
		{"over_ceiling_rejected", ceiling + 1, ceiling, true},
		{"at_ceiling_accepted", ceiling, ceiling, false},
		{"under_ceiling_accepted", ceiling - 1, ceiling, false},
		{"zero_unknown_length_accepted", 0, ceiling, false},
		{"max_int64_over_modest_ceiling_no_wrap", math.MaxInt64, ceiling, true},
		{"max_int64_at_max_ceiling_accepted", math.MaxInt64, math.MaxInt64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckDeclaredSize(tc.declared, tc.ceiling)
			if tc.wantErr {
				if !errors.Is(err, ErrSizeExceeded) {
					t.Fatalf("CheckDeclaredSize(%d, %d) = %v, want ErrSizeExceeded", tc.declared, tc.ceiling, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckDeclaredSize(%d, %d) = %v, want nil", tc.declared, tc.ceiling, err)
			}
		})
	}
}

// TestRegistrySessionReuseAndRelease pins the Registry session lifecycle: the
// same key always yields the SAME *Session (so its accrued limiter state
// persists across lookups), Release drops the entry so a later Session(key)
// hands back a FRESH session with full capacity, and Release of an unknown key
// is a harmless no-op. The re-acquire branch (a key looked up twice returns the
// cached pointer) and Release are exercised end to end.
func TestRegistrySessionReuseAndRelease(t *testing.T) {
	reg := NewRegistry(Config{
		OpsPerSecond:         1,
		OpsBurst:             1, // burst of exactly 1 so the bucket is observably drained
		InFlightBytesCeiling: 1 << 20,
		FDCeiling:            8,
		Clock:                frozenClock(), // frozen: a drained bucket never refills
	})

	// First lookup creates the session; second lookup returns the SAME pointer.
	s1 := reg.Session("sess-a")
	s2 := reg.Session("sess-a")
	if s1 != s2 {
		t.Fatalf("Session(\"sess-a\") returned different pointers on re-acquire")
	}

	// Drain the one ops token on the shared session.
	if err := s1.TryConsumeOp(); err != nil {
		t.Fatalf("first TryConsumeOp: %v", err)
	}
	// The cached session is drained (frozen clock -> no refill): the second
	// pointer sees the same empty bucket.
	if err := s2.TryConsumeOp(); !errors.Is(err, ErrThrottleExceeded) {
		t.Fatalf("cached session bucket not shared: got %v, want ErrThrottleExceeded", err)
	}

	// Release drops the entry; a later lookup hands back a FRESH session with a
	// full bucket.
	reg.Release("sess-a")
	s3 := reg.Session("sess-a")
	if s3 == s1 {
		t.Fatalf("Session after Release returned the stale pointer, want a fresh session")
	}
	if err := s3.TryConsumeOp(); err != nil {
		t.Fatalf("fresh session after Release: TryConsumeOp = %v, want nil (full bucket)", err)
	}

	// Release of an unknown key is a harmless no-op (must not panic).
	reg.Release("never-created")
}

// TestRegistryConcurrentFirstUse pins the double-checked creation under the
// write lock: many goroutines racing on the SAME never-seen key must all get
// the exact same *Session — exactly one create wins and the losers take the
// inner re-check branch (the entry already exists when they grab the write
// lock). Run under -race this also proves the map access is correctly guarded.
func TestRegistryConcurrentFirstUse(t *testing.T) {
	reg := NewRegistry(Config{
		OpsPerSecond:         1,
		OpsBurst:             1,
		InFlightBytesCeiling: 1 << 20,
		FDCeiling:            8,
		Clock:                frozenClock(),
	})

	const goroutines = 64
	got := make([]*Session, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // release all goroutines at once to maximize contention
			got[idx] = reg.Session("hot-key")
		}(i)
	}
	close(start)
	wg.Wait()

	// Every goroutine must observe the identical pointer — only one create won.
	first := got[0]
	if first == nil {
		t.Fatal("Session returned nil")
	}
	for i, s := range got {
		if s != first {
			t.Fatalf("goroutine %d got a different *Session; the double-checked create admitted more than one", i)
		}
	}
}
