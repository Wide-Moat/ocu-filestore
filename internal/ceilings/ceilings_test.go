// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ceilings

import (
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
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
