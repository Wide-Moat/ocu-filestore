// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/ceilings"
	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
)

// This file is the broker-side proof of the SC2 throttle property: a streaming
// fileUpload that is REFUSED by the per-session ops/s token bucket must (a)
// signal the refusal unambiguously in the 0x02 end-stream trailer (an HTTP-200
// stream whose trailer carries connectError code resource_exhausted, NEVER an
// empty/success trailer a client could mistake for success), (b) stage ZERO
// bytes broker-side (no partial stage, no torn object), and (c) lose nothing —
// a retry of the same object after the bucket refills lands byte-identical
// (the SEC-46 retry-no-loss property, observed from the broker side).
//
// Everything under test is REAL: the real ceilings token bucket (no canned
// TryConsumeOp), the real local-volume engine's temp+rename atomicity (no
// in-memory fake), and the real serveStreaming STAGE-0 -> handleFileUpload
// path driven through dispatcher.ServeHTTP. The only test seams are a fake
// clock (so the bucket refill is deterministic, no sleeps) and the two named
// adapters below that bridge the real packages onto the consumer-side seams —
// the same bridges the wiring layer ships, including the throttle sentinel
// remap that lets denyClassForErr classify the refusal as a throttle.

// realCeilingsRegistryAdapter bridges *ceilings.Registry onto the consumer
// CeilingsRegistry seam (string key -> ceilings.SessionKey), mirroring the
// wiring-layer ceilingsAdapter.
type realCeilingsRegistryAdapter struct{ r *ceilings.Registry }

func (a realCeilingsRegistryAdapter) Session(key string) CeilingsSession {
	return realCeilingsSessionAdapter{s: a.r.Session(ceilings.SessionKey(key))}
}
func (a realCeilingsRegistryAdapter) Release(key string) { a.r.Release(ceilings.SessionKey(key)) }

// realCeilingsSessionAdapter remaps the real per-session ceilings sentinels
// onto the southface seam mirrors so denyClassForErr classifies a throttle as
// a throttle (resource_exhausted). This is the same remap the wiring layer's
// ceilingsSessionAdapter performs; without it the raw ceilings sentinel would
// fall through to the internal class.
type realCeilingsSessionAdapter struct{ s *ceilings.Session }

func remapCeilingsErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ceilings.ErrThrottleExceeded):
		return ErrThrottleExceeded
	case errors.Is(err, ceilings.ErrBytesExceeded):
		return ErrBytesExceeded
	case errors.Is(err, ceilings.ErrFDExceeded):
		return ErrFDExceeded
	default:
		return err
	}
}

func (a realCeilingsSessionAdapter) TryConsumeOp() error { return remapCeilingsErr(a.s.TryConsumeOp()) }
func (a realCeilingsSessionAdapter) AcquireBytes(n int64) error {
	return remapCeilingsErr(a.s.AcquireBytes(n))
}
func (a realCeilingsSessionAdapter) ReleaseBytes(n int64) { a.s.ReleaseBytes(n) }
func (a realCeilingsSessionAdapter) TryAcquireFD() error  { return remapCeilingsErr(a.s.TryAcquireFD()) }
func (a realCeilingsSessionAdapter) ReleaseFD()           { a.s.ReleaseFD() }

// realEngineAdapter bridges the real objectstore.Engine (named ScopeID) onto
// the southface.Engine seam (string scope), mirroring the wiring-layer
// engineAdapter so the upload path drives the engine's genuine temp+rename
// atomic commit.
type realEngineAdapter struct{ e objectstore.Engine }

func toSFFileInfo(fi objectstore.FileInfo) FileInfo {
	return FileInfo{Name: fi.Name, Size: fi.Size, ModTime: fi.ModTime, IsDir: fi.IsDir}
}

func (a realEngineAdapter) List(ctx context.Context, scope, path string) ([]FileInfo, error) {
	in, err := a.e.List(ctx, objectstore.ScopeID(scope), path)
	if err != nil {
		return nil, err
	}
	out := make([]FileInfo, len(in))
	for i, fi := range in {
		out[i] = toSFFileInfo(fi)
	}
	return out, nil
}
func (a realEngineAdapter) Stat(ctx context.Context, scope, path string) (FileInfo, error) {
	fi, err := a.e.Stat(ctx, objectstore.ScopeID(scope), path)
	if err != nil {
		return FileInfo{}, err
	}
	return toSFFileInfo(fi), nil
}
func (a realEngineAdapter) MakeDir(ctx context.Context, scope, path string) error {
	return a.e.MakeDir(ctx, objectstore.ScopeID(scope), path)
}
func (a realEngineAdapter) MoveDir(ctx context.Context, scope, src, dst string, overwrite bool) error {
	return a.e.MoveDir(ctx, objectstore.ScopeID(scope), src, dst, overwrite)
}
func (a realEngineAdapter) RemoveDir(ctx context.Context, scope, path string) error {
	return a.e.RemoveDir(ctx, objectstore.ScopeID(scope), path)
}
func (a realEngineAdapter) CopyFile(ctx context.Context, scope, src, dst string, overwrite bool) error {
	return a.e.CopyFile(ctx, objectstore.ScopeID(scope), src, dst, overwrite)
}
func (a realEngineAdapter) MoveFile(ctx context.Context, scope, src, dst string, overwrite bool) error {
	return a.e.MoveFile(ctx, objectstore.ScopeID(scope), src, dst, overwrite)
}
func (a realEngineAdapter) RemoveFile(ctx context.Context, scope, path string) error {
	return a.e.RemoveFile(ctx, objectstore.ScopeID(scope), path)
}
func (a realEngineAdapter) ReadRange(ctx context.Context, scope, path string, offset, length int64, w io.Writer) error {
	return a.e.ReadRange(ctx, objectstore.ScopeID(scope), path, offset, length, w)
}
func (a realEngineAdapter) WriteStream(ctx context.Context, scope, path string, r io.Reader, overwrite bool) error {
	return a.e.WriteStream(ctx, objectstore.ScopeID(scope), path, r, overwrite)
}

var (
	_ CeilingsRegistry = realCeilingsRegistryAdapter{}
	_ CeilingsSession  = realCeilingsSessionAdapter{}
	_ Engine           = realEngineAdapter{}
)

// fakeClock is a manually-advanced clock for the token bucket. The bucket
// refills from the elapsed wall interval; freezing the clock during the burst
// keeps the refused tokens refused, and a single Advance refills it for the
// retry — no sleeps, no tickers, fully deterministic.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// objectAbsent reports whether no object is staged at the engine-relative path
// in the scope's workspace. A successful 1-byte read means bytes are present;
// any read error means nothing is staged (a refused/absent object).
func objectAbsent(d *dispatcher, scope, engRel string) bool {
	var sink bytes.Buffer
	err := d.engine.ReadRange(context.Background(), scope, engRel, 0, 1, &sink)
	return err != nil
}

// readStaged returns the full staged bytes at the engine-relative path.
func readStaged(t *testing.T, d *dispatcher, scope, engRel string, n int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := d.engine.ReadRange(context.Background(), scope, engRel, 0, n, &buf); err != nil {
		t.Fatalf("readStaged %q: %v", engRel, err)
	}
	return buf.Bytes()
}

// TestUploadThrottleAtomicAndSignalled is the SC2 broker-side proof. A tight
// per-session token bucket (2 ops/s, burst 2) is hit with a 6-upload burst on
// one channel scope. The first two consume the burst and commit; uploads 3..6
// are throttled at serveStreaming STAGE-0. The test proves, for every throttled
// upload:
//
//   - the stream is HTTP 200 and the 0x02 trailer carries connectError code
//     resource_exhausted — NEVER an empty/success trailer (a client cannot
//     mistake the refusal for success unless it ignores the trailer entirely);
//   - ZERO bytes are staged for that object broker-side (the throttle
//     short-circuits before WriteStream is ever invoked, so the engine's
//     temp+rename never even begins — no partial stage, no torn object);
//
// and then, after the bucket refills (a single fake-clock advance), a RETRY of
// one previously-throttled object succeeds and lands byte-identical — the
// SEC-46 retry-no-loss property seen from the broker side: a refused upload
// loses nothing and the retry lands.
func TestUploadThrottleAtomicAndSignalled(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}

	// REAL token bucket: 2 ops/s, burst 2. The byte/fd ceilings are generous
	// (they must not be the binding constraint — the throttle is).
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         2,
		OpsBurst:             2,
		InFlightBytesCeiling: 1 << 30,
		FDCeiling:            256,
		Clock:                clock.Now,
	})

	// REAL local-volume engine over a temp workspace: its WriteStream is the
	// temp+rename atomic commit under test. Provision the scope so its workspace
	// directory exists (the engine does not auto-create the scope root on write).
	eng := objectstore.NewLocalVolumeEngine(t.TempDir())
	if err := eng.ProvisionScope(context.Background(), objectstore.ScopeID(streamScope)); err != nil {
		t.Fatalf("ProvisionScope: %v", err)
	}

	g := &fakeGuard{}
	d := newDispatcherWithEngine(
		&fakeResolver{}, // resolves write intent (the upload path needs a write grant)
		g,
		realCeilingsRegistryAdapter{r: reg},
		1<<20, // declared-size ceiling, well above the payloads
		realEngineAdapter{e: eng},
	)
	d.maxFileSize = 1 << 20

	const (
		scope   = streamScope
		burst   = 6
		declSz  = 8
		payload = "ABCDEFGH"
	)
	// Distinct top-level object per request so a throttled object's absence is
	// its own witness (no overwrite/already_exists confound). Flat paths keep
	// the parent at the scope root, which the engine provisions — the engine's
	// WriteStream does not MkdirAll intermediate dirs.
	wirePath := func(i int) string { return "/up-" + string(rune('0'+i)) + ".bin" }
	engRel := func(i int) string { return "up-" + string(rune('0'+i)) + ".bin" }

	type outcome struct {
		index     int
		throttled bool
	}
	var (
		results    []outcome
		successIdx []int
	)

	for i := 0; i < burst; i++ {
		body := concat(
			paramsFrame(t, scope, wirePath(i), declSz),
			chunkFrame(t, []byte(payload)),
			endFrame(t),
		)
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), scope, okIntents())

		// EVERY streaming response is HTTP 200; the verdict rides in the trailer.
		flag, resp := streamTrailer(t, w)
		if flag != endStreamFlag {
			t.Fatalf("upload %d: last frame flag = %#x, want end-stream %#x", i, flag, endStreamFlag)
		}

		if resp.Error == nil {
			// Success trailer ({}). The object MUST be staged byte-identical.
			got := readStaged(t, d, scope, engRel(i), declSz)
			if string(got) != payload {
				t.Fatalf("upload %d: success trailer but staged %q, want %q", i, got, payload)
			}
			results = append(results, outcome{index: i, throttled: false})
			successIdx = append(successIdx, i)
			continue
		}

		// Error trailer. For a throttled upload it MUST be resource_exhausted —
		// an unambiguous refusal, never a success-looking trailer.
		if resp.Error.Code != wireCodeResourceExhausted {
			t.Fatalf("upload %d: error trailer code = %q (msg %q), want %q (a refused upload must signal resource_exhausted, never an ambiguous/success trailer)",
				i, resp.Error.Code, resp.Error.Message, wireCodeResourceExhausted)
		}
		// THROTTLED: zero bytes staged broker-side. No partial stage, no torn
		// object — the object must be wholly absent from the workspace.
		if !objectAbsent(d, scope, engRel(i)) {
			t.Fatalf("upload %d: THROTTLED but bytes were staged broker-side — partial stage / torn object on a refused upload (SC2 defect)", i)
		}
		results = append(results, outcome{index: i, throttled: true})
	}

	// The burst must contain BOTH committed and throttled uploads, else the
	// test proves nothing. With burst 2 and a frozen clock, exactly the first
	// two commit and the remaining four are throttled.
	var nSuccess, nThrottled int
	for _, r := range results {
		if r.throttled {
			nThrottled++
		} else {
			nSuccess++
		}
	}
	if nSuccess != 2 {
		t.Fatalf("committed %d uploads, want exactly 2 (the burst capacity) — clock/bucket not frozen as intended", nSuccess)
	}
	if nThrottled != burst-2 {
		t.Fatalf("throttled %d uploads, want %d (burst exceeded), got results %+v", nThrottled, burst-2, results)
	}

	// --- SEC-46 retry-no-loss, broker side ---
	// Pick a previously-throttled object; it is currently absent (asserted
	// above). Refill the bucket by advancing the clock, then retry the SAME
	// object: it must succeed and land byte-identical. A refused upload lost
	// nothing and the retry lands.
	var retryIdx = -1
	for _, r := range results {
		if r.throttled {
			retryIdx = r.index
			break
		}
	}
	if retryIdx < 0 {
		t.Fatalf("no throttled upload to retry (test setup invariant broken)")
	}
	// Confirm the precondition: the retry target is absent before the retry.
	if !objectAbsent(d, scope, engRel(retryIdx)) {
		t.Fatalf("retry target up-%d existed before retry — a throttled upload leaked bytes", retryIdx)
	}

	// One second of wall time refills the 2 ops/s bucket by 2 tokens (capped at
	// burst 2) — enough for the single retry op.
	clock.Advance(time.Second)

	body := concat(
		paramsFrame(t, scope, wirePath(retryIdx), declSz),
		chunkFrame(t, []byte(payload)),
		endFrame(t),
	)
	w := serveStream(d, OpFileUpload, bytes.NewReader(body), scope, okIntents())
	_, resp := streamTrailer(t, w)
	if resp.Error != nil {
		t.Fatalf("retry of up-%d after refill: error trailer %q (%q), want success", retryIdx, resp.Error.Code, resp.Error.Message)
	}
	got := readStaged(t, d, scope, engRel(retryIdx), declSz)
	if string(got) != payload {
		t.Fatalf("retry of up-%d landed %q, want byte-identical %q (SEC-46 retry-no-loss violated)", retryIdx, got, payload)
	}
}
