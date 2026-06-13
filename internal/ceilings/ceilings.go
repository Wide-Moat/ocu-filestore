// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ceilings is the per-session resource limiter both broker faces
// consult: a file-ops/s token bucket, an in-flight bytes gauge, and an
// open-fd counter, each keyed by an opaque session key so exhausting one
// session never degrades another (NFR-SEC-46). The pre-buffer size check
// rejects an over-ceiling declared body before a single byte is read
// (NFR-SEC-78), and every over-ceiling path returns a typed sentinel —
// nothing is silently truncated or partially staged. SizeLimits mirrors the
// layered transfer defaults pinned by the frozen file-ops contract.
//
// The package answers quota only. Authorization is the resolver's job, path
// resolution and backend I/O belong to the object-store client, and wiring
// these limiters into the dispatch path is the phase-8 consumer's job — no
// other internal package is imported here.
package ceilings

import (
	"errors"
	"sync"
	"time"
)

// SessionKey is the per-session isolation key. The face supplies it from
// the host-attested session scope at accept time; within this package it is
// opaque — no authorization meaning is attached to it.
type SessionKey string

// ClockFunc supplies the current time for rate-limiter arithmetic. The
// wiring layer injects the runtime wall clock in production; tests inject a
// fake (no sleeps, no tickers). This package never reads the wall clock
// itself — every instant flows through this seam.
type ClockFunc func() time.Time

// ErrSizeExceeded — the declared inbound size exceeds the ceiling. The
// reject is pre-buffer: no body byte is read (NFR-SEC-78). Match it with
// errors.Is.
var ErrSizeExceeded = errors.New("ceilings: declared size exceeds ceiling")

// ErrThrottleExceeded — the per-session ops/s token bucket is empty
// (NFR-SEC-46). Match it with errors.Is.
var ErrThrottleExceeded = errors.New("ceilings: ops/s rate limit exceeded for session")

// ErrBytesExceeded — the request would push the session's in-flight bytes
// past the ceiling, or the requested size is negative (NFR-SEC-46). Match
// it with errors.Is.
var ErrBytesExceeded = errors.New("ceilings: in-flight bytes ceiling reached for session")

// ErrFDExceeded — the session's open-fd ceiling is reached (NFR-SEC-46).
// Match it with errors.Is.
var ErrFDExceeded = errors.New("ceilings: open fd ceiling reached for session")

// CheckDeclaredSize rejects a declared inbound body size before any body
// byte is read. declared is the caller-supplied length (Content-Length /
// declared_size_bytes class input); ceiling must be > 0.
//
// declared > ceiling returns ErrSizeExceeded — the caller must not read the
// body. declared <= ceiling returns nil — the body MAY then be read under
// the in-flight gauge's accounting. A declared size of 0 (unknown length)
// is accepted here on purpose: the pre-buffer check is a best-effort early
// reject when the length IS declared; unknown-length bodies are bounded by
// AcquireBytes on each chunk, which is the consumer's job.
//
// Overflow safety: the comparison is direct (T-06-03). Never reformulate it
// as a subtraction — declared-ceiling or ceiling-declared wraps for
// operands near math.MaxInt64.
func CheckDeclaredSize(declared, ceiling int64) error {
	if declared > ceiling {
		return ErrSizeExceeded
	}
	return nil
}

// TokenBucket is a lazy-refill ops/s bucket: tokens replenish on each
// TryConsume call from the elapsed time, capped at burst — no goroutine,
// no ticker. It is NOT concurrency-safe; the owning Session holds its
// mutex around every call.
type TokenBucket struct {
	tokens   float64   // current token count, [0, burst]
	burst    float64   // maximum tokens (capacity)
	ratePerS float64   // tokens added per second
	lastAt   time.Time // time of the last TryConsume call
}

// NewTokenBucket creates a bucket with the given rate (ops/s) and burst.
// The bucket starts full.
func NewTokenBucket(ratePerS, burst float64) TokenBucket {
	return TokenBucket{
		tokens:   burst,
		burst:    burst,
		ratePerS: ratePerS,
	}
}

// TryConsume attempts to consume one token at the given instant, returning
// ErrThrottleExceeded when the bucket is empty. Refill only happens for a
// strictly positive elapsed interval, so a clock that stalls or goes
// backward never drains the bucket and never over-admits (T-06-05). The
// token count never goes negative: one token is subtracted only after
// confirming at least one is present.
func (b *TokenBucket) TryConsume(now time.Time) error {
	if !b.lastAt.IsZero() {
		elapsed := now.Sub(b.lastAt).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.ratePerS
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
		}
	}
	b.lastAt = now

	if b.tokens < 1 {
		return ErrThrottleExceeded
	}
	b.tokens--
	return nil
}

// ByteGauge tracks one session's in-flight bytes against a ceiling. It is
// NOT concurrency-safe; the owning Session holds its mutex around every
// call.
type ByteGauge struct {
	current int64
	ceiling int64
}

// AcquireBytes reserves n bytes. A negative n is a protocol error and an
// over-ceiling n is a quota breach; both return ErrBytesExceeded and
// reserve nothing — there is no partial reservation.
//
// Overflow safety: the guard is n > ceiling-current, never current+n >
// ceiling — the addition form wraps for n near math.MaxInt64 (T-06-03).
// ceiling-current never wraps because current <= ceiling is an invariant.
func (g *ByteGauge) AcquireBytes(n int64) error {
	if n < 0 || n > g.ceiling-g.current {
		return ErrBytesExceeded
	}
	g.current += n
	return nil
}

// ReleaseBytes returns n bytes to the gauge. n must equal the value passed
// to the matching AcquireBytes call. Releasing more than is currently in
// flight is a broken acquire/release pairing — a programmer error, not a
// runtime condition — so it panics rather than going silently negative
// (T-06-04); an error return here would be ignored by the usual
// defer-release pattern.
func (g *ByteGauge) ReleaseBytes(n int64) {
	if n > g.current {
		panic("ceilings: ByteGauge.ReleaseBytes: release exceeds current in-flight bytes (broken pairing)")
	}
	g.current -= n
}

// Config holds the per-session ceiling values a Registry stamps onto each
// new Session. Callers validate the values before constructing a Registry.
type Config struct {
	// OpsPerSecond is the token-bucket refill rate (file ops per second).
	OpsPerSecond float64
	// OpsBurst is the token-bucket capacity; a new session starts with a
	// full bucket.
	OpsBurst float64
	// InFlightBytesCeiling bounds one session's concurrently in-flight
	// bytes.
	InFlightBytesCeiling int64
	// FDCeiling bounds one session's concurrently open file descriptors.
	FDCeiling int32
	// Clock supplies the bucket's notion of now. It must be non-nil: the
	// wiring layer injects the runtime wall clock, tests inject a fake.
	Clock ClockFunc

	// nonEnforcing marks a deliberately non-enforcing registry: every
	// limiter admission short-circuits to nil and the numeric ceilings are
	// not validated. It is unexported so only NewNopRegistry can set it — a
	// production Config built by a caller can never accidentally disable
	// enforcement, and the bypass is a structural flag rather than a
	// too-large-to-dent magnitude.
	nonEnforcing bool
}

// Session groups one session's three limiters under a single mutex. Obtain
// it from Registry.Session; do not construct it directly.
type Session struct {
	mu        sync.Mutex
	clock     ClockFunc
	bucket    TokenBucket
	gauge     ByteGauge
	fdCount   int32
	fdCeiling int32
	// nonEnforcing short-circuits every admission call to nil; set only on
	// sessions minted by a NewNopRegistry registry. See Config.nonEnforcing.
	nonEnforcing bool
}

func newSession(cfg Config) *Session {
	return &Session{
		clock:        cfg.Clock,
		bucket:       NewTokenBucket(cfg.OpsPerSecond, cfg.OpsBurst),
		gauge:        ByteGauge{ceiling: cfg.InFlightBytesCeiling},
		fdCeiling:    cfg.FDCeiling,
		nonEnforcing: cfg.nonEnforcing,
	}
}

// TryConsumeOp consumes one ops/s token, returning ErrThrottleExceeded when
// the session's bucket is empty.
func (s *Session) TryConsumeOp() error {
	if s.nonEnforcing {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bucket.TryConsume(s.clock())
}

// AcquireBytes reserves n in-flight bytes for this session; see
// ByteGauge.AcquireBytes for the refusal and overflow semantics.
func (s *Session) AcquireBytes(n int64) error {
	if s.nonEnforcing {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gauge.AcquireBytes(n)
}

// ReleaseBytes returns n in-flight bytes; call it with the exact n passed
// to the matching AcquireBytes (defer it immediately after a successful
// acquire). Panics on a broken pairing; see ByteGauge.ReleaseBytes.
func (s *Session) ReleaseBytes(n int64) {
	if s.nonEnforcing {
		// AcquireBytes reserved nothing, so there is nothing to release and
		// the broken-pairing panic must not fire.
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gauge.ReleaseBytes(n)
}

// TryAcquireFD claims one open-fd slot, returning ErrFDExceeded when the
// session is at its ceiling. Every successful TryAcquireFD must be paired
// with exactly one ReleaseFD.
func (s *Session) TryAcquireFD() error {
	if s.nonEnforcing {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fdCount >= s.fdCeiling {
		return ErrFDExceeded
	}
	s.fdCount++
	return nil
}

// ReleaseFD returns one open-fd slot. Releasing at zero is a broken
// acquire/release pairing — it panics rather than going silently negative
// (T-06-04).
func (s *Session) ReleaseFD() {
	if s.nonEnforcing {
		// TryAcquireFD claimed nothing, so there is nothing to release and
		// the broken-pairing panic must not fire.
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fdCount == 0 {
		panic("ceilings: Session.ReleaseFD: counter already zero (broken pairing)")
	}
	s.fdCount--
}

// Registry holds the per-session limiters, keyed by SessionKey. It is
// concurrency-safe.
type Registry struct {
	mu       sync.RWMutex
	sessions map[SessionKey]*Session
	cfg      Config
}

// NewRegistry creates a Registry that stamps cfg onto every session it
// creates. The numeric ceilings are validated fail-loud here — the single
// place "callers validate" is enforced — so a misconfigured limiter is a
// loud wiring panic, never a silent permanent throttle (a rate of 0 would
// drain a real bucket once and then deny forever):
//
//   - cfg.Clock must be non-nil: this package keeps the wall clock behind
//     the injected seam, so the caller decides what "now" means.
//   - cfg.OpsPerSecond must be > 0 and cfg.OpsBurst must be >= 1: a bucket
//     that can never refill or never holds a token is unservable.
//   - cfg.InFlightBytesCeiling and cfg.FDCeiling must not be negative.
//
// The deliberately non-enforcing NewNopRegistry sets cfg.nonEnforcing, which
// skips the numeric checks (its sessions short-circuit every admission to
// nil); the nil-clock check always runs.
func NewRegistry(cfg Config) *Registry {
	if cfg.Clock == nil {
		panic("ceilings: NewRegistry: Config.Clock is nil (the wiring layer must inject a clock)")
	}
	if !cfg.nonEnforcing {
		if cfg.OpsPerSecond <= 0 {
			panic("ceilings: NewRegistry: Config.OpsPerSecond must be > 0 (a non-positive rate never refills)")
		}
		if cfg.OpsBurst < 1 {
			panic("ceilings: NewRegistry: Config.OpsBurst must be >= 1 (a sub-one burst can never hold a token)")
		}
		if cfg.InFlightBytesCeiling < 0 {
			panic("ceilings: NewRegistry: Config.InFlightBytesCeiling must not be negative")
		}
		if cfg.FDCeiling < 0 {
			panic("ceilings: NewRegistry: Config.FDCeiling must not be negative")
		}
	}
	return &Registry{
		sessions: make(map[SessionKey]*Session),
		cfg:      cfg,
	}
}

// Session returns the *Session for key, creating it on first use
// (double-checked under the registry lock). The same key always yields the
// same *Session until Release(key) removes it.
func (r *Registry) Session(key SessionKey) *Session {
	r.mu.RLock()
	s, ok := r.sessions[key]
	r.mu.RUnlock()
	if ok {
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok = r.sessions[key]; ok {
		return s
	}
	s = newSession(r.cfg)
	r.sessions[key] = s
	return s
}

// Release removes the session entry for key; a later Session(key) creates
// a fresh session with full capacity. Acquire/release pairs already holding
// the removed *Session remain valid — the pointer stays live until they
// drop it.
func (r *Registry) Release(key SessionKey) {
	r.mu.Lock()
	delete(r.sessions, key)
	r.mu.Unlock()
}

// NewNopRegistry returns an explicitly NON-ENFORCING registry for test and
// wiring use ONLY (the phase 8-11 consumers): every admission call
// short-circuits to nil. Non-enforcement is a structural flag
// (Config.nonEnforcing), not a too-large-to-dent magnitude — it cannot flip
// to enforcing because a ceiling was tuned. The ceiling fields are left at
// their zero values precisely because they are never read in this mode; the
// clock is a fixed instant only to satisfy the non-nil-clock invariant, as
// no limiter here ever depends on time. The accounting panics on a broken
// acquire/release pairing do NOT fire here either: a non-enforcing acquire
// reserves nothing, so its matching release has nothing to return. Never
// deploy it: a production Registry comes from NewRegistry with validated
// ceilings.
func NewNopRegistry() *Registry {
	fixed := time.Unix(0, 0)
	return NewRegistry(Config{
		Clock:        func() time.Time { return fixed },
		nonEnforcing: true,
	})
}

// SizeLimits mirrors the layered transfer size defaults from the frozen
// file-ops contract. The constant defaults here MUST stay byte-identical
// with the contract's JSON defaults; the parity unit test asserts this
// whenever the vendored contract is present.
type SizeLimits struct {
	// RPCMessageCeilingBytes is the per-RPC-message ceiling; transfers
	// above it must be chunked. Default 4 MiB.
	RPCMessageCeilingBytes int64
	// ReadChunkDefaultBytes is the default chunk size for streamed reads.
	// Default 128 MiB.
	ReadChunkDefaultBytes int64
	// VFSCacheMaxSizeBytes is the per-mount local VFS cache ceiling.
	// Default 1 GiB. The mount config owns enforcement guest-side; the
	// broker only carries the contract value.
	VFSCacheMaxSizeBytes int64
	// BrokerMaxFileSizeBytes is the broker-enforced maximum object size.
	// The contract pins no default — it is deployment policy. Zero means
	// unset: a deployment must configure it explicitly, and callers must
	// not pass a zero ceiling to CheckDeclaredSize.
	BrokerMaxFileSizeBytes int64
}

// DefaultSizeLimits returns the contract defaults. BrokerMaxFileSizeBytes
// is 0 (unset — explicit deployment configuration required).
func DefaultSizeLimits() SizeLimits {
	return SizeLimits{
		RPCMessageCeilingBytes: 4_194_304,     // 4 MiB
		ReadChunkDefaultBytes:  134_217_728,   // 128 MiB
		VFSCacheMaxSizeBytes:   1_073_741_824, // 1 GiB
		BrokerMaxFileSizeBytes: 0,             // unset — required config
	}
}
