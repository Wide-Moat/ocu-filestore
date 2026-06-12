// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"sync"
	"testing"
)

// callRecorder records the order of pipeline-visible calls so ordering tests
// can assert audit-before-ack and short-circuit behaviour. Safe for
// concurrent use.
type callRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (c *callRecorder) record(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, name)
}

func (c *callRecorder) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.calls))
	copy(out, c.calls)
	return out
}

func (c *callRecorder) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = nil
}

// fakeGuard is a recording Guard: it appends "mandate" to the shared
// recorder, captures the event, and returns the configured error.
type fakeGuard struct {
	rec    *callRecorder
	err    error
	mu     sync.Mutex
	events []any
}

func (g *fakeGuard) Mandate(_ context.Context, event any) error {
	if g.rec != nil {
		g.rec.record("mandate")
	}
	g.mu.Lock()
	g.events = append(g.events, event)
	g.mu.Unlock()
	return g.err
}

// fakeResolver is a configurable Resolver: it records "resolve", captures
// the caller evidence and request, and returns the configured grant/error.
type fakeResolver struct {
	rec        *callRecorder
	grant      Grant
	err        error
	mu         sync.Mutex
	lastCaller any
	lastReq    ResolveRequest
}

func (r *fakeResolver) Resolve(_ context.Context, caller any, req ResolveRequest) (Grant, error) {
	if r.rec != nil {
		r.rec.record("resolve")
	}
	r.mu.Lock()
	r.lastCaller = caller
	r.lastReq = req
	r.mu.Unlock()
	if r.err != nil {
		return Grant{}, r.err
	}
	return r.grant, nil
}

// fakeCeilingsSession is a configurable CeilingsSession with per-call errors.
type fakeCeilingsSession struct {
	rec      *callRecorder
	opErr    error
	bytesErr error
	fdErr    error
}

func (s *fakeCeilingsSession) TryConsumeOp() error {
	if s.rec != nil {
		s.rec.record("ceilings_op")
	}
	return s.opErr
}
func (s *fakeCeilingsSession) AcquireBytes(int64) error { return s.bytesErr }
func (s *fakeCeilingsSession) ReleaseBytes(int64)       {}
func (s *fakeCeilingsSession) TryAcquireFD() error      { return s.fdErr }
func (s *fakeCeilingsSession) ReleaseFD()               {}

// fakeCeilingsRegistry returns the same fake session for every key and
// records the keys it was asked for, so tests can assert the throttle is
// keyed on the CHANNEL scope, never the body.
type fakeCeilingsRegistry struct {
	session *fakeCeilingsSession
	mu      sync.Mutex
	keys    []string
}

func (r *fakeCeilingsRegistry) Session(key string) CeilingsSession {
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.mu.Unlock()
	return r.session
}

func (r *fakeCeilingsRegistry) Release(string) {}

// Compile-time proof the fakes satisfy the consumer-side seams.
var (
	_ Guard            = (*fakeGuard)(nil)
	_ Resolver         = (*fakeResolver)(nil)
	_ CeilingsSession  = (*fakeCeilingsSession)(nil)
	_ CeilingsRegistry = (*fakeCeilingsRegistry)(nil)
)

// TestFakesSatisfySeams is the loud witness for the compile-time assertions
// above: the in-package fakes implement the consumer-side interfaces.
func TestFakesSatisfySeams(t *testing.T) {
	var (
		_ Guard            = &fakeGuard{}
		_ Resolver         = &fakeResolver{}
		_ CeilingsSession  = &fakeCeilingsSession{}
		_ CeilingsRegistry = &fakeCeilingsRegistry{session: &fakeCeilingsSession{}}
	)
}
