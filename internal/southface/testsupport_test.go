// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import "sync"

// recordingCeilingsSession is a transport-neutral CeilingsSession stub that
// records every acquire/release so a data-plane handler test can assert the
// ceilings gauge balances on every exit (no leaked byte or fd slot on an
// aborted/refused upload or download). It is shared by the multipart-upload and
// octet-stream-download REST handler tests.
type recordingCeilingsSession struct {
	mu            sync.Mutex
	opErr         error
	fdErr         error
	bytesErr      error
	bytesErrAfter int // return bytesErr on the (bytesErrAfter+1)th AcquireBytes
	acquired      int64
	released      int64
	acquireCalls  int
	fdAcquired    int
	fdReleased    int
}

func (s *recordingCeilingsSession) TryConsumeOp() error { return s.opErr }

func (s *recordingCeilingsSession) AcquireBytes(n int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bytesErr != nil && s.acquireCalls >= s.bytesErrAfter {
		s.acquireCalls++
		return s.bytesErr
	}
	s.acquireCalls++
	s.acquired += n
	return nil
}

func (s *recordingCeilingsSession) ReleaseBytes(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.released += n
}

func (s *recordingCeilingsSession) TryAcquireFD() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fdErr != nil {
		return s.fdErr
	}
	s.fdAcquired++
	return nil
}

func (s *recordingCeilingsSession) ReleaseFD() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fdReleased++
}

func (s *recordingCeilingsSession) balanced() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acquired == s.released && s.fdAcquired == s.fdReleased
}

// recordingRegistry returns a fixed recording session for every key and records
// the keys requested (the channel-scope-keying witness).
type recordingRegistry struct {
	sess *recordingCeilingsSession
	mu   sync.Mutex
	keys []string
}

func (r *recordingRegistry) Session(key string) CeilingsSession {
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.mu.Unlock()
	return r.sess
}
func (r *recordingRegistry) Release(string) {}

var (
	_ CeilingsSession  = (*recordingCeilingsSession)(nil)
	_ CeilingsRegistry = (*recordingRegistry)(nil)
)

// newStreamDispatcher builds an engine-backed dispatcher with a recording
// ceilings session and a small whole-object ceiling for the data-plane handler
// tests. It is the shared constructor the multipart-upload and
// octet-stream-download REST handler tests drive their dispatcher through.
func newStreamDispatcher(eng Engine, g Guard, sess *recordingCeilingsSession, maxFile int64) *dispatcher {
	reg := &recordingRegistry{sess: sess}
	d := newDispatcherWithEngine(&fakeResolver{}, g, reg, 1<<20, eng)
	d.maxFileSize = maxFile
	return d
}
