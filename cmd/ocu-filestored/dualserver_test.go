// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeListener is a programmable south/north listener: Serve blocks until either
// serveErr is delivered (a fault) or Close is called (clean), and Close returns
// closeErr. It records whether Close ran.
type fakeListener struct {
	serveErr error
	closeErr error

	mu       sync.Mutex
	closed   bool
	closedCh chan struct{}
	faultCh  chan struct{}
}

func newFakeListener() *fakeListener {
	return &fakeListener{closedCh: make(chan struct{}), faultCh: make(chan struct{})}
}

func (f *fakeListener) Serve() error {
	if f.serveErr != nil {
		// Deliver the fault once: signal faultCh so a test can assert ordering,
		// then return the error.
		close(f.faultCh)
		return f.serveErr
	}
	<-f.closedCh // block until Close (clean shutdown)
	return nil
}

func (f *fakeListener) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.closedCh)
	}
	return f.closeErr
}

func (f *fakeListener) didClose() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// TestDualServerServeReturnsFirstListenerError pins that Serve returns the FIRST
// listener fault (here the north listener faults; the south blocks).
func TestDualServerServeReturnsFirstListenerError(t *testing.T) {
	south := newFakeListener()
	northFault := errors.New("north listener fault")
	north := newFakeListener()
	north.serveErr = northFault

	d := newDualServer(south, north)
	errCh := make(chan error, 1)
	go func() { errCh <- d.Serve() }()

	select {
	case got := <-errCh:
		if !errors.Is(got, northFault) {
			t.Fatalf("Serve = %v, want the north fault", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return on a listener fault")
	}

	// Clean up the still-blocked south listener.
	_ = d.Close()
}

// TestDualServerCloseJoinsBothErrors pins that Close shuts BOTH listeners down
// and joins their errors so neither teardown is dropped.
func TestDualServerCloseJoinsBothErrors(t *testing.T) {
	southErr := errors.New("south close fault")
	northErr := errors.New("north close fault")
	south := newFakeListener()
	south.closeErr = southErr
	north := newFakeListener()
	north.closeErr = northErr

	d := newDualServer(south, north)
	err := d.Close()
	if !errors.Is(err, southErr) || !errors.Is(err, northErr) {
		t.Fatalf("Close = %v, want both south and north errors joined", err)
	}
	if !south.didClose() || !north.didClose() {
		t.Fatalf("Close did not close both listeners (south=%v north=%v)", south.didClose(), north.didClose())
	}
}

// closeGatePatience bounds how long a gatedCloser waits for its peer's Close to
// be entered. It only elapses when the closes do NOT overlap, so a red result
// costs this once instead of hanging the suite.
const closeGatePatience = 2 * time.Second

// errCloseNotConcurrent is what a gatedCloser reports when it waited out the
// gate without its peer's Close ever starting.
var errCloseNotConcurrent = errors.New("peer listener Close was never entered")

// gatedCloser is a listener whose Close blocks until the PEER listener's Close
// has been entered. Two of them wired to each other complete only if both
// Closes are in flight at once; a sequential Close leaves the first one waiting
// on a peer that has not started yet, and it reports that stall as an error.
type gatedCloser struct {
	entered chan struct{} // closed on entry to Close
	peer    chan struct{} // the peer's entered channel
}

// Serve blocks until this listener's Close is entered, mirroring a real
// listener's accept loop.
func (g *gatedCloser) Serve() error {
	<-g.entered
	return nil
}

func (g *gatedCloser) Close() error {
	close(g.entered)
	select {
	case <-g.peer:
		return nil
	case <-time.After(closeGatePatience):
		return errCloseNotConcurrent
	}
}

// TestDualServerClosesBothListenersConcurrently pins that Close puts BOTH
// listener shutdowns in flight at once.
//
// Closing them one after the other costs two things. It adds the two bounded
// drains together, so a stop can take as long as their sum — and every shipped
// stop-grace period is sized on the assumption that it cannot
// (TestShippedStopDeadlinesCoverWorstCaseStopCost derives the deadline from the
// concurrent model this test pins). It also leaves the second listener ACCEPTING
// NEW connections for the whole of the first listener's drain, because
// http.Server.Shutdown closes only its own listener: a plane the operator has
// already told to stop keeps admitting fresh work for up to a full drain.
func TestDualServerClosesBothListenersConcurrently(t *testing.T) {
	south := &gatedCloser{entered: make(chan struct{})}
	north := &gatedCloser{entered: make(chan struct{})}
	south.peer = north.entered
	north.peer = south.entered

	d := newDualServer(south, north)

	start := time.Now()
	err := d.Close()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Close = %v; the two listener Closes did not overlap. A sequential close adds the drain bounds together and lets the second plane admit new work for the whole of the first drain", err)
	}
	if elapsed >= closeGatePatience {
		t.Fatalf("Close took %v, at or past the %v gate; the closes did not overlap", elapsed, closeGatePatience)
	}
}

// TestDualServerNilNorthIsSouthOnly pins that a nil north degrades to south-only:
// Serve and Close act on the south listener alone, with no nil panic.
func TestDualServerNilNorthIsSouthOnly(t *testing.T) {
	southErr := errors.New("south close fault")
	south := newFakeListener()
	south.closeErr = southErr

	d := newDualServer(south, nil)

	// Serve blocks on the south listener until Close; run it in a goroutine.
	serveDone := make(chan error, 1)
	go func() { serveDone <- d.Serve() }()

	err := d.Close()
	if !errors.Is(err, southErr) {
		t.Fatalf("Close = %v, want the south error (south-only)", err)
	}
	if !south.didClose() {
		t.Fatal("south listener was not closed")
	}
	select {
	case serr := <-serveDone:
		if serr != nil {
			t.Fatalf("Serve = %v after a clean south-only Close, want nil", serr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("south-only Serve did not return after Close")
	}
}
