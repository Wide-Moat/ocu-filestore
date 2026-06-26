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
