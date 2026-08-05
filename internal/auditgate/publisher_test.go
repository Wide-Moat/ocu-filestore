// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingPublisher stalls until released, so a test can prove the local commit
// does not wait on fan-out.
type blockingPublisher struct {
	release chan struct{}
	entered chan struct{}
	calls   atomic.Int64
}

func (p *blockingPublisher) Publish(_ context.Context, _ FileActivityEvent) error {
	p.calls.Add(1)
	select {
	case p.entered <- struct{}{}:
	default:
	}
	<-p.release
	return nil
}

// failingPublisher always refuses, standing in for a downstream sink outage.
type failingPublisher struct{ calls atomic.Int64 }

func (p *failingPublisher) Publish(_ context.Context, _ FileActivityEvent) error {
	p.calls.Add(1)
	return errors.New("downstream sink unavailable")
}

// recordingPublisher captures what it was handed, so a test can bind the
// published event to the committed one rather than merely counting calls.
type recordingPublisher struct {
	mu   sync.Mutex
	seen []FileActivityEvent
}

func (p *recordingPublisher) Publish(_ context.Context, ev FileActivityEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, ev)
	return nil
}

func (p *recordingPublisher) events() []FileActivityEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]FileActivityEvent, len(p.seen))
	copy(out, p.seen)
	return out
}

func newSinkForPublisher(t *testing.T) (*FileSink, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func sampleEvent() FileActivityEvent {
	return FileActivityEvent{
		ActivityID: 1,
		Actor:      ActorSubject{},
	}
}

// waitFor polls until cond holds or the deadline passes. Fan-out is
// asynchronous by design, so a test that read the counter once would race the
// publisher goroutine rather than observe its outcome.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestPublisher_LocalCommitDoesNotWaitOnFanOut is the NFR-SEC-79 spill-not-block
// keystone: the local durable commit is the no-loss point and fan-out is
// best-effort, so a stalled downstream sink must not stall the operation.
//
// Non-vacuous: the publisher blocks INDEFINITELY and is released only after
// Mandate has already returned. A synchronous fan-out would deadlock here
// rather than fail an assertion, which is the strongest available signal.
func TestPublisher_LocalCommitDoesNotWaitOnFanOut(t *testing.T) {
	s, _ := newSinkForPublisher(t)
	p := &blockingPublisher{release: make(chan struct{}), entered: make(chan struct{}, 1)}
	s.SetPublisher(p)

	done := make(chan error, 1)
	go func() { done <- s.Mandate(context.Background(), sampleEvent()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Mandate returned %v, want nil while fan-out is stalled", err)
		}
	case <-time.After(2 * time.Second):
		close(p.release)
		t.Fatal("Mandate blocked on a stalled publisher: fan-out is on the hot path")
	}
	close(p.release)
}

// TestPublisher_DownstreamFailureNeitherDeniesNorLosesTheRecord pins the
// fail-OPEN half of NFR-SEC-79 for the file-op producer path: a downstream sink
// failure neither denies the operation nor costs the durable record.
//
// Non-vacuous: it asserts BOTH halves — a nil error from Mandate AND the line
// present in the file. Asserting only the nil error would pass for a sink that
// silently skipped the local write.
func TestPublisher_DownstreamFailureNeitherDeniesNorLosesTheRecord(t *testing.T) {
	s, path := newSinkForPublisher(t)
	p := &failingPublisher{}
	s.SetPublisher(p)

	if err := s.Mandate(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Mandate denied the operation on a downstream failure: %v", err)
	}
	waitFor(t, "the failing publisher to be called", func() bool { return p.calls.Load() == 1 })

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("the durable record is empty after a downstream failure: the local commit was lost")
	}
	if err := Verify(path); err != nil {
		t.Fatalf("chain broken after a downstream failure: %v", err)
	}
}

// TestPublisher_DroppedFanOutIsCounted pins "a dropped fan-out is counted and
// reconciled, never silently lost". Without the counter the fail-open posture
// is indistinguishable from silent loss, which is the exact outcome
// NFR-SEC-79 forbids.
func TestPublisher_DroppedFanOutIsCounted(t *testing.T) {
	s, _ := newSinkForPublisher(t)
	p := &failingPublisher{}
	s.SetPublisher(p)

	if got := s.DroppedFanOut(); got != 0 {
		t.Fatalf("DroppedFanOut before any event = %d, want 0", got)
	}
	for i := 0; i < 3; i++ {
		if err := s.Mandate(context.Background(), sampleEvent()); err != nil {
			t.Fatalf("Mandate: %v", err)
		}
	}
	waitFor(t, "three drops to be counted", func() bool { return s.DroppedFanOut() == 3 })
}

// TestPublisher_SuccessfulFanOutCountsNoDrop is the counter's positive control:
// a counter that only ever increments would satisfy the drop test while telling
// an operator nothing.
func TestPublisher_SuccessfulFanOutCountsNoDrop(t *testing.T) {
	s, _ := newSinkForPublisher(t)
	p := &recordingPublisher{}
	s.SetPublisher(p)

	if err := s.Mandate(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Mandate: %v", err)
	}
	waitFor(t, "the event to be published", func() bool { return len(p.events()) == 1 })
	if got := s.DroppedFanOut(); got != 0 {
		t.Fatalf("DroppedFanOut after a successful fan-out = %d, want 0", got)
	}
}

// TestPublisher_PublishesTheCommittedEvent binds the published event to the
// committed one. A publisher handed a zero-valued or pre-chain event would
// satisfy every counter assertion above while forwarding a record that does not
// correspond to what was durably written.
func TestPublisher_PublishesTheCommittedEvent(t *testing.T) {
	s, _ := newSinkForPublisher(t)
	p := &recordingPublisher{}
	s.SetPublisher(p)

	if err := s.Mandate(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Mandate: %v", err)
	}
	waitFor(t, "the event to be published", func() bool { return len(p.events()) == 1 })

	got := p.events()[0]
	if got.Time == 0 {
		t.Fatal("the published event carries no Time: it is not the committed record")
	}
	if got.PrevHash == "" {
		t.Fatal("the published event carries no PrevHash: it was forwarded before the chain link was set")
	}
	if got.Metadata.Version == "" {
		t.Fatal("the published event carries no schema version: the committed defaults were not applied")
	}
}

// TestPublisher_AbsentPublisherIsNotADrop keeps the counter honest on the
// default deployment: no configured publisher means nothing to fan out, which
// is not a dropped record.
func TestPublisher_AbsentPublisherIsNotADrop(t *testing.T) {
	s, _ := newSinkForPublisher(t)

	if err := s.Mandate(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Mandate: %v", err)
	}
	if got := s.DroppedFanOut(); got != 0 {
		t.Fatalf("DroppedFanOut with no publisher configured = %d, want 0", got)
	}
}

// TestPublisher_NotCalledWhenTheLocalCommitFails pins the ordering: the local
// commit is the no-loss point, so an event that never committed must never be
// forwarded. Publishing a record the durable chain does not hold would make the
// downstream sink disagree with the authoritative local record.
func TestPublisher_NotCalledWhenTheLocalCommitFails(t *testing.T) {
	s, _ := newSinkForPublisher(t)
	p := &recordingPublisher{}
	s.SetPublisher(p)

	// A non-event type is refused before any write: the cheapest local-commit
	// failure that does not require latching the sink.
	if err := s.Mandate(context.Background(), "not an event"); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Mandate(non-event) = %v, want ErrAuditUnavailable", err)
	}
	if got := len(p.events()); got != 0 {
		t.Fatalf("publisher saw %d events for an uncommitted record, want 0", got)
	}
	if got := s.DroppedFanOut(); got != 0 {
		t.Fatalf("DroppedFanOut for an uncommitted record = %d, want 0", got)
	}
}

// TestPublisher_NotCalledWhenTheDurableWriteFails pins fan-out to the write
// SUCCEEDING, not merely to Mandate having been entered. It is the arm that
// separates "forwards what the chain holds" from "forwards what the chain was
// about to hold".
//
// The distinction is not academic: Time and PrevHash are stamped on the event
// BEFORE the write, so an event forwarded early is fully populated and
// indistinguishable from a committed one by inspection alone. Only a write that
// fails after that stamping can tell the two orderings apart — with fan-out
// moved ahead of the durable write, the publisher sees an event whose record
// does not exist and never will, and this test reds.
func TestPublisher_NotCalledWhenTheDurableWriteFails(t *testing.T) {
	s, _ := newSinkForPublisher(t)
	p := &recordingPublisher{}
	s.SetPublisher(p)

	// Fail the append itself: the event is well-formed and fully stamped, so
	// everything upstream of the write behaves exactly as on the happy path.
	fault := &faultSyncer{ws: s.w, failWrite: true}
	s.w = fault

	if err := s.Mandate(context.Background(), sampleEvent()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Mandate on a failing write = %v, want ErrAuditUnavailable", err)
	}

	// Give a mis-ordered fan-out the chance to land before asserting absence:
	// the publish is asynchronous, so an immediate read could observe zero for
	// timing reasons rather than for the ordering this test is about.
	time.Sleep(50 * time.Millisecond)

	if got := len(p.events()); got != 0 {
		t.Fatalf("publisher saw %d events for a record the durable write refused, want 0 "+
			"-- fan-out runs before the local commit, so a downstream sink can hold "+
			"records the authoritative chain does not", got)
	}
	if got := s.DroppedFanOut(); got != 0 {
		t.Fatalf("DroppedFanOut for a record that never committed = %d, want 0", got)
	}
}

// TestPublisher_FanOutPreservesCommitOrder pins the ordering the pipeline is
// specified to carry: canon calls the record "durable, ordered, tamper-evident"
// and the bus "ordered, append-only". A fan-out that spawned one goroutine per
// event would satisfy every other test here — nothing is lost and nothing
// blocks — while delivering a stream the chain order cannot be recovered from.
//
// Non-vacuous: the producers run CONCURRENTLY, which is how the daemon drives
// the sink. A sequential producer cannot expose the defect, because there is
// only ever one goroutine in flight.
func TestPublisher_FanOutPreservesCommitOrder(t *testing.T) {
	s, _ := newSinkForPublisher(t)
	p := &orderRecordingPublisher{}
	s.SetPublisher(p)

	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := sampleEvent()
			ev.ByteCount = int64(i)
			if err := s.Mandate(context.Background(), ev); err != nil {
				t.Errorf("Mandate(%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	waitFor(t, "every committed event to be published", func() bool { return p.count() == n })

	// The chain order is the order Mandate committed under the mutex. The
	// published sequence must be a prefix-preserving replay of it: the
	// sequence numbers the sink assigned must arrive ascending.
	seq := p.sequence()
	for i := 1; i < len(seq); i++ {
		if seq[i] < seq[i-1] {
			t.Fatalf("fan-out delivered commit %d after %d: the ordered record is "+
				"not ordered downstream", seq[i], seq[i-1])
		}
	}
}

// orderRecordingPublisher records the commit sequence of what it receives.
type orderRecordingPublisher struct {
	mu  sync.Mutex
	got []uint64
}

func (p *orderRecordingPublisher) Publish(_ context.Context, ev FileActivityEvent) error {
	// A publish costs real time — a network collector always does. With a
	// goroutine per event this is what lets two in-flight publishes overtake
	// each other; with one worker draining a queue it changes nothing but the
	// wall clock. Without it the race is too narrow to observe reliably and
	// this test would pass against the unordered fan-out.
	// Sleep OUTSIDE the lock. Inside it, the recorder's own mutex would
	// serialise the publishes and hand them out in arrival order, masking the
	// very reordering this test exists to catch.
	time.Sleep(time.Duration(ev.commitSeq%7) * time.Millisecond)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got = append(p.got, ev.commitSeq)
	return nil
}

func (p *orderRecordingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.got)
}

func (p *orderRecordingPublisher) sequence() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]uint64, len(p.got))
	copy(out, p.got)
	return out
}
