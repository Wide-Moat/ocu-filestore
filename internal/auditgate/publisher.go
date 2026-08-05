// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import "context"

// Publisher is the fan-in seam: the contract a customer-supplied collector
// fills to receive the events this daemon has already committed locally
// (ADR-0009 — OCU owns the chain of custody and the local durable commit;
// everything downstream is a published contract the customer fills).
//
// Publish is called ONLY for an event the local durable record already holds,
// and never on the operation's hot path. An implementation may block or fail
// freely: neither outcome can deny or stall the file operation, because the
// local commit is the no-loss point (NFR-SEC-79 durable-first, fail-open). A
// returned error counts as a dropped fan-out and is surfaced for reconciliation
// rather than retried here — retry and ordering policy belong to the collector,
// not to the producer's critical path (NFR-REL-12 spill-not-block).
type Publisher interface {
	Publish(ctx context.Context, event FileActivityEvent) error
}

// SetPublisher installs the fan-in publisher. It is intended for the
// composition layer at wiring time; a nil publisher (the default) means the
// deployment fans out nowhere, which is not a dropped record.
func (s *FileSink) SetPublisher(p Publisher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publisher = p
}

// DroppedFanOut reports how many committed events this sink failed to hand to
// the publisher. It counts drops, never attempts, so a healthy deployment reads
// zero for the daemon's lifetime and a non-zero value means the downstream
// record set is behind the local one by exactly that many events — the
// "counted and reconciled, never silently lost" half of NFR-SEC-79.
//
// A dropped fan-out is NOT an audit failure: the authoritative record is the
// local chain, which is intact by construction whenever this counter moves.
func (s *FileSink) DroppedFanOut() int64 { return s.droppedFanOut.Load() }

// fanOut hands a COMMITTED event to the publisher off the caller's path. It is
// called after the durable write and the chain advance, so the event it
// forwards is byte-for-byte the record the local chain holds.
//
// The goroutine is deliberate: a customer collector is an arbitrary network
// peer, and letting it block the mutex the next Mandate needs would make a slow
// sink into a stall of the file plane — the outcome NFR-REL-12 forbids.
func (s *FileSink) fanOut(p Publisher, ev FileActivityEvent) {
	go func() {
		if err := p.Publish(context.Background(), ev); err != nil {
			s.droppedFanOut.Add(1)
		}
	}()
}
