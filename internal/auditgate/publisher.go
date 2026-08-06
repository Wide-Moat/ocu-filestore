// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import "context"

// ObjectStoreFanInChannel is the audit fan-in channel this component publishes
// to, fixed by the fan-in contract
// (contracts/audit/audit-fanin.asyncapi.yaml, channel objectStoreAudit). The
// contract leaves the PROTOCOL binding open pending the per-seam transport
// decision, so a Publisher implementation chooses its own transport — but not
// its own channel: the pipeline binds the OCSF source to the channel identity,
// so publishing elsewhere would file this component's events under another
// source. TestObjectStoreFanInChannelIsTheContractAddress pins the value.
const ObjectStoreFanInChannel = "audit.ingest.object-store"

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

// SetPublisherOwned installs the publisher AND transfers its lifetime to the
// sink: Close closes the publisher after the queue has drained. It is what a
// composition root wants, because the publisher must outlive the function that
// built it — a `defer p.Close()` in a constructor closes it the moment
// construction returns, and every later event becomes a silent drop while the
// flag, the created file and the boot log all still look correct.
//
// The publisher is closed AFTER the drain, so records committed before Close
// still reach it.
func (s *FileSink) SetPublisherOwned(p interface {
	Publisher
	Close() error
}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publisher = p
	s.ownedPublisher = p
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

// fanOutQueueDepth bounds the in-memory hand-off between the commit path and
// the fan-out worker. It is deliberately finite: an unbounded queue would trade
// the stall NFR-REL-12 forbids for unbounded memory growth under a sink that
// never drains, which fails later and worse. At the bound the commit path drops
// rather than waits — the local record already holds the event, and a counted
// drop is the outcome NFR-SEC-79 prescribes.
const fanOutQueueDepth = 1024

// fanOut hands a COMMITTED event to the publisher off the caller's path. It is
// called under the sink mutex, after the durable write and the chain advance,
// so the event it forwards is byte-for-byte the record the local chain holds
// and the enqueue order IS the chain order.
//
// The work happens on ONE long-lived worker, not a goroutine per event. A
// goroutine per event loses ordering the moment two commits are in flight, and
// canon specifies the record as durable, ORDERED and tamper-evident — a
// downstream stream whose order cannot be recovered is not that record. A
// single worker also keeps the original reason for going async: a customer
// collector is an arbitrary network peer, and letting it block the mutex the
// next Mandate needs would turn a slow sink into a stall of the file plane.
func (s *FileSink) fanOut(p Publisher, ev FileActivityEvent) {
	s.fanOutOnce.Do(func() {
		q := make(chan FileActivityEvent, fanOutQueueDepth)
		s.fanOutQ = q
		s.fanOutDone = make(chan struct{})
		// The worker holds its OWN reference to the channel. Close sets the
		// field to nil, and a worker ranging over the field would then range
		// over nil and block forever instead of draining and exiting.
		go s.fanOutWorker(p, q)
	})
	if s.fanOutQ == nil {
		// Closed: the worker is gone and nothing will drain a send. A record
		// committed at this point is already durable, so this is a counted
		// drop, never a blocked send on a nil channel.
		s.droppedFanOut.Add(1)
		return
	}
	select {
	case s.fanOutQ <- ev:
	default:
		// The queue is full: the collector is not draining. Drop and count,
		// never block — the caller holds the sink mutex, so waiting here would
		// stall every other file operation behind a sink OCU does not control.
		s.droppedFanOut.Add(1)
	}
}

// fanOutWorker drains q in enqueue order, which is commit order, and exits when
// Close closes it. Draining rather than abandoning means records committed
// before Close still reach the collector; closing fanOutDone last is what lets
// Close wait for that drain before closing a publisher it owns.
func (s *FileSink) fanOutWorker(p Publisher, q <-chan FileActivityEvent) {
	defer close(s.fanOutDone)
	for ev := range q {
		if err := p.Publish(context.Background(), ev); err != nil {
			s.droppedFanOut.Add(1)
		}
	}
}
