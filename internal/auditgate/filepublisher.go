// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// errPublisherClosed — a Publish after Close. It is an ordinary fan-out
// failure: the caller counts it as a drop and the operation proceeds, because
// the authoritative record is the local chain, not this file.
var errPublisherClosed = errors.New("auditgate: file publisher is closed")

// FilePublisher is the one-click-solo reference sink for the audit fan-in
// (ADR-0009 names the durable-bus solo reference an embedded append-only file).
// It appends one JSON object per line to its own file, distinct from the
// hash-chained local record: that chain is the non-repudiation point and is
// never rewritten to serve a downstream reader, while this file is a
// replay-from-recovery tail a collector consumes and may rotate.
//
// It is deliberately NOT a network client. The fan-in contract leaves its
// protocol binding open, so shipping a concrete bus or SIEM transport here
// would pin a wire the architecture has not decided; a customer fills the
// Publisher contract with the transport they operate.
//
// The sink does not fsync. Losing its tail costs nothing that matters: every
// record it holds is already durable in the hash-chained local record, and a
// fan-out sink that fsynced would spend the file plane's latency budget on the
// copy rather than on the authoritative write.
type FilePublisher struct {
	mu     sync.Mutex
	f      *os.File
	closed bool
}

var _ Publisher = (*FilePublisher)(nil)

// fanOutRecord is the wire form: the committed event plus the fan-in channel it
// belongs to. A file carries no channel of its own, and the pipeline binds the
// OCSF source to the channel identity, so naming it here is what keeps a
// replayed record attributable to this component.
type fanOutRecord struct {
	Channel string `json:"channel"`
	FileActivityEvent
}

// NewFilePublisher opens (or creates) the append-only fan-out file at path. An
// empty path is a construction error rather than a silent no-op, so a
// deployment that sets the flag to an empty value aborts instead of appearing
// configured while fanning out nowhere.
func NewFilePublisher(path string) (*FilePublisher, error) {
	if path == "" {
		return nil, fmt.Errorf("auditgate: file publisher path is required")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("auditgate: open fan-out sink: %w", err)
	}
	return &FilePublisher{f: f}, nil
}

// Publish appends the event as one JSON line. Any failure is returned so the
// caller counts the drop; it never denies or stalls the file operation.
func (p *FilePublisher) Publish(_ context.Context, ev FileActivityEvent) error {
	line, err := json.Marshal(fanOutRecord{Channel: ObjectStoreFanInChannel, FileActivityEvent: ev})
	if err != nil {
		return fmt.Errorf("auditgate: encode fan-out record: %w", err)
	}
	line = append(line, '\n')

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errPublisherClosed
	}
	if _, err := p.f.Write(line); err != nil {
		return fmt.Errorf("auditgate: write fan-out record: %w", err)
	}
	return nil
}

// Close releases the descriptor. It is idempotent, and a Publish afterwards is
// a counted drop rather than a panic on a nil file.
func (p *FilePublisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.f == nil {
		return nil
	}
	err := p.f.Close()
	p.f = nil
	if err != nil {
		return fmt.Errorf("auditgate: close fan-out sink: %w", err)
	}
	return nil
}
