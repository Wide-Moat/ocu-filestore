// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// genesisInput is the fixed sentinel whose SHA-256 is the prev_hash link of
// the first record in a chain. The named sentinel lets verifiers confirm the
// genesis independently.
const genesisInput = "ocu-audit-genesis-v1"

// Metadata defaults stamped by Mandate when the caller leaves them unset:
// OCSF schema version and the producing product name.
const (
	ocsfSchemaVersion = "1.1.0"
	productName       = "ocu-filestore"
)

// genesisHash returns the chain-link value for the first record.
func genesisHash() [sha256.Size]byte {
	return sha256.Sum256([]byte(genesisInput))
}

// FileSink is the minimal-shelf Guard implementation: an append-only,
// hash-chained JSONL file. Mandate returns nil only after the record is on
// stable storage (O_APPEND write + fsync); any failure returns
// ErrAuditUnavailable and the caller must deny the operation (NFR-SEC-79).
type FileSink struct {
	mu sync.Mutex
	f  *os.File
	// prevLineHash is the SHA-256 of the exact bytes of the last written
	// line, including its trailing newline; genesis when no line exists.
	prevLineHash [sha256.Size]byte
}

var _ Guard = (*FileSink)(nil)

// NewFileSink opens (or creates) the JSONL sink at path.
//
// A new or empty file starts the chain from genesis; creation fsyncs the
// file and then the parent directory so the entry survives a crash. An
// existing non-empty file is untrusted input: its chain is verified from
// genesis and the last complete line's hash is adopted so the next Mandate
// continues the chain. A broken chain (mismatched prev_hash or unparseable
// line) fails the constructor closed — the broker must not start serving on
// a tampered audit file. A trailing partial line with no newline is a torn
// write whose record was never acked (Sync never returned); the un-acked
// bytes are dropped before appending resumes so the next record cannot
// merge into the torn fragment.
func NewFileSink(path string) (*FileSink, error) {
	info, statErr := os.Stat(path)
	isNew := os.IsNotExist(statErr)
	if statErr != nil && !isNew {
		return nil, fmt.Errorf("auditgate: stat sink: %w", statErr)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("auditgate: open sink: %w", err)
	}

	prev := genesisHash()
	switch {
	case isNew:
		// Two-fsync creation: the file, then the parent directory so the
		// new directory entry is durable (POSIX). The directory sync is
		// best-effort — some platforms refuse fsync on a directory fd.
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("auditgate: sync new sink: %w", err)
		}
		if dir, derr := os.Open(filepath.Dir(path)); derr == nil {
			_ = dir.Sync()
			_ = dir.Close()
		}
	case info.Size() > 0:
		rf, err := os.Open(path)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("auditgate: open sink for chain scan: %w", err)
		}
		last, _, torn, scanErr := chainScan(rf)
		_ = rf.Close()
		if scanErr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("auditgate: existing chain invalid, refusing to start: %w", scanErr)
		}
		if torn > 0 {
			// Drop only the un-acked torn bytes; every acked (synced,
			// newline-terminated) record stays.
			if err := f.Truncate(info.Size() - int64(torn)); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("auditgate: drop torn tail: %w", err)
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("auditgate: sync after dropping torn tail: %w", err)
			}
		}
		prev = last
	}

	return &FileSink{f: f, prevLineHash: prev}, nil
}

// Mandate durably records the event and only then returns nil. The event
// must be a FileActivityEvent value; the broker clock stamps Time
// (overwriting any caller-supplied value, NFR-SEC-48), metadata defaults
// are filled if unset, and prev_hash links the record into the chain. Any
// failure — unknown event type, marshal, write, or sync — returns
// ErrAuditUnavailable so the caller denies the operation (fail-closed,
// NFR-SEC-79).
func (s *FileSink) Mandate(ctx context.Context, event any) error {
	ev, ok := event.(FileActivityEvent)
	if !ok {
		return ErrAuditUnavailable
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ev.Time = time.Now().UnixMilli()
	if ev.Metadata.Version == "" {
		ev.Metadata.Version = ocsfSchemaVersion
	}
	if ev.Metadata.Product.Name == "" {
		ev.Metadata.Product.Name = productName
	}
	ev.PrevHash = hex.EncodeToString(s.prevLineHash[:])

	line, err := json.Marshal(ev)
	if err != nil {
		return ErrAuditUnavailable
	}
	line = append(line, '\n')

	// Write directly to the *os.File — never through a buffered writer,
	// which could hold bytes a file Sync does not flush.
	if _, err := s.f.Write(line); err != nil {
		return ErrAuditUnavailable
	}
	if err := s.f.Sync(); err != nil {
		return ErrAuditUnavailable
	}

	// Chain state advances only after the durable write: the hash input is
	// the exact written line bytes including the trailing newline.
	s.prevLineHash = sha256.Sum256(line)
	return nil
}

// Verify reads the JSONL file at path and validates the hash chain from
// genesis. It returns nil for a missing or empty file and for an intact
// chain, and an error naming the broken line on any tamper or truncation
// that breaks a recorded continuation. A trailing partial line with no
// newline is ignored: it is a torn write that was never acked (AUD-02).
func Verify(path string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("auditgate: verify open: %w", err)
	}
	defer f.Close()

	_, _, _, err = chainScan(f)
	return err
}

// chainScan walks a JSONL stream recomputing the hash chain from genesis.
// It returns the hash of the last complete line (genesis when none), the
// number of complete lines verified, and the byte length of a trailing
// partial line with no newline (0 when the stream ends cleanly). Each
// complete line is hashed as the exact written bytes including the
// trailing newline — ReadBytes preserves the delimiter, so the hash input
// needs no reconstruction. Any prev_hash mismatch or unparseable complete
// line is an error naming the line.
func chainScan(r io.Reader) (last [sha256.Size]byte, lines int, torn int, err error) {
	br := bufio.NewReader(r)
	prev := genesisHash()
	lineNum := 0
	for {
		chunk, readErr := br.ReadBytes('\n')
		if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' {
			lineNum++
			var rec struct {
				PrevHash string `json:"prev_hash"`
			}
			if jerr := json.Unmarshal(chunk, &rec); jerr != nil {
				return prev, lineNum - 1, 0, fmt.Errorf("auditgate: chain line %d: parse: %w", lineNum, jerr)
			}
			want := hex.EncodeToString(prev[:])
			if rec.PrevHash != want {
				return prev, lineNum - 1, 0, fmt.Errorf("auditgate: chain broken at line %d: want prev_hash %s got %s", lineNum, want, rec.PrevHash)
			}
			prev = sha256.Sum256(chunk)
		} else if len(chunk) > 0 {
			// Torn un-acked tail: the intact prefix is the chain.
			return prev, lineNum, len(chunk), nil
		}
		if readErr == io.EOF {
			return prev, lineNum, 0, nil
		}
		if readErr != nil {
			return prev, lineNum, 0, fmt.Errorf("auditgate: chain read: %w", readErr)
		}
	}
}
