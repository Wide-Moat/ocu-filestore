// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handlestore

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/objectid"
)

// opPut and opDel are the two durable log-operation discriminators. The log is
// an append-only JSONL stream of these envelopes; replay folds them into the
// in-memory map (put inserts/overwrites, del removes), last-write-wins.
const (
	opPut = "put"
	opDel = "del"
)

// putEnvelope is the on-disk shape of a Put: the discriminator plus the full
// record. The record's own JSON tags (handlestore.Record) are nested under
// "record" so a future op kind can carry a different body without colliding.
type putEnvelope struct {
	Op     string `json:"op"`
	Record Record `json:"record"`
}

// delEnvelope is the on-disk shape of a Delete tombstone: the discriminator,
// the file_id being removed, and the scope it was bound to (recorded so the log
// is self-describing; replay keys deletion by file_id alone).
type delEnvelope struct {
	Op     string `json:"op"`
	FileID string `json:"file_id"`
	Scope  string `json:"scope"`
}

// writeSyncer is the store's append seam: the durable-write pair every mutation
// depends on. The real *os.File satisfies it; tests substitute a faulting
// implementation to exercise the failure latch. It mirrors the audit sink's
// seam of the same name and contract.
type writeSyncer interface {
	io.Writer
	Sync() error
}

// DiskStore is the on-disk durable-append handle store. A mutation (Put,
// Delete) appends its envelope, fsyncs, and only THEN mutates the in-memory
// map — a mutation is acked only after its record is on stable storage
// (audit-before-ack, mirroring auditgate.FileSink). Get and List are served
// from the in-memory map.
//
// A write or sync fault latches the store permanently failed: after a fault,
// file bytes and the in-memory map can no longer be trusted to agree (a partial
// write leaves a fragment a later append would merge into; a failed sync may
// still have reached the platter), so every subsequent MUTATION is refused with
// ErrStoreUnavailable without writing. READS stay resolvable from the map — a
// latched store does not collateral-deny audited reads. Recovery is a restart:
// NewDiskStore re-scans the log from the start.
type DiskStore struct {
	mu sync.Mutex
	f  *os.File
	// w is the durable-write seam; always the underlying *os.File in
	// production.
	w writeSyncer
	// recs is the in-memory projection of the replayed log: file_id -> Record.
	// Get and List read it; Put/Delete mutate it only AFTER the durable write.
	recs map[string]Record
	// refIndex is the (Scope, ObjectRef) -> file_id secondary index EnsureObject
	// resolves put-if-absent against: scope -> normalizedObjectRef -> file_id. It
	// is fully DERIVED from the existing opPut/opDelete log (no new log record
	// shape) and rebuilt at replay — a Put indexes its (scope, ref); a Delete
	// tombstone removes the entry. The ObjectRef key is normalised (a single
	// leading slash stripped, normalizeRef) so a north-created engine-relative ref
	// ("outputs/x") and the same object the engine namespace reports key
	// identically (ADR-0029 inv-5), and one object never mints two handles.
	refIndex map[string]map[string]string
	// tombstonedRefs remembers every (Scope, ObjectRef) a Delete tombstoned so
	// EnsureObject will NOT re-mint a handle for an ObjectRef the operator
	// explicitly deleted (else a north-deleted object silently reappears on the
	// next north-list reconcile). It is rebuilt at replay from opDelete records
	// and set on every Delete. This preserves DELETE's meaning at the handle
	// layer; whether a north delete should ALSO remove the engine bytes is a later
	// ruling (this store carries no engine dependency — it masks the re-mint, it
	// does not erase bytes).
	tombstonedRefs map[string]map[string]bool
	// failed latches true after any write or sync error; it never resets.
	failed bool
	// closed is set by Close after the descriptor is released; a mutation on a
	// closed store is denied fail-closed instead of writing to a nil seam.
	closed bool
	// onLatch is an optional callback invoked EXACTLY ONCE on the transition
	// from healthy to latched. It fires after failed is set and after the mutex
	// is released (to avoid deadlock on re-entry). The composition layer uses it
	// to emit an ERROR log line and flip a latched gauge.
	onLatch func()
	// now is the store clock, injectable for tests; production is time.Now. It
	// stamps Record.CreatedAt — never the caller's value.
	now func() time.Time
}

// The compile-time Store assertion (var _ Store = (*DiskStore)(nil)) lands with
// Delete in delete.go — the last method that completes the interface.

// NewDiskStore opens (or creates) the JSONL handle log at path and replays it
// into the in-memory map.
//
// A new file is created O_APPEND|O_CREATE|O_WRONLY 0o600 and durably
// established with a two-fsync creation (the file, then the parent directory so
// the new directory entry survives a crash; EINVAL/ENOTSUP on the directory
// fsync are tolerated as the platform refusing directory fsync). An existing
// file is replayed line-by-line: each complete (newline-terminated) line is a
// put or del envelope folded into the map last-write-wins. An UNPARSEABLE
// complete line fails the constructor closed — the daemon must not start
// serving on a corrupt log. A trailing partial line with no newline is a torn
// write whose mutation was never acked (Sync never returned); the un-acked
// bytes are dropped (Truncate+Sync) before appending resumes so the next record
// cannot merge into the torn fragment.
func NewDiskStore(path string) (*DiskStore, error) {
	info, statErr := os.Stat(path)
	isNew := os.IsNotExist(statErr)
	if statErr != nil && !isNew {
		return nil, fmt.Errorf("handlestore: stat log: %w", statErr)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("handlestore: open log: %w", err)
	}

	recs := make(map[string]Record)
	// refIndex and tombstonedRefs are DERIVED from the same opPut/opDelete log as
	// recs (no new log shape): a Put indexes its (scope, ref); a Delete removes the
	// index entry and records the tombstoned (scope, ref). Both are rebuilt here at
	// replay so a restart resumes the exact idempotency/mask state.
	refIndex := make(map[string]map[string]string)
	tombstonedRefs := make(map[string]map[string]bool)
	switch {
	case isNew:
		// Two-fsync creation: the file, then the parent directory so the new
		// directory entry is durable (POSIX). Only EINVAL/ENOTSUP on the
		// directory fsync are tolerated; any other error fails construction.
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("handlestore: sync new log: %w", err)
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			_ = f.Close()
			return nil, err
		}
	case info.Size() > 0:
		rf, err := os.Open(path)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("handlestore: open log for replay: %w", err)
		}
		torn, scanErr := replay(rf, recs, refIndex, tombstonedRefs)
		_ = rf.Close()
		if scanErr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("handlestore: existing log invalid, refusing to start: %w", scanErr)
		}
		if torn > 0 {
			// Drop only the un-acked torn bytes; every acked (synced,
			// newline-terminated) record stays.
			if err := f.Truncate(info.Size() - int64(torn)); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("handlestore: drop torn tail: %w", err)
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("handlestore: sync after dropping torn tail: %w", err)
			}
		}
	}

	return &DiskStore{
		f:              f,
		w:              f,
		recs:           recs,
		refIndex:       refIndex,
		tombstonedRefs: tombstonedRefs,
		now:            time.Now,
	}, nil
}

// normalizeRef maps an ObjectRef to the key form the ref index and the tombstone
// mask use: a single leading slash is stripped so a north-created engine-relative
// ref ("outputs/x", stored with no leading slash by the create path) and the same
// object the engine namespace reports key identically (ADR-0029 inv-5). It strips
// AT MOST ONE leading slash (never path.Clean) — the store carries no engine
// dependency and never dereferences the ref, so it must not rewrite the caller's
// reference beyond the one-convention alignment the idempotency key needs.
func normalizeRef(ref string) string {
	return strings.TrimPrefix(ref, "/")
}

// indexRef records fileID as the handle for (scope, normalizeRef(ref)) in idx and
// clears any tombstone mark on that (scope, ref): a fresh Put of a ref revives it
// for EnsureObject (the operator re-created what they had deleted). It is the ONE
// place a Put mutates the secondary index, shared by replay and the live Put path.
func indexRef(idx map[string]map[string]string, tomb map[string]map[string]bool, scope, ref, fileID string) {
	key := normalizeRef(ref)
	byRef := idx[scope]
	if byRef == nil {
		byRef = make(map[string]string)
		idx[scope] = byRef
	}
	byRef[key] = fileID
	if ts := tomb[scope]; ts != nil {
		delete(ts, key)
	}
}

// unindexRef removes the (scope, normalizeRef(ref)) -> file_id entry and marks the
// ref tombstoned so EnsureObject will not re-mint it. It is the ONE place a Delete
// mutates the secondary index, shared by replay and the live Delete path.
func unindexRef(idx map[string]map[string]string, tomb map[string]map[string]bool, scope, ref string) {
	key := normalizeRef(ref)
	if byRef := idx[scope]; byRef != nil {
		delete(byRef, key)
	}
	ts := tomb[scope]
	if ts == nil {
		ts = make(map[string]bool)
		tomb[scope] = ts
	}
	ts[key] = true
}

// syncDir fsyncs the directory at dir so a new entry inside it is durable.
// EINVAL and ENOTSUP — from open or sync — are tolerated as the
// platform/filesystem refusing directory fsync; any other error is returned and
// must fail construction. It mirrors the audit sink's syncDir of the same
// contract.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			return nil
		}
		return fmt.Errorf("handlestore: open log directory: %w", err)
	}
	serr := d.Sync()
	_ = d.Close()
	if serr != nil && !errors.Is(serr, syscall.EINVAL) && !errors.Is(serr, syscall.ENOTSUP) {
		return fmt.Errorf("handlestore: sync log directory: %w", serr)
	}
	return nil
}

// replay folds a JSONL log stream into recs, last-write-wins, and rebuilds the
// two secondary indexes (refIndex, tombstonedRefs) from the SAME opPut/opDelete
// log — no new record shape is read. It returns the byte length of a trailing
// partial line with no newline (0 when the stream ends cleanly) and an error
// naming the first unparseable COMPLETE line — an unparseable complete line is
// corruption the constructor must fail on, never a torn tail. Each complete line
// is a put (insert/overwrite + index) or del (delete + unindex + tombstone)
// envelope; an unknown op or a put with an empty file_id is corruption.
func replay(r io.Reader, recs map[string]Record, refIndex map[string]map[string]string, tombstonedRefs map[string]map[string]bool) (torn int, err error) {
	br := bufio.NewReader(r)
	lineNum := 0
	for {
		chunk, readErr := br.ReadBytes('\n')
		if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' {
			lineNum++
			if aerr := applyLine(chunk, recs, refIndex, tombstonedRefs); aerr != nil {
				return 0, fmt.Errorf("handlestore: log line %d: %w", lineNum, aerr)
			}
		} else if len(chunk) > 0 {
			// Torn un-acked tail: the intact prefix is the log.
			return len(chunk), nil
		}
		if readErr == io.EOF {
			return 0, nil
		}
		if readErr != nil {
			return 0, fmt.Errorf("handlestore: log read: %w", readErr)
		}
	}
}

// applyLine folds one complete JSONL line into recs AND the two secondary
// indexes. It peeks the op discriminator, then unmarshals the matching envelope.
// A put indexes its (scope, ref) -> file_id; a del removes the index entry AND
// records the tombstoned (scope, ref) so EnsureObject will not re-mint it. The
// del envelope carries no ObjectRef, so the ref is read from the record the log
// already put (recs[file_id]) BEFORE it is deleted — the log is self-describing.
// An unparseable line, an unknown op, or a put/del with an empty file_id is
// corruption (returned error).
func applyLine(line []byte, recs map[string]Record, refIndex map[string]map[string]string, tombstonedRefs map[string]map[string]bool) error {
	var head struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		return fmt.Errorf("parse op: %w", err)
	}
	switch head.Op {
	case opPut:
		var env putEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			return fmt.Errorf("parse put: %w", err)
		}
		if env.Record.FileID == "" {
			return errors.New("put record has empty file_id")
		}
		recs[env.Record.FileID] = env.Record
		indexRef(refIndex, tombstonedRefs, env.Record.Scope, env.Record.ObjectRef, env.Record.FileID)
		return nil
	case opDel:
		var env delEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			return fmt.Errorf("parse del: %w", err)
		}
		if env.FileID == "" {
			return errors.New("del record has empty file_id")
		}
		// The del envelope names no ObjectRef; recover it from the record the log
		// already put so the index/tombstone update keys on the same (scope, ref)
		// the put indexed. The envelope's own Scope is the tombstone scope; the ref
		// comes from the still-present record.
		if rec, ok := recs[env.FileID]; ok {
			unindexRef(refIndex, tombstonedRefs, rec.Scope, rec.ObjectRef)
		}
		delete(recs, env.FileID)
		return nil
	default:
		return fmt.Errorf("unknown op %q", head.Op)
	}
}

// Close releases the append file descriptor. It is idempotent: a second call
// (or a call after a prior Close error) is a no-op returning nil. Every acked
// record is already on stable storage (each mutation fsyncs before returning),
// so closing loses no acked data; an in-flight mutation completes under the
// same mutex before Close proceeds. After Close the store owns no descriptor
// and must not be reused for mutation: recovery is a fresh NewDiskStore.
func (s *DiskStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	s.w = nil
	if err != nil {
		return fmt.Errorf("handlestore: close log: %w", err)
	}
	return nil
}

// Latched reports whether the store has permanently failed on a write/sync
// fault. It returns false on a healthy store and true after any mutation
// write/sync error. Once latched the value never resets — recovery is a daemon
// restart. Latched is safe for concurrent use.
func (s *DiskStore) Latched() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

// SetOnLatch registers an optional callback invoked EXACTLY ONCE on the
// transition from healthy to latched, after s.failed is set and the mutex is
// released. Calling it after the store is already latched is a no-op.
func (s *DiskStore) SetOnLatch(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.failed {
		s.onLatch = fn
	}
}

// durableAppend marshals env, appends it with a trailing newline, and fsyncs —
// returning only after the bytes are on stable storage. Any write or sync fault
// latches the store (fired callback after the mutex is released) and returns
// ErrStoreUnavailable WITHOUT mutating the caller's in-memory state: the caller
// folds the mutation into the map only after this returns nil. The caller holds
// s.mu; this method releases and re-acquires it only to fire onLatch.
func (s *DiskStore) durableAppend(env any) error {
	line, err := json.Marshal(env)
	if err != nil {
		// A marshal failure is not a durability fault — nothing was written, so
		// the store is NOT latched. Refuse this mutation only.
		return fmt.Errorf("handlestore: marshal log record: %w", err)
	}
	line = append(line, '\n')

	// Write directly to the file seam — never through a buffered writer, which
	// could hold bytes a file Sync does not flush.
	if _, err := s.w.Write(line); err != nil {
		s.latch()
		return ErrStoreUnavailable
	}
	if err := s.w.Sync(); err != nil {
		s.latch()
		return ErrStoreUnavailable
	}
	return nil
}

// latch sets the failed flag and fires onLatch exactly once, releasing the
// mutex around the callback to avoid deadlock on re-entry. The caller holds
// s.mu on entry and holds it again on return (the deferred Unlock).
func (s *DiskStore) latch() {
	cb := s.onLatch
	s.failed = true
	s.onLatch = nil // fire at most once
	s.mu.Unlock()
	if cb != nil {
		cb()
	}
	s.mu.Lock() // reacquire for the caller's deferred Unlock
}

// Put mints a file_id, stamps CreatedAt from the store clock, durably appends
// the record, and only THEN inserts it into the in-memory map — returning the
// record after the sync (audit-before-ack). It returns ErrStoreUnavailable if
// the store is latched/closed or the durable write/sync faults (the record is
// NOT acked and the map is unchanged). A best-effort ctx pre-check denies an
// already-cancelled request before taking the durable-write lock; once the
// append begins it is uninterruptible (an os.File.Sync cannot be cancelled, and
// abandoning a write mid-flight would risk the torn-write divergence the design
// forbids).
func (s *DiskStore) Put(ctx context.Context, in PutInput) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, ErrStoreUnavailable
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.closed {
		return Record{}, ErrStoreUnavailable
	}

	rec := Record{
		FileID:                objectid.New(),
		Scope:                 in.Scope,
		ObjectRef:             in.ObjectRef,
		Filename:              in.Filename,
		Mime:                  in.Mime,
		Size:                  in.Size,
		CreatedAt:             s.now().UTC().Format(time.RFC3339),
		DownloadablePolicyRef: in.DownloadablePolicyRef,
	}

	if err := s.durableAppend(putEnvelope{Op: opPut, Record: rec}); err != nil {
		return Record{}, err
	}
	// Insert into the map AND the ref index only after the durable write acked. A
	// fresh Put of a previously-deleted ref revives it for EnsureObject (indexRef
	// clears the tombstone) — the operator re-created what they had deleted.
	s.recs[rec.FileID] = rec
	indexRef(s.refIndex, s.tombstonedRefs, rec.Scope, rec.ObjectRef, rec.FileID)
	return rec, nil
}

// EnsureObject is put-if-absent keyed on (Scope, ObjectRef): if a NON-tombstoned
// record already exists for that pair it is returned UNCHANGED (no new mint);
// else a fresh record is durably Put (random FileID, store-stamped CreatedAt) and
// returned. It is the north-list reconcile primitive (ADR-0029:46): the browser
// File Pane lists via the north handle store, but a deliverable the agent wrote
// through the south FUSE mount mints no north handle — so the list reconciles the
// engine namespace by calling EnsureObject for every engine object, and the
// (Scope, ObjectRef) key makes that reconcile IDEMPOTENT (the same object keeps
// the same file_id across every list, the anti-dup invariant).
//
// The tombstone mask is load-bearing for DELETE correctness: an ObjectRef the
// operator explicitly Deleted returns ErrNotFound here — it is NOT re-minted — so
// a north-deleted object does not silently reappear on the next reconcile. This
// preserves DELETE's meaning at the handle layer; whether a north delete should
// ALSO remove the engine bytes is deferred to a later ruling (this store carries
// no engine dependency and erases no bytes — it masks the re-mint only).
//
// It is a MUTATION and fails closed exactly like Put: an already-cancelled ctx,
// a latched store, or a closed store returns ErrStoreUnavailable without writing.
// The north caller (serveList) skips the reconcile when Store.Latched(), so this
// path is not normally hit under a latch — but the guard here is the structural
// one, not the caller's courtesy.
func (s *DiskStore) EnsureObject(ctx context.Context, in EnsureInput) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, ErrStoreUnavailable
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.closed {
		return Record{}, ErrStoreUnavailable
	}

	key := normalizeRef(in.ObjectRef)

	// The tombstone mask FIRST: an ObjectRef the operator deleted must not be
	// re-minted (else a north-deleted object reappears on the next north-list
	// reconcile). Return the SAME ErrNotFound the resolution path uses so the
	// caller (serveList) skips it exactly as it skips an absent ref — the sentinel
	// is the "no handle for this ref, and do not mint one" signal.
	if ts := s.tombstonedRefs[in.Scope]; ts != nil && ts[key] {
		return Record{}, ErrNotFound
	}

	// Put-if-absent: a non-tombstoned record already indexed for (scope, ref) is
	// returned UNCHANGED — no new mint, the anti-dup invariant. The existing
	// file_id is stable across every list.
	if byRef := s.refIndex[in.Scope]; byRef != nil {
		if fileID, ok := byRef[key]; ok {
			if rec, ok := s.recs[fileID]; ok {
				return rec, nil
			}
		}
	}

	// Absent and not tombstoned: mint a fresh handle, durably. CreatedAt is
	// store-clock-stamped (never the engine ModTime — "never the caller's value").
	rec := Record{
		FileID:                objectid.New(),
		Scope:                 in.Scope,
		ObjectRef:             in.ObjectRef,
		Filename:              in.Filename,
		Mime:                  in.Mime,
		Size:                  in.Size,
		CreatedAt:             s.now().UTC().Format(time.RFC3339),
		DownloadablePolicyRef: in.DownloadablePolicyRef,
	}
	if err := s.durableAppend(putEnvelope{Op: opPut, Record: rec}); err != nil {
		return Record{}, err
	}
	s.recs[rec.FileID] = rec
	indexRef(s.refIndex, s.tombstonedRefs, rec.Scope, rec.ObjectRef, rec.FileID)
	return rec, nil
}

// Get resolves a file_id to its record IFF the attested scope byte-matches the
// record's scope. An absent file_id AND a cross-scope file_id both return
// ErrNotFound — the SAME sentinel — so a probe cannot enumerate other scopes'
// handles (anti-enumeration). The scope assertion lives HERE, below the Store
// seam, never in the caller. Get is served from the in-memory map and works on
// a latched store (a write fault never denies an audited read).
//
// The canonical attested-scope source is southface.PeerScope.FilesystemID (the
// host-attested, credential-bound scope the dispatch spine derives per request);
// the caller passes that value verbatim and never a request-supplied field.
func (s *DiskStore) Get(ctx context.Context, fileID, attestedScope string) (Record, error) {
	// Empty attested scope authorizes nothing: reject BEFORE the map lookup so
	// an empty scope can never resolve a record — not even one persisted under
	// an empty Scope (defense-in-depth, keystone-wave followup-2; do not rely
	// only on the credscope sibling). The empty zero record and ErrNotFound are
	// returned identically to the absent/cross-scope case (anti-enumeration).
	if attestedScope == "" {
		return Record{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[fileID]
	if !ok {
		return Record{}, ErrNotFound
	}
	if rec.Scope != attestedScope {
		// Cross-scope is indistinguishable from absent: same sentinel, same
		// zero record. This is the anti-enumeration keystone (ADR-0023).
		return Record{}, ErrNotFound
	}
	return rec, nil
}

// List is implemented in list.go — the cursor-paged, stable-ordered,
// scope-bound page walk (TASK 6).
