// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
)

// TestWriteStreamConcurrentNoReplace pins CONC-02: two concurrent
// overwrite=false writers to the SAME destination — both already past the
// early-Stat fast path (gated by pipes, so each passed the existence check
// while the destination was still absent) — resolve atomically at the link
// commit: EXACTLY ONE wins, the other observes ErrAlreadyExists, and the
// destination carries the winner's bytes intact. Pre-fix, the second
// writer's rename silently replaced the first writer's committed object.
func TestWriteStreamConcurrentNoReplace(t *testing.T) {
	ctx := context.Background()
	eng, base, scope := newLocalEngine(t)

	contents := [][]byte{[]byte("WRITER-A-BODY"), []byte("WRITER-B-BODY")}
	readers := make([]*io.PipeReader, 2)
	writers := make([]*io.PipeWriter, 2)
	for i := range readers {
		readers[i], writers[i] = io.Pipe()
	}

	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each WriteStream runs its early Stat (destination absent for
			// BOTH — the pipe has produced nothing yet, so neither has
			// committed) and then blocks reading its pipe.
			errs[i] = eng.WriteStream(ctx, scope, "race.bin", readers[i], false)
		}(i)
	}

	// Feed and half-close both pipes; both writers then race to commit.
	for i := 0; i < 2; i++ {
		if _, err := writers[i].Write(contents[i]); err != nil {
			t.Fatalf("pipe write %d: %v", i, err)
		}
		if err := writers[i].Close(); err != nil {
			t.Fatalf("pipe close %d: %v", i, err)
		}
	}
	wg.Wait()

	var winners, losers int
	var winnerBody []byte
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
			winnerBody = contents[i]
		case errors.Is(err, ErrAlreadyExists):
			losers++
		default:
			t.Fatalf("writer %d: unexpected error %v (want nil or ErrAlreadyExists)", i, err)
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("winners=%d losers=%d, want exactly 1 winner and 1 already_exists loser", winners, losers)
	}
	if got := readBack(t, eng, scope, "race.bin", 64); !bytes.Equal(got, winnerBody) {
		t.Fatalf("destination = %q, want the winner's intact body %q", got, winnerBody)
	}
	assertNoTempFiles(t, base, scope)
}

// TestCopyFileConcurrentNoReplace pins the CopyFile arm of CONC-02: N
// concurrent overwrite=false copies of distinct sources onto one destination
// yield exactly one winner; every loser gets ErrAlreadyExists (at the early
// fast path or atomically at the link commit) and the destination matches
// one source byte-exactly.
func TestCopyFileConcurrentNoReplace(t *testing.T) {
	ctx := context.Background()
	eng, base, scope := newLocalEngine(t)

	const n = 8
	bodies := make([][]byte, n)
	for i := range bodies {
		bodies[i] = []byte(fmt.Sprintf("COPY-SOURCE-%02d", i))
		if err := eng.WriteStream(ctx, scope, fmt.Sprintf("src%02d.bin", i), bytes.NewReader(bodies[i]), false); err != nil {
			t.Fatalf("seed src%02d: %v", i, err)
		}
	}

	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = eng.CopyFile(ctx, scope, fmt.Sprintf("src%02d.bin", i), "dst.bin", false)
		}(i)
	}
	close(start)
	wg.Wait()

	var winners int
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrAlreadyExists):
		default:
			t.Fatalf("copier %d: unexpected error %v", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners)
	}
	got := readBack(t, eng, scope, "dst.bin", 64)
	matched := false
	for _, b := range bodies {
		if bytes.Equal(got, b) {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("destination %q matches no source body (torn or merged write)", got)
	}
	assertNoTempFiles(t, base, scope)
}

// TestMoveFileConcurrentNoReplace pins the move arm of CONC-02: two
// concurrent overwrite=false moves of distinct files onto one destination —
// exactly one wins (its source is gone), the loser keeps its source intact
// and gets ErrAlreadyExists; the destination is one source's exact bytes.
func TestMoveFileConcurrentNoReplace(t *testing.T) {
	ctx := context.Background()
	eng, base, scope := newLocalEngine(t)

	bodies := [][]byte{[]byte("MOVER-A"), []byte("MOVER-B")}
	for i, b := range bodies {
		if err := eng.WriteStream(ctx, scope, fmt.Sprintf("mv%d.bin", i), bytes.NewReader(b), false); err != nil {
			t.Fatalf("seed mv%d: %v", i, err)
		}
	}

	errs := make([]error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = eng.MoveFile(ctx, scope, fmt.Sprintf("mv%d.bin", i), "moved.bin", false)
		}(i)
	}
	close(start)
	wg.Wait()

	var winner = -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner != -1 {
				t.Fatalf("two winners (%d and %d) on a no-replace move", winner, i)
			}
			winner = i
		case errors.Is(err, ErrAlreadyExists):
		default:
			t.Fatalf("mover %d: unexpected error %v", i, err)
		}
	}
	if winner == -1 {
		t.Fatal("no winner on a no-replace move race")
	}
	loser := 1 - winner

	if got := readBack(t, eng, scope, "moved.bin", 64); !bytes.Equal(got, bodies[winner]) {
		t.Fatalf("destination = %q, want the winner's body %q", got, bodies[winner])
	}
	// The winner's source is gone; the loser's source survives untouched.
	if _, err := eng.Stat(ctx, scope, fmt.Sprintf("mv%d.bin", winner)); err == nil {
		t.Fatalf("winner's source still present after the move")
	}
	if got := readBack(t, eng, scope, fmt.Sprintf("mv%d.bin", loser), 64); !bytes.Equal(got, bodies[loser]) {
		t.Fatalf("loser's source = %q, want untouched %q", got, bodies[loser])
	}
	assertNoTempFiles(t, base, scope)
}
