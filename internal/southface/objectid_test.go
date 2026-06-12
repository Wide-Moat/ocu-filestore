// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"sync"
	"testing"
)

// TestObjectIDLazyMint pins the lazy-mint + reuse + distinct-key + reverse
// lookup contract (D7/Q5).
func TestObjectIDLazyMint(t *testing.T) {
	s := newObjectIDStore()

	id1 := s.idFor("fs-1", "/a")
	if len(id1) != 32 {
		t.Fatalf("minted id %q len = %d, want 32-char hex", id1, len(id1))
	}
	for _, c := range id1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("id %q not lowercase hex", id1)
		}
	}

	// Same (scope,path) reuses the id.
	if got := s.idFor("fs-1", "/a"); got != id1 {
		t.Fatalf("re-observe (fs-1,/a) = %q, want reuse %q", got, id1)
	}

	// Different path -> different id.
	id2 := s.idFor("fs-1", "/b")
	if id2 == id1 {
		t.Fatalf("distinct path got same id %q", id2)
	}

	// Different scope, same path -> different id.
	id3 := s.idFor("fs-2", "/a")
	if id3 == id1 {
		t.Fatalf("distinct scope got same id %q", id3)
	}

	// Reverse lookup returns the stored (scope,path) with its scope intact
	// (the phase-10 cross-scope resolution input).
	v, ok := s.lookup(id1)
	if !ok {
		t.Fatalf("lookup(%q) not found", id1)
	}
	if v.scope != "fs-1" || v.path != "/a" {
		t.Fatalf("lookup(%q) = %+v, want {fs-1,/a}", id1, v)
	}

	if _, ok := s.lookup("never-minted"); ok {
		t.Fatal("lookup of an unminted id reported ok=true, want false")
	}
}

// TestObjectIDConcurrent pins race-clean concurrent minting: every goroutine
// observing the same (scope,path) converges on a single id. Run with -race.
func TestObjectIDConcurrent(t *testing.T) {
	s := newObjectIDStore()
	const n = 64
	ids := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			ids[idx] = s.idFor("fs-c", "/shared")
		}(i)
	}
	wg.Wait()

	first := ids[0]
	for i, id := range ids {
		if id != first {
			t.Fatalf("goroutine %d minted %q, want all-equal %q", i, id, first)
		}
	}
	v, ok := s.lookup(first)
	if !ok || v.scope != "fs-c" || v.path != "/shared" {
		t.Fatalf("lookup(%q) = %+v ok=%v, want {fs-c,/shared}", first, v, ok)
	}
}
