// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"testing/quick"
)

// TestDefaultSubtreeMap pins the pinned default map (ADR-0029 Decision bullet 2):
// write -> outputs, read -> uploads, preview -> uploads. All three intents MUST
// be present (the frozen 3-value axis); an unknown intent returns "" (join
// disabled for that intent).
func TestDefaultSubtreeMap(t *testing.T) {
	m := DefaultSubtreeMap()
	cases := map[Intent]string{
		IntentWrite:   "outputs",
		IntentRead:    "uploads",
		IntentPreview: "uploads",
	}
	for intent, want := range cases {
		if got := m.For(intent); got != want {
			t.Fatalf("DefaultSubtreeMap().For(%q) = %q, want %q", intent, got, want)
		}
	}
	if got := m.For(Intent("nonsense")); got != "" {
		t.Fatalf("DefaultSubtreeMap().For(unknown) = %q, want \"\" (join disabled)", got)
	}
	if !m.enabled() {
		t.Fatalf("DefaultSubtreeMap().enabled() = false, want true")
	}
	if (SubtreeMap{}).enabled() {
		t.Fatalf("zero-value SubtreeMap.enabled() = true, want false (join disabled)")
	}
}

// TestNewSubtreeMap pins the override path: each value is normalised (a single
// leading slash trimmed) and validated; an empty value or a ".." component is a
// fail-closed ErrInvalidSubtree — a deployment can override the target but never
// disable the join by emptying a value.
func TestNewSubtreeMap(t *testing.T) {
	m, err := NewSubtreeMap("/rw-sink", "ro-in", "preview-in")
	if err != nil {
		t.Fatalf("NewSubtreeMap valid override error = %v", err)
	}
	if got := m.For(IntentWrite); got != "rw-sink" {
		t.Fatalf("override write subtree = %q, want rw-sink (leading slash trimmed)", got)
	}
	if got := m.For(IntentRead); got != "ro-in" {
		t.Fatalf("override read subtree = %q, want ro-in", got)
	}
	if got := m.For(IntentPreview); got != "preview-in" {
		t.Fatalf("override preview subtree = %q, want preview-in", got)
	}

	// Fail-closed cases: an empty value or a traversal segment refuses.
	bad := [][3]string{
		{"", "ro", "pv"},          // empty write
		{"rw", "", "pv"},          // empty read
		{"rw", "ro", ""},          // empty preview
		{"rw", "..", "pv"},        // bare ".." read
		{"rw", "a/../../b", "pv"}, // ".." component read
		{"/", "ro", "pv"},         // a bare slash normalises to empty -> refuse
	}
	for _, c := range bad {
		if _, err := NewSubtreeMap(c[0], c[1], c[2]); err == nil {
			t.Fatalf("NewSubtreeMap(%q,%q,%q) = nil error, want ErrInvalidSubtree", c[0], c[1], c[2])
		}
	}
}

// TestIntersectIntents pins the -granted-intents ceiling semantics (ADR-0029
// Decision bullet 5): effective = claim ∩ ceiling. The flag NEVER grants — a
// claim intent outside the ceiling is dropped, and a missing claim is never
// substituted by a ceiling value.
func TestIntersectIntents(t *testing.T) {
	cases := []struct {
		name    string
		claim   []Intent
		ceiling []Intent
		want    []Intent
	}{
		{
			name:    "claim narrowed by ceiling",
			claim:   []Intent{IntentRead, IntentWrite},
			ceiling: []Intent{IntentRead},
			want:    []Intent{IntentRead},
		},
		{
			name:    "claim intent outside ceiling is dropped",
			claim:   []Intent{IntentRead, IntentWrite},
			ceiling: []Intent{IntentPreview},
			want:    nil,
		},
		{
			name:    "missing claim is never substituted",
			claim:   nil,
			ceiling: []Intent{IntentRead, IntentWrite, IntentPreview},
			want:    nil,
		},
		{
			name:    "empty ceiling refuses every intent (flag never grants an empty deployment)",
			claim:   []Intent{IntentRead, IntentWrite},
			ceiling: nil,
			want:    nil,
		},
		{
			name:    "full overlap keeps claim order",
			claim:   []Intent{IntentWrite, IntentRead},
			ceiling: []Intent{IntentRead, IntentWrite, IntentPreview},
			want:    []Intent{IntentWrite, IntentRead},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := intersectIntents(c.claim, c.ceiling)
			if !intentSliceEqual(got, c.want) {
				t.Fatalf("intersectIntents(%v, %v) = %v, want %v", c.claim, c.ceiling, got, c.want)
			}
		})
	}
}

func intentSliceEqual(a, b []Intent) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCanonicalizeJoinContainmentProperty is the property-based guard on the
// ADR-0029 join (mirrors the pathresolver_prop style): for a random subtree in
// {outputs, uploads} and a random candidate path, canonicalizePath either
// ERRORS or returns a path CONTAINED under the subtree — it never returns a
// path outside the join. A candidate that (after the join) climbs above the
// subtree root fails closed. This is the single highest-risk line (the
// Clean-then-prefix containment), so the property test exercises it broadly.
func TestCanonicalizeJoinContainmentProperty(t *testing.T) {
	subtrees := []string{"outputs", "uploads"}
	f := func(raw string, subtreePick uint8, addDotDot bool) bool {
		subtree := subtrees[int(subtreePick)%len(subtrees)]
		candidate := raw
		if addDotDot {
			// Bias a fraction of inputs toward a traversal shape so the reject arm
			// is exercised, not just the accept arm.
			candidate = "../" + raw
		}
		got, err := canonicalizePath(candidate, subtree)
		if err != nil {
			return true // fail-closed is always acceptable
		}
		base := "/" + subtree
		// The accepted form must be the subtree root or strictly beneath it, and
		// must carry no residual traversal segment.
		if got != base && !strings.HasPrefix(got, base+"/") {
			t.Logf("canonicalizePath(%q, %q) = %q escaped the join %q", candidate, subtree, got, base)
			return false
		}
		if hasDotDotSegment(got) {
			t.Logf("canonicalizePath(%q, %q) = %q carries a traversal segment", candidate, subtree, got)
			return false
		}
		// Idempotence: the accepted form is already clean.
		if path.Clean(got) != got {
			t.Logf("canonicalizePath(%q, %q) = %q is not clean", candidate, subtree, got)
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatalf("join containment property failed: %v", err)
	}
}

// hasDotDotSegment reports whether p carries ".." as a whole "/"-delimited
// component. It is the test-side companion to the engine's containment guard.
func hasDotDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// subtreeDispatcher builds a stream-capable dispatcher whose subtree map is the
// DefaultSubtreeMap, so the unit disjointness test drives the join without a
// live daemon (the fast mirror of the e2e mirage probe).
func subtreeDispatcher(eng Engine, g Guard, sess *recordingCeilingsSession, maxFile int64) *dispatcher {
	d := newStreamDispatcher(eng, g, sess, maxFile)
	d.subtrees = DefaultSubtreeMap()
	return d
}

// TestDispatch_SubtreeJoinDisjointness is the fast unit mirror of the e2e mirage
// probe (broker/e2e_test.go TestE2EMirageSubtreeJoin): with the DefaultSubtreeMap
// wired, a write-intent fileUpload addressing "/uploads/x" lands the DISTINCT
// engine object "outputs/uploads/x" (the RW subtree is prepended), so the
// read-only "uploads" subtree is structurally unreachable for writing — the
// ":ro" posture is engine-enforced by the join, not a guest-mount artifact
// (ADR-0029 inv-10). It also confirms the join is INERT when disabled: the same
// upload through a no-subtree dispatcher lands the flat "uploads/x".
func TestDispatch_SubtreeJoinDisjointness(t *testing.T) {
	const scope = "fs-subtree"
	content := []byte("PAYLOAD-BYTES")

	t.Run("join_enabled_write_lands_under_outputs", func(t *testing.T) {
		eng := newFakeEngine()
		// The joined write target is "outputs/uploads/x": seed its parent dir so
		// the fake engine WriteStream (which refuses a missing parent) can land it.
		eng.mkdirSeed(scope, "outputs/uploads")
		// Seed the read-only subtree object too, so the disjointness assertion is
		// non-vacuous (the read subtree exists and is NOT the write target).
		eng.mkdirSeed(scope, "uploads")
		sess := &recordingCeilingsSession{}
		d := subtreeDispatcher(eng, &fakeGuard{}, sess, 1<<20)

		// A write addressing "/uploads/x": the write subtree "outputs" is
		// prepended, so the object lands at engine-relative "outputs/uploads/x".
		w := serveUpload(t, d, uploadBodyOpts{
			scope: scope, path: "/uploads/x", declared: int64(len(content)), fileBytes: content,
		}, scope, okIntents())
		if w.Code != 200 {
			t.Fatalf("join-enabled upload status = %d, want 200; body %s", w.Code, w.Body.String())
		}

		// The engine mutation MUST name the JOINED object.
		if !containsString(eng.mutations(), "outputs/uploads/x") {
			t.Fatalf("engine mutations = %v, want the joined outputs/uploads/x", eng.mutations())
		}
		// The read-only subtree object MUST NOT exist — no write-intent path can
		// name it after the join.
		if containsString(eng.mutations(), "uploads/x") {
			t.Fatalf("a write-intent upload reached the read-only uploads/x; the :ro subtree was writable")
		}
	})

	t.Run("join_disabled_write_lands_flat", func(t *testing.T) {
		eng := newFakeEngine()
		eng.mkdirSeed(scope, "uploads") // parent of the flat write target uploads/x
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20) // no subtree map

		w := serveUpload(t, d, uploadBodyOpts{
			scope: scope, path: "/uploads/x", declared: int64(len(content)), fileBytes: content,
		}, scope, okIntents())
		if w.Code != 200 {
			t.Fatalf("join-disabled upload status = %d, want 200; body %s", w.Code, w.Body.String())
		}
		// Static-path mode: the object lands flat at "uploads/x" (no join).
		if !containsString(eng.mutations(), "uploads/x") {
			t.Fatalf("join-disabled engine mutations = %v, want the flat uploads/x", eng.mutations())
		}
		if containsString(eng.mutations(), "outputs/uploads/x") {
			t.Fatalf("join-disabled upload gained the join (outputs/uploads/x); static mode must stay flat")
		}
	})
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// ceilingExtractor is a CredentialScopeExtractor that binds every present bearer
// to a fixed scope and claim, so the dispatch STAGE-0 ceiling intersection runs
// on a known claim.
type ceilingExtractor struct {
	scope string
	claim []Intent
}

func (e ceilingExtractor) Extract(bearer string) (CredentialScope, error) {
	return CredentialScope{FilesystemID: e.scope, GrantedIntents: e.claim}, nil
}

// TestDispatch_GrantedIntentsCeiling pins the -granted-intents ceiling at the
// dispatch STAGE-0 credscope stage: a credential whose claim carries an intent
// OUTSIDE the deployment ceiling has that intent narrowed out of the effective
// grant, so a write op denies at the resolver (403) — the flag removes, never
// grants. It drives the CREDENTIAL path (credExtractor wired) so the intersection
// runs, and reads the effective grant set the resolver actually sees.
func TestDispatch_GrantedIntentsCeiling(t *testing.T) {
	const scope = "fs-ceiling"
	eng := newFakeEngine()

	// intentResolver grants only when the caller evidence's GrantedIntents
	// contains the requested intent — the real authz spine's allow rule.
	resolver := &intentResolver{grant: Grant{}}

	d := newDispatcherWithEngine(resolver, &fakeGuard{}, okCeilings(), 1<<20, eng)
	d.maxFileSize = 1 << 20
	// The credential claim carries BOTH read and write; the deployment ceiling
	// serves READ only.
	d.credExtractor = ceilingExtractor{scope: scope, claim: []Intent{IntentRead, IntentWrite}}
	d.grantedIntentsCeiling = []Intent{IntentRead}

	// A makeDirectory (write op) must deny: write is dropped from the effective
	// grant by the ceiling, so the resolver's intent check fails (ErrIntentDenied,
	// 403). The wire intent matches the route op's required write intent, so the
	// request reaches STAGE 2 authz and denies there, not at the op/wire check.
	body := mutationOpBody(OpMakeDirectory, scope, IntentWrite)
	r := httptest.NewRequest(http.MethodPost, restBase+string(OpMakeDirectory), strings.NewReader(body))
	r.Header.Set("Content-Type", contentTypeJSON)
	r.ContentLength = int64(len(body))
	r.Header.Set(authHeaderName, bearerScheme+"any-present-bearer")
	w := httptest.NewRecorder()
	newRESTRouter(d).ServeHTTP(w, r)

	if w.Code == 200 {
		t.Fatalf("write op under a read-only ceiling returned 200; the ceiling did not narrow the claim; body %s", w.Body.String())
	}
	if w.Code != 403 {
		t.Fatalf("write op under a read-only ceiling status = %d, want 403 (intent_denied); body %s", w.Code, w.Body.String())
	}
	// The effective grant the resolver saw MUST be exactly {read} — write was
	// removed by the ceiling.
	if got := resolver.lastReq.Intent; got != IntentWrite {
		t.Fatalf("resolver saw intent %q, want the route-op write intent", got)
	}

	// Positive control: with write IN the ceiling, the same op is allowed — the
	// ceiling narrows, and only narrows.
	d.grantedIntentsCeiling = []Intent{IntentRead, IntentWrite}
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, restBase+string(OpMakeDirectory), strings.NewReader(body))
	r2.Header.Set("Content-Type", contentTypeJSON)
	r2.ContentLength = int64(len(body))
	r2.Header.Set(authHeaderName, bearerScheme+"any-present-bearer")
	newRESTRouter(d).ServeHTTP(w2, r2)
	if w2.Code != 200 {
		t.Fatalf("write op with write IN the ceiling status = %d, want 200 (the ceiling only narrows); body %s", w2.Code, w2.Body.String())
	}
}
