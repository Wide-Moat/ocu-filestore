// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

// This file holds the intent->subtree map and the -granted-intents ceiling that
// realise the ADR-0029 engine-side scope-subtree resolution (component-04
// invariant 10). The map is consumed by the dispatch spine and the two
// data-plane ops to derive the join subtree from the ROUTE-OP-required intent
// (NFR-SEC-49: the route op is authoritative, never the wire hint). The ceiling
// is applied at the credscope stage — it narrows the credential's claim, never
// grants — so the existing authz spine keeps gating allow/deny unchanged.

// SubtreeMap maps an authorization intent to the engine-relative subtree the
// engine joins every file-op path under before the invariant-1 traversal check
// (ADR-0029 inv-10). The values are engine-relative with NO leading slash
// ("outputs", "uploads"); canonicalizePath prepends the value before path.Clean
// and rejects any cleaned result that escapes the join.
//
// A write-intent credential addressing "uploads/x" lands the distinct backend
// object "outputs/uploads/x" (the write subtree is prepended), so the read-only
// subtree is unreachable for writing — the ":ro" posture is engine-enforced,
// not a guest-mount artifact.
type SubtreeMap struct {
	// m maps intent to the engine-relative subtree. A nil/empty map disables the
	// join for every intent (For returns ""), which is the static-path mode
	// canonicalizePath preserves verbatim.
	m map[Intent]string
}

// DefaultSubtreeMap returns the pinned default map (ADR-0029 Decision bullet 2):
// write -> outputs (the RW sink), read -> uploads (RO input), preview -> uploads
// (RO input, non-downloadable regardless of stored tag). The map ships pinned so
// the minimal shelf runs zero-config; a deployment may override the values but
// can never bypass the join (see NewSubtreeMap). Preview MUST be present — the
// frozen intent axis is 3-valued {read, write, preview}.
func DefaultSubtreeMap() SubtreeMap {
	return SubtreeMap{m: map[Intent]string{
		IntentWrite:   "outputs",
		IntentRead:    "uploads",
		IntentPreview: "uploads",
	}}
}

// For returns the engine-relative subtree bound to intent, or "" when the intent
// is absent from the map (join-disabled for that intent). An empty return makes
// canonicalizePath fall back to static-path mode for the request.
func (s SubtreeMap) For(i Intent) string { return s.m[i] }

// ReadSubtree returns the engine-relative read-intent subtree the north
// human->sandbox create joins every uploaded object under (ADR-0029:46), or ""
// when the join is disabled (static-path mode, an empty map). It is the SAME
// value the south read-mount joins under, so a browser File-Pane upload lands
// where the agent's read plane looks (the default map pins it to "uploads"). An
// accessor on this documented config surface is public API, not a leaked
// private helper: the composition root injects this value into the north create
// at construction rather than the north hardcoding a landing const.
func (s SubtreeMap) ReadSubtree() string { return s.m[IntentRead] }

// enabled reports whether the map binds any subtree — a fully empty map means
// the join is disabled deployment-wide (the shipped static bind), a non-empty
// map means the join is active. Serve uses it to decide whether to wire the map
// onto the dispatcher at all.
func (s SubtreeMap) enabled() bool { return len(s.m) > 0 }

// NewSubtreeMap builds an OVERRIDE subtree map from the three engine-relative
// values a deployment supplies for {write, read, preview}. Each value is
// normalised (a single leading slash is trimmed) and validated: an empty value
// after trimming, or a value carrying a ".." component, is a wiring fault that
// fails loud (a deployment can override the join target, never disable the join
// by setting it empty). All three intents MUST carry a non-empty value — the
// frozen intent axis is 3-valued, so a map missing any of {read, write, preview}
// is refused. The returned map never grants a bypass: every intent it serves
// carries a real subtree.
func NewSubtreeMap(write, read, preview string) (SubtreeMap, error) {
	w, err := normalizeSubtree(write)
	if err != nil {
		return SubtreeMap{}, err
	}
	r, err := normalizeSubtree(read)
	if err != nil {
		return SubtreeMap{}, err
	}
	p, err := normalizeSubtree(preview)
	if err != nil {
		return SubtreeMap{}, err
	}
	// Disjointness boot-guard (ADR-0029:53): the WRITE subtree — the RW sink and
	// the downloadable-allow prefix — MUST be disjoint from both the READ and the
	// PREVIEW subtrees. A perverse override (e.g. read -> "outputs") would land the
	// north human->sandbox create (which joins the READ subtree, ADR-0029:46)
	// inside the write/downloadable prefix, making a human input egress-eligible
	// and reopening the NFR-SEC-73 exfil split. Read and preview MAY be equal (the
	// pinned default has both at "uploads"), so the guard is WRITE-vs-{read,preview}
	// only. It fails the BOOT loud, never the upload.
	if subtreesOverlap(w, r) || subtreesOverlap(w, p) {
		return SubtreeMap{}, ErrSubtreeOverlap
	}
	return SubtreeMap{m: map[Intent]string{
		IntentWrite:   w,
		IntentRead:    r,
		IntentPreview: p,
	}}, nil
}

// subtreesOverlap reports whether two engine-relative subtrees share a path
// region: they are equal, or one is a path-prefix of the other on a "/"
// component boundary. It mirrors the broker pathUnderPrefix semantics — "a"
// overlaps "a/b" and "a" == "a", but "ab" does NOT overlap "a" (the boundary is
// a whole component, never a raw byte prefix). Both inputs are already
// normalised (no leading slash, no ".." segment) by normalizeSubtree, so the
// comparison is on the clean engine-relative form. It compares "/"-delimited
// components (via splitSlash) so subtree.go keeps its zero-import convention.
func subtreesOverlap(a, b string) bool {
	if a == b {
		return true
	}
	return hasPathPrefix(a, b) || hasPathPrefix(b, a)
}

// hasPathPrefix reports whether prefix is a strict path-prefix of path on a
// component boundary: every component of prefix equals the leading component of
// path AND path has at least one further component. Equal paths are NOT a strict
// prefix (subtreesOverlap handles equality separately). "a" is a prefix of
// "a/b"; "ab" is NOT a prefix of "a" (component-boundary, never a byte prefix).
func hasPathPrefix(path, prefix string) bool {
	ps := splitSlash(prefix)
	ss := splitSlash(path)
	if len(ss) <= len(ps) {
		return false
	}
	for i := range ps {
		if ps[i] != ss[i] {
			return false
		}
	}
	return true
}

// normalizeSubtree trims a single leading slash and rejects an empty or
// traversal-bearing value. The engine-relative convention is no-leading-slash,
// so a supplied "/outputs" normalises to "outputs"; an empty value or one with a
// ".." component is a fail-closed wiring fault (ErrInvalidSubtree) — a
// deployment can never disable the join or point it out of the scope tree.
func normalizeSubtree(v string) (string, error) {
	if len(v) > 0 && v[0] == '/' {
		v = v[1:]
	}
	if v == "" {
		return "", ErrInvalidSubtree
	}
	for _, seg := range splitSlash(v) {
		if seg == ".." {
			return "", ErrInvalidSubtree
		}
	}
	return v, nil
}

// splitSlash splits an engine-relative path on "/" into its components. It is a
// tiny local helper so subtree.go carries no strings import churn beyond what
// engine.go already pulls in for the package.
func splitSlash(v string) []string {
	var out []string
	start := 0
	for i := 0; i < len(v); i++ {
		if v[i] == '/' {
			out = append(out, v[start:i])
			start = i + 1
		}
	}
	out = append(out, v[start:])
	return out
}

// intersectIntents returns the intents present in BOTH claim and ceiling — the
// EFFECTIVE grant set (ADR-0029 Decision bullet 5). The ceiling (-granted-intents)
// is a static deployment flag naming the intents the deployment serves; it NEVER
// grants. An intent in the claim but outside the ceiling is dropped; a MISSING
// claim (nil/empty) is never substituted by a ceiling value, so the effective
// set is empty and every op denies at the resolver. The result preserves the
// claim's order and contains no duplicates beyond the claim's own.
func intersectIntents(claim, ceiling []Intent) []Intent {
	if len(claim) == 0 {
		return nil
	}
	inCeiling := make(map[Intent]struct{}, len(ceiling))
	for _, c := range ceiling {
		inCeiling[c] = struct{}{}
	}
	out := make([]Intent, 0, len(claim))
	for _, i := range claim {
		if _, ok := inCeiling[i]; ok {
			out = append(out, i)
		}
	}
	return out
}
