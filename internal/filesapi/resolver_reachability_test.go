// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/authz"
	"github.com/Wide-Moat/ocu-filestore/internal/broker"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// TestShippedGrantLeavesResolverNoAxisToFail is the LEDGER for the reachability
// paragraph on fencedGrantedIntents. It is NOT an assertion that the current
// posture is the one we want — it is the opposite: it records, in a form that
// reds, that under the composition the daemon actually builds, the Resolver has
// no axis left to fail on, so this package's resolver-error deny arms cannot be
// reached by any deployment input.
//
// It asks the SHIPPED resolver the SHIPPED scope source's grant, in each of the
// exact ResolveRequest / CallerEvidence shapes the six served verbs build:
//
//   - the resolver is broker.NewResolver(authz.New(
//     broker.NewPrefixDownloadablePolicy(cfg.dlPrefixes))) — the one
//     cmd/ocu-filestored/main.go wires into filesapi.Deps.Resolver;
//   - the scope is NewFencedScopeSource().Scope(req) — the one main.go wires
//     into filesapi.Deps.Scope, with no flag to swap it;
//   - the per-verb Path/Intent/GrantedIntents triples are copied from the
//     handlers (list.go, metadata.go, content.go, archive.go, delete.go,
//     create.go).
//
// The prefix set is the only deployment-tunable input on this path, so the table
// runs both an in-prefix and an out-of-prefix path: neither changes the verdict,
// because the prefix policy resolves a downloadable VALUE and never an error.
//
// It reds when the answer changes — which is the point. If the F9 scope source
// starts carrying a real per-verb intent grant (the open owner question), or a
// tag source that can fail replaces the prefix policy, or a handler stops
// deriving both scope fields from the same attested id, some shape here starts
// returning an error and this test fails. Whoever makes that change must then
// rewrite BOTH this test and the fencedGrantedIntents paragraph together, which
// is exactly the coupling the ledger exists to force. The complementary pin is
// TestFencedScopeSourcePresentHeader, which fixes the grant itself at [read].
func TestShippedGrantLeavesResolverNoAxisToFail(t *testing.T) {
	// The resolver exactly as the composition root builds it. "outputs" stands in
	// for cfg.dlPrefixes; the value is irrelevant to the verdict and the table
	// below proves it by probing on both sides of the prefix boundary.
	resolver := broker.NewResolver(authz.New(broker.NewPrefixDownloadablePolicy([]string{"outputs"})))

	// The scope exactly as the shipped ScopeSource derives it from an F9 request.
	req := httptest.NewRequest(http.MethodGet, filesRoot, nil)
	req.Header.Set(fencedScopeHeader, "fs-fleet")
	ps, ok := NewFencedScopeSource().Scope(req)
	if !ok {
		t.Fatal("the shipped scope source refused a well-formed attested header")
	}

	// Each row is one served verb's Resolve call, verbatim from its handler.
	cases := []struct {
		verb     string
		path     string
		intent   southface.Intent
		evidence []southface.Intent
	}{
		{"list", listScopeRootPath, southface.IntentRead, ps.GrantedIntents},
		{"metadata (out of prefix)", "uploads/a.txt", southface.IntentRead, ps.GrantedIntents},
		{"metadata (in prefix)", "outputs/a.txt", southface.IntentRead, ps.GrantedIntents},
		{"content (out of prefix)", "uploads/a.txt", southface.IntentRead, ps.GrantedIntents},
		{"content (in prefix)", "outputs/a.txt", southface.IntentRead, ps.GrantedIntents},
		{"archive member", "outputs/a.txt", southface.IntentRead, ps.GrantedIntents},
		{"delete", "uploads/a.txt", southface.IntentWrite, writeEvidenceIntents(ps)},
		{"create", "uploads/a.txt", southface.IntentWrite, writeEvidenceIntents(ps)},
	}
	for _, c := range cases {
		t.Run(c.verb, func(t *testing.T) {
			rr := southface.ResolveRequest{Filesystem: ps.FilesystemID, Path: c.path, Intent: c.intent}
			ev := southface.CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: c.evidence}
			if _, err := resolver.Resolve(context.Background(), ev, rr); err != nil {
				t.Fatalf("shipped resolver denied %s (path=%q intent=%s evidence=%v): %v\n"+
					"The reachability paragraph on fencedGrantedIntents says no deployment input can\n"+
					"reach this package's resolver-error deny arms. That is no longer true. Update the\n"+
					"paragraph and this ledger together.",
					c.verb, c.path, c.intent, c.evidence, err)
			}
		})
	}
}
