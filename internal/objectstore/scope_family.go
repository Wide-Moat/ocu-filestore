// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package objectstore

import (
	"fmt"
	"regexp"
)

// derivedShape matches any scope id ENDING in the fixed derived-scope suffix
// ("-" + 16 lowercase hex). It is the structural complement of a family's
// member shape: a BASE carrying this suffix is refused at construction, so the
// families of two distinct deployments are disjoint by construction -- with a
// fixed 17-byte suffix, base1+"-"+h1 == base2+"-"+h2 forces base1 == base2,
// and base1 == base2+"-"+h would make base1 derived-shaped, which no family
// admits as a base. Without this refusal a deployment whose base happened to
// be derived-shaped relative to another's would sit INSIDE that other
// deployment's family, and the wider family guard would admit a scope
// steering into the foreign backend prefix.
var derivedShape = regexp.MustCompile(`-[0-9a-f]{16}$`)

// ScopeFamily is the SINGLE source of the deployment scope-family predicate
// (ADR-0030 per-chat derivation x ADR-0013/0029 engine confinement): the base
// scope itself plus every legitimately-derived per-chat scope
// "<base>-<16 lowercase hex>". Both the scope-confined guard and the
// lazy-provision scaffolder decide membership through ONE ScopeFamily built at
// compose, so the admitting predicate and the scaffolding predicate can never
// drift apart -- two private copies of this rule are exactly how the D5
// composition defect arose. The zero value contains nothing (fail-closed).
type ScopeFamily struct {
	base string
	re   *regexp.Regexp
}

// NewScopeFamily builds the family rooted at base. It refuses a base that
// fails the scope-id shape guard, and -- load-bearing, see derivedShape -- a
// base that is itself derived-shaped.
func NewScopeFamily(base ScopeID) (ScopeFamily, error) {
	if err := validateScopeID(base); err != nil {
		return ScopeFamily{}, fmt.Errorf("scope family base: %w", err)
	}
	if derivedShape.MatchString(string(base)) {
		return ScopeFamily{}, fmt.Errorf("%w: family base %q is derived-shaped (ends in -<16 hex>)", ErrInvalidScopeID, base)
	}
	return ScopeFamily{
		base: string(base),
		re:   regexp.MustCompile("^" + regexp.QuoteMeta(string(base)) + "-[0-9a-f]{16}$"),
	}, nil
}

// Contains reports whether scope is a member of the family: the base itself,
// or "<base>-<16 lowercase hex>". The zero-value family contains nothing.
func (f ScopeFamily) Contains(scope ScopeID) bool {
	if f.re == nil {
		return false
	}
	s := string(scope)
	return s == f.base || f.re.MatchString(s)
}

// Base returns the family's base scope. Zero value returns "".
func (f ScopeFamily) Base() ScopeID { return ScopeID(f.base) }

// valid reports whether the family was built by NewScopeFamily (a zero value
// is not valid and must be refused by any constructor taking a family).
func (f ScopeFamily) valid() bool { return f.re != nil }
