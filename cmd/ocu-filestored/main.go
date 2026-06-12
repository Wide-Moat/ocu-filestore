// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command ocu-filestored is the storage-broker daemon (component-04): one
// process, two faces (guest-mount south, data-plane-client north), one
// backend credential. This build is a wiring scaffold: it parses and
// validates its flag surface, then refuses with a typed error — every seam
// it wires is stubbed until its implementation PR lands.
//
// The south-face flag surface is API and frozen here: -south-socket-dir (the
// host-owned 0700 directory the south face provisions per-session sockets
// into), -audit-sink (the audit gate's file-sink path), -profile and
// -tenancy (the admission profile/tenancy axes). The values for -profile and
// -tenancy are validated eagerly, but the full-serve path still refuses with
// errNotBuilt — the listener, admission, and audit seams are not wired until
// the composition phase. The north-face ingress is distinct from any MCP
// listener by deploy policy.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
)

// errNotBuilt is the scaffold refusal: the broker's seams are stubs in this
// build. Match it with errors.Is.
var errNotBuilt = errors.New("ocu-filestored: storage broker not implemented in this build")

// errBadProfile rejects an admission profile outside the legal set. Match it
// with errors.Is.
var errBadProfile = errors.New("ocu-filestored: unknown admission profile")

// errBadTenancy rejects a tenancy mode outside the legal set. Match it with
// errors.Is.
var errBadTenancy = errors.New("ocu-filestored: unknown tenancy mode")

// legalProfiles mirrors the admission profile vocabulary the daemon binds to
// in the composition phase (the admission seam lives on its own branch); the
// value set is reproduced here so the flag validates without importing the
// unmerged package.
var legalProfiles = map[string]struct{}{
	"trusted_operator":   {},
	"internal_workforce": {},
	"untrusted":          {},
}

// legalTenancies mirrors the admission tenancy vocabulary, reproduced locally
// for the same reason as legalProfiles.
var legalTenancies = map[string]struct{}{
	"single-tenant": {},
	"multi-tenant":  {},
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ocu-filestored:", err)
		os.Exit(1)
	}
}

// run parses and validates the deployment flag surface (north ingress,
// backend engine, south-face socket directory, audit sink, admission profile
// and tenancy), then refuses with errNotBuilt — the serve path is unbuilt
// until the composition phase.
func run(args []string) error {
	fs := flag.NewFlagSet("ocu-filestored", flag.ContinueOnError)

	fs.String("north-listen", "127.0.0.1:7080",
		"file/UI ingress bind address (north face); distinct from any MCP listener by deploy policy")
	engine := fs.String("engine", "local-volume",
		"backend object-store engine: local-volume | s3 (ADR-0010)")
	fs.Int("max-request-bytes", 52428800,
		"north-face inbound body ceiling, rejected pre-buffer (NFR-SEC-78); default 50 MiB")
	fs.String("south-socket-dir", "/run/ocu-filestore/sessions",
		"host-owned 0700 directory the south face provisions per-session unix sockets into")
	fs.String("audit-sink", "/var/log/ocu-filestore/audit.log",
		"audit gate file-sink path; an audit-write failure denies the operation (NFR-SEC-79)")
	profile := fs.String("profile", "trusted_operator",
		"admission profile: trusted_operator | internal_workforce | untrusted")
	tenancy := fs.String("tenancy", "single-tenant",
		"tenancy mode: single-tenant | multi-tenant")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if _, err := objectstore.ParseEngine(*engine); err != nil {
		return err
	}
	if _, ok := legalProfiles[*profile]; !ok {
		return fmt.Errorf("%w: %q", errBadProfile, *profile)
	}
	if _, ok := legalTenancies[*tenancy]; !ok {
		return fmt.Errorf("%w: %q", errBadTenancy, *tenancy)
	}
	return errNotBuilt
}
