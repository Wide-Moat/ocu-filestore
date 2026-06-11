// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command ocu-filestored is the storage-broker daemon (component-04): one
// process, two faces (guest-mount south, data-plane-client north), one
// backend credential. This build is a wiring scaffold: it parses and
// validates its flag surface, then refuses with a typed error — every seam
// it wires is stubbed until its implementation PR lands.
//
// Deliberately missing flags: the south-face transport binding, the
// credential source, the audit sink, and the per-session ceilings need an
// implementation to mean anything — flag names are API, so none ships
// before its seam does. The north-face ingress is distinct from any MCP
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

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ocu-filestored:", err)
		os.Exit(1)
	}
}

// run parses and validates the deployment flag surface (north ingress,
// backend engine), then refuses with errNotBuilt.
func run(args []string) error {
	fs := flag.NewFlagSet("ocu-filestored", flag.ContinueOnError)

	fs.String("north-listen", "127.0.0.1:7080",
		"file/UI ingress bind address (north face); distinct from any MCP listener by deploy policy")
	engine := fs.String("engine", "local-volume",
		"backend object-store engine: local-volume | s3 (ADR-0010)")
	fs.Int("max-request-bytes", 52428800,
		"north-face inbound body ceiling, rejected pre-buffer (NFR-SEC-78); default 50 MiB")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if _, err := objectstore.ParseEngine(*engine); err != nil {
		return err
	}
	return errNotBuilt
}
