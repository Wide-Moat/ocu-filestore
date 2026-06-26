// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"

	"github.com/Wide-Moat/ocu-filestore/internal/northface"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// dualServer fans the southface.Server lifecycle across the south mount RPC
// listener and the north Files-API listener (Mount B). It honours the
// southface.Server seam so the daemon's serveUntilSignal drives both through one
// handle.
//
// Serve runs both listeners concurrently and returns the FIRST listener error
// (whichever fails first) — a fault on either plane stops the daemon, exactly as
// a single-listener fault does today. Close shuts BOTH down and joins their
// errors so neither teardown is dropped behind the other.
//
// A nil north listener degrades to south-only: Serve/Close act on the south
// listener alone (the --handle-store-disabled phase, where Mount B is not
// constructed). The two listeners are PHYSICALLY distinct binds — the dualServer
// never multiplexes them onto one socket.
type dualServer struct {
	south southface.Server
	north northface.Server
}

// newDualServer wraps the south listener and an optional north listener. A nil
// north yields a south-only server (no Mount B this phase).
func newDualServer(south southface.Server, north northface.Server) *dualServer {
	return &dualServer{south: south, north: north}
}

// compile-time proof a *dualServer honours the southface.Server seam the daemon
// lifecycle drives.
var _ southface.Server = (*dualServer)(nil)

// Serve runs the south and north listeners concurrently and returns the first
// error either produces. A nil north degrades to serving the south alone. The
// caller's Close unblocks both Serves (each collapses its clean shutdown to
// nil), so this returns nil on a clean stop.
func (d *dualServer) Serve() error {
	if d.north == nil {
		return d.south.Serve()
	}

	errCh := make(chan error, 2)
	go func() { errCh <- d.south.Serve() }()
	go func() { errCh <- d.north.Serve() }()

	// Return the FIRST result. The caller's Close shuts the OTHER listener down
	// (collapsing its clean shutdown to nil); serveUntilSignal drains the
	// remaining goroutine via Close, so a leak is not possible here.
	return <-errCh
}

// Close shuts both listeners down and joins their errors so a teardown fault on
// either plane is never silently dropped. A nil north closes the south alone.
func (d *dualServer) Close() error {
	southErr := d.south.Close()
	if d.north == nil {
		return southErr
	}
	northErr := d.north.Close()
	return errors.Join(southErr, northErr)
}
