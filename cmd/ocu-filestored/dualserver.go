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
// a single-listener fault does today. Close shuts BOTH down concurrently and
// joins their errors so neither teardown is dropped behind the other.
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

// Close shuts both listeners down CONCURRENTLY and joins their errors so a
// teardown fault on either plane is never silently dropped. A nil north closes
// the south alone.
//
// The two closes overlap deliberately. Each listener's Close is a bounded drain,
// and running them one after the other would cost their SUM — every shipped
// stop-grace period is sized on the concurrent model, so a sequential close puts
// a graceful stop over the deadline and the service manager SIGKILLs the daemon
// mid-drain. Worse, a listener keeps ACCEPTING new connections until its own
// Close runs (http.Server.Shutdown closes only its own listener), so a
// sequential close leaves the second plane admitting fresh work for the whole of
// the first plane's drain — after the operator asked the daemon to stop.
//
// Overlapping is safe because the two listeners are physically distinct binds
// over the SAME stateless adapters, which already serve both planes at once
// while running; a concurrent drain adds no sharing that Serve does not have.
// Neither drain depends on the other having finished.
//
// TestDualServerClosesBothListenersConcurrently pins the overlap;
// TestShippedStopDeadlinesCoverWorstCaseStopCost sizes the deadlines on it.
func (d *dualServer) Close() error {
	if d.north == nil {
		return d.south.Close()
	}

	northErr := make(chan error, 1)
	go func() { northErr <- d.north.Close() }()
	southErr := d.south.Close()
	return errors.Join(southErr, <-northErr)
}
