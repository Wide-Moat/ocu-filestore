// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build darwin

package southface

import (
	"errors"
	"net"
	"testing"
)

// TestExtractPeerCredDarwinSentinel pins the darwin loud-skip stub: there is no
// SO_PEERCRED equivalent on this build target, so extractPeerCred returns the
// errPeerCredUnsupported sentinel (matchable with errors.Is) regardless of the
// connection. The accept gate treats this as "no host-peer match" and closes
// the connection, so the SEC-76 peer-cred enforcement is Linux-real; this test
// closes the darwin-only cold stub and proves the gate has a sentinel to key on.
func TestExtractPeerCredDarwinSentinel(t *testing.T) {
	// A real (closed) unix socket pair: the stub ignores the conn entirely, but
	// passing a genuine net.Conn (not nil) proves the sentinel is unconditional
	// rather than a nil-guard artifact.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	uid, pid, err := extractPeerCred(c1)
	if !errors.Is(err, errPeerCredUnsupported) {
		t.Fatalf("extractPeerCred err = %v, want errPeerCredUnsupported (darwin loud-skip stub)", err)
	}
	if uid != 0 || pid != 0 {
		t.Fatalf("extractPeerCred = (uid=%d, pid=%d), want (0, 0) on the unsupported path", uid, pid)
	}
}
