// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build darwin

package southface

import (
	"errors"
	"net"
)

// errPeerCredUnsupported reports that this build target has no SO_PEERCRED
// equivalent wired in. Match it with errors.Is.
var errPeerCredUnsupported = errors.New("southface: peer-cred extraction unsupported on this platform")

// extractPeerCred is the darwin loud-skip stub: the peer-cred accept gate
// (NFR-SEC-76) is enforced on Linux, the deployment target. The host-peer
// definition is uid == broker uid (os.Getuid), confirmed in the composition
// phase; darwin only needs to compile so the package cross-builds and the
// Linux-gated tests can loud-skip via runtime.GOOS.
func extractPeerCred(conn net.Conn) (uid uint32, pid int32, err error) {
	_ = conn
	return 0, 0, errPeerCredUnsupported
}
