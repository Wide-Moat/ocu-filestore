// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux

package southface

import (
	"errors"
	"net"
	"syscall"
)

// extractPeerCred reads the kernel-attested peer credentials of a unix-socket
// connection via SO_PEERCRED (NFR-SEC-76). The credentials are supplied by the
// kernel at connect time, not by the peer, so they cannot be forged across the
// socket. The host-peer definition is uid == broker uid (os.Getuid); the gate
// drops any uid that does not match before a single HTTP byte is parsed.
//
// This is the Linux-real implementation; the darwin counterpart is a loud-skip
// stub. Linux CI is the enforcement target.
func extractPeerCred(conn net.Conn) (uid uint32, pid int32, err error) {
	uc, ok := conn.(syscallConner)
	if !ok {
		return 0, 0, errors.New("southface: connection does not expose SyscallConn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var (
		cred    *syscall.Ucred
		credErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return 0, 0, ctrlErr
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return cred.Uid, cred.Pid, nil
}
