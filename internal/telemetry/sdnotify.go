// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry

import (
	"net"
	"os"
)

// SdNotifyReady sends the READY=1 notification to systemd via the
// NOTIFY_SOCKET unix datagram socket. It returns nil when NOTIFY_SOCKET is
// unset or empty (the daemon is not managed by systemd, or the integration is
// disabled) — an unset socket is not an error; the daemon's fail-soft posture
// for optional integrations applies. Any dial or write error is returned so
// the caller can log it without crashing.
func SdNotifyReady() error {
	return sdNotify("READY=1")
}

// SdNotifyStopping sends the STOPPING=1 notification to systemd via the
// NOTIFY_SOCKET unix datagram socket. Same no-op and error semantics as
// SdNotifyReady.
func SdNotifyStopping() error {
	return sdNotify("STOPPING=1")
}

// sdNotify opens the NOTIFY_SOCKET, writes msg as a datagram, and closes.
// If NOTIFY_SOCKET is unset or empty it returns nil immediately. Errors from
// dial or write are returned; the caller decides whether to log or ignore them.
func sdNotify(msg string) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	conn, err := net.Dial("unixgram", sock)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	return err
}
