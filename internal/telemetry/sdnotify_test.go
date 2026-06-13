// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// TestSdNotifyReadyNoopWhenUnset pins the no-op contract: SdNotifyReady returns
// nil when NOTIFY_SOCKET is unset, without panicking or dialling anything.
func TestSdNotifyReadyNoopWhenUnset(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := telemetry.SdNotifyReady(); err != nil {
		t.Fatalf("SdNotifyReady (unset): got %v, want nil", err)
	}
}

// TestSdNotifyStoppingNoopWhenUnset pins the same for SdNotifyStopping.
func TestSdNotifyStoppingNoopWhenUnset(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := telemetry.SdNotifyStopping(); err != nil {
		t.Fatalf("SdNotifyStopping (unset): got %v, want nil", err)
	}
}

// TestSdNotifyReadyWritesDatagram pins the READY=1 datagram: when NOTIFY_SOCKET
// is set to a bound unixgram socket, SdNotifyReady dials and writes exactly
// "READY=1".
func TestSdNotifyReadyWritesDatagram(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "notify.sock")

	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer ln.Close()

	t.Setenv("NOTIFY_SOCKET", sockPath)
	if err := telemetry.SdNotifyReady(); err != nil {
		t.Fatalf("SdNotifyReady: got %v, want nil", err)
	}

	buf := make([]byte, 128)
	n, err := ln.Read(buf)
	if err != nil {
		t.Fatalf("Read from notify socket: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("SdNotifyReady datagram: got %q, want %q", got, "READY=1")
	}
}

// TestSdNotifyStoppingWritesDatagram pins the STOPPING=1 datagram: when
// NOTIFY_SOCKET is set, SdNotifyStopping writes exactly "STOPPING=1".
func TestSdNotifyStoppingWritesDatagram(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "notify.sock")

	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer ln.Close()

	t.Setenv("NOTIFY_SOCKET", sockPath)
	if err := telemetry.SdNotifyStopping(); err != nil {
		t.Fatalf("SdNotifyStopping: got %v, want nil", err)
	}

	buf := make([]byte, 128)
	n, err := ln.Read(buf)
	if err != nil {
		t.Fatalf("Read from notify socket: %v", err)
	}
	if got := string(buf[:n]); got != "STOPPING=1" {
		t.Fatalf("SdNotifyStopping datagram: got %q, want %q", got, "STOPPING=1")
	}
}

// TestSdNotifySocketEnvVarRespected pins that each call reads NOTIFY_SOCKET
// at call time (not at package init), so t.Setenv is effective.
func TestSdNotifySocketEnvVarRespected(t *testing.T) {
	// First: no socket — no-op.
	t.Setenv("NOTIFY_SOCKET", "")
	if err := telemetry.SdNotifyReady(); err != nil {
		t.Fatalf("first call (unset): %v", err)
	}

	// Second: valid socket — must write.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "n2.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer ln.Close()
	os.Setenv("NOTIFY_SOCKET", sockPath) // intentional: t.Setenv would conflict with first t.Setenv
	defer os.Unsetenv("NOTIFY_SOCKET")

	if err := telemetry.SdNotifyReady(); err != nil {
		t.Fatalf("second call (set): %v", err)
	}
	buf := make([]byte, 128)
	n, _ := ln.Read(buf)
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("second call datagram: got %q, want READY=1", got)
	}
}
