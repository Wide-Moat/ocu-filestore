// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// TestFanOutSinkAbsentByDefault pins the minimal shelf: with no
// -audit-fanout-sink the daemon composes and fans out nowhere. The file-system
// sink alone is the whole minimal-shelf tamper-evidence story, so an
// unconfigured fan-out is the normal deployment, never an error.
func TestFanOutSinkAbsentByDefault(t *testing.T) {
	cfg := validBrokerConfig(t)
	if cfg.auditFanOutPath != "" {
		t.Fatalf("the default config carries a fan-out path %q", cfg.auditFanOutPath)
	}
	m := telemetry.NewBrokerMetrics("test")
	l := observ.NewLogger(&strings.Builder{}, slog.LevelDebug)

	srv, err := compose(cfg, l, m)
	if err != nil {
		t.Fatalf("compose with no fan-out sink: %v", err)
	}
	defer srv.Close()
}

// TestFanOutSinkUnopenableAbortsBoot pins the fail-closed half. A configured
// path that cannot be opened is a misconfiguration, and booting anyway would
// leave an operator believing events reach a collector they never reach —
// worse than refusing to start, because the belief outlives the boot log.
func TestFanOutSinkUnopenableAbortsBoot(t *testing.T) {
	cfg := validBrokerConfig(t)
	// A path under a directory that does not exist: open fails, and no amount
	// of retrying inside the daemon would fix it.
	cfg.auditFanOutPath = filepath.Join(shortDir(t), "no-such-dir", "fanout.jsonl")

	m := telemetry.NewBrokerMetrics("test")
	l := observ.NewLogger(&strings.Builder{}, slog.LevelDebug)

	srv, err := compose(cfg, l, m)
	if err == nil {
		srv.Close()
		t.Fatal("compose accepted an unopenable fan-out path: the daemon would run " +
			"with a fan-out that silently goes nowhere")
	}
	if !strings.Contains(err.Error(), "fan-out") {
		t.Fatalf("compose error %q does not name the fan-out sink", err)
	}
}

// TestFanOutSinkWiredWhenConfigured pins that a usable path actually reaches
// the sink. Without this the two tests above would both pass against a daemon
// that parsed the flag and never wired anything.
func TestFanOutSinkWiredWhenConfigured(t *testing.T) {
	cfg := validBrokerConfig(t)
	cfg.auditFanOutPath = filepath.Join(shortDir(t), "fanout.jsonl")

	m := telemetry.NewBrokerMetrics("test")
	l := observ.NewLogger(&strings.Builder{}, slog.LevelDebug)

	srv, err := compose(cfg, l, m)
	if err != nil {
		t.Fatalf("compose with a usable fan-out path: %v", err)
	}
	defer srv.Close()

	// Opening the sink creates the file; its absence would mean the path was
	// parsed into config and never handed to a publisher.
	if _, err := os.Stat(cfg.auditFanOutPath); err != nil {
		t.Fatalf("the fan-out sink file was not created at %q: %v", cfg.auditFanOutPath, err)
	}
}
