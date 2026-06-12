// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// serveFakeResolver is a minimal Resolver that always grants. The Serve
// lifecycle tests never drive a request through it; they only need a non-nil
// seam so the wiring guard passes.
type serveFakeResolver struct{}

func (serveFakeResolver) Resolve(context.Context, any, ResolveRequest) (Grant, error) {
	return Grant{}, nil
}

// serveFakeGuard always mandates successfully.
type serveFakeGuard struct{}

func (serveFakeGuard) Mandate(context.Context, any) error { return nil }

// serveFakeEngine is a do-nothing engine; the Serve lifecycle tests register
// it only so the dispatcher wires the handler registry.
type serveFakeEngine struct{}

func (serveFakeEngine) List(context.Context, string, string) ([]FileInfo, error) {
	return nil, nil
}
func (serveFakeEngine) Stat(context.Context, string, string) (FileInfo, error) {
	return FileInfo{}, nil
}
func (serveFakeEngine) MakeDir(context.Context, string, string) error                { return nil }
func (serveFakeEngine) MoveDir(context.Context, string, string, string, bool) error  { return nil }
func (serveFakeEngine) RemoveDir(context.Context, string, string) error              { return nil }
func (serveFakeEngine) CopyFile(context.Context, string, string, string, bool) error { return nil }
func (serveFakeEngine) MoveFile(context.Context, string, string, string, bool) error { return nil }
func (serveFakeEngine) RemoveFile(context.Context, string, string) error             { return nil }
func (serveFakeEngine) ReadRange(context.Context, string, string, int64, int64, io.Writer) error {
	return nil
}
func (serveFakeEngine) WriteStream(context.Context, string, string, io.Reader, bool) error {
	return nil
}

// serveAllowAllChecker is a peerChecker that admits every connection as the
// host uid, so the lifecycle tests can dial without a Linux peer-cred path.
func serveAllowAllChecker(uid uint32) peerChecker {
	return func(net.Conn) (uint32, int32, error) { return uid, 0, nil }
}

func serveValidConfig(t *testing.T, dir string) Config {
	t.Helper()
	return Config{
		Resolver:          serveFakeResolver{},
		Guard:             serveFakeGuard{},
		Ceilings:          ceilingsRegistryStub(),
		Engine:            serveFakeEngine{},
		Registry:          NewSessionRegistry(),
		Entry:             SessionEntry{FilesystemID: "fs-serve-01", GrantedIntents: []Intent{IntentRead, IntentWrite}},
		Dir:               dir,
		SizeCeiling:       4 << 20,
		BrokerMaxFileSize: 1 << 30,
		CheckPeer:         serveAllowAllChecker(7),
		HostUID:           7,
	}
}

// ceilingsRegistryStub returns a non-enforcing CeilingsRegistry for the Serve
// lifecycle tests. A nil-safe in-package fake keeps the test independent of
// the broker adapter package.
func ceilingsRegistryStub() CeilingsRegistry { return serveFakeCeilings{} }

type serveFakeCeilings struct{}

func (serveFakeCeilings) Session(string) CeilingsSession { return serveFakeSession{} }
func (serveFakeCeilings) Release(string)                 {}

type serveFakeSession struct{}

func (serveFakeSession) TryConsumeOp() error      { return nil }
func (serveFakeSession) AcquireBytes(int64) error { return nil }
func (serveFakeSession) ReleaseBytes(int64)       {}
func (serveFakeSession) TryAcquireFD() error      { return nil }
func (serveFakeSession) ReleaseFD()               {}

// TestServeRejectsUnsetBrokerMaxFileSize pins SEC-46/78: a non-positive
// BrokerMaxFileSize is a wiring fault that returns a typed error, never a
// silent default.
func TestServeRejectsUnsetBrokerMaxFileSize(t *testing.T) {
	dir := shortSocketDir(t)
	for _, bad := range []int64{0, -1} {
		cfg := serveValidConfig(t, dir)
		cfg.BrokerMaxFileSize = bad
		if _, err := Serve(cfg); !errors.Is(err, ErrBrokerMaxFileSizeUnset) {
			t.Fatalf("Serve(BrokerMaxFileSize=%d): got %v, want ErrBrokerMaxFileSizeUnset", bad, err)
		}
	}
}

// TestServeRejectsNilSeams pins the fail-loud wiring guard: a nil
// Resolver/Guard/Engine returns ErrSeamMissing, never a latent nil-deref on
// the serve path.
func TestServeRejectsNilSeams(t *testing.T) {
	dir := shortSocketDir(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"nil_resolver", func(c *Config) { c.Resolver = nil }},
		{"nil_guard", func(c *Config) { c.Guard = nil }},
		{"nil_engine", func(c *Config) { c.Engine = nil }},
		{"nil_ceilings", func(c *Config) { c.Ceilings = nil }},
		{"nil_registry", func(c *Config) { c.Registry = nil }},
		{"nil_checkpeer", func(c *Config) { c.CheckPeer = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := serveValidConfig(t, dir)
			tc.mutate(&cfg)
			if _, err := Serve(cfg); !errors.Is(err, ErrSeamMissing) {
				t.Fatalf("Serve(%s): got %v, want ErrSeamMissing", tc.name, err)
			}
		})
	}
}

// TestServeSetsMaxFileSizeFromConfig pins finding #2: the returned server's
// dispatcher carries maxFileSize == cfg.BrokerMaxFileSize, NOT sizeCeiling.
// This is the only place the unexported field is set from a flag value.
func TestServeSetsMaxFileSizeFromConfig(t *testing.T) {
	dir := shortSocketDir(t)
	cfg := serveValidConfig(t, dir)
	cfg.SizeCeiling = 4 << 20
	cfg.BrokerMaxFileSize = 123_456_789
	srv, err := Serve(cfg)
	if err != nil {
		t.Fatalf("Serve: unexpected error %v", err)
	}
	defer srv.Close()
	sess, ok := srv.(*session)
	if !ok {
		t.Fatalf("Serve returned %T, want *session", srv)
	}
	d, ok := sess.srv.Handler.(*dispatcher)
	if !ok {
		t.Fatalf("session handler is %T, want *dispatcher", sess.srv.Handler)
	}
	if d.maxFileSize != cfg.BrokerMaxFileSize {
		t.Fatalf("maxFileSize = %d, want %d (BrokerMaxFileSize, not sizeCeiling)", d.maxFileSize, cfg.BrokerMaxFileSize)
	}
	if d.maxFileSize == d.sizeCeiling {
		t.Fatalf("maxFileSize must be distinct from sizeCeiling; both are %d", d.maxFileSize)
	}
}

// TestServeServesAndCloses pins the lifecycle: the returned Server serves on a
// real unix socket and Close releases the scope binding and unlinks the
// socket.
func TestServeServesAndCloses(t *testing.T) {
	dir := shortSocketDir(t)
	cfg := serveValidConfig(t, dir)
	srv, err := Serve(cfg)
	if err != nil {
		t.Fatalf("Serve: unexpected error %v", err)
	}
	sess := srv.(*session)
	socketPath := sess.socketPath
	if filepath.Dir(socketPath) != dir {
		t.Fatalf("socket %q not under dir %q", socketPath, dir)
	}
	if _, ok := cfg.Registry.Lookup(socketPath); !ok {
		t.Fatalf("Serve did not provision the scope binding for %q", socketPath)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()
	// Give Serve a moment to enter the accept loop, then dial once to prove
	// the socket is live.
	time.Sleep(20 * time.Millisecond)
	conn, dialErr := net.Dial("unix", socketPath)
	if dialErr != nil {
		t.Fatalf("dial %q: %v", socketPath, dialErr)
	}
	_ = conn.Close()

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("Serve returned %v, want nil on clean shutdown", err)
	}
	if _, ok := cfg.Registry.Lookup(socketPath); ok {
		t.Fatalf("Close did not release the scope binding for %q", socketPath)
	}
	if _, statErr := os.Stat(socketPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Close did not unlink the socket %q (stat err %v)", socketPath, statErr)
	}
}

// TestHostPeerCheckerIsTheRealGate pins that HostPeerChecker returns the
// package's real extractPeerCred wiring (the SEC-76 gate), not a
// reimplementation.
func TestHostPeerCheckerIsTheRealGate(t *testing.T) {
	if HostPeerChecker() == nil {
		t.Fatal("HostPeerChecker returned nil; the SEC-76 gate must be wired")
	}
}
