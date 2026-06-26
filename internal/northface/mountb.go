// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package northface

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/observ"
)

// errMountConfig refuses a misconfigured Mount B north listener (empty bind
// address, an unreadable/unparseable cert+key pair, or a nil handler). A defect
// fails loud at construction rather than binding a half-configured listener.
// Match it with errors.Is.
var errMountConfig = errors.New("northface: Mount B misconfigured")

// Timeouts for the north TLS listener mirror the south face's posture
// (NFR-SEC-46): a header timeout bounds a peer that never finishes its request
// headers, and an idle timeout reaps idle keep-alive connections. ReadTimeout /
// WriteTimeout stay UNSET so a legitimately-long content stream is not capped
// connection-wide; the content handler bounds a stall per write instead.
const (
	mountReadHeaderTimeout = 10 * time.Second
	mountIdleTimeout       = 2 * time.Minute
	mountDrainTimeout      = 25 * time.Second
)

// MountB is the north Files-API host-leg listener (Mount B): a dedicated TLS
// HTTP server on a SEPARATE bind from the south mount RPC, serving the injected
// Files-API handler. It honours the northface.Server seam (Serve/Close).
//
// It reuses the south face's certificate SOURCE by loading the SAME cert/key
// PEM paths independently — two tls.Certificate values from one PEM pair (one
// identity, two listeners), satisfying the ADR-0023 SHAPE ruling. It is NOT a
// path-prefix on the south server and does NOT route through the south spine:
// the separate bind is the physical trust boundary between the no-credential
// /v1/files plane and the egress-credential south plane.
type MountB struct {
	bindAddr string
	srv      *http.Server
}

// compile-time proof a *MountB honours the northface.Server seam.
var _ Server = (*MountB)(nil)

// NewMountB builds the north Files-API listener bound to bindAddr, serving
// handler over the certificate at certFile/keyFile (the SAME paths the south
// face loads — one identity, two listeners). The certificate is loaded at
// construction (a defect refuses startup, never a lazy first-request failure).
// The TLS config pins MinVersion TLS 1.2 and advertises h2. A nil logger yields
// a discard-all logger. The listener does not accept connections until Serve is
// called.
func NewMountB(bindAddr, certFile, keyFile string, handler http.Handler, logger *slog.Logger) (*MountB, error) {
	if bindAddr == "" {
		return nil, fmt.Errorf("%w: a bind address is required", errMountConfig)
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("%w: a TLS certificate and key are required", errMountConfig)
	}
	if handler == nil {
		return nil, fmt.Errorf("%w: a handler is required", errMountConfig)
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		// The wrapped error carries the PATHS (not a key byte) — LoadX509KeyPair
		// never interpolates the private-key material into its error text.
		return nil, fmt.Errorf("%w: %v", errMountConfig, err)
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	srv := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ErrorLog:          observ.ErrorLog(logger),
		ReadHeaderTimeout: mountReadHeaderTimeout,
		IdleTimeout:       mountIdleTimeout,
	}

	return &MountB{bindAddr: bindAddr, srv: srv}, nil
}

// Serve binds the TLS listener and accepts connections until Close shuts the
// server down. A clean shutdown returns nil (http.ErrServerClosed collapsed to
// nil). The certificate is already loaded into the server's TLSConfig, so
// ServeTLS is called with empty file arguments.
func (m *MountB) Serve() error {
	ln, err := net.Listen("tcp", m.bindAddr)
	if err != nil {
		return err
	}
	err = m.srv.ServeTLS(ln, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close shuts the server down with a BOUNDED drain. In-flight operations get up
// to mountDrainTimeout to finish or fail fail-closed; stragglers past the bound
// are force-closed. A drain expiry never hides a force-close error — both
// surface via errors.Join.
func (m *MountB) Close() error {
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), mountDrainTimeout)
	defer cancelDrain()
	shutdownErr := m.srv.Shutdown(drainCtx)
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, m.srv.Close())
	}
	return shutdownErr
}
