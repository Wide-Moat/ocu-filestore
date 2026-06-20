// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

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

// errTLSConfig refuses a misconfigured TLS south-face server (empty bind
// address, or an unreadable / unparseable cert+key pair). A defect fails loud
// at construction rather than binding a half-configured listener. Match it with
// errors.Is.
var errTLSConfig = errors.New("southface: TLS server misconfigured")

// Timeouts (NFR-SEC-46) for the TLS south-face server:
//
//   - tlsReadHeaderTimeout bounds a peer that connects and never finishes its
//     request headers. It also re-arms the per-request connection deadline so a
//     handler-set body deadline never poisons the next request on a kept-alive
//     connection.
//   - tlsIdleTimeout reaps idle keep-alive connections.
//
// ReadTimeout / WriteTimeout stay UNSET on purpose: a connection-wide cap would
// kill a legitimately-long streamed upload/download. The data-plane handlers
// bound a STALL instead with per-iteration deadlines re-armed via
// http.NewResponseController — the upload handler re-arms a read deadline before
// every body read, the download handler re-arms a write deadline before every
// flush — so a slow-but-progressing transfer keeps extending its deadline while a
// stall (no byte for the frame timeout) trips it and aborts the operation
// fail-closed (NFR-SEC-46).
const (
	tlsReadHeaderTimeout = 10 * time.Second
	tlsIdleTimeout       = 2 * time.Minute
)

// tlsServer is the south-face TLS HTTP/2 server: it terminates the
// edge-originated HTTPS the guest dials (guest -> edge -> service), serving the
// REST router over the injected TLS certificate. It honours the frozen
// southface.Server seam (Serve/Close). It replaces the retired per-session
// unix-socket server: identity no longer arrives as a kernel peer credential
// but as the edge-injected Authorization: Bearer the credential-scope source
// reads.
type tlsServer struct {
	bindAddr string
	srv      *http.Server
}

// compile-time proof a tlsServer honours the frozen Server seam.
var _ Server = (*tlsServer)(nil)

// newTLSServer builds the south-face TLS HTTP/2 server bound to bindAddr,
// serving handler over the certificate at certFile/keyFile. The certificate is
// loaded at construction (a defect refuses startup, never a lazy failure on the
// first request). The TLS config pins MinVersion TLS 1.2 and advertises h2 so
// the server attempts HTTP/2; the ErrorLog is bridged into the structured slog
// stream. The server does not accept connections until Serve is called.
//
// A nil logger yields a discard-all logger (the caller normalises it before
// calling here).
func newTLSServer(bindAddr, certFile, keyFile string, handler http.Handler, logger *slog.Logger) (*tlsServer, error) {
	if bindAddr == "" {
		return nil, fmt.Errorf("%w: a bind address is required", errTLSConfig)
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("%w: a TLS certificate and key are required", errTLSConfig)
	}
	if handler == nil {
		return nil, fmt.Errorf("%w: a handler is required", errTLSConfig)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		// The wrapped error carries the PATHS (not a key byte) — LoadX509KeyPair
		// never interpolates the private-key material into its error text.
		return nil, fmt.Errorf("%w: %v", errTLSConfig, err)
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		// Advertise HTTP/2 then HTTP/1.1 so a guest that only speaks HTTP/1.1
		// still connects; ForceAttemptHTTP2 on the server's Protocols is set
		// via NextProtos here (the server side negotiates h2 through ALPN).
		NextProtos: []string{"h2", "http/1.1"},
	}

	srv := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ErrorLog:          observ.ErrorLog(logger),
		ReadHeaderTimeout: tlsReadHeaderTimeout,
		IdleTimeout:       tlsIdleTimeout,
	}

	return &tlsServer{bindAddr: bindAddr, srv: srv}, nil
}

// Serve binds the TLS listener and accepts connections until Close shuts the
// server down. A clean shutdown returns nil (http.ErrServerClosed is collapsed
// to nil). The certificate and key are already loaded into the server's
// TLSConfig, so ServeTLS is called with empty file arguments.
func (s *tlsServer) Serve() error {
	ln, err := net.Listen("tcp", s.bindAddr)
	if err != nil {
		return err
	}
	err = s.srv.ServeTLS(ln, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// tlsShutdownDrainTimeout bounds the graceful drain in Close: in-flight
// operations get this long to finish before stragglers are force-closed. The
// caller's teardown (erase-before-reuse, NFR-SEC-54) runs AFTER Close returns,
// so an unbounded drain would be an unbounded teardown delay; the bound stays
// under typical service-manager stop grace periods so the drain, the
// force-close, AND the scope erase all fit before a SIGKILL.
const tlsShutdownDrainTimeout = 25 * time.Second

// Close shuts the server down with a BOUNDED drain. In-flight operations get up
// to tlsShutdownDrainTimeout to finish or fail fail-closed, never
// half-acknowledged; stragglers past the bound are force-closed so teardown can
// always proceed. A drain expiry never hides a force-close error — both surface
// via errors.Join.
func (s *tlsServer) Close() error {
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), tlsShutdownDrainTimeout)
	defer cancelDrain()
	shutdownErr := s.srv.Shutdown(drainCtx)
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, s.srv.Close())
	}
	return shutdownErr
}
