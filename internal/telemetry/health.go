// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry

import (
	"fmt"
	"net/http"
	"strings"
)

// ReadyProbe is a named readiness check. Check returns nil when the probe
// passes and a non-nil error when it fails. The Name appears in the /readyz
// 503 body when the probe fails — names only, no error message text (T-14-09:
// the body must never carry a path, payload, or credential).
type ReadyProbe struct {
	Name  string
	Check func() error
}

// RegisterHealthHandlers registers /healthz (liveness) and /readyz (readiness)
// on mux. The handlers are served over the loopback ops listener (plan 02's
// registration seam) and need no second listener.
//
// /healthz returns 200 whenever the process is serving — pure liveness,
// independent of the audit latch and engine state. An orchestrator that
// cannot distinguish liveness from readiness MUST use /readyz for traffic
// gating (T-14-12).
//
// /readyz returns 200 only when every probe in the probes slice returns nil.
// If any probe fails, /readyz returns 503 with a plain-text body listing the
// name of each failing probe separated by newlines. A nil or empty probes
// slice is vacuously ready (200).
//
// Only GET and HEAD are accepted on both routes; any other method returns 405.
func RegisterHealthHandlers(mux *http.ServeMux, probes []ReadyProbe) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Run every probe; collect the names of failing probes.
		var failed []string
		for _, p := range probes {
			if p.Check != nil {
				if err := p.Check(); err != nil {
					// T-14-09: name only — never the error message text.
					failed = append(failed, p.Name)
				}
			}
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if len(failed) == 0 {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ok")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		// Body: one failing probe name per line. T-14-09: names only,
		// never the probe's error message, no path, no payload.
		fmt.Fprintln(w, strings.Join(failed, "\n"))
	})
}
