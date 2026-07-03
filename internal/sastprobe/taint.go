// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package sastprobe is a THROWAWAY probe for the CodeQL gate two-sided proof.
// DO NOT MERGE.
package sastprobe

import (
	"net/http"
	"os/exec"
)

// VulnHandler builds a shell command from untrusted request input and executes
// it — a textbook command-injection taint flow (source: r.URL.Query(); sink:
// exec.Command). CodeQL go/command-injection (security-severity 9.8) flags this
// at SARIF level "error", so the codeql.yml gate MUST turn the job RED.
func VulnHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	out, _ := exec.Command("sh", "-c", "echo "+name).CombinedOutput() //nolint:gosec // intentional taint probe
	_, _ = w.Write(out)
}
