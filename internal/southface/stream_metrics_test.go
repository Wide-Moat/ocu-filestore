// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// TestFileUploadRecordsOps pins southface-02 for the upload data plane: an
// allow books ops_total{fileUpload,allow,none} plus an engine-stage
// observation, and a deny books ops_total{fileUpload,deny,<class>} (never an
// allow).
func TestFileUploadRecordsOps(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 1<<20)
		m := telemetry.NewBrokerMetrics("v0.0.0-test")
		d.brokerMetrics = m

		body := concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertSuccessTrailer(t, w)

		if got := opsTotalFor(t, m, "fileUpload", "allow", denyclassNone); got != 1 {
			t.Fatalf("ops_total{fileUpload,allow,none} = %d, want 1", got)
		}
		if got := opsTotals(t, m)["deny"]; got != 0 {
			t.Fatalf("ops_total deny = %d, want 0 on the upload allow path", got)
		}
		if got := stageObservations(t, m, "engine"); got != 1 {
			t.Fatalf("engine stage observations = %d, want 1 (WriteStream timed)", got)
		}
	})

	t.Run("deny size_exceeded", func(t *testing.T) {
		eng := newFakeEngine()
		sess := &recordingCeilingsSession{}
		// Whole-object ceiling of 4 bytes; an 8-byte declaration is refused
		// PRE-BUFFER (size_exceeded) before any chunk.
		d := newStreamDispatcher(eng, &fakeGuard{}, sess, 4)
		m := telemetry.NewBrokerMetrics("v0.0.0-test")
		d.brokerMetrics = m

		body := concat(paramsFrame(t, streamScope, "/up.bin", 8), chunkFrame(t, []byte("ABCDEFGH")), endFrame(t))
		w := serveStream(d, OpFileUpload, bytes.NewReader(body), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodeInvalidArgument)

		totals := opsTotals(t, m)
		if totals["allow"] != 0 {
			t.Fatalf("ops_total allow = %d, want 0 on the upload deny path", totals["allow"])
		}
		if got := opsTotalFor(t, m, "fileUpload", "deny", denySizeExceeded); got != 1 {
			t.Fatalf("ops_total{fileUpload,deny,size_exceeded} = %d, want 1", got)
		}
	})
}

// TestFileDownloadRecordsOps pins southface-02 for the download data plane: an
// allow books ops_total{fileDownload,allow,none} plus an engine-stage
// observation, and a non-downloadable deny books
// ops_total{fileDownload,deny,not_downloadable} (never an allow).
func TestFileDownloadRecordsOps(t *testing.T) {
	const (
		path    = "/dl.bin"
		engPath = "dl.bin"
	)
	content := []byte("HELLO_DOWNLOAD_BYTES")

	discoverUUID := func(t *testing.T, d *dispatcher) string {
		t.Helper()
		w := serveOp(d, OpListDirectory, listBody(streamScope, "/", 0, "", false), streamScope, okIntents())
		resp := decodeList(t, w)
		for _, e := range resp.Entries {
			if e.File != nil && e.File.Path == path {
				return e.File.UUID
			}
		}
		t.Fatalf("listDirectory did not emit a uuid for %s", path)
		return ""
	}

	t.Run("allow", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putBytes(streamScope, engPath, content)
		d := newStreamDispatcher(eng, &fakeGuard{}, &recordingCeilingsSession{}, 1<<20)
		d.resolver = &fakeResolver{grant: Grant{Downloadable: true}}
		m := telemetry.NewBrokerMetrics("v0.0.0-test")
		d.brokerMetrics = m

		uuid := discoverUUID(t, d)
		body := downloadParamsFrame(t, streamScope, uuid, nil)
		w := serveStream(d, OpFileDownload, bytes.NewReader(body), streamScope, okIntents())
		assertSuccessTrailer(t, w)

		if got := opsTotalFor(t, m, "fileDownload", "allow", denyclassNone); got != 1 {
			t.Fatalf("ops_total{fileDownload,allow,none} = %d, want 1", got)
		}
		// listDirectory above booked one allow too; assert no deny was booked.
		if got := opsTotals(t, m)["deny"]; got != 0 {
			t.Fatalf("ops_total deny = %d, want 0 on the download allow path", got)
		}
		if got := stageObservations(t, m, "engine"); got < 1 {
			t.Fatalf("engine stage observations = %d, want >= 1 (ReadRange timed)", got)
		}
	})

	t.Run("deny not_downloadable", func(t *testing.T) {
		eng := newFakeEngine()
		eng.putBytes(streamScope, engPath, content)
		d := newStreamDispatcher(eng, &fakeGuard{}, &recordingCeilingsSession{}, 1<<20)
		// First discover the uuid with a downloadable grant, then flip the grant
		// off for the actual download so the broker refuses not_downloadable.
		d.resolver = &fakeResolver{grant: Grant{Downloadable: true}}
		uuid := discoverUUID(t, d)

		m := telemetry.NewBrokerMetrics("v0.0.0-test")
		d.brokerMetrics = m
		d.resolver = &fakeResolver{grant: Grant{Downloadable: false}}

		body := downloadParamsFrame(t, streamScope, uuid, nil)
		w := serveStream(d, OpFileDownload, bytes.NewReader(body), streamScope, okIntents())
		assertErrorTrailer(t, w, wireCodePermissionDenied)

		totals := opsTotals(t, m)
		if totals["allow"] != 0 {
			t.Fatalf("ops_total allow = %d, want 0 on the download deny path", totals["allow"])
		}
		if got := opsTotalFor(t, m, "fileDownload", "deny", denyNotDownloadable); got != 1 {
			t.Fatalf("ops_total{fileDownload,deny,not_downloadable} = %d, want 1", got)
		}
	})
}
