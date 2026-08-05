// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// TestFilePublisher_WritesTheEventAsOneJSONLine pins the reference sink's wire
// form: one JSON object per line, so a collector can tail the file without a
// framing negotiation the contract has not pinned.
func TestFilePublisher_WritesTheEventAsOneJSONLine(t *testing.T) {
	path := tempPath(t, "fanout.jsonl")
	p, err := NewFilePublisher(path)
	if err != nil {
		t.Fatalf("NewFilePublisher: %v", err)
	}
	defer p.Close()

	ev := FileActivityEvent{FilesystemID: "fs-a", Intent: "write"}
	if err := p.Publish(context.Background(), ev); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("wrote %d lines, want 1: %q", len(lines), body)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("line is not a JSON object: %v (%q)", err, lines[0])
	}
	if got["filesystem_id"] != "fs-a" {
		t.Fatalf("filesystem_id = %v, want fs-a", got["filesystem_id"])
	}
}

// TestFilePublisher_CarriesTheFanInChannel pins the source identity onto every
// published record. The pipeline binds the OCSF source to the channel it
// arrived on; a file has no channel of its own, so the reference sink names it
// in the envelope or the identity is simply lost.
func TestFilePublisher_CarriesTheFanInChannel(t *testing.T) {
	path := tempPath(t, "fanout.jsonl")
	p, err := NewFilePublisher(path)
	if err != nil {
		t.Fatalf("NewFilePublisher: %v", err)
	}
	defer p.Close()

	if err := p.Publish(context.Background(), FileActivityEvent{FilesystemID: "fs-a"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	body, _ := os.ReadFile(path)
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(body))), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["channel"] != ObjectStoreFanInChannel {
		t.Fatalf("channel = %v, want %q -- a record with no channel cannot be "+
			"attributed to this source", got["channel"], ObjectStoreFanInChannel)
	}
}

// TestFilePublisher_AppendsAcrossEvents keeps the sink append-only: canon names
// the solo-reference bus an "embedded append-only file", and a sink that
// truncated would silently discard the history a collector replays from.
func TestFilePublisher_AppendsAcrossEvents(t *testing.T) {
	path := tempPath(t, "fanout.jsonl")
	p, err := NewFilePublisher(path)
	if err != nil {
		t.Fatalf("NewFilePublisher: %v", err)
	}
	defer p.Close()

	for _, fsid := range []string{"fs-1", "fs-2", "fs-3"} {
		if err := p.Publish(context.Background(), FileActivityEvent{FilesystemID: fsid}); err != nil {
			t.Fatalf("Publish(%s): %v", fsid, err)
		}
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	var seen []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("line not JSON: %v", err)
		}
		if s, ok := rec["filesystem_id"].(string); ok {
			seen = append(seen, s)
		}
	}
	want := []string{"fs-1", "fs-2", "fs-3"}
	if len(seen) != len(want) {
		t.Fatalf("read %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("record %d = %q, want %q (order is not preserved)", i, seen[i], want[i])
		}
	}
}

// TestFilePublisher_ReopenKeepsPriorRecords pins the recovery property: a
// restart must not cost the records a collector has not yet replayed.
func TestFilePublisher_ReopenKeepsPriorRecords(t *testing.T) {
	path := tempPath(t, "fanout.jsonl")

	first, err := NewFilePublisher(path)
	if err != nil {
		t.Fatalf("NewFilePublisher: %v", err)
	}
	if err := first.Publish(context.Background(), FileActivityEvent{FilesystemID: "before"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := NewFilePublisher(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()
	if err := second.Publish(context.Background(), FileActivityEvent{FilesystemID: "after"}); err != nil {
		t.Fatalf("Publish after reopen: %v", err)
	}

	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), `"before"`) {
		t.Fatalf("reopening truncated the prior records:\n%s", body)
	}
	if !strings.Contains(string(body), `"after"`) {
		t.Fatalf("the post-reopen record is missing:\n%s", body)
	}
}

// TestFilePublisher_ClosedSinkReportsTheDrop is the seam's contract with the
// counter: a Publish that cannot land must return an error, because that is
// what the fan-out counts. A sink swallowing the failure would leave
// DroppedFanOut reading zero through an outage.
func TestFilePublisher_ClosedSinkReportsTheDrop(t *testing.T) {
	path := tempPath(t, "fanout.jsonl")
	p, err := NewFilePublisher(path)
	if err != nil {
		t.Fatalf("NewFilePublisher: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Publish(context.Background(), FileActivityEvent{FilesystemID: "fs-a"}); err == nil {
		t.Fatal("Publish on a closed sink returned nil: the drop would never be counted")
	}
}

// TestFilePublisher_RefusesAnEmptyPath keeps construction fail-closed, so a
// deployment that sets the flag to an empty value aborts rather than silently
// fanning out nowhere while appearing configured.
func TestFilePublisher_RefusesAnEmptyPath(t *testing.T) {
	if _, err := NewFilePublisher(""); err == nil {
		t.Fatal("NewFilePublisher(\"\") returned no error")
	}
}
