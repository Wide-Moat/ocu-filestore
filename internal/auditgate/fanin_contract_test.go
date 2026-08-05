// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fanInContractLines reads the vendored audit fan-in AsyncAPI document as lines.
// It mirrors the storage parity tests: the contract is read from the vendored
// copy the CI byte-identity gate pins to canon, and scanned line-wise rather
// than through a YAML library, so the check adds no dependency to a package on
// the audit path.
func fanInContractLines(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "audit", "audit-fanin.asyncapi.yaml"))
	if err != nil {
		t.Fatalf("read vendored fan-in contract: %v", err)
	}
	return strings.Split(string(raw), "\n")
}

// flowSeq reads a flow-style sequence (`key: [a, b, c]`) from the first line
// whose trimmed form starts with the given key. It returns nil when the key is
// absent, which every caller treats as a failure rather than an empty set.
func flowSeq(lines []string, key string) []string {
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, key) {
			continue
		}
		open := strings.Index(t, "[")
		closeIdx := strings.LastIndex(t, "]")
		if open < 0 || closeIdx < open {
			continue
		}
		var out []string
		for _, part := range strings.Split(t[open+1:closeIdx], ",") {
			if v := strings.TrimSpace(part); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	return nil
}

// TestFileActivityEventCarriesTheFanInRequiredOverlay binds the emitted event to
// the frozen contract's NFR-SEC-79 overlay: filesystem_id, intent and
// downloadable are non-optional on every file-activity event, on both faces.
//
// The overlay is the part a Go struct can silently drift from. The OCSF base
// class is referenced by URL and is not ours to check here, but the three
// OCU-mandatory fields are exactly the ones a refactor could rename or drop
// while every existing test — which asserts behaviour, never the wire — stayed
// green. The required list is read out of the contract rather than hard-coded,
// so widening the overlay in canon reds this test instead of passing silently.
func TestFileActivityEventCarriesTheFanInRequiredOverlay(t *testing.T) {
	lines := fanInContractLines(t)

	required := flowSeq(lines, "required: [filesystem_id")
	if len(required) == 0 {
		t.Fatal("the fan-in overlay's required list was not found in the vendored contract: " +
			"the contract read is wrong, so this test would pass against any event shape")
	}

	// Marshal a zero event: the JSON tags are what reaches the bus, and a zero
	// value still emits every field that is not omitempty.
	blob, err := json.Marshal(FileActivityEvent{})
	if err != nil {
		t.Fatalf("marshal FileActivityEvent: %v", err)
	}
	var onWire map[string]any
	if err := json.Unmarshal(blob, &onWire); err != nil {
		t.Fatalf("unmarshal FileActivityEvent: %v", err)
	}

	for _, field := range required {
		if _, present := onWire[field]; !present {
			t.Errorf("the fan-in contract requires %q on every file-activity event, but "+
				"FileActivityEvent does not emit it; on-wire keys: %v", field, keysOf(onWire))
		}
	}
}

// TestObjectStoreFanInChannelIsTheContractAddress pins the channel this
// component publishes to. The address is the one part of the fan-in binding the
// contract DOES fix — the protocol is deliberately left open — and a publisher
// aimed at the wrong channel would be accepted by a permissive broker and land
// this component's events under another source's identity, which is the
// host-attested-source invariant the whole pipeline rests on.
func TestObjectStoreFanInChannelIsTheContractAddress(t *testing.T) {
	lines := fanInContractLines(t)

	var addr string
	for i, ln := range lines {
		if strings.TrimSpace(ln) != "objectStoreAudit:" {
			continue
		}
		for _, next := range lines[i+1:] {
			trimmed := strings.TrimSpace(next)
			if strings.HasPrefix(trimmed, "address:") {
				addr = strings.TrimSpace(strings.TrimPrefix(trimmed, "address:"))
				break
			}
		}
		break
	}
	if addr == "" {
		t.Fatal("objectStoreAudit channel address not found in the vendored contract")
	}
	if addr != ObjectStoreFanInChannel {
		t.Fatalf("ObjectStoreFanInChannel = %q, contract address = %q", ObjectStoreFanInChannel, addr)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
