// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
)

// TestMapAuditEventAllowUpload pins the WIRE-AUDIT mapping for an ALLOW
// upload: class_uid 1001, category_uid 1, activity_id 1 (Create), and
// outcome.disposition_id "allow" with no x_deny_reason. Time/metadata/prev_hash
// are stamped by Mandate, so the golden asserts only the deterministic
// pre-Mandate fields.
func TestMapAuditEventAllowUpload(t *testing.T) {
	e := auditEvent{
		Op:           OpFileUpload,
		Scope:        "fs-golden-01",
		Path:         "/golden.bin",
		Intent:       IntentWrite,
		PeerUID:      1000,
		PeerPID:      4242,
		ActivityID:   activityCreate,
		ObjectHandle: "fs-golden-01:/golden.bin",
		ByteCount:    42,
		Downloadable: false,
	}
	got := mapAuditEvent(e)

	if got.ClassUID != 1001 {
		t.Fatalf("ClassUID = %d, want 1001", got.ClassUID)
	}
	if got.CategoryUID != 1 {
		t.Fatalf("CategoryUID = %d, want 1", got.CategoryUID)
	}
	if got.ActivityID != auditgate.ActivityCreate {
		t.Fatalf("ActivityID = %d, want ActivityCreate(1)", got.ActivityID)
	}
	if got.Actor.UserUID != strconv.FormatUint(uint64(e.PeerUID), 10) {
		t.Fatalf("Actor.UserUID = %q, want %q", got.Actor.UserUID, strconv.FormatUint(uint64(e.PeerUID), 10))
	}
	if got.Actor.SessionUID != e.Scope {
		t.Fatalf("Actor.SessionUID = %q, want %q", got.Actor.SessionUID, e.Scope)
	}
	if got.Actor.ProcessPID != e.PeerPID {
		t.Fatalf("Actor.ProcessPID = %d, want %d (the gate-attested peer pid)", got.Actor.ProcessPID, e.PeerPID)
	}
	if got.FilesystemID != e.Scope {
		t.Fatalf("FilesystemID = %q, want %q", got.FilesystemID, e.Scope)
	}
	if got.ObjectHandle != e.ObjectHandle {
		t.Fatalf("ObjectHandle = %q, want %q", got.ObjectHandle, e.ObjectHandle)
	}
	if got.ByteCount != e.ByteCount {
		t.Fatalf("ByteCount = %d, want %d", got.ByteCount, e.ByteCount)
	}
	if got.Intent != string(e.Intent) {
		t.Fatalf("Intent = %q, want %q", got.Intent, e.Intent)
	}
	if got.Downloadable != e.Downloadable {
		t.Fatalf("Downloadable = %v, want %v", got.Downloadable, e.Downloadable)
	}
	if got.Outcome.DispositionID != auditgate.DispositionAllow {
		t.Fatalf("DispositionID = %q, want allow", got.Outcome.DispositionID)
	}
	if got.Outcome.XDenyReason != "" {
		t.Fatalf("allow event carries x_deny_reason %q, want empty", got.Outcome.XDenyReason)
	}
	// Mandate stamps these; the pre-Mandate record leaves them zero.
	if got.Time != 0 || got.PrevHash != "" {
		t.Fatalf("Time/PrevHash must be zero pre-Mandate; got Time=%d PrevHash=%q", got.Time, got.PrevHash)
	}

	// The marshalled record carries the pinned OCSF keys/values.
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe struct {
		ClassUID    int `json:"class_uid"`
		CategoryUID int `json:"category_uid"`
		ActivityID  int `json:"activity_id"`
		Outcome     struct {
			DispositionID string `json:"disposition_id"`
			XDenyReason   string `json:"x_deny_reason"`
		} `json:"outcome"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if probe.ClassUID != 1001 || probe.CategoryUID != 1 || probe.ActivityID != 1 {
		t.Fatalf("marshalled record: class_uid/category_uid/activity_id = %d/%d/%d, want 1001/1/1", probe.ClassUID, probe.CategoryUID, probe.ActivityID)
	}
	if probe.Outcome.DispositionID != "allow" {
		t.Fatalf("marshalled disposition = %q, want allow", probe.Outcome.DispositionID)
	}
	if probe.Outcome.XDenyReason != "" {
		t.Fatalf("marshalled allow event carries x_deny_reason %q, want empty", probe.Outcome.XDenyReason)
	}
}

// TestMapAuditEventDenyRead is the WIRE-AUDIT non-vacuity counter: a DENY read
// maps to activity_id 2 (Read) and outcome.disposition_id "deny" carrying the
// broker-resolved x_deny_reason. The allow/deny pair proves the mapping is not
// all-pass.
func TestMapAuditEventDenyRead(t *testing.T) {
	e := auditEvent{
		Op:           OpReadFile,
		Scope:        "fs-golden-01",
		Path:         "/secret.bin",
		Intent:       IntentRead,
		PeerUID:      1000,
		ActivityID:   activityRead,
		ObjectHandle: "fs-golden-01:/secret.bin",
		Downloadable: false,
		DenyReason:   denyScopeMismatch,
	}
	got := mapAuditEvent(e)

	if got.ActivityID != auditgate.ActivityRead {
		t.Fatalf("ActivityID = %d, want ActivityRead(2)", got.ActivityID)
	}
	if got.Outcome.DispositionID != auditgate.DispositionDeny {
		t.Fatalf("DispositionID = %q, want deny", got.Outcome.DispositionID)
	}
	if got.Outcome.XDenyReason != denyScopeMismatch {
		t.Fatalf("XDenyReason = %q, want %q", got.Outcome.XDenyReason, denyScopeMismatch)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe struct {
		ActivityID int `json:"activity_id"`
		Outcome    struct {
			DispositionID string `json:"disposition_id"`
			XDenyReason   string `json:"x_deny_reason"`
		} `json:"outcome"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if probe.ActivityID != 2 {
		t.Fatalf("marshalled activity_id = %d, want 2", probe.ActivityID)
	}
	if probe.Outcome.DispositionID != "deny" || probe.Outcome.XDenyReason != denyScopeMismatch {
		t.Fatalf("marshalled deny outcome = %q/%q, want deny/%q", probe.Outcome.DispositionID, probe.Outcome.XDenyReason, denyScopeMismatch)
	}
}

// TestMapAuditEventDeliveredToRealFileSink pins Pitfall 1: the mapped record is
// the concrete auditgate.FileActivityEvent the real *FileSink.Mandate
// type-asserts. A *FileSink given the mapped event accepts it (durable write),
// where the raw auditEvent would be refused as ErrAuditUnavailable.
func TestMapAuditEventDeliveredToRealFileSink(t *testing.T) {
	dir := shortSocketDir(t)
	sink, err := auditgate.NewFileSink(dir + "/audit.jsonl")
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	e := auditEvent{
		Op:           OpListDirectory,
		Scope:        "fs-golden-01",
		Path:         "/",
		Intent:       IntentRead,
		ActivityID:   activityRead,
		ObjectHandle: "fs-golden-01:/",
	}
	if err := sink.Mandate(t.Context(), mapAuditEvent(e)); err != nil {
		t.Fatalf("Mandate(mapped event): got %v, want nil — the real sink must accept the mapped record", err)
	}
	// The raw spine event is NOT a FileActivityEvent; the real sink refuses it.
	if err := sink.Mandate(t.Context(), e); err == nil {
		t.Fatal("Mandate(raw auditEvent): got nil, want a refusal — the raw spine event is not the OCSF record")
	}
}
