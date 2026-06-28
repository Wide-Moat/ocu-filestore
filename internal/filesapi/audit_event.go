// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filesapi

import (
	"strconv"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

// The Files-API plane emits OCSF File System Activity records (class_uid 1001,
// category_uid 1) directly as auditgate.FileActivityEvent values — the south
// face's auditEvent intermediary is a south-package type, so this plane builds
// the real record itself. The Guard the broker wires type-asserts this concrete
// type at Mandate; a raw struct of any other shape is refused as
// ErrAuditUnavailable and the operation fails closed.
//
// ObjectHandle is ALWAYS the backend object reference (Record.ObjectRef /
// Record.AuditObjectHandle), NEVER the public file_id (ADR-0023 honesty-fix):
// the durable activity log names the stored object the operation actually
// touched, while the caller-facing handle stays out of the handle field.
//
// Time, Metadata, and PrevHash are LEFT zero: Mandate stamps the broker clock
// time (NFR-SEC-48), fills the metadata defaults, and chains prev_hash. The
// field order of the literal MUST match the struct declaration in
// auditgate/event.go — that order is the JSON marshal order and therefore the
// hash-chain input.

// readAllowEvent builds the ALLOW audit event for a content read. ActivityID is
// a Read; Downloadable carries the broker-resolved grant (NFR-SEC-73, resolved
// at read); ByteCount is left zero (the record names the access, not the
// streamed total, mirroring the south download). It is passed through
// Guard.Mandate BEFORE the first byte (audit-before-ack, SEC-79).
func readAllowEvent(ps southface.PeerScope, rec handlestore.Record, grant southface.Grant, reqID string) auditgate.FileActivityEvent {
	return auditgate.FileActivityEvent{
		ClassUID:    1001,
		CategoryUID: 1,
		ActivityID:  auditgate.ActivityRead,
		Actor: auditgate.ActorSubject{
			UserUID:    strconv.FormatUint(uint64(ps.UID), 10),
			SessionUID: ps.FilesystemID,
			ProcessPID: ps.PID,
		},
		FilesystemID:   ps.FilesystemID,
		ObjectHandle:   rec.AuditObjectHandle(),
		ByteCount:      0,
		Intent:         string(southface.IntentRead),
		Downloadable:   grant.Downloadable,
		Outcome:        auditgate.Outcome{DispositionID: auditgate.DispositionAllow},
		CorrelationUID: reqID,
	}
}

// readDenyEvent builds the DENY audit event for a content read refused before
// any byte (e.g. a non-downloadable grant). The wire MAY degrade away from this
// truth (anti-enumeration), but the audit record carries the broker-resolved
// truth in XDenyReason. Downloadable carries the grant value that produced the
// refusal so the record is honest about what was resolved.
func readDenyEvent(ps southface.PeerScope, rec handlestore.Record, grant southface.Grant, auditReason, reqID string) auditgate.FileActivityEvent {
	return auditgate.FileActivityEvent{
		ClassUID:    1001,
		CategoryUID: 1,
		ActivityID:  auditgate.ActivityRead,
		Actor: auditgate.ActorSubject{
			UserUID:    strconv.FormatUint(uint64(ps.UID), 10),
			SessionUID: ps.FilesystemID,
			ProcessPID: ps.PID,
		},
		FilesystemID:   ps.FilesystemID,
		ObjectHandle:   rec.AuditObjectHandle(),
		ByteCount:      0,
		Intent:         string(southface.IntentRead),
		Downloadable:   grant.Downloadable,
		Outcome:        auditgate.Outcome{DispositionID: auditgate.DispositionDeny, XDenyReason: auditReason},
		CorrelationUID: reqID,
	}
}

// deleteAllowEvent builds the ALLOW audit event for a delete. ActivityID is a
// Delete; ObjectHandle is the resolved Record's backend reference. It is
// Mandated AFTER the successful Get (the record exists and its scope matched) and
// BEFORE the tombstone (audit-before-ack: the durable record names the object
// the delete is about to remove). Downloadable is irrelevant to a delete and
// left false.
func deleteAllowEvent(ps southface.PeerScope, rec handlestore.Record, reqID string) auditgate.FileActivityEvent {
	return auditgate.FileActivityEvent{
		ClassUID:    1001,
		CategoryUID: 1,
		ActivityID:  auditgate.ActivityDelete,
		Actor: auditgate.ActorSubject{
			UserUID:    strconv.FormatUint(uint64(ps.UID), 10),
			SessionUID: ps.FilesystemID,
			ProcessPID: ps.PID,
		},
		FilesystemID:   ps.FilesystemID,
		ObjectHandle:   rec.AuditObjectHandle(),
		ByteCount:      0,
		Intent:         string(southface.IntentWrite),
		Outcome:        auditgate.Outcome{DispositionID: auditgate.DispositionAllow},
		CorrelationUID: reqID,
	}
}

// deleteDenyEvent builds the DENY audit event for a delete refused after the Get
// resolved the record but before the tombstone (e.g. the store latched on the
// mutation path). It names the resolved object so the durable record is honest
// about what the refused delete concerned.
func deleteDenyEvent(ps southface.PeerScope, rec handlestore.Record, auditReason, reqID string) auditgate.FileActivityEvent {
	return auditgate.FileActivityEvent{
		ClassUID:    1001,
		CategoryUID: 1,
		ActivityID:  auditgate.ActivityDelete,
		Actor: auditgate.ActorSubject{
			UserUID:    strconv.FormatUint(uint64(ps.UID), 10),
			SessionUID: ps.FilesystemID,
			ProcessPID: ps.PID,
		},
		FilesystemID:   ps.FilesystemID,
		ObjectHandle:   rec.AuditObjectHandle(),
		ByteCount:      0,
		Intent:         string(southface.IntentWrite),
		Outcome:        auditgate.Outcome{DispositionID: auditgate.DispositionDeny, XDenyReason: auditReason},
		CorrelationUID: reqID,
	}
}
