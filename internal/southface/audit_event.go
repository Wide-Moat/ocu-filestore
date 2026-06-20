// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"strconv"

	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
)

// mapAuditEvent maps the spine's broker-resolved-truth auditEvent onto the
// real OCSF File System Activity record (auditgate.FileActivityEvent,
// class_uid 1001, category_uid 1). The spine adopts the real type here so the
// concrete *auditgate.FileSink type-assert succeeds at Mandate — the raw
// auditEvent would be refused as ErrAuditUnavailable and every operation would
// silently fail-closed (Pitfall 1).
//
// Time, Metadata, and PrevHash are LEFT zero: Mandate stamps the broker clock
// time (NFR-SEC-48), fills the metadata defaults, and chains prev_hash. The
// deterministic fields below are the broker-resolved truth.
//
// The FileActivityEvent literal MUST keep the field order of the struct
// declaration in auditgate/event.go — that order is the JSON marshal order and
// therefore the hash-chain input; do not reorder it.
//
// ActivityID carries the OCSF activity id (Create=1 upload, Read=2 read/list,
// Delete=4). Open=14 (preview) is NOT emitted by the current spine —
// activityForOp has no preview branch (preview ops are unimplemented this
// build). Downloadable is resolved at read and carried on the record, never
// stamped at write (NFR-SEC-73). An audit-write failure denies the operation
// before any 2xx (NFR-SEC-79).
func mapAuditEvent(e auditEvent) auditgate.FileActivityEvent {
	outcome := auditgate.Outcome{DispositionID: auditgate.DispositionAllow}
	if e.DenyReason != "" {
		outcome = auditgate.Outcome{
			DispositionID: auditgate.DispositionDeny,
			XDenyReason:   e.DenyReason,
		}
	}
	return auditgate.FileActivityEvent{
		ClassUID:    1001,
		CategoryUID: 1,
		ActivityID:  auditgate.ActivityID(e.ActivityID),
		// Time/Metadata stamped by Mandate — leave zero.
		Actor: auditgate.ActorSubject{
			UserUID:    strconv.FormatUint(uint64(e.PeerUID), 10),
			SessionUID: e.Scope,
			ProcessPID: e.PeerPID,
		},
		FilesystemID: e.Scope,
		ObjectHandle: e.ObjectHandle,
		ByteCount:    e.ByteCount,
		Intent:       string(e.Intent),
		Downloadable: e.Downloadable,
		Outcome:      outcome,
		// PrevHash chained by Mandate — leave empty.
		CorrelationUID: e.RequestID,
	}
}

// streamAuditEvent builds a fileUpload audit event from the resolved params +
// grant. ActivityID is a Create (an upload produces a new object);
// Downloadable carries the resolved grant; ByteCount carries the declared
// size (the upload's intended byte count). The durable encoding is the audit
// gate's; the REST multipart handler passes the value through Guard.Mandate.
// reqID is the T2-18 per-request correlation id threaded end-to-end.
func (d *dispatcher) streamAuditEvent(ps PeerScope, req ResolveRequest, grant Grant, declared int64, reqID string) auditEvent {
	return auditEvent{
		Op:           OpFileUpload,
		Scope:        ps.FilesystemID,
		Path:         req.Path,
		Intent:       req.Intent,
		PeerUID:      ps.UID,
		PeerPID:      ps.PID,
		ActivityID:   activityCreate,
		ObjectHandle: ps.FilesystemID + ":" + req.Path,
		ByteCount:    declared,
		Downloadable: grant.Downloadable,
		RequestID:    reqID,
	}
}

// streamDownloadAuditEvent builds a fileDownload ALLOW audit event from the
// resolved (scope, path) + grant. ActivityID is a Read; ByteCount is left zero
// (the audit records the access, not the streamed byte total); Downloadable
// carries the broker-resolved grant (NFR-SEC-73, resolved at read). The REST
// octet-stream handler passes the value through Guard.Mandate before the first
// byte (audit-before-ack, SEC-79).
func (d *dispatcher) streamDownloadAuditEvent(ps PeerScope, req ResolveRequest, grant Grant, reqID string) auditEvent {
	return auditEvent{
		Op:           OpFileDownload,
		Scope:        ps.FilesystemID,
		Path:         req.Path,
		Intent:       req.Intent,
		PeerUID:      ps.UID,
		PeerPID:      ps.PID,
		ActivityID:   activityRead,
		ObjectHandle: ps.FilesystemID + ":" + req.Path,
		ByteCount:    0,
		Downloadable: grant.Downloadable,
		RequestID:    reqID,
	}
}
