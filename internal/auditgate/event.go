// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auditgate

// ActivityID is the OCSF activity_id enum for file-system operations, as
// pinned by contracts/storage/file-artifact-api.schema.json
// (FileActivityEvent.activity_id).
type ActivityID int

// Pinned activity_id values (the upload/download mapping is OCU design;
// OCSF carries no native upload/download id).
const (
	ActivityCreate ActivityID = 1  // upload / create
	ActivityRead   ActivityID = 2  // read / list / download
	ActivityDelete ActivityID = 4  // delete
	ActivityOpen   ActivityID = 14 // preview-render
)

// DispositionID is the contract's outcome.disposition_id string enum
// ("allow"/"deny"). It is distinct from the OCSF base-schema integer
// disposition_id; the contract's string form is the authoritative wire
// representation for this broker.
type DispositionID string

// Pinned disposition values.
const (
	DispositionAllow DispositionID = "allow"
	DispositionDeny  DispositionID = "deny"
)

// ActorSubject carries the host-attested caller identity recorded on the
// event. The face that terminates the connection attests these values;
// this package records what it is given — the attestation boundary is the
// face, never a caller-supplied claim (NFR-SEC-79).
//
// Field declaration order is the JSON marshal order and therefore part of
// the hash-chain input — append new fields, never reorder. ProcessPID is
// the kernel-attested peer process id from the south-face accept gate
// (SO_PEERCRED); zero (omitted) when the platform or face supplies none.
// It is an OCU record extension beyond the contract's pinned actor
// {user_uid, session_uid} pair, in the same class as the time/metadata/
// prev_hash base-event extensions already carried.
type ActorSubject struct {
	UserUID    string `json:"user_uid,omitempty"`
	SessionUID string `json:"session_uid,omitempty"`
	ProcessPID int32  `json:"process_pid,omitempty"`
}

// Outcome carries the allow/deny decision. XDenyReason is present iff the
// disposition is deny; it carries the south-face DenyReason vocabulary
// (contracts/storage/file-ops.schema.json) as a plain string — this
// package does not import internal/authz.
type Outcome struct {
	DispositionID DispositionID `json:"disposition_id"`
	XDenyReason   string        `json:"x_deny_reason,omitempty"`
}

// Product names the producing component inside Metadata.
type Product struct {
	Name string `json:"name"`
}

// Metadata is the minimal OCSF base_event metadata object: the OCSF schema
// version and the producing product. Mandate fills unset fields with the
// package defaults.
type Metadata struct {
	Version string  `json:"version"`
	Product Product `json:"product"`
}

// FileActivityEvent is the broker's OCSF File System Activity record
// (class_uid 1001, category_uid 1), frozen here for both faces. The
// required field set and JSON names are pinned by
// contracts/storage/file-artifact-api.schema.json (FileActivityEvent).
// time and metadata are OCSF base_event requirements stamped broker-side;
// prev_hash is the OCU chain-link extension carrying the lowercase-hex
// SHA-256 of the previous written line (AUD-02).
//
// Field declaration order is the JSON marshal order and therefore part of
// the hash-chain input — do not reorder fields.
type FileActivityEvent struct {
	ClassUID    int        `json:"class_uid"`    // const 1001
	CategoryUID int        `json:"category_uid"` // const 1
	ActivityID  ActivityID `json:"activity_id"`
	// Time is epoch milliseconds, stamped by Mandate from the broker
	// clock; a caller-supplied value never reaches the record
	// (NFR-SEC-48).
	Time         int64        `json:"time"`
	Metadata     Metadata     `json:"metadata"`
	Actor        ActorSubject `json:"actor"`
	FilesystemID string       `json:"filesystem_id"`
	ObjectHandle string       `json:"object_handle"` // the {filesystem_id, path} handle
	ByteCount    int64        `json:"byte_count"`
	Intent       string       `json:"intent"`       // "read" / "write" / "preview"
	Downloadable bool         `json:"downloadable"` // resolved at read, never stamped at write (NFR-SEC-73)
	Outcome      Outcome      `json:"outcome"`
	PrevHash     string       `json:"prev_hash"`
}
