// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package southface terminates the file-operation RPC from the session
// sandbox — the guest-mount face of the broker. The wire surface is the
// file-ops contract in the architecture repo (operation names and
// authorization axes are pinned; per-operation bodies marked TBD there stay
// TBD here — this package never invents a body).
//
// Accept-time rules: the listener accepts a connection only from the host
// peer (non-host peers dropped before any frame is parsed, NFR-SEC-76), and
// every operation is attributed by host-derived identity — a guest-supplied
// session/tenant id is a hint cross-checked against it, never the identity
// (NFR-SEC-43). Per-session file-ops/s, in-flight-byte, and fd ceilings
// throttle fail-closed per session, not broker-wide (NFR-SEC-46).
package southface

// Op names one south-face file operation, mirroring the file-ops contract
// enum. The set is frozen there; adding an op is a contract change in the
// architecture repo first.
type Op string

const (
	OpListDirectory     Op = "listDirectory"
	OpMakeDirectory     Op = "makeDirectory"
	OpMoveDirectory     Op = "moveDirectory"
	OpRemoveDirectory   Op = "removeDirectory"
	OpCreateFile        Op = "createFile"
	OpReadFile          Op = "readFile"
	OpReadMetadata      Op = "readMetadata"
	OpGetFileMetadata   Op = "getFileMetadata"
	OpListFiles         Op = "listFiles"
	OpCopyFile          Op = "copyFile"
	OpMoveFile          Op = "moveFile"
	OpRemoveFile        Op = "removeFile"
	OpFileUpload        Op = "fileUpload"
	OpFileDownload      Op = "fileDownload"
	OpImportFiles       Op = "importFiles"
	OpImportZip         Op = "importZip"
	OpMigrateFilesystem Op = "migrateFilesystem"
	OpRemoveFilesystem  Op = "removeFilesystem"
)

// Server is the south-face listener seam. The implementation PR binds it to
// the host-side per-session channel, wires the authz resolver and the
// audit gate in front of the object-store client, and carries the
// per-session ceilings. The transport and message-set encoding are
// component-spec choices, not contract.
type Server interface {
	// Serve accepts host-peer connections until the context is cancelled
	// or a fatal listener error occurs.
	Serve() error
	// Close releases the listener; in-flight operations finish or fail
	// fail-closed, never half-acknowledged.
	Close() error
}
