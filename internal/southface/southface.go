// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package southface terminates the file-operation RPC from the session
// sandbox — the guest-mount face of the broker. The wire surface is the
// file-ops contract in the architecture repo (operation names and
// authorization axes are pinned; per-operation bodies marked TBD there stay
// TBD here — this package never invents a body).
//
// Transport: REST over the edge-injected-credential HTTPS the guest dials
// (guest -> edge -> service). Every operation is attributed by the
// credential-bound filesystem scope the edge injects on Authorization: Bearer —
// a guest-supplied filesystem_id is a hint cross-checked against it, never the
// identity (NFR-SEC-43). The service mints/signs nothing (invariant 3); the
// edge owns weak-JWT validation and the credential exchange. Per-session
// file-ops/s, in-flight-byte, and fd ceilings throttle fail-closed per session,
// not broker-wide (NFR-SEC-46).
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

	// The next three are frozen contract OperationName-enum members whose
	// request/response bodies are still x-ocu-tbd in the contract. They are
	// DISTINCT enum names — not aliases of OpRemoveFile/OpReadMetadata/
	// OpGetFileMetadata — so the Op set covers the whole frozen enum
	// (TestOpEnumMatchesContract). No handler, no required-intent row, and no
	// knownOps entry: they are not routable until the contract pins their
	// bodies. Adding a handler here would mean inventing a body the contract has
	// not frozen, which this package never does.
	OpFileDelete              Op = "fileDelete"
	OpReadFileMetadata        Op = "readFileMetadata"
	OpReleaseQuarantinedFiles Op = "releaseQuarantinedFiles"
)

// Server is the south-face listener seam. The implementation binds it to the
// TLS HTTP/2 server, wires the authz resolver and the audit gate in front of
// the object-store client, and carries the per-session ceilings. The transport
// and message-set encoding are component-spec choices, not contract.
type Server interface {
	// Serve binds the listener and accepts connections until Close shuts the
	// server down or a fatal listener error occurs.
	Serve() error
	// Close releases the listener; in-flight operations finish or fail
	// fail-closed, never half-acknowledged.
	Close() error
}
