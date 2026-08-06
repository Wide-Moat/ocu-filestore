// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"errors"
	"path"

	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
)

// fileObjectType is the ADR-0028 object discriminator. The dialect pins it to
// the constant `file`; the store holds no other object class.
const fileObjectType = "file"

// recordToFileObject projects a durable record onto the ADR-0028 wire shape.
// Every field is store-held: nothing here is caller-supplied, and downloadable
// is deliberately absent — it is a read-time authorization output resolved from
// the prefix grant (NFR-SEC-73), never a stored or transported field.
func recordToFileObject(rec handlestore.Record) fileObject {
	return fileObject{
		ID:        rec.FileID,
		Type:      fileObjectType,
		Filename:  rec.Filename,
		MimeType:  rec.Mime,
		SizeBytes: rec.Size,
		CreatedAt: rec.CreatedAt,
	}
}

// denyHandleStoreErr maps a store error onto the south deny vocabulary.
//
// ErrNotFound covers BOTH an absent id and one bound to another scope: the
// store collapses the two so a valid id minted in another session cannot probe
// scope membership. The handler must not re-distinguish them — doing so would
// rebuild the existence oracle the collapse exists to deny (ADR-0036).
func denyHandleStoreErr(hc handlerCtx, err error) {
	switch {
	case errors.Is(err, handlestore.ErrNotFound):
		hc.mandateDeny(denyNotFound, denyNotFound, "no such file_id in this scope")
	case errors.Is(err, handlestore.ErrStoreUnavailable):
		hc.mandateDeny(denyBackendUnavailable, denyBackendUnavailable, "handle store unavailable")
	default:
		hc.mandateDeny(denyBackendUnavailable, denyBackendUnavailable, "handle store error")
	}
}

// handleGetFileMetadata serves the by-handle metadata read (ADR-0036). The
// request carries the durable file_id; the response is the ADR-0028 FileObject
// the north getFile returns for the same record, because one record read
// through two doors must not answer in two dialects.
func handleGetFileMetadata(d *handlerDeps, hc handlerCtx) opOutcome {
	var req getFileMetadataRequest
	if !decodeOp(hc, &req) {
		return outcomeDenyRecorded()
	}
	if !requireHandles(d, hc) {
		return outcomeDenyRecorded()
	}
	if req.FileID == "" {
		// An empty handle addresses nothing. It degrades to not_found like any
		// unresolvable id rather than to invalid_argument, so a caller cannot
		// tell an unusable handle from an absent one.
		hc.mandateDeny(denyNotFound, denyNotFound, "no such file_id in this scope")
		return outcomeDenyRecorded()
	}

	rec, err := d.handles.Get(hc.ctxOrBackground(), req.FileID, hc.ps.FilesystemID)
	if err != nil {
		denyHandleStoreErr(hc, err)
		return outcomeDenyRecorded()
	}
	writeJSON(hc.w, recordToFileObject(rec))
	return outcomeAllow()
}

// handleFileDelete serves the by-handle delete (ADR-0036), distinct from
// removeFile which is path-addressed. A repeat delete answers not_found, the
// same as a handle that never existed, so the verb offers no existence oracle.
func handleFileDelete(d *handlerDeps, hc handlerCtx) opOutcome {
	var req fileDeleteRequest
	if !decodeOp(hc, &req) {
		return outcomeDenyRecorded()
	}
	if !assertWriteGrant(hc) {
		return outcomeDenyRecorded()
	}
	if !requireHandles(d, hc) {
		return outcomeDenyRecorded()
	}
	if req.FileID == "" {
		hc.mandateDeny(denyNotFound, denyNotFound, "no such file_id in this scope")
		return outcomeDenyRecorded()
	}

	if err := d.handles.Delete(hc.ctxOrBackground(), req.FileID, hc.ps.FilesystemID); err != nil {
		denyHandleStoreErr(hc, err)
		return outcomeDenyRecorded()
	}
	writeJSON(hc.w, ackResponse{})
	return outcomeAllow()
}

// handleListFiles enumerates the scope's objects (ADR-0036). The page is the
// ADR-0028 envelope; the cursor stays opaque on this plane too, because the
// store's keyset token carries the (created_at, file_id) boundary tuple and a
// bare id cannot resume that walk.
func handleListFiles(d *handlerDeps, hc handlerCtx) opOutcome {
	var req listFilesRequest
	if !decodeOp(hc, &req) {
		return outcomeDenyRecorded()
	}
	if !requireHandles(d, hc) {
		return outcomeDenyRecorded()
	}

	page, err := d.handles.List(hc.ctxOrBackground(), handlestore.ListInput{
		Scope:  hc.ps.FilesystemID,
		Cursor: req.After,
		Limit:  req.Limit,
		Order:  listOrderFromWire(req.Order),
	})
	if err != nil {
		denyHandleStoreErr(hc, err)
		return outcomeDenyRecorded()
	}

	// A page is always an array on the wire, never null: a client that
	// destructures `data` must not have to special-case the empty scope.
	objects := make([]fileObject, 0, len(page.Records))
	for _, rec := range page.Records {
		objects = append(objects, recordToFileObject(rec))
	}
	resp := listFilesResponse{
		Data:       objects,
		HasMore:    page.HasMore,
		NextCursor: page.NextCursor,
	}
	if len(objects) > 0 {
		resp.FirstID = objects[0].ID
		resp.LastID = objects[len(objects)-1].ID
	}
	writeJSON(hc.w, resp)
	return outcomeAllow()
}

// listOrderFromWire maps the request's order selector onto the store direction.
// It is tolerant, mirroring the north face (ADR-0037): only the literal "desc"
// selects the descending walk, and every other value — including an absent one
// — is the ascending default. A direction is a rendering preference, not an
// authorization input, so an unrecognised value renders ascending rather than
// refusing the listing.
func listOrderFromWire(order string) handlestore.ListOrder {
	if order == "desc" {
		return handlestore.ListOrderDesc
	}
	return handlestore.ListOrderAsc
}

// createFilenameFromParams derives the record's display name. The south params
// frame carries no filename field, so it is always the path leaf -- the same
// fallback the north create applies when its optional filename is absent, which
// keeps one record readable identically through either door.
func createFilenameFromParams(params uploadParamsFrame) string {
	leaf := path.Base(enginePath(params.Path))
	if leaf == "" || leaf == "." || leaf == "/" {
		return enginePath(params.Path)
	}
	return leaf
}

// createObjectRef derives the ObjectRef a south create records. It is a named
// function rather than an inline expression so a test can bind to the value the
// handler actually records: the rule it encodes is invisible on this face --
// the create succeeds and returns a valid FileObject whatever is stored here --
// and only surfaces on the north list, whose EnsureObject reconcile keys on
// (Scope, ObjectRef) and mints a SECOND handle for the same object when this
// disagrees with what the engine wrote under.
func createObjectRef(params uploadParamsFrame) string {
	return enginePath(params.Path)
}
