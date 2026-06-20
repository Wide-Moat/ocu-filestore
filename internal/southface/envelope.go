// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// PENDING-PHASE-7(A1-route): restBase is the REST route prefix every
// south-face operation hangs off — a request targets POST restBase + <op>;
// the operation is the trailing path segment and the method is always POST.
// Any path outside this prefix, or one naming an op outside the frozen enum, is
// not a member of this service. Sibling-proven, frozen pending #292.
const restBase = "/v1/filestore/fs/"

// contentTypeJSON is the request/response media type for the 16 unary REST-JSON
// ops (and the fileDownload request body). The streaming fileUpload carries
// multipart/form-data instead; the router does content negotiation.
const contentTypeJSON = "application/json"

// Envelope decode sentinels. Each maps to a deny class in deny.go; the
// dispatcher classifies them with errors.Is. Match with errors.Is.
var (
	// errMalformedEnvelope — the request body is not a single well-formed
	// JSON object matching the envelope, or carries an unknown top-level
	// field or a trailing value. Maps to invalid_argument.
	errMalformedEnvelope = errors.New("southface: malformed request envelope")

	// errDeclaredSizeExceeded — the request's declared or streamed body
	// exceeds the policy ceiling. Maps to size_exceeded -> invalid_argument
	// (NFR-SEC-78).
	errDeclaredSizeExceeded = errors.New("southface: declared body size exceeds ceiling")

	// errUnknownRoute — the request path is not a member of the south-face
	// service (a path outside restBase, or one naming an op outside the frozen
	// enum). On the router boundary it is a 404 (anti-enumeration: an unknown op
	// is indistinguishable from a missing object); on the in-handler decode path
	// it maps to invalid_argument.
	errUnknownRoute = errors.New("southface: unknown route")

	// errBadContentType — the request Content-Type is not application/json.
	// Maps to invalid_argument.
	errBadContentType = errors.New("southface: Content-Type must be application/json")

	// errBadMethod — the request method is not POST against a valid route.
	// Maps to a 405 Method Not Allowed (handled out of band of the deny
	// mapper).
	errBadMethod = errors.New("southface: method not allowed")

	// errRouteOpMismatch — the decoded envelope op disagrees with the route
	// op. Maps to invalid_argument.
	errRouteOpMismatch = errors.New("southface: route op disagrees with envelope op")
)

// knownOps is the closed set of routable operations: all 18 from the frozen
// southface.Op enum. A route op outside this set is unknown.
var knownOps = map[Op]struct{}{
	OpListDirectory:     {},
	OpMakeDirectory:     {},
	OpMoveDirectory:     {},
	OpRemoveDirectory:   {},
	OpCreateFile:        {},
	OpReadFile:          {},
	OpReadMetadata:      {},
	OpGetFileMetadata:   {},
	OpListFiles:         {},
	OpCopyFile:          {},
	OpMoveFile:          {},
	OpRemoveFile:        {},
	OpFileUpload:        {},
	OpFileDownload:      {},
	OpImportFiles:       {},
	OpImportZip:         {},
	OpMigrateFilesystem: {},
	OpRemoveFilesystem:  {},
}

// opRequiredIntent is the CLOSED route-op -> required-intent map (NFR-SEC-49,
// invariant 4). The op the route names is the AUTHORITATIVE statement of what
// the request does; the wire authorization_metadata.intent is an untrusted
// hint. The dispatch spine derives the authz intent from this map and refuses
// any wire intent that disagrees (errRouteOpMismatch), so a session granted
// only read can never reach a mutating handler by declaring intent=read on a
// mutation route. Every op in knownOps MUST have a row here — the spine fails
// closed on an absent row. The read/write split mirrors the guest mount's own
// per-op intent stamping (read-class lookups vs write-class mutations).
var opRequiredIntent = map[Op]Intent{
	// Read-class: lookups and content reads.
	OpListDirectory:   IntentRead,
	OpReadFile:        IntentRead,
	OpReadMetadata:    IntentRead,
	OpGetFileMetadata: IntentRead,
	OpListFiles:       IntentRead,
	OpFileDownload:    IntentRead,

	// Write-class: every namespace or content mutation.
	OpMakeDirectory:     IntentWrite,
	OpMoveDirectory:     IntentWrite,
	OpRemoveDirectory:   IntentWrite,
	OpCreateFile:        IntentWrite,
	OpCopyFile:          IntentWrite,
	OpMoveFile:          IntentWrite,
	OpRemoveFile:        IntentWrite,
	OpFileUpload:        IntentWrite,
	OpImportFiles:       IntentWrite,
	OpImportZip:         IntentWrite,
	OpMigrateFilesystem: IntentWrite,
	OpRemoveFilesystem:  IntentWrite,
}

// requiredIntentForOp returns the authoritative intent for a routed op.
// ok=false names a wiring fault (an op outside the closed map) and the caller
// MUST fail closed. No op maps to IntentPreview on this face: preview is the
// north-face render axis and is never a legal south-face wire intent.
func requiredIntentForOp(op Op) (Intent, bool) {
	intent, ok := opRequiredIntent[op]
	return intent, ok
}

// PENDING-PHASE-7(A1-route): parseRoute matches a request's method and path
// against the south-face REST surface, returning the routed Op. The op is the
// trailing path segment of restBase; the method is always POST. A non-POST
// method to a restBase route is errBadMethod (405 with Allow: POST); a path
// outside restBase or one naming an op outside the frozen enum is
// errUnknownRoute (404 at the router). Sibling-proven, frozen pending #292.
func parseRoute(method, path string) (Op, error) {
	if !strings.HasPrefix(path, restBase) {
		return "", errUnknownRoute
	}
	if method != http.MethodPost {
		return "", errBadMethod
	}
	op := Op(strings.TrimPrefix(path, restBase))
	if _, ok := knownOps[op]; !ok {
		return "", errUnknownRoute
	}
	return op, nil
}

// checkContentType enforces application/json for unary requests; a charset or
// other parameter after the media type is tolerated.
func checkContentType(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if strings.TrimSpace(ct) != contentTypeJSON {
		return errBadContentType
	}
	return nil
}

// unaryEnvelope is the spine's view of a unary request body. The spine decodes
// only what it needs to route and to cross-check scope and intent; the
// per-operation bodies stay phase 9/10 and are never invented here. The struct
// is strict: DisallowUnknownFields rejects any field outside this set.
type unaryEnvelope struct {
	// FilesystemID is the guest-supplied scope hint, cross-checked against
	// the channel-bound scope before any handler runs (D2/NFR-SEC-43).
	FilesystemID string `json:"filesystem_id"`
	// Path is the object path inside the scope (absent on uuid-keyed ops).
	Path string `json:"path"`
	// AuthorizationMetadata carries the intent axis and the read-time
	// downloadable hint (D3).
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// authorizationMetadata mirrors the D3 authorization axes carried on every
// request body.
type authorizationMetadata struct {
	// Intent is the requested intent axis value (read/write/preview).
	Intent Intent `json:"intent"`
	// Downloadable is the read-time hint; the broker resolves the authoritative
	// value at read and never trusts this at write (NFR-SEC-73).
	Downloadable bool `json:"downloadable"`
}

// decodeUnaryEnvelope decodes a unary request body into out under the SEC-51/78
// rules: a Content-Length above the ceiling is rejected before any body byte
// is read; a MaxBytesReader backstop always applies (catching an absent or
// lying Content-Length); the JSON decoder rejects unknown top-level fields and
// any trailing value. A size violation returns errDeclaredSizeExceeded; any
// other decode fault returns errMalformedEnvelope. It never panics on
// adversarial input.
func decodeUnaryEnvelope(w http.ResponseWriter, r *http.Request, ceiling int64, out any) error {
	if cl := r.ContentLength; cl > 0 && cl > ceiling {
		return errDeclaredSizeExceeded
	}
	r.Body = http.MaxBytesReader(w, r.Body, ceiling)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errDeclaredSizeExceeded
		}
		return errMalformedEnvelope
	}
	// Single-value enforcement: a second decode must hit EOF. Any further
	// token (a second JSON value) is a malformed envelope.
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		return errMalformedEnvelope
	}
	return nil
}

// decodeStrictBytes strict-decodes a single JSON object from an in-memory body
// buffer into out: unknown fields are rejected (DisallowUnknownFields) and a
// trailing second value is rejected (single-value enforcement). It is the
// no-network decode path the spine and the per-op handlers share over the
// buffered body — the size ceiling / MaxBytesReader backstop is applied once
// when the body is read, so no reader is needed here. Any decode fault returns
// errMalformedEnvelope.
func decodeStrictBytes(body []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errMalformedEnvelope
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		return errMalformedEnvelope
	}
	return nil
}

// decodeUnaryEnvelopeBytes decodes the spine's routing/cross-check view
// (filesystem_id, path, authorization_metadata) from the buffered body. It is
// deliberately LENIENT on unknown fields: the op-specific fields (source,
// destination, limit, cursor, recursive, overwrite_existing, make_parents) are
// part of the real body and are STRICT-decoded by the per-op handler, which
// owns the authoritative schema. The spine still rejects a body that is not a
// single well-formed JSON object (a decode error or a trailing second value);
// the unknown-field guard moves to the handler where the full schema is known.
//
// The phase-8 strict envelope decode (decodeUnaryEnvelope, the reader path)
// stays unchanged for the reader API and its tests; the buffered path used by
// the dispatcher is the one that must admit op-specific fields.
func decodeUnaryEnvelopeBytes(body []byte, out *unaryEnvelope) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(out); err != nil {
		return errMalformedEnvelope
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		return errMalformedEnvelope
	}
	return nil
}

// denyClassForDecodeErr maps an envelope/route decode sentinel to its deny
// class. errBadMethod is handled out of band (405) and is not mapped here.
func denyClassForDecodeErr(err error) string {
	switch {
	case errors.Is(err, errDeclaredSizeExceeded):
		return denySizeExceeded
	case errors.Is(err, errMalformedEnvelope),
		errors.Is(err, errUnknownRoute),
		errors.Is(err, errBadContentType),
		errors.Is(err, errRouteOpMismatch):
		return denyMalformed
	default:
		return denyInternal
	}
}
