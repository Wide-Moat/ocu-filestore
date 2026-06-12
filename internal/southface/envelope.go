// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// servicePrefix is the Connect route prefix for the south-face service. A
// unary or streaming request targets servicePrefix + <op>; any other path is
// not a member of this service.
const servicePrefix = "/ocu.filestore.v1alpha.FilesystemService/"

// connectProtocolVersionHeader and its required value pin the Connect unary
// contract: the header is REQUIRED on every request and its only legal value
// is "1"; absent or wrong is invalid_argument before the body is parsed (D1).
const (
	connectProtocolVersionHeader = "Connect-Protocol-Version"
	connectProtocolVersion       = "1"
	contentTypeJSON              = "application/json"
)

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
	// service. Maps to invalid_argument.
	errUnknownRoute = errors.New("southface: unknown route")

	// errBadVersion — the Connect-Protocol-Version header is absent or not
	// "1". Maps to invalid_argument.
	errBadVersion = errors.New("southface: missing or wrong Connect-Protocol-Version")

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

// parseRoute matches a request's method and path against the south-face
// service, returning the routed Op. A non-POST method to any path is
// errBadMethod; a path outside the service prefix or naming an unknown op is
// errUnknownRoute.
func parseRoute(method, path string) (Op, error) {
	if method != http.MethodPost {
		return "", errBadMethod
	}
	if !strings.HasPrefix(path, servicePrefix) {
		return "", errUnknownRoute
	}
	op := Op(strings.TrimPrefix(path, servicePrefix))
	if _, ok := knownOps[op]; !ok {
		return "", errUnknownRoute
	}
	return op, nil
}

// checkVersion enforces the REQUIRED Connect-Protocol-Version header (D1).
func checkVersion(r *http.Request) error {
	if r.Header.Get(connectProtocolVersionHeader) != connectProtocolVersion {
		return errBadVersion
	}
	return nil
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

// denyClassForDecodeErr maps an envelope/route decode sentinel to its deny
// class. errBadMethod is handled out of band (405) and is not mapped here.
func denyClassForDecodeErr(err error) string {
	switch {
	case errors.Is(err, errDeclaredSizeExceeded):
		return denySizeExceeded
	case errors.Is(err, errMalformedEnvelope),
		errors.Is(err, errUnknownRoute),
		errors.Is(err, errBadVersion),
		errors.Is(err, errBadContentType),
		errors.Is(err, errRouteOpMismatch):
		return denyMalformed
	default:
		return denyInternal
	}
}
