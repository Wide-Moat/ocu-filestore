// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"net/http"
	"strings"
)

// PENDING-PHASE-7(A1-route): the south-face REST router. Every operation is
// POST restBase + <op>; the operation is the trailing path segment. A non-POST
// method to a restBase route is 405 with an Allow: POST header; a path naming an
// op outside the frozen enum (or one outside restBase) is 404 — an unknown op is
// indistinguishable from a missing object (anti-enumeration). Request content is
// negotiated by transport class: the 16 unary ops carry application/json; the
// fileUpload op carries multipart/form-data and rides the streaming path this
// wave (the dispatcher's own per-op streaming branch). The router wraps the
// surviving dispatcher.ServeHTTP — it does NOT re-run the LOCKED STAGE 0->4
// pipeline; it owns only the route boundary. Sibling-proven, frozen pending #292.

// multipartContentType is the request media type the fileUpload op carries
// (multipart/form-data with a generated boundary). The router recognises it for
// content negotiation; the boundary parameter follows the media type, so the
// match is a media-type prefix, never a byte-equality.
const multipartContentType = "multipart/form-data"

// restRouter is the south-face HTTP entrypoint: it resolves the route boundary
// (method, op existence, content negotiation) and delegates a well-formed
// request to the wrapped dispatcher. It carries no pipeline state of its own;
// the dispatcher owns the LOCKED STAGE 0->4 spine and re-parses the route to
// drive the per-op handler.
type restRouter struct {
	// dispatcher is the wrapped LOCKED-spine handler. A well-formed unary request
	// is delegated to it verbatim. The two data-plane ops take dedicated REST
	// entries on the dispatcher instead: fileUpload routes to serveUploadMultipart
	// and fileDownload to serveDownloadOctetStream, so no op rides the retired
	// Connect streaming branch.
	dispatcher *dispatcher
}

// newRESTRouter wraps a dispatcher in the REST route boundary. The returned
// handler is the south-face http.Handler the TLS server binds.
func newRESTRouter(dispatcher *dispatcher) *restRouter {
	return &restRouter{dispatcher: dispatcher}
}

// ServeHTTP resolves the REST route boundary then delegates a well-formed
// request to the wrapped dispatcher. The boundary rules (A1):
//
//   - A path outside restBase, or one naming an op outside the frozen enum, is
//     404 (an unknown op is indistinguishable from a missing object).
//   - A non-POST method to a known op route is 405 with Allow: POST.
//   - A POST to a known op is delegated to the dispatcher, which re-parses the
//     route and runs the LOCKED STAGE 0->4 spine (unary) or the streaming branch
//     (fileUpload multipart / fileDownload). The router stamps the x-request-id
//     header only via the dispatcher (it never writes a success body itself).
//
// The router writes its OWN refusals (405/404) as REST BoundedReason denies so a
// route-boundary refusal carries the same diagnostic body shape as a
// pipeline-stage refusal. It does not mint a correlation id for a boundary
// refusal — the dispatcher owns the per-request id, and a request that never
// reaches the dispatcher has no pipeline to correlate.
func (rt *restRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op, known := routeOp(r.URL.Path)
	if !known {
		// Unknown op or a path outside restBase: 404 (anti-enumeration). The
		// not_found deny class maps to 404 via the surviving status table.
		writeRESTDeny(w, mapDeny(denyNotFound), "unknown operation")
		return
	}
	if r.Method != http.MethodPost {
		// A known op reached with a non-POST method: 405 with Allow: POST. The
		// malformed deny class maps to 400, overridden to 405 for the HTTP method
		// semantics (the body is diagnostic only; the status is authoritative).
		w.Header().Set("Allow", http.MethodPost)
		writeRESTDeny(w, mapDeny(denyMalformed).withStatus(http.StatusMethodNotAllowed), "method not allowed")
		return
	}
	// Content negotiation by op transport class. The two data-plane ops own
	// dedicated entrypoints; every other op (the 16 unary-JSON ops) rides the
	// dispatcher's LOCKED STAGE 0->4 spine. The dispatcher's STAGE-0 Content-Type
	// gate (unary) enforces the EXACT application/json media type and owns every
	// unary media-type refusal; each data-plane entry owns its own request parse,
	// so the route boundary stays a thin classifier.
	//
	//   - PENDING-PHASE-7(A2-multipart): fileUpload (multipart/form-data)
	//     dispatches to serveUploadMultipart.
	//   - PENDING-PHASE-7(A2-octet): fileDownload (application/json request,
	//     application/octet-stream response) dispatches to
	//     serveDownloadOctetStream. With this, BOTH data-plane ops are REST-routed
	//     and NO op rides the retired Connect streaming branch.
	if negotiatedRequestClass(op, r) == multipartContentType {
		rt.dispatcher.serveUploadMultipart(w, r)
		return
	}
	if op == OpFileDownload {
		rt.dispatcher.serveDownloadOctetStream(w, r)
		return
	}
	rt.dispatcher.ServeHTTP(w, r)
}

// negotiatedRequestClass classifies an op's request body framing at the route
// boundary: fileUpload carrying a multipart/form-data body is the multipart
// class; every other op (and a fileUpload not carrying multipart, which the
// dispatcher's gate will refuse) is the JSON class. It is the single
// route-boundary view of request framing the data-plane wave's multipart
// dispatch will key on; this wave it is observational and the dispatcher owns
// every media-type refusal.
func negotiatedRequestClass(op Op, r *http.Request) string {
	if op == OpFileUpload && isMultipartRequest(r) {
		return multipartContentType
	}
	return contentTypeJSON
}

// routeOp resolves a request path to its op, reporting whether the path is a
// member of the south-face REST surface. A path outside restBase, or one naming
// an op outside the frozen enum, is not a member (known=false). It is the
// router-boundary counterpart to parseRoute: parseRoute folds the method check
// into its result (errBadMethod vs errUnknownRoute), while routeOp resolves only
// op membership so the router can order its own 404-before-405 boundary.
func routeOp(path string) (Op, bool) {
	if !strings.HasPrefix(path, restBase) {
		return "", false
	}
	op := Op(strings.TrimPrefix(path, restBase))
	if _, ok := knownOps[op]; !ok {
		return "", false
	}
	return op, true
}

// isMultipartRequest reports whether a request carries a multipart/form-data
// body (the fileUpload transport class). The boundary parameter follows the
// media type, so the check is a media-type prefix match tolerant of the
// boundary and any other parameter. The router uses it for content negotiation;
// the dispatcher's streaming gate enforces the exact streaming media type this
// wave.
func isMultipartRequest(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct) == multipartContentType
}
