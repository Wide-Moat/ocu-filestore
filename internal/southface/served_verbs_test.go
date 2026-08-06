// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package southface

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
)

// servedOutOfBand are the ops the REST router dispatches to a dedicated
// entrypoint BEFORE the unary registry is consulted, so their registry entry
// stays `unimplemented` while the verb itself serves. Counting registry
// entries alone therefore under-reports what the build answers, and reads as a
// gap that is not there.
var servedOutOfBand = map[Op]struct{}{
	OpFileUpload:   {}, // serveUploadMultipart
	OpFileDownload: {}, // serveDownloadOctetStream
	OpCreateFile:   {}, // multipart write, ADR-0036 create whole
}

// contractBlocked are the ROUTABLE ops whose request/response field set is NOT
// pinned by a field-level source. `contracts/storage/file-ops.schema.json`
// carries them under x-ocu-tbd-bodies with the governing reason: fill each only
// when a field-level source pins it. They route, and answer 501. They are
// unbuilt because the canon does not yet say what their bodies are — writing
// handlers for them would invent the contract from the implementation side.
var contractBlocked = map[Op]struct{}{
	OpImportFiles:       {},
	OpImportZip:         {},
	OpMigrateFilesystem: {},
	OpRemoveFilesystem:  {},
}

// unroutable are the frozen-enum ops held out of knownOps entirely: they carry
// Op constants for full-enum coverage but no route, so naming one answers 404
// (unknown route), not 501. The distinction is deliberate — see the knownOps
// doc comment. Listing them here keeps the partition over the WHOLE frozen
// enum, so an op cannot go missing by silently leaving knownOps.
var unroutable = map[Op]struct{}{
	OpReadFileMetadata:        {},
	OpReleaseQuarantinedFiles: {},
}

// TestEveryFrozenOpIsServedOrContractBlocked partitions the frozen op enum into
// exactly two sets and pins the boundary between them.
//
// The point is the PARTITION, not the count. An op that gains a handler must
// leave contractBlocked in the same commit, and an op whose handler is dropped
// must be listed as blocked — either way this test names the op that moved
// rather than reporting a number that drifted. A bare count would go green
// against the wrong op gaining a handler while another lost one.
func TestEveryFrozenOpIsServedOrContractBlocked(t *testing.T) {
	// Build the dispatcher the way Serve does: engine wired, so the registry
	// carries its real handlers rather than the engine-nil spine view.
	d := newDispatcherWithEngine(nil, nil, nil, 0, newFakeEngine())

	// Iterate the CONTRACT's enum, not knownOps: an op dropped from knownOps
	// would otherwise vanish from the partition instead of being reported.
	// That is how readFileMetadata and releaseQuarantinedFiles hid — they are
	// frozen-enum members with no route at all.
	frozen := loadContract(t).Defs.OperationName.Enum

	var served, blocked, held, unaccounted []string
	for _, name := range frozen {
		op := Op(name)
		_, isBlocked := contractBlocked[op]
		_, isHeld := unroutable[op]
		_, isOutOfBand := servedOutOfBand[op]
		_, isRoutable := knownOps[op]

		// The registry is TOTAL — newHandlerRegistry seeds every frozen op with
		// the 501 stub — so presence proves nothing and the entry must be
		// compared against the stub itself.
		hasHandler := false
		if h, ok := d.registry[op]; ok {
			hasHandler = !isUnimplementedStub(h)
		}

		switch {
		case hasHandler || isOutOfBand:
			served = append(served, name)
			if isBlocked || isHeld {
				t.Errorf("op %q serves but is still declared unbuilt: drop it "+
					"from contractBlocked/unroutable in the commit that built it", op)
			}
		case isHeld:
			held = append(held, name)
			if isRoutable {
				t.Errorf("op %q is declared unroutable but IS in knownOps: it "+
					"now answers 501 rather than 404, so the contract pinned "+
					"its body — move it to contractBlocked or build it", op)
			}
		case isBlocked:
			blocked = append(blocked, name)
			if !isRoutable {
				t.Errorf("op %q is declared contract-blocked (routable, 501) "+
					"but is absent from knownOps, so it answers 404 instead", op)
			}
		default:
			unaccounted = append(unaccounted, name)
		}
	}
	sort.Strings(served)
	sort.Strings(blocked)
	sort.Strings(held)
	sort.Strings(unaccounted)

	if len(unaccounted) > 0 {
		t.Errorf("op(s) %v neither serve nor are declared unbuilt. A frozen op "+
			"with no handler and no x-ocu-tbd-bodies entry is an unexplained "+
			"501: either build it, or record why the contract cannot pin its "+
			"body yet.", unaccounted)
	}

	// The three states must cover the whole frozen enum.
	if got, want := len(served)+len(blocked)+len(held), len(frozen); got != want {
		t.Errorf("partition covers %d ops, frozen enum has %d", got, want)
	}
	t.Logf("served=%d %v", len(served), served)
	t.Logf("contract-blocked (routable, 501)=%d %v", len(blocked), blocked)
	t.Logf("unroutable (404 until the contract pins a body)=%d %v", len(held), held)
}

// isUnimplementedStub reports whether h is the 501 stub, by function identity.
// The handlers cannot be told apart by invoking them here: a real handler
// decodes its op body and dereferences the engine seam, so calling one with a
// bare handlerCtx panics rather than answering.
func isUnimplementedStub(h opHandler) bool {
	return reflect.ValueOf(h).Pointer() == reflect.ValueOf(unimplemented).Pointer()
}

// TestUnimplementedStubStillDenies401 pins the behaviour the identity check
// above stands in for. Without it, a stub rewritten to return a different class
// (or to answer success) would leave the partition test green while every
// "blocked" op silently changed what it answers.
func TestUnimplementedStubStillDenies(t *testing.T) {
	rec := httptest.NewRecorder()
	out := unimplemented(&handlerDeps{}, handlerCtx{w: rec})
	if out.denyClass != denyUnimplemented {
		t.Errorf("unimplemented stub returned deny class %q, want %q",
			out.denyClass, denyUnimplemented)
	}
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("unimplemented stub wrote HTTP %d, want %d — the 501 status is "+
			"authoritative for an op whose contract body is not pinned",
			rec.Code, http.StatusNotImplemented)
	}
}
