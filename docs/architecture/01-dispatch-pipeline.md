<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# South-face dispatch pipeline (LOCKED STAGE 0 → 4)

This document is the architecture and implementation reference for the
south-face request spine — the part of the broker that terminates the
file-operation RPC arriving from the session sandbox (the guest-mount face).
It explains **how** the spine is built and **why** the stage ordering is
load-bearing. It is the design layer; the operator-facing layers live
elsewhere and are cross-linked rather than repeated:

- Running the daemon, flags, signals, audit-latch recovery: [operations.md](../operations.md).
- Choosing and configuring a storage backend: [engines.md](../engines.md).
- Flag/environment surface and admission rules: [configuration.md](../configuration.md).
- Running the suite, coverage floor, property tests: [testing.md](../testing.md).

The broker is component-04 of the architecture. The behaviours below realise
the NFR-SEC rows the dispatch path is responsible for: scope binding
(NFR-SEC-43), engine-credential isolation (NFR-SEC-16/25), the three-axis
deny-by-default authorization with `downloadable` resolved at read
(NFR-SEC-49, NFR-SEC-73), audit-before-acknowledge fail-closed
(NFR-SEC-79), the host-peer accept gate (NFR-SEC-76), and the per-request and
whole-object size ceilings (NFR-SEC-46/78).

All code references below name the actual file and function in
`internal/southface/`. Everything stated here is the behaviour the committed
code exhibits today.

---

## 1. Why the pipeline is locked

Every accepted request runs through one ordered pipeline implemented in
`dispatch.go:ServeHTTP`. The ordering is not an accident of how the code grew —
it is the security property. Each stage establishes an invariant the next
stage relies on, and **no stage trusts the request body until the body's scope
hint has been cross-checked against the host-attested channel identity**. The
governing rule, stated in the `ServeHTTP` doc comment, is: the order is
load-bearing and must not be reordered.

The pipeline is:

| Stage | Name | What it establishes | Trusts the body? |
|-------|------|---------------------|------------------|
| 0 | Header / throttle gate | Route, protocol version, content type, channel scope, declared-size pre-buffer reject, ops/s throttle — **no body byte is read** | No |
| 1 | Strict envelope decode | The body is a single well-formed JSON object; its scope/intent fields are now readable | Reads, does not yet trust |
| 1b | Channel-scope cross-check | The body's `filesystem_id` equals the channel-bound scope | Now trusted for scope |
| 2 | Route-op → required-intent authz | The route op (not the wire intent) determines the required intent; the resolver re-derives the grant | Trusted |
| 3 | Audit Mandate **before** any 2xx | A broker-resolved-truth allow record durably lands before the operation is acknowledged | Trusted |
| 4 | Per-op handler | The cleared request reaches the registered handler | Trusted |

Two cross-cutting wrappers sit **outside** the locked order and never modify
it:

- **Panic containment** (`panic_recovery.go:recoverDispatch`), a deferred
  `recover()` registered before STAGE 0 runs.
- **Metric/log instrumentation** (the `denyOp` / `recordAllow` /
  `observeStage` calls), which are strictly additive observation around the
  existing stage calls — they wrap calls, they never reorder them.

### Stage-by-stage sequence (unary request)

```mermaid
sequenceDiagram
    autonumber
    participant G as Guest (session sandbox)
    participant S as ServeHTTP (spine)
    participant R as Resolver (authz)
    participant A as Guard (audit gate)
    participant H as Handler (STAGE 4)
    participant E as Engine

    G->>S: POST /…/FilesystemService/<op> (Connect unary JSON)
    Note over S: STAGE 0 — mint x-request-id, parse route,<br/>check version + Content-Type, read PeerScope,<br/>Content-Length pre-buffer reject, ops/s throttle
    Note over S: No body byte read yet
    S->>S: STAGE 1 — buffer body once (MaxBytesReader), strict-decode envelope
    S->>S: STAGE 1b — env.filesystem_id == PeerScope.FilesystemID ?
    alt scope hint disagrees
        S-->>G: permission_denied + x-deny-reason: scope_mismatch
    end
    S->>S: STAGE 2 — requiredIntentForOp(op); wire intent must equal it
    S->>R: Resolve(evidence=channel scope, intent=route-derived)
    R-->>S: Grant{Downloadable}
    S->>A: STAGE 3 — Mandate(allow event) BEFORE any 2xx
    alt audit gate down
        S-->>G: unavailable (no x-deny-reason)
    end
    A-->>S: ok (durably landed)
    S->>H: STAGE 4 — registry[op](deps, ctx)
    H->>E: engine verb (Stat/List/MakeDir/…)
    E-->>H: result
    H-->>G: 200 + op body (or framed handler-stage deny)
```

---

## 2. STAGE 0 — header / throttle gate (no body byte read)

`dispatch.go:ServeHTTP` runs STAGE 0 entirely on request metadata. The
invariant is that nothing here may read or trust a body byte: a malformed,
oversized, or hostile body must be rejected on its envelope, never by parsing
it (NFR-SEC-76/78). The steps, in order:

1. **Mint the correlation id and stamp it immediately.**
   `newCorrelationID` (`deny.go`) returns a 32-char lowercase hex token from
   16 bytes of `crypto/rand`; a failing kernel CSPRNG is treated as
   unrecoverable and panics. The id is set on the `x-request-id` response
   header **before any code path that could call `WriteHeader`**, so it is
   present on **every** response — allow and deny, unary and streaming. It is
   high-cardinality and deliberately **never** used as a metric label (it links
   the log line, the audit record, and the wire response only).

2. **Derive a request-scoped logger.** `d.logger.With(request_id)` so every
   subsequent log line for this request carries the id without each call site
   passing it.

3. **Register panic containment.** `defer d.recoverDispatch(w, &reqLog)()` —
   see [§8](#8-panic-containment).

4. **Parse the route.** `envelope.go:parseRoute` matches the method and path.
   A non-POST is `errBadMethod` → a 405 with an `Allow: POST` header (the
   Connect code stays `invalid_argument`, but HTTP method semantics demand
   405, applied through `DenyVerdict.withStatus`). A path outside the service
   prefix `/ocu.filestore.v1alpha.FilesystemService/` or naming an op outside
   the closed `knownOps` set is `errUnknownRoute` → `invalid_argument`. No body
   byte has been read.

5. **Streaming branch (here, by per-op flag).** If `isStreamingOp(op)` is true
   (`fileUpload` or `fileDownload`), dispatch hands off to
   `stream_handler.go:serveStreaming` and returns. This branch is taken
   **before** the unary content-type and Content-Length checks on purpose: the
   unary `checkContentType` hard-equals `application/json` and the unary
   Content-Length pre-buffer reject would both kill a chunked
   `application/connect+json` upload. The branch is on a per-op flag, not a
   content-type sniff. See [§7](#7-streaming-dispatch).

6. **Version header.** `checkVersion` requires `Connect-Protocol-Version: 1`;
   absent or wrong is `invalid_argument` before the body is parsed.

7. **Content-Type.** `checkContentType` requires `application/json` (a trailing
   `;charset=…` parameter is tolerated).

8. **PeerScope from the connection context.** `peerScopeFromContext` reads the
   host-attested channel identity (UID/PID/filesystem id/granted intents)
   established at accept time. Its **absence is a wiring fault and fails
   closed** to `internal`/500 — the spine never proceeds without a channel
   binding (NFR-SEC-43/76).

9. **Declared-size pre-buffer reject (NFR-SEC-78).** A unary request carries a
   known-size body, so an **absent Content-Length** (`r.ContentLength < 0`) is
   refused (`malformed_envelope`) before any byte is read; a Content-Length **above the
   per-message ceiling** is a `size_exceeded` deny. This is the cheap reject
   that runs before the buffer is even allocated.

10. **Ops/s throttle, keyed on the CHANNEL scope.** `d.ceilings.Session(ps.FilesystemID).TryConsumeOp()`.
    The throttle key is the channel scope (`PeerScope`), **never** a body field —
    consistent with the rule that nothing trusts the body before STAGE 1b. A
    throttle breach is `resource_exhausted` with **no** `x-deny-reason` header.

Faults before the op is known (unknown route, bad method) record no
`ops_total` entry because there is no op to label; they use the plain
`denyWithLog`. Once the op is known, refusals flow through the `denyOp`
closure, which writes the wire deny **and** records exactly one
`ops_total{op, outcome=deny, deny_class}` entry.

---

## 3. STAGE 1 — strict envelope decode

The body is read **once**, through a `http.MaxBytesReader` backstop bound to
the per-message size ceiling, into an in-memory buffer (`io.ReadAll`). The same
buffer is handed to the per-op handler later, so the handler re-decodes the
op-specific fields **without a second network read** — the single read keeps
the size ceiling intact.

- A `MaxBytesError` from the read (a body that exceeds the ceiling, including a
  lying or absent Content-Length that slipped the STAGE-0 cheap check) maps to
  `size_exceeded`.
- Any other read error maps to `malformed_envelope`.

The spine then strict-decodes its **routing/cross-check view** of the body with
`envelope.go:decodeUnaryEnvelopeBytes` into `unaryEnvelope`
(`{filesystem_id, path, authorization_metadata{intent, downloadable}}`). This
decode is **deliberately lenient on unknown fields**: the op-specific fields
(`source`, `destination`, `limit`, `cursor`, `recursive`, `overwrite_existing`,
`make_parents`, …) belong to the real per-op body and are strict-decoded later
by the handler, which owns the authoritative schema. The spine decode still
rejects a body that is not a single well-formed JSON object — a decode error or
a trailing second JSON value is `malformed_envelope`.

> The package also carries a fully strict reader-path decoder
> (`decodeUnaryEnvelope`, with `DisallowUnknownFields`) and a strict in-memory
> decoder (`decodeStrictBytes`) used by the handlers. The dispatcher uses the
> lenient buffered envelope decode at STAGE 1 and the strict `decodeStrictBytes`
> at STAGE 4, so the unknown-field guard lands where the full schema is known.

---

## 4. STAGE 1b — channel-scope cross-check

This is the firewall between untrusted body and trusted body. The decoded
`env.FilesystemID` is an **untrusted hint**. If it does not equal the
channel-bound `ps.FilesystemID`, the request is a `scope_mismatch` deny
(`permission_denied` + `x-deny-reason`) and **the handler is never reached**
(NFR-SEC-43). The host-attested channel scope is authoritative; a guest cannot
reach into another scope by writing a different `filesystem_id` in its body.

There is no route-op-vs-envelope-op cross-check because the unary body carries
no op field in this build: the **route op is authoritative** and the body's
scope and intent are the only cross-checked fields. (The op cross-check is
implicit — the route names the op, and the next stage binds that op to its
required intent.)

After STAGE 1b, the body's scope is trusted; everything downstream keys on the
channel scope.

---

## 5. STAGE 2 — route-op → required-intent authz (the AUTHZ-01 binding)

This stage carries the authorization fix the system is built around. The
principle, stated in both `dispatch.go:ServeHTTP` and the
`envelope.go:opRequiredIntent` doc comment:

> The op the route names is the **authoritative** statement of what the request
> does; the wire `authorization_metadata.intent` is an **untrusted hint**.

The closed map `envelope.go:opRequiredIntent` binds each routable op to the
intent it requires — read-class lookups/content-reads to `IntentRead`, every
namespace or content mutation to `IntentWrite`. `requiredIntentForOp` looks it
up; an op absent from the closed map is a **wiring fault and fails closed**
(`internal`/500).

The fix has two halves:

1. **The intent passed to the resolver is derived from the route op, never
   from the wire.** `requiredIntent := requiredIntentForOp(op)` is what the
   `ResolveRequest.Intent` carries into `d.resolver.Resolve`. A session granted
   only read can therefore never reach a mutating handler.

2. **A wire intent that disagrees with the route op's required intent is
   refused before the resolver is consulted.** If
   `env.AuthorizationMetadata.Intent != requiredIntent`, the request is
   `errRouteOpMismatch` → `malformed_envelope`/`invalid_argument`, and `Resolve` is
   never called. This closes the attack where a caller declares `intent=read`
   on a mutation route to slip a read-only grant past authorization.

The resolver is then consulted with **caller evidence built from the channel
scope, never from a request field**:

```
evidence := CallerEvidence{Scope: ps.FilesystemID, GrantedIntents: ps.GrantedIntents}
req      := ResolveRequest{Filesystem: env.FilesystemID, Path: env.Path, Intent: requiredIntent}
grant, err := d.resolver.Resolve(r.Context(), evidence, req)
```

A resolver error maps through `deny.go:denyClassForErr` (the three-axis
deny sentinels — `ErrScopeMismatch`, `ErrIntentDenied`, `ErrNotDownloadable`,
`ErrLeaseExpired`, plus size/throttle/audit/aborted classes). The returned
`Grant` carries `Downloadable`, which the read path resolves **at read** and
the write path never stamps (NFR-SEC-73).

A note on `IntentPreview`: no op maps to it on this face. Preview is the
north-face render axis and is never a legal south-face wire intent
(`requiredIntentForOp` doc comment).

---

## 6. STAGE 3 — audit Mandate before acknowledge (fail-closed)

Before **any** 2xx can be written, the spine emits a broker-resolved-truth
**allow** record and requires it to land durably (NFR-SEC-79). This is
audit-before-acknowledge: the operation is not acknowledged to the guest until
its allow record is durable.

`dispatch.go:auditEvent` builds the per-op allow event with the op-aware
fields:

- **ActivityID** (`activityForOp`): make/move/copy → Create (1); remove →
  Delete (4); listing and the rest → Read (2). There is no rename/move
  activity id, so a move/copy is recorded as a Create on the **produced**
  (destination) handle.
- **ObjectHandle** (`objectHandleForOp`): `scope:path`, where for
  move/copy the path is the **destination** read out of the buffered body (the
  spine envelope carries no destination field, so the handle is recovered from
  the same buffer the handler will re-decode).
- **Intent** = the route-derived required intent.
- **Downloadable** = the resolved grant's value.
- **RequestID** = the STAGE-0 correlation id (one id, end to end).

`d.guard.Mandate(ctx, …)` is the gate call. **An audit-write failure denies the
operation** (`denyClassForErr(mandateErr)` → typically `audit_down` →
`unavailable`, with **no** `x-deny-reason`) and the handler is never invoked.
On success the spine emits a DEBUG-level allow line carrying the op and
request id, then proceeds.

The pre-handler allow Mandate stays at STAGE 3, before STAGE 4. A
**handler-stage** operational refusal (e.g. a non-empty directory, a
not-downloadable read) emits a **second**, compensating deny event through the
`mandateDeny` hook — see [§6.1](#61-the-mandatedeny-hook-and-the-d8-degrade-rule).

### 6.1 The `mandateDeny` hook and the D8 degrade rule

The spine builds a `mandateDeny(auditReason, wireClass, message)` closure and
passes it to the handler. It lets a handler-stage refusal emit its own deny
audit event **before** the wire deny, **without** relocating the spine's
pre-handler allow Mandate into per-op code (the locked ordering is preserved).
The handler supplies only the per-op deny content; the spine owns the Mandate
ordering and the wire write.

Two reasons a deny event is needed at the handler stage:

- The STAGE-3 record asserts **allow**. If an operation is then refused inside
  the handler, the durable chain's terminal record would falsely assert allow
  for a refused op. The compensating deny event captures that the op did **not**
  take effect.
- The **audited truth** and the **wire reason** may differ (the **D8 degrade
  rule**). The audit record carries the broker-resolved truth; the wire may
  degrade away from it for anti-enumeration.

The hook's own failure path is fail-closed: if the **deny** Mandate fails, the
verdict degrades to `audit_down`/`unavailable` with no `x-deny-reason`. The
reasoning (in the `mandateDeny` comment): if the deny record did not durably
land, the chain's last record would be the STAGE-3 allow — asserting allow for
a refused op — so the wire must say `unavailable` and carry no truth header
(the truth header only ever accompanies a recorded truth).

---

## 7. STAGE 4 — per-op handler dispatch

The cleared request reaches `d.registry[op]`. A route op absent from the
registry is a wiring fault → `unimplemented`/501 (fails closed). The handler
runs with a `handlerCtx` carrying the request context, the response writer, the
routed op, the **buffered body** (re-decoded for op-specific fields), the
channel `PeerScope`, the resolved `Grant`, and the `mandateDeny` hook.

### 7.1 Exactly-once metric accounting

The handler reports an `opOutcome` (`handler_stub.go`) so the spine records
`ops_total` **exactly once** for the dispatched op:

- `outcomeAllow()` — the handler wrote a success response → spine records
  `outcome=allow, deny_class=none`.
- `outcomeDenyRecorded()` — the handler refused **through** `mandateDeny`,
  which already recorded the deny → spine records **nothing further**.
- `outcomeDeny(class)` — the handler wrote the wire error **directly** (a
  malformed op body, a malformed cursor, the unimplemented stub) and never
  touched the counter → spine records the single deny from `class`.

This closes a prior bug where `recordAllow` fired unconditionally and a
handler that refused internally still booked a spurious `outcome=allow`.

### 7.2 Defense-in-depth at the handler

Every mutation handler runs `handlers.go:assertWriteGrant` **before any engine
touch**: even if the STAGE-2 route-op→intent binding were ever regressed, a
session whose channel-bound grant set lacks `IntentWrite` can never reach a
mutating engine verb. `handleReadFile` mirrors this with a
`grant.Downloadable` check **first**, before any engine call, reading **only**
the broker-resolved grant — never the wire `downloadable` flag (NFR-SEC-73).

### 7.3 The 10 implemented vs 8 unimplemented ops

The frozen `Op` enum (`southface.go`) has 18 members. The registry
(`handler_stub.go:newHandlerRegistry`) is built from the **closed** op set with
every entry pointing at `unimplemented`, guaranteeing full coverage;
`newDispatcherWithEngine` then replaces the implemented ops when an engine is
bound. A dispatcher built with a nil engine (the spine-only tests) leaves every
op unimplemented.

**10 implemented** (real handlers over the engine seam):

| Op | Handler | Path |
|----|---------|------|
| `listDirectory` | `handleListDirectory` | unary (STAGE 4 registry) |
| `makeDirectory` | `handleMakeDirectory` | unary |
| `moveDirectory` | `handleMoveDirectory` | unary |
| `removeDirectory` | `handleRemoveDirectory` | unary |
| `copyFile` | `handleCopyFile` | unary |
| `moveFile` | `handleMoveFile` | unary |
| `removeFile` | `handleRemoveFile` | unary |
| `readFile` | `handleReadFile` | unary |
| `fileUpload` | `handleFileUpload` | **streaming** (out-of-band, [§8](#8-streaming-dispatch)) |
| `fileDownload` | `handleFileDownload` | **streaming** (out-of-band) |

`fileUpload` and `fileDownload` are dispatched out-of-band via
`serveStreaming` and are **never read from the registry**, so their registry
entries stay `unimplemented` and are never reached on the streaming path.

**8 unimplemented** (TBD per the frozen contract — the bodies are not pinned, so
no handler is invented):

`createFile`, `readMetadata`, `getFileMetadata`, `listFiles`, `importFiles`,
`importZip`, `migrateFilesystem`, `removeFilesystem`. Each resolves to
`handler_stub.go:unimplemented` → `unimplemented`/501 with no `x-deny-reason`.
The registry is complete; those bodies are not.

---

## 8. Streaming dispatch

The two highest-volume data-plane ops, `fileUpload` and `fileDownload`, run on
a streaming path that diverges from the unary spine at STAGE 0. The contract:
**the stream is always HTTP 200**; every verdict — allow or deny — rides in a
framed trailer, never a unary error body. This is so the guest's
trailer-authoritative retry logic always sees the verdict in the same place.

### 8.1 The 5-byte frame envelope

`stream.go` defines the codec, byte-identical to the guest framer:

```
+--------+--------+--------+--------+--------+===============+
| flag   |        payload length (uint32 BE) |   payload …   |
| 1 byte |        4 bytes, big-endian         | compact JSON  |
+--------+--------+--------+--------+--------+===============+
```

- **byte 0 — flag.** `0x00` = data frame (params or chunk on intake; content
  on a download response). `0x02` = end-stream frame carrying the verdict
  (`{}` success, or `{"error":{code,message}}`).
- **bytes 1–4 — payload length** as a big-endian `uint32`.
- **payload** — compact JSON.

`readFrame` checks the declared length against `maxInboundFrame` (4 MiB)
**before allocating any payload buffer**, so a corrupt or desynced length
cannot drive a multi-GiB allocation; an over-cap length is `errFrameTooLarge` →
`resource_exhausted` (a **transport** reject, distinct from the policy
`size_exceeded` deny applied to `declared_size_bytes`). `writeFrame` writes the
header then the payload (a zero-length payload writes only the header).
`writeEndStream` writes the terminal `0x02` trailer — a nil error writes the
literal `{}` success body; the trailer writer **is** the frame writer, the
single path every reject and the success path use, and it is written **before**
intake is closed on a mid-stream reject.

### 8.2 Streaming STAGE-0 gate

`serveStreaming` mirrors the unary STAGE-0 with three differences:

1. **PeerScope first.** Without the channel binding there is no scope to key
   audit/ceilings on. This is the **one** streaming fault written as a unary
   error (`internal`) — there is no session to frame a trailer against, and the
   200 header has not yet been committed.
2. **Then commit the HTTP 200 header** (`application/connect+json`). From here
   every refusal is a framed `0x02` trailer.
3. It admits `application/connect+json` (not `application/json`) via
   `checkStreamContentType`, and **does not** apply the unary Content-Length
   pre-buffer reject (a chunked body has no fixed length; size policy moves to
   `declared_size_bytes` after the params frame). The ops/s throttle is still
   keyed on the channel scope.

Each streaming STAGE-0 deny records `ops_total` directly, mirroring the unary
`denyOp` choke point.

### 8.3 Upload contract (`handleFileUpload`)

```mermaid
sequenceDiagram
    autonumber
    participant G as Guest
    participant U as handleFileUpload
    participant R as Resolver
    participant A as Guard (audit)
    participant P as io.Pipe
    participant E as engine.WriteStream

    G->>U: 0x00 params frame {filesystem_id, path, declared_size_bytes, overwrite_existing}
    Note over U: read EXACTLY one params frame (per-frame read deadline armed)
    U->>U: declared_size_bytes > 0 ? (else invalid_argument)
    U->>U: params.filesystem_id == channel scope ? (else scope_mismatch trailer)
    U->>R: Resolve(intent=write) from channel scope
    R-->>U: Grant
    U->>U: checkDeclaredSize(declared, maxFileSize) BEFORE any chunk (SEC-46)
    U->>A: Mandate ALLOW before any chunk (audit-before-ack)
    alt audit down
        U-->>G: 0x02 unavailable trailer
    end
    U->>U: TryAcquireFD (fd ceiling)
    loop each 0x00 chunk frame
        G->>U: 0x00 {chunk:"<base64>"}
        U->>U: acc += n; acc > declared ? → size_exceeded trailer (atomic abort)
        U->>U: AcquireBytes(n) (in-flight byte ceiling)
        U->>P: pw.Write(chunk)
        P->>E: WriteStream reassembles (temp + rename)
    end
    G->>U: 0x02 end-stream (client half-close = authoritative end)
    U->>U: acc == declared ? (else size_exceeded trailer, atomic abort)
    U->>P: pw.Close() → WriteStream commits (object visible only now)
    U-->>G: 0x02 success trailer ( = the ack)
```

Load-bearing details from the code:

- **One params frame first.** A read error or a leading end-stream frame is a
  hard abort. `declared_size_bytes` is **required** (`<= 0` denies
  `invalid_argument`, no escape hatch).
- **Everything keys on the channel scope**, never the params value; a params
  `filesystem_id` that disagrees is `scope_mismatch`.
- **Pre-buffer size reject** (`checkDeclaredSize`, NFR-SEC-46) runs **before
  any chunk byte is read** — zero chunk bytes read on reject. `checkDeclaredSize`
  is a single `>` comparison (overflow-safe; never a subtraction); a declaration
  exactly at the ceiling is admitted (strict `>`). The whole-object ceiling
  `maxFileSize` is **distinct** from the per-message ceiling `sizeCeiling`: an
  unwired dispatcher leaves `maxFileSize` at 0 and therefore **refuses any
  non-empty upload** — fail-closed and loud, never a silent placeholder.
- **Audit ALLOW before any chunk**; an audit-down error denies before any
  chunk.
- **Ceilings released on every exit.** The fd ceiling brackets the open handle;
  the in-flight byte ceiling brackets reassembly, released via `defer` on every
  path.
- **Atomicity on abort.** Reassembly is a single `io.Pipe` →
  `engine.WriteStream(overwrite=params.OverwriteExisting)`. An aborted upload
  closes the pipe with the non-EOF `errStreamAborted` sentinel, **never** raw
  `io.EOF` — `io.Copy` inside `WriteStream` treats a pipe read returning EOF as
  a clean end-of-stream and would commit the partial bytes, so the sentinel
  forces `WriteStream` to fail and reclaim the temp. An aborted upload stages
  nothing visible.
- **Size enforcement is two-directional.** Over-declaration (`acc > declared`)
  aborts at the ceiling; under-declaration (`acc != declared` at half-close)
  also aborts — both `size_exceeded`, staging nothing.
- **Every reject writes the `0x02` trailer before closing intake**; the deny
  trailer's own Mandate-failure path degrades to `unavailable`, mirroring the
  unary `mandateDeny` rule.
- **The success ack IS the trailer.** The allow Mandate already preceded it.

### 8.4 Download contract (`handleFileDownload`)

- Read **exactly one** `0x00` params frame; strict-decode it.
- Cross-check `filesystem_id` against the channel scope.
- Resolve the `uuid → (scope, path)` through the **session-scoped**
  `objectIDStore`. An unknown uuid is `not_found`. A **cross-scope** uuid (the
  stored scope differs from the channel scope) **audits as `scope_mismatch`**
  but **degrades to `not_found` on the wire** (the D8 anti-enumeration rule —
  a valid uuid from another session cannot be used to probe scope membership).
  The `ops_total` deny_class is the audited **truth** (`scope_mismatch`), not
  the degraded wire class.
- `Resolve(intent=read)`; then **DOWNLOADABLE@READ** from the broker-resolved
  grant (NFR-SEC-73) — the wire flag is never consulted; a non-downloadable
  grant denies.
- A whole-object read (nil `Range`) resolves its length from a `Stat` run
  **before** the ALLOW Mandate, so a vanished object records a single deny, not
  an allow-then-deny pair. That `Stat` is panic-contained
  (`statSizeContained`) so it cannot escape the streaming contract.
- **Mandate the ALLOW before the first data frame**; an audit-write failure
  denies before any byte is sent.
- Stream the bytes via `engine.ReadRange(offset, length)` in
  `downloadChunkSize` (256 KiB) chunks, each a `0x00` data frame
  `{"data":"<base64>"}`, then a `0x02` success trailer. A mid-stream engine
  error terminates with a `0x02` error trailer. A client disconnect mid-stream
  books the verdict as `aborted` so the dropped download is still visible in
  `ops_total`.

---

## 9. Deny vocabulary and wire-code mapping

Every refusal the spine writes flows through **one** mapper in `deny.go` —
the single source of truth. The deny-class token strings are owned by the
shared, zero-dependency `internal/denyclass` package, consumed by both the
south face and the telemetry `deny_class` label enum, so the two can never
drift (a drift-guard test fails if `denyTable` loses a class the shared
vocabulary defines).

### 9.1 The classes

The **first six** are the contract's deny vocabulary — the **only** values that
may ever surface in an `x-deny-reason` header:

| Deny class | Wire code | HTTP | `x-deny-reason`? |
|------------|-----------|------|------------------|
| `scope_mismatch` | `permission_denied` | 403 | yes |
| `intent_denied` | `permission_denied` | 403 | yes |
| `not_downloadable` | `permission_denied` | 403 | yes |
| `lease_expired` | `unauthenticated` | 401 | yes |
| `size_exceeded` | `invalid_argument` | 400 | no |
| `not_found` | `not_found` | 404 | no |

The remaining classes are capacity, conflict, registry, and system states.
They **never** carry the header; their names exist for the audit record and the
wire-code mapping only:

| Deny class | Wire code | HTTP | `x-deny-reason`? |
|------------|-----------|------|------------------|
| `malformed_envelope` | `invalid_argument` | 400 | no |
| `directory_not_empty` | `invalid_argument` | 400 | no |
| `throttle` | `resource_exhausted` | 429 | no |
| `audit_down` | `unavailable` | 503 | no |
| `backend_unavailable` | `unavailable` | 503 | no |
| `already_exists` | `already_exists` | 409 | no |
| `aborted` | `aborted` | 409 | no |
| `unimplemented` | `unimplemented` | 501 | no |
| `internal` | `internal` | 500 | no |

The header is gated by `DenyVerdict.WireHeader`, which `denyTable` sets `true`
**only** for the four authorization verdicts whose wire code is
`permission_denied` or `unauthenticated`. An unknown class fails closed to
`internal`/500 with no header (`mapDeny`).

### 9.2 The D8 audit-truth-vs-wire-degrade rule

`DenyVerdict` separates four things:

- **`AuditReason`** — the broker-resolved **truth** that goes into the audit
  record.
- **`WireCode` / `WireStatus`** — what the caller sees, which **may degrade
  away from the truth** for anti-enumeration.
- **`WireHeader`** — gates `x-deny-reason: <AuditReason>` to authorization
  verdicts only.
- **`CorrelationID`** — links the audited record to the wire response whenever
  truth and wire differ; callers set it to the per-request id so the audit
  record, the `x-request-id` header, and the log line share **one** id.

`mapDeny(class)` produces a verdict with wire reason **equal** to the truth (no
degrade). `mapDenyDegraded(auditReason, wireClass)` produces the split: the
audit carries `auditReason`, the wire carries `wireClass`'s code/status/header.
The canonical degrade is the cross-scope download (audited `scope_mismatch`,
wire `not_found`) and the engine path-escape (audited `scope_mismatch`, wire
`not_found`) — see `handlers.go:auditTruthForEngineErr`. Operators still see the
real reason: the deny WARN log line carries `deny_class = AuditReason` (the
truth), never the degraded wire reason (`denyWith` / `denyWithLog`).

### 9.3 Error → class classification

- `deny.go:denyClassForErr` maps consumer-side seam sentinels. It classifies
  `context.Canceled` / `context.DeadlineExceeded` **first** as `aborted` (a
  clean client disconnect or deadline, not a generic error), then the
  three-axis authz sentinels, then size/throttle/audit. An error outside the
  known set fails closed to `internal`.
- `envelope.go:denyClassForDecodeErr` maps envelope/route decode sentinels:
  `size_exceeded` for the size sentinel; `malformed_envelope` for the
  malformed-envelope / unknown-route / bad-version / bad-content-type /
  route-op-mismatch sentinels; `internal` otherwise. (`errBadMethod` is handled
  out of band as the 405.)
- `handlers.go:auditTruthForEngineErr` names the audited truth for engine
  errors (the path-escape → `scope_mismatch` truth that degrades to the
  `not_found` wire class is the D8 case).

---

## 10. Panic containment

`panic_recovery.go:recoverDispatch` is a deferred `recover()` registered at the
top of `ServeHTTP`, **outside** the locked STAGE 0→4 pipeline — a pure additive
safety net. On a panic it:

1. Logs at ERROR (never the panic value — it may contain request bytes),
   carrying `deny_class = internal` and the request-scoped logger (so the
   request id is present once STAGE 0 has initialised it; it falls back to the
   base logger otherwise).
2. Makes a **best-effort** audit Mandate for an internal-deny event on an
   **independent `context.Background()`** (the original request context may be
   cancelled or panicking) so the panic is audited per the NFR-SEC-79
   fail-closed intent. This is wrapped in a nested `recover()` so a panicking
   guard cannot undo the wire deny.
3. Writes a structured `internal`/500 Connect error — the caller sees a typed
   error, **never** a naked connection drop or an unfinished response. Also
   wrapped in a nested `recover()`.

The streaming engine goroutines have their own containment:
`recoverWriteStream` and `recoverReadStream` catch a panicking engine
`WriteStream` / `ReadRange`, close the pipe with the `errInternalPanic`
sentinel (unblocking the peer side of the pipe immediately), and send the
sentinel on the error channel so the streaming handler drains and writes a deny
trailer. `errInternalPanic` maps through `denyClassForEngineErr` →
`internal` → `wireCodeInternal`, the same path as any other unrecognised engine
fault. The engine's temp+rename atomicity guarantees no torn object is visible
after a recovered upload panic.

---

## 11. Invariants summary

| Invariant | Where enforced | NFR |
|-----------|----------------|-----|
| No body byte read or trusted before STAGE 1b | STAGE 0 ordering; throttle keyed on channel scope | SEC-76/78 |
| Channel scope is authoritative; body `filesystem_id` is a hint | STAGE 1b cross-check | SEC-43 |
| Route op (not wire intent) determines required intent; disagreement refused | STAGE 2 `opRequiredIntent` + mismatch reject | SEC-49 |
| Deny-by-default authz re-derived per request from channel evidence | STAGE 2 `Resolve` | SEC-49 |
| `downloadable` resolved at read from the broker grant, never the wire flag | `handleReadFile` / download `grant.Downloadable` check | SEC-73 |
| Audit allow record durable before any 2xx; audit-down denies | STAGE 3 Mandate | SEC-79 |
| Handler-stage refusal emits a compensating deny event | `mandateDeny` hook | SEC-79 |
| Audited truth may differ from the degraded wire reason | `DenyVerdict` / `mapDenyDegraded` (D8) | — |
| Per-request and whole-object size ceilings, fail-closed | STAGE-0 pre-buffer reject; `checkDeclaredSize` | SEC-46/78 |
| Streaming verdict always in an HTTP-200 framed trailer | `serveStreaming` / `writeEndStream` | — |
| Panic returns a typed deny, audited best-effort, never a naked drop | `recoverDispatch` | SEC-79 |
| One mapper for every refusal; deny vocabulary single-sourced | `deny.go` / `internal/denyclass` | — |

---

For how to operate the daemon that hosts this pipeline, see
[operations.md](../operations.md). For the backend engines the STAGE-4 handlers
call, see [engines.md](../engines.md). For how the pipeline is tested
(including the property tests on the authz binding and path resolution), see
[testing.md](../testing.md).

_Maintainer contact: developer@widemoat.ai_
