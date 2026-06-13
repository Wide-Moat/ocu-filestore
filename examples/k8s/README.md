# Kubernetes deployment examples — ocu-filestored

This directory contains applyable Kubernetes manifests for the storage broker
(`ocu-filestored`, component-04). The examples target the initial
**single-tenant `trusted_operator` shelf**: one broker instance per tenant, the
local-volume engine backed by RWO PersistentVolumeClaims, and a sandbox peer
co-located in the same Pod via a shared emptyDir socket volume.

Questions or issues: developer@widemoat.ai

---

## File index

| File | Purpose |
|------|---------|
| `pvc.yaml` | PersistentVolumeClaims for engine-root and audit-sink (RWO) |
| `broker-deployment.yaml` | Deployment running the broker alone (no co-located peer) |
| `sandbox-peer-pod.yaml` | Pod running the broker and a sandbox peer in the same pod |

---

## Apply order

PVCs must exist before the Deployment or Pod that references them:

```sh
kubectl apply -f examples/k8s/pvc.yaml
kubectl apply -f examples/k8s/broker-deployment.yaml
# or, for the colocation example:
kubectl apply -f examples/k8s/sandbox-peer-pod.yaml
```

Verify the PVCs are bound before applying the Deployment:

```sh
kubectl get pvc ocu-filestored-engine-root ocu-filestored-audit
```

---

## One broker per tenant (NFR-SEC-76)

The broker's accept gate uses `SO_PEERCRED` to extract the kernel-attested uid
and pid of every connecting peer. It admits **only** a peer whose uid equals the
broker's own uid (65532). This check fires on every `accept()`, not just at
startup.

A single broker instance therefore serves exactly one guest peer. **Do not share
a broker instance across tenants.** Each tenant gets its own Pod (or Deployment
with `replicas: 1`), its own PVCs, and its own socket-dir emptyDir. This is a
hard architectural constraint enforced both by the accept gate and by the RWO
PVCs — no two instances can mount the same volume simultaneously.

If you need multi-tenant operation, that is a separate shelf requiring a
dedicated design. The manifests here describe the single-tenant shelf only.

---

## RWO / single-writer rationale

Both PVCs (`ocu-filestored-engine-root` and `ocu-filestored-audit`) use
`accessModes: [ReadWriteOnce]`. This is the storage-level guarantee that only a
single pod may mount the volume at a time.

**Why RWO is required (not a convenience default):**

1. **Hash-chained audit sink.** The OCSF JSONL audit file is a hash-chained
   append log: each record's `prev_hash` is the SHA-256 of the immediately
   preceding line. Two writers would produce interleaved, non-sequential records
   that cannot be verified by `auditgate.Verify`. The chain would be silently
   broken (NFR-SEC-79).

2. **Local-volume engine scope operations.** `TeardownScope` performs a
   recursive directory removal (erase-before-reuse, NFR-SEC-54). Concurrent
   access from two processes during teardown is undefined and dangerous — one
   could be writing while the other is removing.

3. **Single-instance flock guard.** The daemon acquires `LOCK_EX|LOCK_NB` on a
   lock file at startup (T2-7). This is a second enforcement layer at the
   filesystem level. If two pods somehow mounted the same RWX volume, the second
   would refuse to start. RWO prevents the situation from arising at the storage
   level.

**Never change to ReadWriteMany.** A distributed filesystem that allows
concurrent mounts does not provide the guarantees the broker depends on.

---

## Socket-dir sharing model

The south face serves exclusively over per-session Unix sockets placed in
`-south-socket-dir` (`/run/ocu-filestore/sessions`). Unix sockets are bound to
the filesystem namespace and cannot cross pod boundaries.

The socket-dir is an `emptyDir` volume, scoped to the pod lifetime:

- The broker creates per-session sockets here (`bind()`) and accepts connections.
- The sandbox peer mounts the same volume and dials the socket (`connect()`).
- No other path exists between the broker and the peer.

The peer container's `readOnly: true` volume mount is correct: the peer only
needs to dial the socket (which requires execute permission on the directory), not
create one. The broker sets the socket-dir mode to 0700 owned by uid 65532, so
only a process running as uid 65532 can list or access the directory.

---

## securityContext and seccomp

Every container in these manifests runs with the full hardened securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
```

### Seccomp: RuntimeDefault vs Localhost

The manifests use `seccompProfile.type: RuntimeDefault` (the cluster's built-in
profile) as the **portable default**. This works on any Kubernetes cluster
without any node-level configuration.

For tighter confinement, the shipped `deploy/seccomp/ocu-filestored.json`
(T2-15, NFR-SEC-02) is a broker-specific default-deny allowlist: 143 syscalls
across 16 annotated groups, tightened from the OCI/Moby container default.
To use it as a `Localhost` profile:

1. Copy the profile to each node's seccomp directory:
   ```sh
   # The path varies by kubelet configuration:
   # - kubeadm default: /var/lib/kubelet/seccomp/
   # - containerd default: /var/lib/containerd/seccomp/
   # Adjust NODE_SECCOMP_DIR for your cluster.
   NODE_SECCOMP_DIR=/var/lib/kubelet/seccomp
   cp deploy/seccomp/ocu-filestored.json \
     ${NODE_SECCOMP_DIR}/ocu-filestored/ocu-filestored.json
   ```

2. Replace the seccompProfile stanza in the manifests:
   ```yaml
   seccompProfile:
     type: Localhost
     localhostProfile: ocu-filestored/ocu-filestored.json
   ```

RuntimeDefault is recommended unless node-level profile deployment is part of
your operational workflow. Both provide meaningful seccomp confinement; the
Localhost profile is simply narrower.

### Landlock (future)

Landlock self-restriction (Linux 5.13+) would let the daemon confine its own
filesystem view to exactly the three writable mounts at startup. This is
documented as a future enhancement in the roadmap (T2-15 optional). It requires
a Go source change and must loud-degrade on older kernels; it is not implemented
in the current release.

---

## Liveness and readiness probes

### Liveness (`/healthz`)

The `livenessProbe` uses the daemon's own `-health-check` self-probe mode as an
`exec` probe. The distroless image has no shell or `curl`, so the daemon binary
serves as its own liveness prober: it dials its own ops listener `/healthz` and
exits 0 (alive) or non-zero (unreachable). This mirrors the compose healthcheck
and the Dockerfile `HEALTHCHECK` directive.

```yaml
livenessProbe:
  exec:
    command:
      - /usr/local/bin/ocu-filestored
      - -health-check
```

### Readiness

The `readinessProbe` also uses the daemon's `-health-check` self-probe mode as
an `exec` probe — **not** an `httpGet` probe.

The reason is the ops listener's bind posture. The daemon binds its ops
listener to loopback only (`127.0.0.1:9464`); this is a deliberate security
choice and the daemon must not be changed to bind a non-loopback address. A
kubelet `httpGet` probe, however, is **not** issued from inside the container:
the kubelet dials the pod from the node and a `host: 127.0.0.1` field resolves
to the **node's** own loopback, which never reaches the pod's network
namespace. An `httpGet` probe against a loopback-bound listener therefore never
succeeds, and the pod would never become Ready.

An `exec` probe runs the command **inside the container**, where `127.0.0.1` is
the pod's own loopback and the self-probe reaches the ops listener. The
distroless image has no shell or `curl`, so the daemon binary serves as its own
prober:

```yaml
readinessProbe:
  exec:
    command:
      - /usr/local/bin/ocu-filestored
      - -health-check
```

The `-health-check` self-probe dials the ops listener and confirms the daemon
is serving on its loopback endpoint. The richer audit-latch readiness
distinction (`/readyz` returning 503 when the audit sink is latched — see the
audit-latch recovery runbook in docs/operations.md) is observable directly on
the ops listener from inside the pod, but a kubelet probe of a loopback-bound
listener must go through an `exec` probe rather than `httpGet`.

---

## Customising the deployment

All broker flags also have `OCU_FILESTORE_*` environment variable equivalents
(see docs/operations.md for the full table). Use a ConfigMap or a Deployment
env block to override defaults without modifying these manifests. For example:

```yaml
env:
  - name: OCU_FILESTORE_BROKER_MAX_FILE_SIZE
    value: "524288000"  # 500 MiB
  - name: OCU_FILESTORE_GRANTED_INTENTS
    value: "read,write,preview"
```

Credential-bearing variables (`OCU_S3_ACCESS_KEY_ID`,
`OCU_S3_SECRET_ACCESS_KEY`) must come from a Secret, not a ConfigMap:

```yaml
env:
  - name: OCU_S3_ACCESS_KEY_ID
    valueFrom:
      secretKeyRef:
        name: ocu-s3-credentials
        key: access-key-id
```

These examples target the local-volume engine (no S3 credentials needed). For
the S3 engine, add the required S3 flags and credential Secret; see
docs/engines.md for full details.
