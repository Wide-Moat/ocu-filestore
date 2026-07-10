// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command ocu-filestored is the storage-broker daemon (component-04): one
// process, two faces (guest-mount south, data-plane-client north), one backend
// credential. This build composes the south face into a real, dialable daemon:
// it parses the flag surface, runs the startup admission gate BEFORE binding
// any listener (NFR-SEC-60), constructs the local-volume engine, the three-axis
// resolver, the fail-closed audit sink, and the per-session ceilings registry,
// wraps them in the broker adapters, provisions a session scope, and serves the
// south-face TLS HTTPS listener. The guest reaches that listener outbound
// through the Egress edge (guest -> edge -> service direct HTTPS); there is no
// unix socket.
//
// The south-face transport flags are -south-bind (the service_url the guest
// dials through the edge) and the REQUIRED -tls-cert / -tls-key (the service's
// own server certificate and private key). The rest of the surface: -tenancy /
// -profile (the admission axes), -audit-sink, -engine / -engine-root, the s3
// backing-store flags (-s3-bucket / -s3-endpoint / -s3-region / -s3-path-style /
// -s3-credential-file), -broker-max-file-size (>0, the whole-object ceiling),
// -filesystem-id, -granted-intents, -downloadable-prefixes, -max-request-bytes
// (the per-RPC-message ceiling), and the optional per-session ops token-bucket
// tuning pair -ops-per-second (>0) / -ops-burst (>=1). The north Files-API
// listener (Mount B, ADR-0023) binds on -north-bind (deprecated alias
// -north-listen) and is live ONLY when -handle-store is set; otherwise only the
// south listener binds.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/Wide-Moat/ocu-filestore/internal/admission"
	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/authz"
	"github.com/Wide-Moat/ocu-filestore/internal/broker"
	"github.com/Wide-Moat/ocu-filestore/internal/ceilings"
	"github.com/Wide-Moat/ocu-filestore/internal/filesapi"
	"github.com/Wide-Moat/ocu-filestore/internal/flock"
	"github.com/Wide-Moat/ocu-filestore/internal/handlestore"
	"github.com/Wide-Moat/ocu-filestore/internal/northface"
	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
	"github.com/Wide-Moat/ocu-filestore/internal/observ"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
	"github.com/Wide-Moat/ocu-filestore/internal/telemetry"
)

// version is the build tag stamped by the release pipeline via
// `-ldflags "-X main.version=<tag>"`. A non-release build reports "dev".
var version = "dev"

// versionString reports the daemon build identity on one line: the stamped
// version, the VCS revision and commit time when the build carries them
// (runtime/debug build info; a dirty working tree is marked), and the Go
// toolchain version.
func versionString() string {
	var b strings.Builder
	b.WriteString("ocu-filestored " + version)
	if info, ok := debug.ReadBuildInfo(); ok {
		var rev, vcsTime, modified string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.time":
				vcsTime = s.Value
			case "vcs.modified":
				modified = s.Value
			}
		}
		if rev != "" {
			if len(rev) > 12 {
				rev = rev[:12]
			}
			if modified == "true" {
				rev += "-dirty"
			}
			b.WriteString(" (" + rev)
			if vcsTime != "" {
				b.WriteString(" " + vcsTime)
			}
			b.WriteString(")")
		}
		if info.GoVersion != "" {
			b.WriteString(" " + info.GoVersion)
		}
	}
	return b.String()
}

// errHealthCheckFailed is returned by runHealthCheck when /healthz does not
// answer 200 (the daemon is unreachable or not serving). Match it with
// errors.Is.
var errHealthCheckFailed = errors.New("ocu-filestored: health-check probe failed")

// runHealthCheck is the -health-check self-probe mode: it dials -ops-listen
// /healthz and returns nil (exit 0) if the response is 200, otherwise a typed
// error (non-zero). This is the container-healthcheck probe: the distroless
// image has no shell/curl, so the HEALTHCHECK exec's the daemon binary itself
// with -health-check instead of a curl one-liner.
func runHealthCheck(opsListenAddr string) error {
	if opsListenAddr == "" {
		return fmt.Errorf("%w: -ops-listen is empty; no ops listener to probe", errHealthCheckFailed)
	}
	url := "http://" + opsListenAddr + "/healthz"
	resp, err := http.Get(url) //nolint:noctx // short-lived self-probe, no context needed
	if err != nil {
		return fmt.Errorf("%w: %v", errHealthCheckFailed, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: /healthz returned %d", errHealthCheckFailed, resp.StatusCode)
	}
	return nil
}

// errBadProfile rejects an admission profile outside the legal set. Match it
// with errors.Is.
var errBadProfile = errors.New("ocu-filestored: unknown admission profile")

// errBadTenancy rejects a tenancy mode outside the legal set. Match it with
// errors.Is.
var errBadTenancy = errors.New("ocu-filestored: unknown tenancy mode")

// errMissingRequiredFlag is returned when a required flag is empty or a
// numeric ceiling is non-positive after parse. Match it with errors.Is. Its
// message names the offending flag so the operator (and the release-gating CI
// smoke) can see which flag is missing.
var errMissingRequiredFlag = errors.New("ocu-filestored: required flag missing or invalid")

// errBadIntent rejects a -granted-intents value outside the wire intent
// vocabulary. Match it with errors.Is.
var errBadIntent = errors.New("ocu-filestored: unknown granted intent")

// auditLockSuffix names the exclusive flock file that guards the audit hash
// chain. It is the audit-sink path plus this suffix, so the lock is keyed on
// the very resource it protects: two daemons pointed at the same -audit-sink
// collide on this lock regardless of their -south-bind address, and a daemon
// pointed at a different sink takes a distinct lock (T2-7, LIFE-07).
const auditLockSuffix = ".lock"

// errAlreadyRunning wraps flock.ErrAlreadyRunning with a human message that
// names the resource so the operator knows which lock to inspect.
var errAlreadyRunning = errors.New("ocu-filestored: another instance is already running (holds the audit-sink lock)")

// errHandleStoreAlreadyRunning is the handle-store analog of errAlreadyRunning:
// a SEPARATE flock on <handle-store>.lock guards the durable file_id log against
// two daemons interleaving appends, so the resource named in the refusal is the
// handle store, not the audit sink (the two stores can live on distinct paths).
var errHandleStoreAlreadyRunning = errors.New("ocu-filestored: another instance is already running (holds the handle-store lock)")

// tenancyAdmission maps the Phase-8-frozen hyphenated -tenancy flag values to
// the admission package's underscored constants. The flag value set is frozen
// (single-tenant | multi-tenant) and is NOT byte-identical to admission's
// vocabulary, so this lookup is load-bearing — admission compares by exact
// map-key identity with no case-fold or normalization.
var tenancyAdmission = map[string]admission.Tenancy{
	"single-tenant": admission.TenancySingleTenant,
	"multi-tenant":  admission.TenancyMultiTenant,
}

// profileAdmission maps the -profile flag values to the admission profile
// constants. The flag values already match admission's vocabulary
// byte-for-byte; the explicit map keeps the legal set and the mapping in one
// place and lets an unknown value refuse before admission.
var profileAdmission = map[string]admission.WorkloadTrustProfile{
	"trusted_operator":   admission.ProfileTrustedOperator,
	"internal_workforce": admission.ProfileInternalWorkforce,
	"untrusted":          admission.ProfileUntrusted,
}

// intentVocabulary maps the -granted-intents tokens to the southface intent
// values. read/write/preview is the frozen wire vocabulary.
var intentVocabulary = map[string]southface.Intent{
	"read":    southface.IntentRead,
	"write":   southface.IntentWrite,
	"preview": southface.IntentPreview,
}

// Per-session ceiling defaults for the minimal trusted_operator shelf. They
// are conservative non-zero values. The ops token-bucket pair is
// operator-tunable via -ops-per-second / -ops-burst (these consts are the
// flag defaults); the byte and fd ceilings stay fixed this phase.
const (
	defaultOpsPerSecond  = 100.0
	defaultOpsBurst      = 200.0
	defaultInFlightBytes = int64(1) << 31 // 2 GiB in flight per session
	defaultFDCeiling     = int32(256)
)

// Lifecycle deadlines: the two engine lifecycle calls run under bounded
// contexts — never context.Background() bare — so a hung backend can never
// wedge startup or teardown indefinitely. Teardown sweeps a whole scope on a
// network engine (paginated listings, batched deletes), so its bound is
// generous but finite.
const (
	provisionTimeout = 1 * time.Minute
	teardownTimeout  = 10 * time.Minute
)

// defaultNorthBind is the loopback bind the north Files-API listener (Mount B)
// falls back to when cfg.northBind is empty. It matches the --north-bind flag
// default and exists so a direct compose() call (a test that builds brokerConfig
// without going through validate) still gets a concrete bind.
const defaultNorthBind = "127.0.0.1:7080"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ocu-filestored:", err)
		os.Exit(1)
	}
}

// brokerConfig holds the validated, flag-derived inputs the composition needs.
type brokerConfig struct {
	engineKind       objectstore.EngineKind
	engineRoot       string
	s3CredentialFile string
	s3Bucket         string
	s3Endpoint       string
	s3Region         string
	s3PathStyle      bool
	auditSink        string
	// handleStore is the durable file_id->handle store path (ADR-0023). Empty
	// disables the index this phase (the north listener is inert), so it is
	// OPTIONAL and validated only for parent-dir creatability when non-empty.
	handleStore string
	// bindAddr/certFile/keyFile carry the TLS HTTPS south-face transport: the
	// service_url the guest dials outbound through the Egress edge, and the
	// service's own server certificate and private key.
	bindAddr string
	// northBind is the north Files-API TLS bind (Mount B, ADR-0023). The north
	// listener is constructed only when handleStore is non-empty; it reuses the
	// south certFile/keyFile (one identity, two listeners).
	northBind      string
	certFile       string
	keyFile        string
	filesystemID   string
	maxFileSize    int64
	maxRequestByte int64
	opsPerSecond   float64
	opsBurst       float64
	grantedIntents []southface.Intent
	dlPrefixes     []string
	// subtrees is the ADR-0029 intent->subtree join map. It is the zero-value
	// (join disabled, static-path mode) unless a deployment sets the -subtree-*
	// override flags; validate builds it from those flags fail-closed.
	subtrees southface.SubtreeMap
	// claimsBind, when true, makes the credential extractor parse the
	// edge-validated bearer's filesystem_id/intent claims (ADR-0029 interim seam)
	// instead of binding every present bearer to the static configured scope.
	claimsBind bool
	profile    admission.WorkloadTrustProfile
	tenancy    admission.Tenancy
	// logLevel is the validated slog.Level for the daemon's JSON logger.
	logLevel slog.Level
	// opsListen is the bind address for the loopback-only ops listener
	// (/metrics). An empty string disables the ops listener entirely.
	// A non-loopback address is refused pre-bind (errOpsListenNotLoopback).
	opsListen string
}

// run parses and validates the frozen flag surface, then composes and serves
// the daemon. A parse error other than -h/-help propagates; -h/-help returns
// nil; -version prints the build identity and returns nil (exit 0). A
// non-admitted profile/tenancy/credential triple, or a missing/invalid
// required flag, returns a typed error BEFORE any socket is bound.
//
// run is the production entry (main() calls it): the serve loop stops on
// SIGTERM/SIGINT. It delegates to runCtx with a never-cancelled background
// context, so the only stop trigger in production is the OS signal.
func run(args []string) error {
	return runCtx(context.Background(), args)
}

// runCtx is run with an injectable parent context. The serve loop stops on
// SIGTERM/SIGINT OR when ctx is cancelled (both drive the same clean-drain
// teardown). Cancelling ctx lets a caller stop a serving daemon WITHOUT a
// process-global signal — tests use it so a self-signal can never terminate the
// test binary. Production passes context.Background(), which never cancels, so
// the signal remains the sole stop trigger and behaviour is unchanged.
func runCtx(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ocu-filestored", flag.ContinueOnError)

	showVersion := fs.Bool("version", false,
		"print the version, VCS revision, and Go toolchain, then exit 0")
	healthCheck := fs.Bool("health-check", false,
		"self-probe mode: dial -ops-listen /healthz and exit 0 (alive) or non-zero (unreachable); requires no serving flags")
	logLevel := fs.String("log-level", "info",
		"structured log level: debug | info | warn | error (default info)")
	opsListen := fs.String("ops-listen", "127.0.0.1:9464",
		"loopback-only bind address for the ops listener (/metrics); empty disables; non-loopback refused pre-bind")
	// North Files-API transport (Mount B): a SEPARATE TLS listener from the south
	// mount RPC, serving the /v1/files handler (ADR-0023). --north-bind is the
	// live flag; --north-listen is its retained DEPRECATED ALIAS (the frozen flag
	// surface is never silently dropped — an operator setting the old name still
	// works). The north listener is constructed only when --handle-store is set
	// (the durable file_id index the Files-API plane resolves against); with no
	// handle store the north plane stays inert and only the south listener binds.
	northBind := fs.String("north-bind", "127.0.0.1:7080",
		"north Files-API TLS bind address (Mount B, ADR-0023); live only when --handle-store is set, reusing the south TLS cert")
	northListen := fs.String("north-listen", "",
		"DEPRECATED alias for --north-bind (retained so the frozen flag surface is never dropped); --north-bind wins when both are set")
	// South-face TLS transport: the service_url the guest dials outbound through
	// the Egress edge (guest -> edge -> service direct HTTPS), and the service's
	// own server certificate. PENDING-PHASE-7: the canon route/credential shapes
	// are sibling-proven but not yet frozen in component-04.
	southBind := fs.String("south-bind", "127.0.0.1:7443",
		"south-face TLS HTTPS bind address (the service_url the guest dials outbound through the Egress edge)")
	tlsCert := fs.String("tls-cert", "",
		"REQUIRED south-face TLS server certificate PEM path")
	tlsKey := fs.String("tls-key", "",
		"REQUIRED south-face TLS server private-key PEM path")
	engine := fs.String("engine", "local-volume",
		"backend object-store engine: local-volume | s3 (ADR-0010)")
	maxRequestBytes := fs.Int64("max-request-bytes", 52428800,
		"per-RPC-message inbound body ceiling, rejected pre-buffer (NFR-SEC-78); default 50 MiB")
	auditSink := fs.String("audit-sink", "",
		"REQUIRED audit gate file-sink path; an audit-write failure denies the operation (NFR-SEC-79)")
	handleStore := fs.String("handle-store", "",
		"durable file_id->handle store path (Files-API north face, ADR-0023); empty disables the index this phase")
	profile := fs.String("profile", "trusted_operator",
		"admission profile: trusted_operator | internal_workforce | untrusted")
	tenancy := fs.String("tenancy", "single-tenant",
		"tenancy mode: single-tenant | multi-tenant")
	engineRoot := fs.String("engine-root", "",
		"REQUIRED local-volume engine root: the customer workspace volume directory")
	s3CredentialFile := fs.String("s3-credential-file", "",
		"s3 engine only: PATH to a 0600 daemon-owned file holding access_key_id=/secret_access_key= lines; the secret itself NEVER arrives as a flag value (T1-7). Env fallback: "+objectstore.EnvS3AccessKeyID+"/"+objectstore.EnvS3SecretAccessKey)
	s3Bucket := fs.String("s3-bucket", "",
		"REQUIRED for -engine s3: the single backend bucket all scopes live under")
	s3Endpoint := fs.String("s3-endpoint", "",
		"REQUIRED for -engine s3: the backend endpoint URL (custom endpoints switch checksums to WhenRequired)")
	s3Region := fs.String("s3-region", "us-east-1",
		"s3 engine signing region")
	s3PathStyle := fs.Bool("s3-path-style", false,
		"s3 engine only: path-style addressing (required by most single-host S3-compatible backends)")
	maxFileSize := fs.Int64("broker-max-file-size", 0,
		"REQUIRED whole-object upload ceiling in bytes (>0); the fileUpload pre-buffer reject (NFR-SEC-46/78)")
	filesystemID := fs.String("filesystem-id", "",
		"REQUIRED host-attested filesystem scope bound to the session")
	grantedIntents := fs.String("granted-intents", "read,write",
		"comma-separated session intent grant set from read,write,preview")
	downloadablePrefixes := fs.String("downloadable-prefixes", "",
		"comma-separated broker-side downloadable prefixes, engine-relative no leading slash e.g. outputs (ADR-0029 inv-5; a leading slash is tolerated and trimmed); empty = nothing downloadable")
	// ADR-0029 intent->subtree join overrides. All empty (the default) keeps the
	// static-path layout (join disabled). Setting ANY of the three requires ALL
	// three to be a non-empty engine-relative path (no leading slash, no ".."):
	// the join is engine-enforced and a deployment can override the target but
	// never disable it by setting an empty value (validate fails closed).
	subtreeRW := fs.String("subtree-rw", "",
		"ADR-0029 write-intent subtree (engine-relative, no leading slash), e.g. outputs; requires -subtree-ro/-subtree-preview when set")
	subtreeRO := fs.String("subtree-ro", "",
		"ADR-0029 read-intent subtree (engine-relative, no leading slash), e.g. uploads; requires -subtree-rw/-subtree-preview when set")
	subtreePreview := fs.String("subtree-preview", "",
		"ADR-0029 preview-intent subtree (engine-relative, no leading slash), e.g. uploads; requires -subtree-rw/-subtree-ro when set")
	opsPerSecond := fs.Float64("ops-per-second", defaultOpsPerSecond,
		"per-session file-ops token-bucket refill rate in ops/s (>0); the throttle ceiling (NFR-SEC-46)")
	opsBurst := fs.Float64("ops-burst", defaultOpsBurst,
		"per-session file-ops token-bucket capacity in tokens (>=1); a session starts with a full bucket")
	// -claims-bind (ADR-0029, PR-B test seam): when set, the credential extractor
	// parses the EDGE-VALIDATED bearer's filesystem_id and intent CLAIMS instead of
	// binding every present bearer to the static configured scope. It JWKS-verifies
	// NOTHING (the edge owns weak-JWT validation; the service mints/signs nothing —
	// inv3). This is the interim seam that lets the per-mount intent claim reach the
	// engine before the PR-C control mint + ADR-0019 intent-keyed exchange land; the
	// per-request filesystem_id cross-check still rejects a claim that disagrees with
	// -filesystem-id.
	claimsBind := fs.Bool("claims-bind", false,
		"parse the edge-validated bearer's filesystem_id/intent claims (ADR-0029 interim seam); JWKS-verifies nothing")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	// Apply OCU_FILESTORE_* env-var fallbacks for any flag not explicitly set
	// by the caller. Explicit flags always win; env vars are consulted only for
	// absent flags. Credential-bearing flags are excluded from this map (see
	// credentialBearingFlags and T2-17). A malformed env-var value is a typed
	// error the same as a malformed flag.
	if err := applyEnvFallbacks(fs); err != nil {
		return err
	}

	// -version prints the build identity and exits 0 before any validation:
	// an operator (and the release smoke) must be able to interrogate a
	// binary without supplying the required serving flags.
	if *showVersion {
		fmt.Println(versionString())
		return nil
	}

	// -health-check self-probe mode: dial the daemon's own /healthz on
	// -ops-listen and exit 0 on a 200 response, non-zero otherwise. This
	// short-circuits before validate so a container healthcheck only needs
	// the two flags, not the full serving set. The NOTIFY_SOCKET env var
	// is not consulted in this mode.
	if *healthCheck {
		return runHealthCheck(*opsListen)
	}

	// Resolve the north bind address: --north-bind wins; --north-listen is the
	// retained deprecated alias. The alias is honoured only when --north-bind was
	// NOT explicitly set AND the alias carries a value, so an operator setting
	// both gets --north-bind. The frozen --north-listen flag is never silently
	// dropped — an operator using the old name alone still binds Mount B.
	northBindExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "north-bind" {
			northBindExplicit = true
		}
	})
	northBindAddr := *northBind
	if !northBindExplicit && *northListen != "" {
		northBindAddr = *northListen
	}

	cfg, err := validate(rawFlags{
		engine:               *engine,
		engineRoot:           *engineRoot,
		auditSink:            *auditSink,
		handleStore:          *handleStore,
		northBind:            northBindAddr,
		southBind:            *southBind,
		tlsCert:              *tlsCert,
		tlsKey:               *tlsKey,
		filesystemID:         *filesystemID,
		profile:              *profile,
		tenancy:              *tenancy,
		grantedIntents:       *grantedIntents,
		downloadablePrefixes: *downloadablePrefixes,
		subtreeRW:            *subtreeRW,
		subtreeRO:            *subtreeRO,
		subtreePreview:       *subtreePreview,
		maxFileSize:          *maxFileSize,
		maxRequestBytes:      *maxRequestBytes,
		opsPerSecond:         *opsPerSecond,
		opsBurst:             *opsBurst,
		s3CredentialFile:     *s3CredentialFile,
		s3Bucket:             *s3Bucket,
		s3Endpoint:           *s3Endpoint,
		s3Region:             *s3Region,
		s3PathStyle:          *s3PathStyle,
		logLevelStr:          *logLevel,
		opsListenAddr:        *opsListen,
	})
	if err != nil {
		return err
	}
	// -claims-bind is a pass-through bool (no validation): set it on the config
	// after validate so the credential extractor picks the claims-parsing mode.
	cfg.claimsBind = *claimsBind

	// Build the structured logger AFTER validate (which refused bad flags)
	// and BEFORE compose (which binds sockets). The logger is the first
	// real infrastructure; everything from here on emits structured JSON.
	l := observ.NewLogger(os.Stderr, cfg.logLevel)

	// Build the broker metric set from the current version string. The set is
	// passed into compose (so the dispatcher records ops_total and stage
	// latencies) and into the ops listener (so /metrics serves it).
	m := telemetry.NewBrokerMetrics(version)

	// Construct the loopback-only ops listener BEFORE the south face, so /metrics
	// is available as soon as the daemon is "ready". An empty -ops-listen
	// disables the listener; a non-loopback address was refused in validate.
	// The Serve goroutine is NOT launched here: compose() registers /healthz and
	// /readyz on this listener's mux, and the http.ServeMux Handle-before-Serve
	// contract means those routes must be wired before accepting connections.
	// Launching Serve up here would open a window where a probe hits an
	// unregistered route and gets 404; the goroutine starts after compose below.
	var opsListener *telemetry.OpsListener
	if cfg.opsListen != "" {
		opsListener, err = telemetry.NewOpsListener(cfg.opsListen, m, l)
		if err != nil {
			return err
		}
		l.Info("ops listener constructed", slog.String("addr", opsListener.Addr()))
	}

	// Startup echo at INFO: operator configuration summary. NEVER includes
	// a credential byte — only the validated, non-secret flag surface.
	l.Info("ocu-filestored starting",
		slog.String("version", version),
		slog.String("engine", string(cfg.engineKind)),
		slog.String("south_bind", cfg.bindAddr),
		slog.String("audit_sink", cfg.auditSink),
		slog.String(observ.KeyScope, cfg.filesystemID),
		slog.String("profile", string(cfg.profile)),
		slog.String("tenancy", string(cfg.tenancy)),
		slog.Int64("max_file_size", cfg.maxFileSize),
		slog.Int64("max_request_bytes", cfg.maxRequestByte),
		slog.Float64("ops_per_second", cfg.opsPerSecond),
		slog.Float64("ops_burst", cfg.opsBurst),
		// NOTE: s3CredentialFile is logged as a PATH only (not the file
		// contents). Path logging at INFO is safe: the file path is
		// operator-visible deployment configuration, not a secret value.
		// The file's credential bytes never enter a log line.
		slog.String("s3_credential_file", cfg.s3CredentialFile),
	)

	// Single-instance flock guard (T2-7, LIFE-07): acquire one exclusive
	// non-blocking flock BEFORE removing any stale socket and binding. The lock
	// is keyed on the -audit-sink resource (<audit-sink>.lock) and is sufficient
	// to prevent two daemons on the SAME scope from interleaving appends and
	// corrupting the hash chain: one daemon = one filesystem_id = one audit-sink,
	// so two daemons on the same scope share the same sink and collide here.
	//
	// A per-socket-directory lock was intentionally removed: the legitimate
	// deployment topology is N daemons (one per filesystem_id) sharing ONE
	// socket directory, each binding its own <filesystem_id>.sock there. A
	// per-directory lock over-restricts to one daemon per directory, refusing
	// the second through Nth daemons in that topology. The per-scope
	// audit-sink lock fully preserves the no-interleaved-chain guarantee
	// without imposing that topology restriction.
	//
	// The lock releases on process exit even on SIGKILL (the kernel releases
	// fds on process termination), so there is no stale-lock problem across
	// crashes. The sink's parent directory is the audit sink's own;
	// NewFileSink creates the sink and fsyncs that directory, but the lock
	// file is opened first, so ensure the directory exists.
	auditSinkAbs, absErr := filepath.Abs(cfg.auditSink)
	if absErr != nil {
		if opsListener != nil {
			_ = opsListener.Close()
		}
		return absErr
	}
	auditSinkDir := filepath.Dir(auditSinkAbs)
	if err := os.MkdirAll(auditSinkDir, 0o700); err != nil {
		if opsListener != nil {
			_ = opsListener.Close()
		}
		return err
	}
	// os.MkdirAll applies the requested mode through the process umask, so a
	// freshly created directory under the default umask 022 lands at 0755 — not
	// the 0700 we ask for. Chmod the leaf unconditionally to PIN 0700: the audit
	// sink and its lock file hold the hash-chained activity log and must not sit
	// in a world-traversable directory. Chmod ignores umask, so this is the
	// load-bearing step. (A pre-existing directory keeps whatever mode the
	// operator set on its ancestors; only the audit-sink leaf is pinned here.)
	if err := os.Chmod(auditSinkDir, 0o700); err != nil {
		if opsListener != nil {
			_ = opsListener.Close()
		}
		return err
	}
	auditLockPath := auditSinkAbs + auditLockSuffix
	afl, auditLockErr := flock.Acquire(auditLockPath)
	if auditLockErr != nil {
		if opsListener != nil {
			_ = opsListener.Close()
		}
		if errors.Is(auditLockErr, flock.ErrAlreadyRunning) {
			l.Error("single-instance guard: another daemon holds the audit-sink lock; refusing to start",
				slog.String("lock_file", auditLockPath),
			)
			return errAlreadyRunning
		}
		return auditLockErr
	}
	// Release the audit-sink lock when the daemon exits (after teardown).
	defer afl.Release()
	l.Info("single-instance audit-sink lock acquired", slog.String("lock_file", auditLockPath))

	// Handle-store single-instance guard: when --handle-store is set, acquire a
	// SEPARATE exclusive flock on <handle-store>.lock BEFORE compose opens the
	// durable log, mirroring the audit-sink guard. The durable file_id log is an
	// append-only stream a second daemon must not interleave; the lock is keyed
	// on the handle-store resource so two daemons sharing a handle store collide
	// while distinct stores take distinct locks. An empty --handle-store skips
	// the guard entirely (no store this phase). The parent directory is created
	// 0700 like the audit sink's, so the durable log never sits world-traversable.
	if cfg.handleStore != "" {
		handleStoreAbs, hsAbsErr := filepath.Abs(cfg.handleStore)
		if hsAbsErr != nil {
			if opsListener != nil {
				_ = opsListener.Close()
			}
			return hsAbsErr
		}
		handleStoreDir := filepath.Dir(handleStoreAbs)
		if err := os.MkdirAll(handleStoreDir, 0o700); err != nil {
			if opsListener != nil {
				_ = opsListener.Close()
			}
			return err
		}
		// Chmod ignores umask, so this PINS 0700 on the leaf directory even when
		// MkdirAll landed it at 0755 under the default umask (same rationale as
		// the audit-sink leaf).
		if err := os.Chmod(handleStoreDir, 0o700); err != nil {
			if opsListener != nil {
				_ = opsListener.Close()
			}
			return err
		}
		handleLockPath := handleStoreAbs + auditLockSuffix
		hfl, handleLockErr := flock.Acquire(handleLockPath)
		if handleLockErr != nil {
			if opsListener != nil {
				_ = opsListener.Close()
			}
			if errors.Is(handleLockErr, flock.ErrAlreadyRunning) {
				l.Error("single-instance guard: another daemon holds the handle-store lock; refusing to start",
					slog.String("lock_file", handleLockPath),
				)
				return errHandleStoreAlreadyRunning
			}
			return handleLockErr
		}
		defer hfl.Release()
		l.Info("single-instance handle-store lock acquired", slog.String("lock_file", handleLockPath))
	}

	srv, err := compose(cfg, l, m, opsListener)
	if err != nil {
		if opsListener != nil {
			_ = opsListener.Close()
		}
		return err
	}
	l.Info("session provisioned",
		slog.String(observ.KeyScope, cfg.filesystemID),
	)

	// Now that compose() has registered /healthz and /readyz on the ops
	// listener's mux, start accepting connections. Launching Serve here (not at
	// construction) closes the Handle-before-Serve gap: every probe route is
	// wired before the first connection is accepted, so an orchestrator probe
	// can never hit a 404 on /healthz or /readyz during startup.
	if opsListener != nil {
		go opsListener.Serve()
		l.Info("ops listener started", slog.String("addr", opsListener.Addr()))
	}
	return serveUntilSignal(ctx, srv, l, opsListener)
}

// serveUntilSignal serves srv until either Serve returns on its own (a
// listener fault), SIGTERM/SIGINT arrives, or parent is cancelled. On a signal
// or a parent cancellation the session begins its bounded drain (southface
// force-closes stragglers past the bound) then Close drains, releases ceilings,
// and closes the handle-store fd. Close does NOT erase the scope — shutdown is
// not an owner-change event. Every exit path combines the serve and close
// results with errors.Join, so a close error is never silently dropped behind
// a serve error (or vice versa).
//
// parent is the caller's stop context. The signal context is derived from it,
// so cancelling parent drives the same clean-drain path as an OS signal. In
// production parent is context.Background() (never cancelled) and the OS signal
// is the only trigger; a test passes a cancellable context to stop the daemon
// without a process-global signal.
//
// l is the structured logger. Lifecycle events (signal received, drain
// starting, teardown done) are emitted at INFO so operators following the
// daemon's log stream can track shutdown without parsing the binary.
//
// opsListener is the loopback ops listener; if non-nil it is shut down
// alongside the south face server. A nil opsListener is a no-op.
func serveUntilSignal(parent context.Context, srv southface.Server, l *slog.Logger, opsListener *telemetry.OpsListener) error {
	ctx, stop := signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	l.Info("south face listening; waiting for signal")

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	// Notify systemd that the daemon is ready. If NOTIFY_SOCKET is unset this
	// is a no-op; any error is logged but does not stop the daemon (the ops
	// listener's fail-soft posture applies to optional integrations).
	if err := telemetry.SdNotifyReady(); err != nil {
		l.Warn("sd_notify READY failed", slog.String("err", err.Error()))
	}

	shutdownOpsListener := func() error {
		if opsListener == nil {
			return nil
		}
		return opsListener.Close()
	}

	select {
	case err := <-serveErr:
		// Serve ended without a signal (listener fault): teardown still runs.
		l.Info("serve returned early; running teardown")
		closeErr := srv.Close()
		opsErr := shutdownOpsListener()
		l.Info("teardown complete")
		return errors.Join(err, closeErr, opsErr)
	case <-ctx.Done():
		// Signal received. Stop intercepting FIRST so a second
		// SIGTERM/SIGINT during a wedged drain kills the process hard
		// (default disposition) instead of being swallowed.
		l.Info("signal received; starting bounded drain")
		stop()
		// Notify systemd that the daemon is stopping. Errors are logged,
		// not surfaced — the shutdown path must always complete.
		if err := telemetry.SdNotifyStopping(); err != nil {
			l.Warn("sd_notify STOPPING failed", slog.String("err", err.Error()))
		}
		closeErr := srv.Close()
		opsErr := shutdownOpsListener()
		// Close shut the listener down, so Serve returns promptly (a clean
		// shutdown collapses to nil); drain the goroutine and surface both.
		serveResult := <-serveErr
		l.Info("teardown complete")
		return errors.Join(serveResult, closeErr, opsErr)
	}
}

// rawFlags is the unvalidated flag surface handed to validate. It mirrors the
// daemon's command-line flags one field per flag, BEFORE any parsing or
// admission. Passing this struct (instead of a long positional argument list)
// names every value at the call site, so a reorder of two same-typed fields
// (e.g. the s3Bucket/s3Endpoint/s3Region strings, or the southBind/tlsCert/
// tlsKey strings) can no longer compile silently into a swapped meaning.
// validate consumes a rawFlags and returns the validated brokerConfig.
type rawFlags struct {
	engine               string
	engineRoot           string
	auditSink            string
	handleStore          string
	northBind            string
	southBind            string
	tlsCert              string
	tlsKey               string
	filesystemID         string
	profile              string
	tenancy              string
	grantedIntents       string
	downloadablePrefixes string
	subtreeRW            string
	subtreeRO            string
	subtreePreview       string
	maxFileSize          int64
	maxRequestBytes      int64
	opsPerSecond         float64
	opsBurst             float64
	s3CredentialFile     string
	s3Bucket             string
	s3Endpoint           string
	s3Region             string
	s3PathStyle          bool
	logLevelStr          string
	opsListenAddr        string
}

// validate parses and checks the flag surface, returning a brokerConfig or a
// typed error. Required flags (-engine-root, -audit-sink, -filesystem-id, a
// positive -broker-max-file-size) are checked after parse and never panic.
// The optional ops token-bucket pair defaults to 100/200; an explicit
// non-positive -ops-per-second or an -ops-burst below one whole token (which
// would wedge the bucket) is a wiring fault and refuses with the same typed
// error. An unknown -log-level token refuses with errBadLogLevel (via
// observ.ParseLevel) BEFORE any socket is bound.
func validate(r rawFlags) (brokerConfig, error) {
	var cfg brokerConfig

	// Destructure the named flag surface into the locals the checks below
	// read. The names match the rawFlags fields one-for-one.
	engine := r.engine
	engineRoot := r.engineRoot
	auditSink := r.auditSink
	southBind := r.southBind
	tlsCert := r.tlsCert
	tlsKey := r.tlsKey
	filesystemID := r.filesystemID
	profile := r.profile
	tenancy := r.tenancy
	grantedIntents := r.grantedIntents
	downloadablePrefixes := r.downloadablePrefixes
	maxFileSize := r.maxFileSize
	maxRequestBytes := r.maxRequestBytes
	opsPerSecond := r.opsPerSecond
	opsBurst := r.opsBurst
	s3CredentialFile := r.s3CredentialFile
	s3Bucket := r.s3Bucket
	s3Endpoint := r.s3Endpoint
	s3Region := r.s3Region
	s3PathStyle := r.s3PathStyle
	logLevelStr := r.logLevelStr
	opsListenAddr := r.opsListenAddr

	// -log-level is validated FIRST — before any engine or socket flag — so
	// an unknown level token is refused pre-bind with a clear typed error.
	level, err := observ.ParseLevel(logLevelStr)
	if err != nil {
		return cfg, err
	}
	cfg.logLevel = level

	// -ops-listen is validated BEFORE any bind: a non-loopback address is
	// refused fail-closed (no socket opened). An empty value disables the
	// listener — no error.
	if err := telemetry.ValidateOpsListenAddr(opsListenAddr); err != nil {
		return cfg, fmt.Errorf("ocu-filestored: -ops-listen %q: %w", opsListenAddr, err)
	}
	cfg.opsListen = opsListenAddr

	kind, err := objectstore.ParseEngine(engine)
	if err != nil {
		return cfg, err
	}

	// An s3-only flag on a non-s3 engine refuses — a silently inert flag
	// would lie about the deployment's credential posture.
	if s3CredentialFile != "" && kind != objectstore.S3 {
		return cfg, fmt.Errorf("%w: -s3-credential-file is only valid with -engine s3", errMissingRequiredFlag)
	}

	prof, ok := profileAdmission[profile]
	if !ok {
		return cfg, fmt.Errorf("%w: %q", errBadProfile, profile)
	}
	ten, ok := tenancyAdmission[tenancy]
	if !ok {
		return cfg, fmt.Errorf("%w: %q", errBadTenancy, tenancy)
	}

	// Engine-conditional required-flag matrix: each engine kind REQUIRES its
	// own backing-store flags and REFUSES the other kind's — a silently
	// inert backing-store flag would lie about what the daemon serves.
	switch kind {
	case objectstore.LocalVolume:
		if engineRoot == "" {
			return cfg, fmt.Errorf("%w: -engine-root is required", errMissingRequiredFlag)
		}
		if s3Bucket != "" {
			return cfg, fmt.Errorf("%w: -s3-bucket is only valid with -engine s3", errMissingRequiredFlag)
		}
		if s3Endpoint != "" {
			return cfg, fmt.Errorf("%w: -s3-endpoint is only valid with -engine s3", errMissingRequiredFlag)
		}
		if s3PathStyle {
			return cfg, fmt.Errorf("%w: -s3-path-style is only valid with -engine s3", errMissingRequiredFlag)
		}
	case objectstore.S3:
		if engineRoot != "" {
			return cfg, fmt.Errorf("%w: -engine-root is not valid for the s3 engine (the backing store is the bucket)", errMissingRequiredFlag)
		}
		if s3Bucket == "" {
			return cfg, fmt.Errorf("%w: -s3-bucket is required for the s3 engine", errMissingRequiredFlag)
		}
		if s3Endpoint == "" {
			return cfg, fmt.Errorf("%w: -s3-endpoint is required for the s3 engine", errMissingRequiredFlag)
		}
		if s3Region == "" {
			return cfg, fmt.Errorf("%w: -s3-region is required for the s3 engine", errMissingRequiredFlag)
		}
	}
	if auditSink == "" {
		return cfg, fmt.Errorf("%w: -audit-sink is required", errMissingRequiredFlag)
	}
	// South-face TLS transport (the service the guest dials through the edge):
	// the bind address and the server cert+key are required — the service speaks
	// REST over HTTPS, so a missing cert/key is a wiring fault, not a default.
	if southBind == "" {
		return cfg, fmt.Errorf("%w: -south-bind is required", errMissingRequiredFlag)
	}
	if tlsCert == "" {
		return cfg, fmt.Errorf("%w: -tls-cert is required (the south-face TLS server certificate)", errMissingRequiredFlag)
	}
	if tlsKey == "" {
		return cfg, fmt.Errorf("%w: -tls-key is required (the south-face TLS server private key)", errMissingRequiredFlag)
	}
	if filesystemID == "" {
		return cfg, fmt.Errorf("%w: -filesystem-id is required", errMissingRequiredFlag)
	}
	if maxFileSize <= 0 {
		return cfg, fmt.Errorf("%w: -broker-max-file-size must be > 0", errMissingRequiredFlag)
	}
	if opsPerSecond <= 0 {
		return cfg, fmt.Errorf("%w: -ops-per-second must be > 0", errMissingRequiredFlag)
	}
	if opsBurst < 1 {
		return cfg, fmt.Errorf("%w: -ops-burst must be >= 1", errMissingRequiredFlag)
	}

	intents, err := parseIntents(grantedIntents)
	if err != nil {
		return cfg, err
	}

	// ADR-0029 intent->subtree join map. All three overrides empty (the default)
	// keeps the static-path layout (join disabled). Setting ANY of the three
	// requires ALL three — southface.NewSubtreeMap validates each is a non-empty
	// engine-relative path with no traversal segment and fails closed otherwise, so
	// a deployment can override the join target but never disable it by half-setting
	// or emptying a value.
	subtrees, err := buildSubtreeMap(r.subtreeRW, r.subtreeRO, r.subtreePreview)
	if err != nil {
		return cfg, err
	}

	// EXFIL-BAR (ADR-0029 Alternatives bullet 3): the whole-scope "*" downloadable
	// token holds both directions of the scope tree, making every human upload
	// egress-eligible and reopening the read-vs-remove split NFR-SEC-73 holds. It
	// is refused for the fleet posture (single-tenant trusted_operator): the
	// downloadable allow rule keys on the "outputs" subtree prefix, which the join
	// makes expressible, so "*" is never needed and never accepted here.
	if err := rejectWildcardDownloadable(downloadablePrefixes, prof, ten); err != nil {
		return cfg, err
	}

	cfg = brokerConfig{
		engineKind:       kind,
		engineRoot:       engineRoot,
		s3CredentialFile: s3CredentialFile,
		s3Bucket:         s3Bucket,
		s3Endpoint:       s3Endpoint,
		s3Region:         s3Region,
		s3PathStyle:      s3PathStyle,
		auditSink:        auditSink,
		handleStore:      r.handleStore,
		bindAddr:         southBind,
		northBind:        r.northBind,
		certFile:         tlsCert,
		keyFile:          tlsKey,
		filesystemID:     filesystemID,
		maxFileSize:      maxFileSize,
		maxRequestByte:   maxRequestBytes,
		opsPerSecond:     opsPerSecond,
		opsBurst:         opsBurst,
		grantedIntents:   intents,
		dlPrefixes:       splitNonEmpty(downloadablePrefixes),
		subtrees:         subtrees,
		profile:          prof,
		tenancy:          ten,
		logLevel:         level,
		opsListen:        opsListenAddr,
	}
	return cfg, nil
}

// parseIntents converts the comma-separated -granted-intents value to the
// southface intent slice, rejecting an unknown token with a typed error.
func parseIntents(s string) ([]southface.Intent, error) {
	tokens := splitNonEmpty(s)
	out := make([]southface.Intent, 0, len(tokens))
	for _, tok := range tokens {
		intent, ok := intentVocabulary[tok]
		if !ok {
			return nil, fmt.Errorf("%w: %q", errBadIntent, tok)
		}
		out = append(out, intent)
	}
	return out, nil
}

// errSubtreePartial rejects a half-set subtree override: setting ANY of the
// three -subtree-* flags requires ALL three (the frozen 3-value intent axis).
// Match it with errors.Is.
var errSubtreePartial = errors.New("ocu-filestored: -subtree-rw, -subtree-ro and -subtree-preview must all be set together (or all empty for the pinned default map)")

// errWildcardDownloadable rejects the whole-scope "*" downloadable token for the
// fleet posture (ADR-0029 exfil-bar): "*" makes every human upload egress-eligible
// and reopens the read-vs-remove split NFR-SEC-73 holds. Match it with errors.Is.
var errWildcardDownloadable = errors.New("ocu-filestored: -downloadable-prefixes \"*\" (whole-scope downloadable) is refused for the single-tenant trusted_operator fleet posture; key the allow rule on the outputs subtree instead (ADR-0029)")

// buildSubtreeMap constructs the ADR-0029 intent->subtree join map from the
// three -subtree-* override flags. All three empty (the default) returns the
// zero-value map (join disabled, static-path mode). Setting ANY of the three
// requires ALL three — a half-set is errSubtreePartial — and each is validated by
// southface.NewSubtreeMap (non-empty, engine-relative, no ".."). A deployment can
// override the join target but never disable it by emptying one value.
func buildSubtreeMap(rw, ro, preview string) (southface.SubtreeMap, error) {
	anySet := rw != "" || ro != "" || preview != ""
	if !anySet {
		// Zero override => the pinned default map (ADR-0029 Decision bullet 2:
		// "ships pinned so the minimal shelf runs zero-config; a deployment may
		// override the map, never bypass it"). The join is ON by default; a
		// deployment supplying no subtree flags still runs the engine-enforced
		// split, not the flat static-path layout.
		return southface.DefaultSubtreeMap(), nil
	}
	if rw == "" || ro == "" || preview == "" {
		return southface.SubtreeMap{}, errSubtreePartial
	}
	return southface.NewSubtreeMap(rw, ro, preview)
}

// rejectWildcardDownloadable enforces the ADR-0029 exfil-bar: the whole-scope
// "*" downloadable token is refused for the single-tenant trusted_operator fleet
// posture. A "*" token anywhere in the comma-separated -downloadable-prefixes
// value fails closed. Other postures (internal_workforce, untrusted, or a
// non-single-tenant tenancy) are unconstrained here — the guard targets the fleet
// cell the split protects. The raw flag string is inspected (before splitNonEmpty
// drops it) so a "*" token is caught verbatim.
func rejectWildcardDownloadable(prefixes string, prof admission.WorkloadTrustProfile, ten admission.Tenancy) error {
	if prof != admission.ProfileTrustedOperator || ten != admission.TenancySingleTenant {
		return nil
	}
	for _, tok := range splitNonEmpty(prefixes) {
		if tok == "*" {
			return errWildcardDownloadable
		}
	}
	return nil
}

// splitNonEmpty splits a comma-separated list, trimming spaces and dropping
// empty tokens. An empty input yields an empty slice.
func splitNonEmpty(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// envVarName converts a flag name to the canonical OCU_FILESTORE_* environment
// variable name: dashes are replaced with underscores and the result is
// uppercased with the OCU_FILESTORE_ prefix. For example, "engine-root"
// becomes "OCU_FILESTORE_ENGINE_ROOT".
func envVarName(flagName string) string {
	return "OCU_FILESTORE_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// credentialBearingFlags lists the flags excluded from the generic
// OCU_FILESTORE_* env-fallback map. These flags carry backend credential
// values or reference credential material; their secure intake path is
// separate (static env vars or 0600 credential files — see T1-7), and a
// generic config-env alias would create a second, less-audited path to the
// same secrets. The flags excluded are:
//
//   - s3-credential-file: path to the 0600 daemon-owned credential file;
//     excluded because a generic env alias could be confused with the
//     per-value credential env vars (EnvS3AccessKeyID/EnvS3SecretAccessKey)
//     and because the 0600-file intake is the sole authorized path.
//
// No other flag in the current surface carries a raw secret value — the S3
// access-key-id and secret-access-key travel only through the objectstore
// package's dedicated EnvS3* env vars, never through flags at all.
var credentialBearingFlags = map[string]struct{}{
	"s3-credential-file": {},
}

// envFallbackMap is the complete set of flag names that accept an
// OCU_FILESTORE_* environment-variable fallback. The map is built once at
// init from all declared flags minus the credentialBearingFlags set. The
// value is the canonical env-var name (produced by envVarName).
//
// Precedence: an explicitly-set flag on the command line ALWAYS wins; the
// env var is only consulted for flags that were NOT provided by the caller.
// Detection relies on flag.Visit after fs.Parse, which iterates only over
// flags that were explicitly set by the caller.
var envFallbackMap = func() map[string]string {
	// The daemon's full flag surface. Mirroring this slice here is intentional:
	// the authoritative list of env-mappable flags is explicit and testable
	// (the test asserts that each entry resolves to a live *flag.Flag at
	// parse time, so a renamed flag breaks the test loudly).
	names := []string{
		"version",
		"health-check",
		"log-level",
		"ops-listen",
		"north-bind",
		"north-listen",
		"engine",
		"max-request-bytes",
		"south-bind",
		"tls-cert",
		"tls-key",
		"audit-sink",
		"handle-store",
		"profile",
		"tenancy",
		"engine-root",
		"s3-bucket",
		"s3-endpoint",
		"s3-region",
		"s3-path-style",
		"broker-max-file-size",
		"filesystem-id",
		"granted-intents",
		"downloadable-prefixes",
		"subtree-rw",
		"subtree-ro",
		"subtree-preview",
		"claims-bind",
		"ops-per-second",
		"ops-burst",
	}
	m := make(map[string]string, len(names))
	for _, name := range names {
		if _, excluded := credentialBearingFlags[name]; !excluded {
			m[name] = envVarName(name)
		}
	}
	return m
}()

// applyEnvFallbacks applies OCU_FILESTORE_* environment variables as
// fallback values for any flag in fs that was NOT explicitly set by the
// caller. Explicit flags (detected via flag.Visit after Parse) always win;
// env vars are only consulted for unset flags, so:
//
//   - Explicit flag set → flag value used (env var ignored)
//   - Flag absent, env var set → env var value applied
//   - Flag absent, env var unset → flag default retained
//
// The function applies the env var by calling fs.Set(name, value), which
// exercises the flag's own type-parsing logic. A malformed env-var value
// (e.g. OCU_FILESTORE_BROKER_MAX_FILE_SIZE="abc") returns the same typed
// parse error as a malformed flag on the command line.
//
// Credential-bearing flags are not present in envFallbackMap and are
// therefore silently skipped (their secure intake path is unaffected).
func applyEnvFallbacks(fs *flag.FlagSet) error {
	// Collect flags that were explicitly set by the caller.
	explicit := make(map[string]struct{})
	fs.Visit(func(f *flag.Flag) {
		explicit[f.Name] = struct{}{}
	})

	// For each env-mappable flag not explicitly set, apply the env var.
	for flagName, envVar := range envFallbackMap {
		if _, set := explicit[flagName]; set {
			continue // explicit flag wins; env var ignored
		}
		val := os.Getenv(envVar)
		if val == "" {
			continue // env var not set; retain the flag default
		}
		if err := fs.Set(flagName, val); err != nil {
			return fmt.Errorf("ocu-filestored: env var %s=%q: %w", envVar, val, err)
		}
	}
	return nil
}

// selectCredentialSource picks the s3 backend credential source from the flag
// surface: the static host-local intake (the engine's OWN backend credential,
// NFR-SEC-25). The admitted credential KIND flows from the returned source's
// Kind() — never hard-wired for the s3 engine (the local-volume path keeps the
// hard-wired host-local kind: it exercises a filesystem permission, not a
// backend credential). The bucket/region parameters are retained on the
// signature for the composition call site but no longer drive a per-session
// policy (the broker mints nothing).
//
// The broker mints/signs nothing (invariant 3): the broker-signs / AssumeRole
// per-session credential-minting path is retired. The engine's OWN backend
// credential is the static host-local source; the edge performs the RFC-8693
// credential exchange for the guest, not the service.
func selectCredentialSource(cfg brokerConfig, _, _ string) (objectstore.CredentialSource, error) {
	return objectstore.NewStaticCredentialSource(cfg.s3CredentialFile)
}

// backendDialTimeout / backendTLSHandshakeTimeout / backendIdleConnTimeout /
// backendExpectContinue bound the engine's backend dial so a wedged backend can
// never hang a dial or handshake indefinitely. Verb-level deadlines stay with
// the caller's ctx.
const (
	backendDialTimeout         = 10 * time.Second
	backendTLSHandshakeTimeout = 10 * time.Second
	backendIdleConnTimeout     = 90 * time.Second
	backendExpectContinue      = 1 * time.Second
)

// newCredentialScopeExtractor wires the daemon's credential-scope source: it
// derives the credential-bound filesystem scope from the edge-injected
// Authorization: Bearer the service receives on every admitted request.
//
// PENDING-PHASE-7(A5-credscope): the credential authority's contract for HOW
// the bound filesystem_id and intent grant are carried on the injected
// credential is unpinned. In the interim single-tenant trusted_operator cell,
// the edge has already validated+stripped the guest's weak session JWT and
// injected the real backend credential; the daemon binds every PRESENT bearer
// to the configured single-tenant scope (filesystem-id + granted-intents). The
// per-request filesystem_id cross-check (the surviving channel-scope check)
// still rejects a body that disagrees with this bound scope (403). An ABSENT
// bearer is rejected upstream (errMissingBearer -> 401). The bind does NOT
// JWKS-verify the bearer — the edge owns weak-JWT validation; the service
// mints/signs nothing (invariant 3).
func newCredentialScopeExtractor(cfg brokerConfig) southface.CredentialScopeExtractor {
	fsid := cfg.filesystemID
	intents := cfg.grantedIntents
	claimsBind := cfg.claimsBind
	return southface.NewCredentialScopeExtractor(func(bearer string) (southface.CredentialScope, error) {
		// A present-but-empty token is rejected before this bind by
		// bearerFromRequest; an empty bound FilesystemID is treated as a
		// rejection by the extractor.
		if bearer == "" {
			return southface.CredentialScope{}, nil
		}
		if claimsBind {
			// ADR-0029 interim seam: parse the edge-validated bearer's
			// filesystem_id/intent CLAIMS. The service JWKS-verifies NOTHING (the
			// edge owns weak-JWT validation; the service mints/signs nothing —
			// inv3). A claim carrying no filesystem_id is a rejection (empty
			// FilesystemID); an unparseable token is a rejection too.
			return bearerClaimsScope(bearer)
		}
		// Default interim bind: bind a present bearer to the single-tenant
		// configured scope (filesystem-id + granted-intents).
		return southface.CredentialScope{
			FilesystemID:   fsid,
			GrantedIntents: intents,
		}, nil
	})
}

// bearerClaimsScope parses the CLAIMS of an edge-validated bearer (a JWT-shaped
// token) into a CredentialScope WITHOUT verifying the signature. It reads the
// payload's filesystem_id and intent claims: filesystem_id binds the scope, and
// a present intent claim maps to the single-element GrantedIntents grant set the
// per-mount credential carries (ADR-0029 — the edge exchanges per {filesystem_id,
// intent}). A token that is not three dot-separated segments, an undecodable
// payload, or a claim carrying no filesystem_id is a rejection (empty
// FilesystemID -> the extractor rejects). The service verifies no signature and
// mints nothing (inv3).
func bearerClaimsScope(bearer string) (southface.CredentialScope, error) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return southface.CredentialScope{}, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return southface.CredentialScope{}, nil
	}
	var claims struct {
		FilesystemID string `json:"filesystem_id"`
		Intent       string `json:"intent"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return southface.CredentialScope{}, nil
	}
	var grants []southface.Intent
	if intent, ok := intentVocabulary[claims.Intent]; ok {
		grants = []southface.Intent{intent}
	}
	return southface.CredentialScope{
		FilesystemID:   claims.FilesystemID,
		GrantedIntents: grants,
	}, nil
}

// newBackendTLSClient builds the s3 engine's backend HTTP client: a strict
// fail-closed TLS transport (MinVersion TLS 1.2, no InsecureSkipVerify path),
// HTTP/2 attempted, bounded timeouts, and — critically — http.Transport.Proxy
// left NIL: an HTTPS_PROXY/HTTP_PROXY/NO_PROXY environment variable can neither
// redirect nor bypass the backend leg (NFR-SEC-16, NFR-SEC-85). It is the
// engine's OWN backend dial (NFR-SEC-25), distinct from the guest's
// edge-injected credential path.
//
// PENDING-PHASE-7(engine-leg-egress): whether this backend leg retains an
// egress proxy is an unfrozen ADR-0011-vs-new-model reconciliation; this client
// is a plain direct strict-TLS dial in the interim (docs/pending-phase7.md).
func newBackendTLSClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   backendDialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   backendTLSHandshakeTimeout,
			IdleConnTimeout:       backendIdleConnTimeout,
			ExpectContinueTimeout: backendExpectContinue,
			ForceAttemptHTTP2:     true,
		},
	}
}

// compose runs the startup admission gate and, on admit, constructs the seams,
// wraps them in the broker adapters, provisions the engine scope, and returns
// the per-session south-face Server. A non-admitted triple returns the
// admission refusal BEFORE any socket is bound (NFR-SEC-60); the caller serves
// the returned Server and Closes it for teardown (engine TeardownScope +
// registry/ceilings Release).
//
// l is threaded into the southface.Config so the session's dispatcher, the
// accept gate, and the http.Server ErrorLog all emit structured JSON via the
// same handler.
//
// m is the broker metric set; it is wired into the southface dispatcher for
// ops_total and stage-latency instrumentation, and into the accept gate for
// peer counters.
//
// ol is the loopback ops listener; when non-nil compose registers /healthz and
// /readyz with the audit-latch and engine-root readiness probes. A nil
// opsListener skips probe registration (unit tests that don't start a listener).
func compose(cfg brokerConfig, l *slog.Logger, m *telemetry.BrokerMetrics, ol ...*telemetry.OpsListener) (southface.Server, error) {
	// Unpack the optional ops listener (variadic for backward compat in tests
	// that pass none).
	var opsListener *telemetry.OpsListener
	if len(ol) > 0 {
		opsListener = ol[0]
	}
	// Engine-kind construction inputs FIRST — both ADR-0010 kinds are real.
	// For s3: the dial path is the storage-lane transport (or the loud
	// dev-direct rig client), the credential arrives through the
	// CredentialSource seam, and the admitted credential KIND flows from
	// that source. For local-volume the credential kind stays hard-wired:
	// it exercises a filesystem permission, not a backend credential.
	var (
		eng        objectstore.Engine
		s3Provider aws.CredentialsProvider
		s3Client   *http.Client
	)
	credKind := admission.CredHostLocalLongLived
	switch cfg.engineKind {
	case objectstore.LocalVolume:
		// Constructed after admission below.
	case objectstore.S3:
		var err error
		// PENDING-PHASE-7(engine-leg-egress): the engine's OWN backend leg
		// dials with a plain strict-TLS client (MinVersion 1.2, ForceAttemptHTTP2,
		// never http.ProxyFromEnvironment). The retired storage-lane fixed-proxy
		// transport carried the GUEST data path, which is now guest->edge->service
		// direct HTTPS; whether the engine's backend dial retains an egress proxy
		// is an unfrozen ADR-0011-vs-new-model reconciliation (docs/pending-phase7.md).
		s3Client = newBackendTLSClient()
		source, err := selectCredentialSource(cfg, cfg.s3Bucket, cfg.s3Region)
		if err != nil {
			return nil, err
		}
		s3Provider, err = source.Provider(context.Background())
		if err != nil {
			return nil, err
		}
		credKind = source.Kind()
	default:
		return nil, fmt.Errorf("%w %q", objectstore.ErrUnknownEngine, cfg.engineKind)
	}

	// Admission FIRST — refuse before binding any socket (NFR-SEC-60).
	if err := admission.Admit(cfg.profile, cfg.tenancy, credKind); err != nil {
		return nil, err
	}
	if err := admission.AdmitBrokerMode(cfg.profile, cfg.tenancy); err != nil {
		return nil, err
	}

	// Construct the seams.
	switch cfg.engineKind {
	case objectstore.LocalVolume:
		eng = objectstore.NewLocalVolumeEngine(cfg.engineRoot)
	case objectstore.S3:
		var err error
		eng, err = objectstore.NewS3Engine(objectstore.S3Config{
			Endpoint:     cfg.s3Endpoint,
			Region:       cfg.s3Region,
			Bucket:       cfg.s3Bucket,
			UsePathStyle: cfg.s3PathStyle,
			Credentials:  s3Provider,
			HTTPClient:   s3Client,
		})
		if err != nil {
			return nil, err
		}
	}
	resolver := authz.New(broker.NewPrefixDownloadablePolicy(cfg.dlPrefixes))
	sink, err := auditgate.NewFileSink(cfg.auditSink)
	if err != nil {
		// An unwritable sink refuses to serve — fail-closed (NFR-SEC-79).
		return nil, err
	}

	// Wire the on-latch callback: emits an ERROR slog line and flips the
	// audit_sink_latched gauge to 1 the moment the fail-closed audit latch
	// trips. The latch turning the broker into a 100%-deny machine is now
	// observable (SEC-79 made observable; T-14-10).
	// The callback captures l and m by pointer (both are already pointers), safe.
	sink.SetOnLatch(func() {
		l.Error("audit sink latched; broker serving 100% denies until restart",
			slog.String(observ.KeyReason, "audit_latch"))
		m.SetAuditSinkLatched(1)
	})

	// Durable file_id handle store (ADR-0023). OPTIONAL this phase: an empty
	// --handle-store leaves hStore nil (the north listener is inert, so the
	// index is unused). When set, NewDiskStore opens/replays the log under the
	// flock run() already holds, and the on-latch callback emits an ERROR line
	// and flips the handle_store_latched gauge — making the fail-closed durable
	// latch observable exactly like the audit sink's.
	var hStore *handlestore.DiskStore
	if cfg.handleStore != "" {
		hStore, err = handlestore.NewDiskStore(cfg.handleStore)
		if err != nil {
			return nil, err
		}
		hStore.SetOnLatch(func() {
			l.Error("handle store latched; durable file_id index refusing mutations until restart",
				slog.String(observ.KeyReason, "handle_store_latch"))
			m.SetHandleStoreLatched(1)
		})
	}

	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         cfg.opsPerSecond,
		OpsBurst:             cfg.opsBurst,
		InFlightBytesCeiling: defaultInFlightBytes,
		FDCeiling:            defaultFDCeiling,
		Clock:                time.Now,
	})

	// Provision = ensure-scaffold-if-absent, idempotent, does NOT erase;
	// erase is owner-change-driven (TeardownScope), never boot-driven.
	scope := objectstore.ScopeID(cfg.filesystemID)
	provisionCtx, cancelProvision := context.WithTimeout(context.Background(), provisionTimeout)
	defer cancelProvision()
	if err := eng.ProvisionScope(provisionCtx, scope); err != nil {
		return nil, err
	}

	// Seed subtree dir-markers after provision (idempotent scaffold). The engine
	// stays subtree-agnostic; compose supplies the list via the SubtreeMap. The
	// loop collects the distinct non-empty For() values across the three intent
	// axes, then calls MakeDir for each, treating ErrExist as success (idempotent:
	// a restart re-provisions without erasing and this loop is a no-op).
	// Approach (a): engine.MakeDir is the tested path; no engine-interface change.
	{
		// Collect distinct non-empty subtree values from the three intent axes and
		// seed a dir-marker for each (idempotent: ErrExist is treated as success).
		// A zero-value SubtreeMap has no non-empty For() values and the loop is a
		// no-op; a configured map yields at most two distinct subtrees (read and
		// preview share "uploads" under the default). The engine stays subtree-
		// agnostic; compose supplies the subtree list via the SubtreeMap (approach a).
		seen := make(map[string]struct{})
		for _, intent := range []southface.Intent{southface.IntentWrite, southface.IntentRead, southface.IntentPreview} {
			sub := cfg.subtrees.For(intent)
			if sub == "" {
				continue
			}
			if _, dup := seen[sub]; dup {
				continue
			}
			seen[sub] = struct{}{}
			if err := eng.MakeDir(provisionCtx, scope, sub); err != nil && !errors.Is(err, fs.ErrExist) {
				return nil, fmt.Errorf("scaffold subtree %q: %w", sub, err)
			}
		}
	}

	// Rollback latch (FILESTORED-11): the scope is now provisioned. If ANY
	// post-provision step fails before ownership passes to teardownServer,
	// compose returns nil,err WITHOUT a closer for that scope. This deferred
	// rollback releases the durable handle-store fd on every post-provision
	// error path so a failed compose never leaks an open log fd. It does NOT
	// erase the scope — a composition failure is not an owner-change event;
	// erase-before-reuse is TeardownScope's responsibility, called only on an
	// explicit owner-change grant. Disarmed (committed = true) once the
	// teardownServer takes ownership.
	committed := false
	defer func() {
		if committed {
			return
		}
		// Release the durable handle-store descriptor on the rollback path so a
		// failed compose does not leak an open log fd (ownership has not yet
		// passed to teardownServer).
		if hStore != nil {
			_ = hStore.Close()
		}
	}()

	// Build the broker adapters ONCE so the south spine and the north Files-API
	// plane (Mount B) share the same stateless seam wrappers — one set of
	// adapters, both planes (the Q-SEAMREUSE ruling). The adapters are stateless
	// views over the shared resolver/sink/registry/engine, so reusing them across
	// the two listeners is correct (and the only honest wiring: one broker, one
	// audit gate, one credential).
	resolverSeam := broker.NewResolver(resolver)
	guardSeam := broker.NewGuard(sink)
	ceilingsSeam := broker.NewCeilings(reg)
	engineSeam := broker.NewEngine(eng)

	srv, err := southface.Serve(southface.Config{
		Resolver:          resolverSeam,
		Guard:             guardSeam,
		Ceilings:          ceilingsSeam,
		Engine:            engineSeam,
		CredExtractor:     newCredentialScopeExtractor(cfg),
		Subtrees:          cfg.subtrees,
		GrantedIntents:    cfg.grantedIntents,
		BindAddr:          cfg.bindAddr,
		CertFile:          cfg.certFile,
		KeyFile:           cfg.keyFile,
		SizeCeiling:       cfg.maxRequestByte,
		BrokerMaxFileSize: cfg.maxFileSize,
		Logger:            l,
		BrokerMetrics:     m,
	})
	if err != nil {
		return nil, err
	}

	// North Files-API listener (Mount B, ADR-0023): constructed ONLY when a
	// durable handle store is configured — the Files-API plane resolves file_ids
	// against it, so with no store the north plane stays inert and only the south
	// listener binds. Mount B is a SEPARATE TLS listener reusing the south cert
	// SOURCE (the same cert/key PATHS), serving the filesapi handler; it is the
	// physical trust boundary between the no-credential /v1/files plane and the
	// egress-credential south mount RPC. The dualServer fans Serve/Close across
	// both; a nil north degrades to south-only.
	var north northface.Server
	if hStore != nil {
		// Default the north bind if a caller (e.g. a direct compose test that
		// constructs brokerConfig without going through validate) left it empty,
		// so the Mount B listener always has a concrete loopback bind.
		northBind := cfg.northBind
		if northBind == "" {
			northBind = defaultNorthBind
		}
		handler, herr := filesapi.NewHandler(filesapi.Deps{
			Resolver:    resolverSeam,
			Guard:       guardSeam,
			Engine:      engineSeam,
			Ceilings:    ceilingsSeam,
			Store:       hStore,
			Scope:       filesapi.NewFencedScopeSource(),
			SizeCeiling: cfg.maxRequestByte,
			// The create path's pre-assembly size reject reads the SAME whole-object
			// ceiling the south face's upload path reads (cfg.maxFileSize, bound from
			// the broker-max-file-size flag): one ceiling, both planes.
			MaxFileSize: cfg.maxFileSize,
			// The north create joins every upload under the deployment map's READ
			// subtree (ADR-0029:46, the human->sandbox direction), so a File-Pane
			// upload lands where the south read-mount looks. This tracks the SAME
			// resolved SubtreeMap the south dispatcher uses (cfg.subtrees); an empty
			// read subtree (join-disabled map) leaves the create in static-path mode.
			CreateSubtree: cfg.subtrees.ReadSubtree(),
			Logger:        l,
		})
		if herr != nil {
			_ = srv.Close()
			return nil, herr
		}
		mountB, merr := northface.NewMountB(northBind, cfg.certFile, cfg.keyFile, handler, l)
		if merr != nil {
			_ = srv.Close()
			return nil, merr
		}
		north = mountB
		l.Info("north Files-API listener constructed (Mount B)",
			slog.String("north_bind", northBind))
	}

	// Register /healthz and /readyz on the ops listener if one was provided.
	// The audit-latch probe reads FileSink.Latched(); the engine-root probe runs
	// a bounded List(scope, ".") — no Engine interface widening (plan decision).
	if opsListener != nil {
		probes := []telemetry.ReadyProbe{
			{
				Name: "audit_latch",
				Check: func() error {
					if sink.Latched() {
						return errors.New("audit sink latched")
					}
					return nil
				},
			},
			{
				Name: "engine_root",
				Check: func() error {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, err := eng.List(ctx, scope, ".")
					return err
				},
			},
		}
		// handle_store_latch readiness: when the store is configured, /readyz
		// turns unhealthy the moment its durable write/sync latch trips, so an
		// orchestrator can stop routing to a daemon whose file_id index can no
		// longer durably record mutations. An unconfigured store contributes no
		// probe (the index is inert this phase).
		if hStore != nil {
			probes = append(probes, telemetry.ReadyProbe{
				Name: "handle_store_latch",
				Check: func() error {
					if hStore.Latched() {
						return errors.New("handle store latched")
					}
					return nil
				},
			})
		}
		telemetry.RegisterOpsListenerHealthHandlers(opsListener, probes)
	}

	// Ownership of the provisioned scope now passes to teardownServer. Disarm
	// the rollback latch (FILESTORED-11) so the deferred TeardownScope above
	// does not erase a live scope on the error path.
	committed = true

	// Fan the south listener and the optional north Files-API listener into one
	// southface.Server handle (the daemon lifecycle drives a single Serve/Close).
	// A nil north degrades the dualServer to south-only.
	fanned := newDualServer(srv, north)

	// Wrap the server so Close drains the session, releases the per-session
	// ceilings, and closes the handle-store fd — all without touching the scope
	// on disk. TeardownScope is the owner-change verb (callers: explicit grant
	// only, never process lifecycle); Close does NOT call it.
	return &teardownServer{
		Server:      fanned,
		ceiling:     reg,
		fsid:        cfg.filesystemID,
		handleStore: hStore,
	}, nil
}

// teardownServer wraps the per-session south-face Server so Close also drains
// in-flight requests, releases the per-session ceilings entry, and closes the
// durable handle-store descriptor. It does NOT erase the scope on Close —
// erase-before-reuse (TeardownScope) is owner-change-driven, never triggered
// by process shutdown. The southface session's own Close releases the registry
// binding and unlinks the socket.
type teardownServer struct {
	southface.Server
	ceiling *ceilings.Registry
	fsid    string
	// handleStore is the durable file_id handle store opened in compose, or nil
	// when --handle-store was empty. Close releases its descriptor; every acked
	// record is already fsynced, so closing loses no durable data.
	handleStore *handlestore.DiskStore
}

// Close drains in-flight requests, releases the per-session ceilings, and
// closes the durable handle-store fd. It does NOT call TeardownScope — process
// shutdown is not an owner-change event; a clean stop must not evict the
// owner's data. All errors surface via errors.Join so no failure is silently
// dropped behind another.
func (t *teardownServer) Close() error {
	closeErr := t.Server.Close()
	t.ceiling.Release(ceilings.SessionKey(t.fsid))
	// Release the durable handle-store descriptor (no-op when unconfigured).
	// Every acked record is already fsynced, so closing loses no durable data;
	// the error joins the others so it is never silently dropped.
	var handleStoreErr error
	if t.handleStore != nil {
		handleStoreErr = t.handleStore.Close()
	}
	return errors.Join(closeErr, handleStoreErr)
}
