// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command ocu-filestored is the storage-broker daemon (component-04): one
// process, two faces (guest-mount south, data-plane-client north), one backend
// credential. This build composes the south face into a real, dialable daemon:
// it parses the frozen flag surface, runs the startup admission gate BEFORE
// binding any socket (NFR-SEC-60), constructs the local-volume engine, the
// three-axis resolver, the fail-closed audit sink, and the per-session
// ceilings registry, wraps them in the broker adapters, provisions a session
// scope, and serves the per-session unix-socket listener.
//
// The south-face flag surface is API and frozen: -south-socket-dir (the
// host-owned 0700 directory per-session sockets are minted into),
// -tenancy/-profile (the admission axes), -audit-sink, -engine/-engine-root,
// -broker-max-file-size (>0, the whole-object ceiling), -filesystem-id,
// -granted-intents, -downloadable-prefixes, -max-request-bytes (the
// per-RPC-message ceiling), and the optional per-session ops token-bucket
// tuning pair -ops-per-second (>0) / -ops-burst (>=1). -north-listen parses
// but binds nothing this phase (the north face is deferred).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Wide-Moat/ocu-filestore/internal/admission"
	"github.com/Wide-Moat/ocu-filestore/internal/auditgate"
	"github.com/Wide-Moat/ocu-filestore/internal/authz"
	"github.com/Wide-Moat/ocu-filestore/internal/broker"
	"github.com/Wide-Moat/ocu-filestore/internal/ceilings"
	"github.com/Wide-Moat/ocu-filestore/internal/objectstore"
	"github.com/Wide-Moat/ocu-filestore/internal/southface"
)

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

// errS3EngineUnavailable refuses `-engine s3` loudly, BEFORE admission and
// before any socket is bound: ADR-0010 names the s3 kind from day one, but
// until the real engine is composed the daemon must never silently serve
// local-volume under the s3 name. Match it with errors.Is.
var errS3EngineUnavailable = errors.New("ocu-filestored: s3 engine not available in this build")

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
	auditSink        string
	socketDir        string
	filesystemID     string
	maxFileSize      int64
	maxRequestByte   int64
	opsPerSecond     float64
	opsBurst         float64
	grantedIntents   []southface.Intent
	dlPrefixes       []string
	profile          admission.WorkloadTrustProfile
	tenancy          admission.Tenancy
}

// run parses and validates the frozen flag surface, then composes and serves
// the daemon. A parse error other than -h/-help propagates; -h/-help returns
// nil. A non-admitted profile/tenancy/credential triple, or a missing/invalid
// required flag, returns a typed error BEFORE any socket is bound.
func run(args []string) error {
	fs := flag.NewFlagSet("ocu-filestored", flag.ContinueOnError)

	fs.String("north-listen", "127.0.0.1:7080",
		"file/UI ingress bind address (north face); PARSED BUT INERT this phase — binds nothing")
	engine := fs.String("engine", "local-volume",
		"backend object-store engine: local-volume | s3 (ADR-0010)")
	maxRequestBytes := fs.Int64("max-request-bytes", 52428800,
		"per-RPC-message inbound body ceiling, rejected pre-buffer (NFR-SEC-78); default 50 MiB")
	socketDir := fs.String("south-socket-dir", "/run/ocu-filestore/sessions",
		"host-owned 0700 directory the south face provisions per-session unix sockets into")
	auditSink := fs.String("audit-sink", "",
		"REQUIRED audit gate file-sink path; an audit-write failure denies the operation (NFR-SEC-79)")
	profile := fs.String("profile", "trusted_operator",
		"admission profile: trusted_operator | internal_workforce | untrusted")
	tenancy := fs.String("tenancy", "single-tenant",
		"tenancy mode: single-tenant | multi-tenant")
	engineRoot := fs.String("engine-root", "",
		"REQUIRED local-volume engine root: the customer workspace volume directory")
	s3CredentialFile := fs.String("s3-credential-file", "",
		"s3 engine only: PATH to a 0600 daemon-owned file holding access_key_id=/secret_access_key= lines; the secret itself NEVER arrives as a flag value (T1-7). Env fallback: "+objectstore.EnvS3AccessKeyID+"/"+objectstore.EnvS3SecretAccessKey)
	maxFileSize := fs.Int64("broker-max-file-size", 0,
		"REQUIRED whole-object upload ceiling in bytes (>0); the fileUpload pre-buffer reject (NFR-SEC-46/78)")
	filesystemID := fs.String("filesystem-id", "",
		"REQUIRED host-attested filesystem scope bound to the session socket")
	grantedIntents := fs.String("granted-intents", "read,write",
		"comma-separated session intent grant set from read,write,preview")
	downloadablePrefixes := fs.String("downloadable-prefixes", "",
		"comma-separated broker-side downloadable prefixes (NFR-SEC-73); empty = nothing downloadable")
	opsPerSecond := fs.Float64("ops-per-second", defaultOpsPerSecond,
		"per-session file-ops token-bucket refill rate in ops/s (>0); the throttle ceiling (NFR-SEC-46)")
	opsBurst := fs.Float64("ops-burst", defaultOpsBurst,
		"per-session file-ops token-bucket capacity in tokens (>=1); a session starts with a full bucket")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	cfg, err := validate(*engine, *engineRoot, *auditSink, *socketDir, *filesystemID,
		*profile, *tenancy, *grantedIntents, *downloadablePrefixes, *maxFileSize, *maxRequestBytes,
		*opsPerSecond, *opsBurst, *s3CredentialFile)
	if err != nil {
		return err
	}

	srv, err := compose(cfg)
	if err != nil {
		return err
	}
	defer srv.Close()
	return srv.Serve()
}

// validate parses and checks the flag surface, returning a brokerConfig or a
// typed error. Required flags (-engine-root, -audit-sink, -filesystem-id, a
// positive -broker-max-file-size) are checked after parse and never panic.
// The optional ops token-bucket pair defaults to 100/200; an explicit
// non-positive -ops-per-second or an -ops-burst below one whole token (which
// would wedge the bucket) is a wiring fault and refuses with the same typed
// error.
func validate(engine, engineRoot, auditSink, socketDir, filesystemID,
	profile, tenancy, grantedIntents, downloadablePrefixes string,
	maxFileSize, maxRequestBytes int64, opsPerSecond, opsBurst float64,
	s3CredentialFile string) (brokerConfig, error) {
	var cfg brokerConfig

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

	if engineRoot == "" {
		return cfg, fmt.Errorf("%w: -engine-root is required", errMissingRequiredFlag)
	}
	if auditSink == "" {
		return cfg, fmt.Errorf("%w: -audit-sink is required", errMissingRequiredFlag)
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

	cfg = brokerConfig{
		engineKind:       kind,
		engineRoot:       engineRoot,
		s3CredentialFile: s3CredentialFile,
		auditSink:        auditSink,
		socketDir:        socketDir,
		filesystemID:     filesystemID,
		maxFileSize:      maxFileSize,
		maxRequestByte:   maxRequestBytes,
		opsPerSecond:     opsPerSecond,
		opsBurst:         opsBurst,
		grantedIntents:   intents,
		dlPrefixes:       splitNonEmpty(downloadablePrefixes),
		profile:          prof,
		tenancy:          ten,
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

// compose runs the startup admission gate and, on admit, constructs the seams,
// wraps them in the broker adapters, provisions the engine scope, and returns
// the per-session south-face Server. A non-admitted triple returns the
// admission refusal BEFORE any socket is bound (NFR-SEC-60); the caller serves
// the returned Server and Closes it for teardown (engine TeardownScope +
// registry/ceilings Release).
func compose(cfg brokerConfig) (southface.Server, error) {
	// Engine-kind gate FIRST — before admission and before any socket bind:
	// `-engine s3` must refuse loudly until the real s3 engine is composed
	// (ADR-0010 names both kinds; a silent local-volume fallback would lie).
	switch cfg.engineKind {
	case objectstore.LocalVolume:
		// The composed path below.
	case objectstore.S3:
		return nil, errS3EngineUnavailable
	default:
		return nil, fmt.Errorf("%w %q", objectstore.ErrUnknownEngine, cfg.engineKind)
	}

	// The credential kind is not a free flag: the minimal shelf admits exactly
	// one long-lived cell, host-local long-lived (A2). Hard-wire it.
	const credKind = admission.CredHostLocalLongLived

	// Admission FIRST — refuse before binding any socket (NFR-SEC-60).
	if err := admission.Admit(cfg.profile, cfg.tenancy, credKind); err != nil {
		return nil, err
	}
	if err := admission.AdmitBrokerMode(cfg.profile, cfg.tenancy); err != nil {
		return nil, err
	}

	// Construct the seams.
	eng := objectstore.NewLocalVolumeEngine(cfg.engineRoot)
	resolver := authz.New(broker.NewPrefixDownloadablePolicy(cfg.dlPrefixes))
	sink, err := auditgate.NewFileSink(cfg.auditSink)
	if err != nil {
		// An unwritable sink refuses to serve — fail-closed (NFR-SEC-79).
		return nil, err
	}
	reg := ceilings.NewRegistry(ceilings.Config{
		OpsPerSecond:         cfg.opsPerSecond,
		OpsBurst:             cfg.opsBurst,
		InFlightBytesCeiling: defaultInFlightBytes,
		FDCeiling:            defaultFDCeiling,
		Clock:                time.Now,
	})

	// Erase-before-reuse: provision the scope's storage at grant on the real
	// engine directly (lifecycle is not a consumer-seam verb). TeardownScope
	// runs on Close (NFR-SEC-54).
	scope := objectstore.ScopeID(cfg.filesystemID)
	provisionCtx, cancelProvision := context.WithTimeout(context.Background(), provisionTimeout)
	defer cancelProvision()
	if err := eng.ProvisionScope(provisionCtx, scope); err != nil {
		return nil, err
	}

	srv, err := southface.Serve(southface.Config{
		Resolver:          broker.NewResolver(resolver),
		Guard:             broker.NewGuard(sink),
		Ceilings:          broker.NewCeilings(reg),
		Engine:            broker.NewEngine(eng),
		Registry:          southface.NewSessionRegistry(),
		Entry:             southface.SessionEntry{FilesystemID: cfg.filesystemID, GrantedIntents: cfg.grantedIntents},
		Dir:               cfg.socketDir,
		SizeCeiling:       cfg.maxRequestByte,
		BrokerMaxFileSize: cfg.maxFileSize,
		CheckPeer:         southface.HostPeerChecker(),
		HostUID:           uint32(os.Getuid()),
	})
	if err != nil {
		return nil, err
	}
	// Wrap the server so Close also tears down the scope (erase-before-reuse)
	// and releases the per-session ceilings (NFR-SEC-54).
	return &teardownServer{
		Server:  srv,
		engine:  eng,
		ceiling: reg,
		scope:   scope,
		fsid:    cfg.filesystemID,
	}, nil
}

// teardownServer wraps the per-session south-face Server so Close also runs
// the scope erase-before-reuse (engine.TeardownScope, NFR-SEC-54) and releases
// the per-session ceilings entry. The southface session's own Close already
// releases the registry binding and unlinks the socket.
type teardownServer struct {
	southface.Server
	engine  objectstore.Engine
	ceiling *ceilings.Registry
	scope   objectstore.ScopeID
	fsid    string
}

// Close shuts the session down, erases the scope (erase-before-reuse), and
// releases the per-session ceilings. The session Close error takes precedence;
// the teardown error is reported only if the session closed cleanly.
func (t *teardownServer) Close() error {
	closeErr := t.Server.Close()
	teardownCtx, cancelTeardown := context.WithTimeout(context.Background(), teardownTimeout)
	defer cancelTeardown()
	teardownErr := t.engine.TeardownScope(teardownCtx, t.scope)
	t.ceiling.Release(ceilings.SessionKey(t.fsid))
	if closeErr != nil {
		return closeErr
	}
	return teardownErr
}
