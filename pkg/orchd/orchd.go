// Package orchd is janus-orchd: the process that owns an evidence directory
// and serves it.
//
// Everything before Phase 4 was a command that ran, wrote its log and exited.
// That works exactly once per directory, because one process writes an evidence
// directory — and Phase 4 needs an SDK, an MCP proxy, a console and a
// coordinator to be appending at the same time. So one of them has to own the
// log and the rest have to ask it. This package is the owner.
//
// It is a host for pkg/saga, not a second implementation of it. The state
// machine, the scheduler, the compensation planner and the gate admission
// checks are the same code the chaos suite has been killing since Phase 2; what
// is new is that the participants are somewhere else, and a step therefore sits
// PREPARED for a while with nobody in the process able to say how it went. That
// gap is the only change the saga package needed (saga.Reporter).
//
// Two rules shape everything here, and both are easier to break than to notice:
//
//   - There is no fast path. Every effectful operation goes through gate
//     admission, the registry, the outbox and the log in the same order a
//     single-process coordinator takes them. An RPC that skipped a gate would
//     look, in the log, exactly like an attack that had succeeded.
//
//   - An acknowledgement means the evidence exists. Every write RPC returns
//     after the append is durable, never before. A service that acknowledged
//     first and appended later would be fast, and would be claiming evidence
//     that a crash in the window destroys — which is precisely the failure
//     evidence-before-effect exists to make impossible.
package orchd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/clockwire"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/clockatt"
	"github.com/mustafarslan/janus/pkg/evidence/fence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/identity"
	"go.opentelemetry.io/otel/metric"

	"github.com/mustafarslan/janus/pkg/outbox"
	projstore "github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/telemetry"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// Options configures a Server.
type Options struct {
	// Dir is the evidence directory this process will own. Opening it takes
	// the writer lock, and failing to take it is the honest outcome: two
	// daemons on one directory is the situation the lock exists to refuse.
	Dir string
	// Tenant binds this daemon to one tenant. It is stamped onto everything
	// appended here and cannot be set by a caller (pkg/tenancy). The zero
	// value is a single-tenant deployment.
	//
	// One tenant per daemon rather than a tenant field on each request: a
	// request field would make the tenant a routing key, and routing by a
	// value the caller controls is the arrangement where a bug in the routing
	// is a disclosure. Here the caller cannot address another tenant's log
	// because this process does not have it open.
	Tenant tenancy.Tenant
	// Signer signs sealed segments. It is the interface rather than the on-disk
	// key type so that custody can live in another process (janus-signer) or in
	// an HSM without this package knowing which.
	Signer segment.Signer
	// SyncMode is the durability barrier. It is not defaulted to something
	// convenient: a deployment that means to run without a barrier has to say
	// so, because the difference is invisible until the power goes out.
	SyncMode segment.SyncMode
	// SegmentTargetBytes triggers rotation once a segment reaches this size.
	// Zero takes the appender's default of 16 MiB.
	//
	// It is configurable because rotation is what *seals* a segment, and a
	// sealed segment is what the replication drill's signature checking and the
	// WORM tier both act on. A drill that could not rotate would exercise
	// neither, while reporting a pass.
	SegmentTargetBytes int64
	// Policy is the gate policy sagas are admitted under. A server without one
	// cannot admit anything, which is the right refusal — a coordinator whose
	// judge is absent does not proceed.
	Policy *gate.Policy
	// Cadence is how long an evaluation stays good for, by risk tier. Nil
	// means no periodic revalidation is scheduled, which is the behaviour
	// before revalidation was scheduled and is deliberately the default: a guessed cadence is a
	// control that looks configured and is not.
	Cadence *registry.Cadence
	// StandbyKeys are writer public keys to declare in the log at start-up, so
	// that a replica promoted later can sign with one.
	//
	// It has to happen here, while this primary is healthy, and the reason is
	// that trust extends *forward*, a key being introduced in a segment
	// the current key signed. At failover the old region is gone, so a standby
	// key first declared by the promoted writer would dangle from no in-chain
	// declaration — and an auditor following the log from one root could not
	// reach it. They would need a second root handed to them out of band,
	// precisely when things have gone wrong, which is when a withheld key and a
	// corrupt segment are hardest to tell apart.
	//
	// Configuration and not an RPC, deliberately. A caller that could extend
	// writer trust could introduce the key that signs a forged history — the
	// same reasoning `pkg/console` uses to refuse issuer trust over the wire,
	// with more at stake, because the writer key is this system's root.
	//
	// Declaring a key already in the log is a no-op, so restarting with the same
	// flag records nothing.
	StandbyKeys keys.PublicKeySet
	// IssuerKeys are the OIDC issuers' signing keys to trust at start-up, keyed
	// by issuer, so that an approval can carry an identity at all.
	//
	// Configuration and not an RPC, for this reason: a caller that
	// could add a trusted issuer could mint tokens establishing any role. A
	// stolen console session cannot reach the daemon's command line. Revocation
	// *is* an RPC, because it removes authority rather than granting it and
	// moves the system fail-closed — the same asymmetry that let
	// RevokeCredential through the wire while registration stayed narrower.
	//
	// Empty is the default and it is not neutral: with no issuer trusted, every
	// assertion-bearing approval is refused. That was the only possible state
	// before issuer keys could be declared, in every deployment.
	IssuerKeys map[string][]identity.IssuerKey
	// Fence, when non-nil, is a held writer lease. The appender consults it
	// before sealing any segment, and losing it stops the write path.
	//
	// Acquired by the caller rather than here, because acquiring it can fail for
	// a reason the operator has to act on — another writer holds this log — and
	// that failure belongs at start-up in main, beside the other refusals, not
	// buried in a constructor.
	Fence *fence.Lease
	// ClockSources are the time references this deployment attests its clock
	// against, tried in order until one answers. Empty means no attestation is
	// taken and every event says so by carrying no attestation reference.
	//
	// Empty is the default for the same reason Cadence's nil is, and for one
	// more: Janus must install air-gapped with no mandatory external
	// dependency, and a default pointing at somebody's NTP server would put one
	// in the write path of every deployment that never thought about it.
	ClockSources []clockatt.Source
	// ClockInterval is how often an attestation is taken. Zero takes the
	// package default of five minutes.
	ClockInterval time.Duration
	// ClockTolerance is the synchronisation bound this deployment claims to
	// hold. Zero takes the package default of one second, RTS 25's figure for
	// activity other than high-frequency trading.
	ClockTolerance time.Duration
	// RequireCallerSignatures refuses an unsigned answer, declaration, result
	// or saga begin from a participant whose manifest declares no key.
	// A participant whose manifest declares one must always sign, whatever this
	// says: the manifest is signed under its principal's key and is in the log,
	// so a deployment cannot quietly waive a key it declared. False keeps
	// keyless participants working, and they are then exactly as spoofable as
	// before -- which the daemon's flag says, and the audit names.
	RequireCallerSignatures bool
	// HumanRelayers are the participants allowed to relay a person's answer --
	// the console, typically. When set, an answer with a human subject must be
	// signed by one of them; an agent that could record "alice approved" in its
	// own name would be authoring its own permission. Empty leaves human answers
	// as they were, unless RequireCallerSignatures is set, in which case they
	// must be signed by a participant of kind SYSTEM or HUMAN.
	HumanRelayers []string
	// Participant is the identity this process records under. It is the
	// daemon's own identity, never the caller's: the log says who appended,
	// and who asked is inside the record.
	Participant evidence.ParticipantRef
	// ProjectionDSN points at the Postgres holding the relational projections.
	// When it is set, frontier gates are answered from a
	// scoped query against those tables instead of by replaying every saga in
	// the directory; when it is empty they are answered by the replay, which is
	// slower and always correct.
	//
	// Empty is a supported deployment, not a degraded one. What the projection
	// buys is a flatter cost curve on a long log, and a deployment small
	// enough not to care should not be made to run a database. What it must not
	// become is a switch between two different *answers*: the equivalence is
	// asserted in pkg/projection's tests, and when the database is
	// unreachable, frontier gates refuse, exactly as they do
	// when no index is configured at all.
	ProjectionDSN string
	// TickInterval is how often this daemon does the work nothing asks it for.
	// Zero means the default; a negative value turns the ticker off entirely.
	//
	// Two things happen on it, and they arrived in that order:
	//
	// Folding the projection, for readers this process does not contain. Every
	// in-process reader — admission, ResolveParticipant, a frontier gate — folds
	// on demand before it answers and never waits for the ticker; a console in
	// another process cannot, because it holds no writer lock and folds nothing.
	//
	// Expiring gates whose deadline has passed. A saga held at a gate
	// returns ErrWaiting and then nothing runs, so without a ticker there is no
	// process to notice — which is why this ticker runs whether or not a
	// projection is configured. A timeout that only worked when a reporting
	// database was attached would not be a control.
	//
	// Seconds, not milliseconds. The fold takes the projector's lock and the
	// in-process readers queue behind it, so a ticker running hot would add
	// latency to the very admissions it is not there to serve.
	TickInterval time.Duration
	// SandboxTargets are the delivery targets an exploratory saga may reach.
	// It is the daemon's configuration and never
	// anything a caller sends: a plan that could nominate its own sandbox would
	// put the exemption in the hands of the party the mode exists to constrain.
	//
	// Empty means an exploratory saga releases nothing at all, which is the
	// right default for a mode whose entire meaning is "not for real".
	SandboxTargets []string
	// Deliverers is the outbox's map of target to transport. A target with no
	// deliverer cannot have its effects released, which is a refusal rather
	// than a silent hold.
	Deliverers map[string]outbox.Deliverer
	// MaxAttempts bounds outbox delivery attempts. Zero takes the outbox's own
	// default of five.
	MaxAttempts uint32
}

// Server is the orchestrator daemon.
type Server struct {
	janusv1.UnimplementedOrchestratorServiceServer

	dir    string
	tenant tenancy.Tenant
	app    *evidence.Appender
	// projection is the store backing frontier decisions, or nil when this
	// daemon answers them by replaying the log. It is held only so Close can
	// release the pool; nothing reads it, because the only consumer is the
	// IndexFunc the keeper already holds.
	projection *projstore.Store
	// projector folds this daemon's log into the projection. It is nil when no
	// projection is configured, and every read path falls back to the log.
	projector *projstore.Projector
	// clock attests this process's wall clock. It does nothing when no source
	// is configured, which is what "no attestation reference" on an event means.
	clock *clockwire.Clock
	fence *fence.Lease
	// requireSigned and humanRelayers are Options.RequireCallerSignatures and
	// Options.HumanRelayers.
	requireSigned bool
	humanRelayers []string
	// signing is the registry the caller checks read, folded once and kept:
	// folding it walks the whole log, which admission can afford once per saga
	// and the decision path cannot afford once per step. It is exact because
	// nothing else can append while this process holds the writer lock, and
	// the one path here that records a registry event forgets it.
	signingMu sync.Mutex
	signing   *registry.Registry
	// stopFold ends the background fold; foldDone closes when it has stopped.
	// Both are nil when no projection is configured.
	stopFold context.CancelFunc
	foldDone chan struct{}
	// lagMetric is the projection-lag callback registration, kept so it can be
	// unregistered. The instruments live on the global meter under fixed names,
	// so two daemons in one process would otherwise leave two callbacks
	// answering for one gauge.
	lagMetric metric.Registration
	engine    *gate.Engine
	// cadence schedules periodic revalidations. Nil disables them.
	cadence     *registry.Cadence
	keeper      saga.Gatekeeper
	participant evidence.ParticipantRef

	// releaser is swapped when the set of connected deliverers changes, so it
	// is read through currentReleaser rather than used directly. The breakers
	// and the attempt budget outlive the swap: a target that has been failing
	// must not get a clean breaker every time some unrelated deliverer
	// connects.
	releaserMu  sync.RWMutex
	releaser    *outbox.Releaser
	deliverers  deliverers
	breakers    *outbox.Breakers
	maxAttempts uint32
	// telemetry emits spans. It is a pointer into the evidence rather than a
	// copy of it, and it is a no-op unless whoever runs this process wired up
	// an exporter — see pkg/telemetry on why a trace is not a record.
	telemetry *telemetry.Recorder
	// static are the deliverers compiled in by the caller, which stay
	// registered for the life of the process. A test injects here; a
	// deployment connects a stream.
	static map[string]outbox.Deliverer
	// sandboxTargets are the targets an exploratory saga may reach. Fixed at
	// construction: a target that could become a sandbox while the daemon runs
	// would be an exemption somebody could grant after the fact.
	sandboxTargets []string

	// mu guards sagas and the watcher set. It is never held while a saga is
	// being driven: driving appends to the log, which can block on a barrier,
	// and a lock held across an fsync would serialise every unrelated caller
	// behind the slowest disk write in the process.
	mu    sync.Mutex
	sagas map[string]*hosted

	watch watchers
}

// hosted is the per-saga state this process holds that is not in the log.
//
// There is deliberately almost nothing here. The outcomes map is the one piece
// of memory in the whole design, and it exists for a single RPC's duration:
// CompleteStep puts an outcome in it and drives the saga, which appends it. A
// crash in that window loses the map and the log has no result — which is
// exactly the state the participant's at-least-once retry is for.
type hosted struct {
	// driving serialises driving one saga. Two callers completing two steps of
	// the same saga must not both drive it: the coordinator holds no memory, so
	// they would race to record the same transition and one would lose.
	//
	// It is separate from mu because the coordinator calls back into the
	// program while a drive is in progress — one mutex for both would deadlock
	// on the first step it asked about.
	driving sync.Mutex

	mu sync.Mutex
	// outcomes is keyed by attemptKey. A compensation is keyed by the undo
	// step id at attempt zero, because a compensation has no attempt counter.
	outcomes map[string]saga.StepOutcome
	// declared holds what a participant said it would do, keyed the same way.
	// A key present with a nil map is a step declared with no facts, which is
	// the ordinary case and is different from a step not declared at all.
	declared map[string]map[string]saga.FactValue
	// spawns is the sub-saga a step delegates to, keyed by step id rather than
	// by attempt: the coordinator derives an attempt-scoped child id of its own
	// from this one, so what is declared here is the delegation, not the
	// particular child.
	spawns map[string]*janusv1.ChildSaga
}

func attemptKey(stepID string, attempt uint32) string {
	return fmt.Sprintf("%s#%d", stepID, attempt)
}

// New opens the evidence directory and returns a server that owns it.
func New(opts Options) (*Server, error) {
	if opts.Dir == "" {
		return nil, errors.New("orchd: an evidence directory is required")
	}
	if opts.Policy == nil {
		return nil, errors.New("orchd: a gate policy is required; a server that admitted " +
			"sagas without one would be deciding that every effect is unconditionally allowed")
	}
	if opts.Participant.ID == "" {
		return nil, errors.New("orchd: a participant identity is required, because every " +
			"record this process appends has to say who appended it")
	}

	// The clock is built before the appender because the appender reads its Ref
	// on every batch, and it is fed by the appender because an attestation is an
	// evidence event like any other. The cycle is broken by both sides being
	// lazy: `Ref` is called per batch and answers "" until the first attestation
	// lands, and `Bind` hands over the appender before the loop is ever started.
	//
	// The wiring itself is `pkg/clockwire`, shared with every other process that
	// writes an evidence log — the interception edges most of all, because they
	// record what a regulator asks about.
	clock, err := clockwire.New(clockwire.Config{
		Sources:     opts.ClockSources,
		Interval:    opts.ClockInterval,
		Tolerance:   opts.ClockTolerance,
		Participant: opts.Participant,
		OnBreach: func(a clockatt.Attestation) {
			log.Printf("orchd: clock outside the declared tolerance: %s", a.Summary())
		},
	})
	if err != nil {
		return nil, fmt.Errorf("orchd: clock attestation: %w", err)
	}

	app, err := evidence.Open(evidence.Options{
		Dir: opts.Dir, Signer: opts.Signer, SyncMode: opts.SyncMode, Tenant: opts.Tenant,
		SegmentTargetBytes:  opts.SegmentTargetBytes,
		ClockAttestationRef: clock.Ref,
		// Nil-safe: with no fence this is a call that returns nil, which is the
		// unfenced behaviour and is what every deployment gets by default.
		BeforeSeal: opts.Fence.CheckOrNil,
	})
	if err != nil {
		if errors.Is(err, evidence.ErrLocked) {
			return nil, fmt.Errorf("%w: another process owns %s — one process writes an "+
				"evidence directory, so stop that one before starting this", err, opts.Dir)
		}
		return nil, fmt.Errorf("orchd: open %s: %w", opts.Dir, err)
	}

	// Live: this process owns the writer lock on the directory, so its own
	// appender is the authority on what has been acknowledged.
	index := gate.IndexFromLiveLog(opts.Dir, func() uint64 { return app.Stats().LastSeq })
	var store *projstore.Store
	var projector *projstore.Projector
	if opts.ProjectionDSN != "" {
		store, err = projstore.Open(context.Background(), opts.ProjectionDSN)
		if err != nil {
			_ = app.Close()
			return nil, fmt.Errorf("orchd: open the projection: %w", err)
		}
		// The head the projection is required to have reached is read from the
		// appender, which is this process: orchd owns the writer lock on the
		// directory, so nothing else can be adding to the log behind it.
		projector = projstore.NewProjector(store, opts.Dir)
		index = projector.FrontierIndex(context.Background(),
			func() uint64 { return app.Stats().LastSeq })
	}

	srv := &Server{
		requireSigned:  opts.RequireCallerSignatures,
		humanRelayers:  slices.Clone(opts.HumanRelayers),
		fence:          opts.Fence,
		projection:     store,
		projector:      projector,
		dir:            opts.Dir,
		tenant:         opts.Tenant,
		app:            app,
		engine:         gate.NewEngine(opts.Policy),
		cadence:        opts.Cadence,
		keeper:         gate.NewKeeper(index),
		participant:    opts.Participant,
		clock:          clock,
		sagas:          map[string]*hosted{},
		breakers:       outbox.NewBreakers(outbox.BreakerConfig{}),
		telemetry:      telemetry.New("janus-orchd"),
		maxAttempts:    opts.MaxAttempts,
		static:         opts.Deliverers,
		sandboxTargets: opts.SandboxTargets,
	}
	for target, d := range opts.Deliverers {
		srv.deliverers.set(target, d)
	}
	// Before the ticker and before anything is served: the first attestation is
	// the one every later append points at.
	clock.Bind(app)
	clock.Start(context.Background())
	if err := srv.declareStandbyKeys(opts.StandbyKeys); err != nil {
		_ = app.Close()
		return nil, err
	}
	if err := srv.declareIssuerKeys(opts.IssuerKeys); err != nil {
		_ = app.Close()
		return nil, err
	}
	// Started whether or not a projection is configured: the fold is optional,
	// the gate expiry is not.
	srv.startTicker(opts.TickInterval)
	srv.rebuildReleaser()
	if srv.currentReleaser() == nil {
		_ = app.Close()
		return nil, errors.New("orchd: the outbox could not be built")
	}
	return srv, nil
}

// defaultTickInterval is how often the daemon does unprompted work.
//
// Five seconds is chosen against what it is for: a person refreshing a console,
// and a deadline measured in hours. A page up to five seconds behind is
// unremarkable and says so on itself; a gate expiring five seconds late is not a
// number anybody can perceive. A ticker fast enough to be invisible would be
// taking the projector's lock hundreds of times an hour for a reader that may
// not exist.
const defaultTickInterval = 5 * time.Second

// startTicker runs the daemon's unprompted work on an interval.
//
// A fold that fails is logged and the lag metric shows it; it does not stop the
// daemon. That is deliberate and it is safe because nothing in this process
// depends on the ticker: every in-process reader folds for itself and refuses
// for itself if it cannot. What a failing ticker costs is a console
// that goes stale, and a console that goes stale says so on the page — which is
// a much better outcome than a coordinator that stopped because a reporting
// database did.
// liveRead is how this daemon reads the directory it owns: the acknowledged
// head, and the appender as the locator for a saga's records.
func (s *Server) liveRead() []evidence.ReadOption {
	return []evidence.ReadOption{
		evidence.AsOf(s.app.Stats().LastSeq),
		evidence.WithLocator(s.app),
	}
}

func (s *Server) startTicker(every time.Duration) {
	switch {
	case every < 0:
		return
	case every == 0:
		every = defaultTickInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.stopFold = cancel
	s.foldDone = make(chan struct{})

	// The lag metric only where there is a projection to lag. A gauge answering
	// zero without one would read as "caught up" rather than "not configured".
	//
	// Guarded around the registration alone, and not by returning: an earlier
	// version returned here, which left `foldDone` created and the goroutine
	// below never started — so every Close on a daemon without a projection
	// waited forever on a channel nothing would close.
	if s.projection != nil {
		reg, err := s.telemetry.ProjectionLag("janus-orchd",
			func(ctx context.Context) (uint64, uint64, error) {
				projected, _, err := s.projection.Head(ctx)
				if err != nil {
					return 0, 0, err
				}
				return projected, s.app.Stats().LastSeq, nil
			})
		if err != nil {
			log.Printf("orchd: the projection lag will not be reported: %v", err)
		} else {
			s.lagMetric = reg
		}
	}

	go func() {
		defer close(s.foldDone)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// The fold is what a projection-backed deployment needs and is
				// skipped without one; the expiry below runs either way.
				if s.projector != nil {
					// Skipped while a decision is already folding: the ticker
					// exists so a quiet projection does not drift, and queueing
					// it behind a gate decision that is doing the same work
					// only adds latency to that decision.
					if !s.projector.FoldInFlight() {
						if at, err := s.projector.CatchUp(ctx); err != nil && ctx.Err() == nil {
							log.Printf("orchd: folding the projection: %v", err)
						} else if err == nil {
							s.projector.NoteFolded(at)
						}
					}
				}
				if ctx.Err() == nil {
					s.expireDueGates(ctx)
				}
				if ctx.Err() == nil {
					s.requireDueRevalidations(ctx)
				}
			}
		}
	}()
}

// Close releases the evidence directory.
func (s *Server) Close() error {
	s.clock.Stop()
	if s.stopFold != nil {
		s.stopFold()
		<-s.foldDone
	}
	if s.lagMetric != nil {
		_ = s.lagMetric.Unregister()
		s.lagMetric = nil
	}
	s.watch.closeAll()
	if s.projection != nil {
		s.projection.Close()
	}
	return s.app.Close()
}

// hostedSaga returns the per-saga state, creating it on first use.
func (s *Server) hostedSaga(sagaID string) *hosted {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.sagas[sagaID]
	if !ok {
		h = &hosted{
			outcomes: map[string]saga.StepOutcome{},
			declared: map[string]map[string]saga.FactValue{},
			spawns:   map[string]*janusv1.ChildSaga{},
		}
		s.sagas[sagaID] = h
	}
	return h
}

// forget drops the memory held for a saga that has reached a terminal state.
// Nothing is lost: everything that mattered is in the log, and a late report
// against a finished saga is answered from the projection.
func (s *Server) forget(sagaID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sagas, sagaID)
}
