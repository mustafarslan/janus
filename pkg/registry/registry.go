package registry

import (
	"fmt"
	"sort"
	"strings"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/template"
	"google.golang.org/protobuf/proto"
)

// The registry as a projection.
//
// Nothing in this file is the system of record. The log is. A Registry is what
// you get by folding the registry events out of an evidence directory, in
// sequence order, through a state machine that refuses illegal transitions —
// the same shape as the saga projection, for the same reason.
//
// It buys three things that a table would not. Resolution can be asked
// as of a sequence, so "which manifest governed this step" is answerable at the
// moment the step ran rather than only now. An auditor holding a bundle can
// rebuild it without the registry service. And a registry that has been
// tampered with is caught by the same chain check as everything else, because
// its history is in the same chain.

// Entry is one manifest version's standing in the registry.
type Entry struct {
	ParticipantID  string
	Version        string
	ContentAddress string
	Manifest       *Manifest
	// Template is set instead of Manifest when this entry is a saga template.
	// Exactly one of the two is non-nil.
	Template  *template.Template
	Signature *janusv1.ManifestSignature
	State     State

	// Evaluation is the most recent conformance report attached to this
	// version, passing or not. A failing one is kept: "this was tested and it
	// did not pass" is the part somebody needs to see.
	Evaluation *janusv1.EvaluationReport
	// Change describes what this version altered relative to its predecessor.
	Change *janusv1.ChangeRecord
	// PendingTriggers are revalidation triggers no evaluation has covered yet.
	// A version owing any of these cannot be activated.
	PendingTriggers []string
	// Reason is why the last human-driven transition happened — the content of
	// a suspension.
	Reason string

	RegisteredSeq uint64
	ActivatedSeq  uint64
	// EvaluatedSeq is where in the log this version's evidence was established:
	// the sequence of its most recent *passing* evaluation, or zero if it has
	// none.
	//
	// Failing runs deliberately do not move it. A version that failed a re-run
	// has not established anything, and a seq that advanced on failure would let
	// a template clear a finding about stale evidence by failing a check.
	//
	// An inherited evaluation carries the *predecessor's* seq rather than its
	// own event's. `InheritEvaluation` says it "carries no checks of its own",
	// so the place in the log where the evidence was established is where the
	// predecessor established it — and a successor that read as freshly
	// evaluated on the strength of inheriting would be the exact overclaim the
	// inheritance event exists to avoid making.
	//
	// Distinct from `ValidatedAt`, which is a wall clock and answers "is this
	// due for periodic review". This answers "what else in the log had
	// already happened when this evidence was established", which is a question
	// about order and needs the sequence.
	EvaluatedSeq uint64
	LastSeq      uint64

	// ValidatedAt is when this version's standing was last established: the
	// wall clock of its most recent evaluation, or of its registration if it
	// has never been evaluated.
	//
	// It is the anchor a periodic revalidation counts from, and it is one
	// anchor rather than two on purpose — it is costly to have
	// the enforcer and the auditor disagree about where a deadline started.
	ValidatedAt time.Time
}

// Registry is the folded state of every manifest the log has seen.
type Registry struct {
	// entries is participant -> version -> entry.
	entries map[string]map[string]*Entry
	// order preserves registration order per participant, so "the latest
	// version" means the latest registered rather than the highest string.
	order map[string][]string
	// templates and templateOrder are the same two structures for saga
	// templates (template.go). They are separate from `entries` so that
	// no reader of participants can see a template by accident — see the note
	// in template.go for why a kind flag on one map was the wrong shape.
	templates     map[string]map[string]*Entry
	templateOrder map[string][]string
	lastSeq       uint64
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		entries:       map[string]map[string]*Entry{},
		order:         map[string][]string{},
		templates:     map[string]map[string]*Entry{},
		templateOrder: map[string][]string{},
	}
}

// Event is one registry event as read from the log.
type Event struct {
	Seq uint64
	// Wall is when the appender recorded this event.
	//
	// The registry did not carry it until a periodic revalidation needed an
	// anchor to count a cadence from. It is
	// the recorded wall clock rather than a time any reader computes, for the
	// reason that holds for gate expiry: a schedule derived from "now" at
	// read time makes two readers of the same log disagree about whether a
	// version was in good standing.
	Wall    time.Time
	Payload []byte
}

// LastSeq is the sequence of the last event folded in.
func (r *Registry) LastSeq() uint64 { return r.lastSeq }

// Resolve returns a manifest version's entry.
//
// It resolves in any state, including RETIRED. A saga that ran two years ago
// pinned whatever was active then, and an audit of that saga has to be able to
// see the manifest it ran under — invariant I8 is about resolvability, not
// about current standing. Whether the version may be pinned *now* is a separate
// question, asked by Admit.
func (r *Registry) Resolve(participantID, version string) (*Entry, bool) {
	byVersion, ok := r.entries[participantID]
	if !ok {
		return nil, false
	}
	e, ok := byVersion[version]
	return e, ok
}

// Active returns the participant's active version, if it has one.
func (r *Registry) Active(participantID string) (*Entry, bool) {
	for _, v := range r.order[participantID] {
		if e := r.entries[participantID][v]; e.State == StateActive {
			return e, true
		}
	}
	return nil, false
}

// Versions returns a participant's versions in registration order.
func (r *Registry) Versions(participantID string) []*Entry {
	out := make([]*Entry, 0, len(r.order[participantID]))
	for _, v := range r.order[participantID] {
		out = append(out, r.entries[participantID][v])
	}
	return out
}

// Participants returns every participant id the registry knows, sorted.
func (r *Registry) Participants() []string {
	out := make([]string, 0, len(r.entries))
	for id := range r.entries {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ClassifyAction reports the effect class a participant's active manifest
// declares for an action.
//
// This is what replaces the static table janus-mcpd carried through Phase 0: a
// tool's class comes from a signed, evaluated declaration rather than from a
// file somebody edited. An action the active manifest does not declare returns
// false, and the caller's fail-closed default applies — an unregistered tool is
// treated as irreversible until it proves otherwise.
func (r *Registry) ClassifyAction(participantID, action string) (janusv1.EffectClass, bool) {
	e, ok := r.Active(participantID)
	if !ok {
		return janusv1.EffectClass_EFFECT_CLASS_UNSPECIFIED, false
	}
	return e.Manifest.EffectClassOf(action)
}

// Classifier adapts the registry to the interception edge's Classifier
// interface (pkg/mcp), bound to one participant.
//
// It is a value rather than a closure over the registry so that a proxy holds
// something inspectable, and it deliberately does not refresh: a long-running
// proxy that silently picked up a new manifest mid-session would classify two
// calls in one session under two different declarations, and the evidence would
// not say which. Re-resolving is a restart, which is visible.
type Classifier struct {
	registry      *Registry
	participantID string
}

// ClassifierFor returns a classifier bound to a participant.
func (r *Registry) ClassifierFor(participantID string) Classifier {
	return Classifier{registry: r, participantID: participantID}
}

// Classify implements the interception edge's Classifier.
func (c Classifier) Classify(action string) (janusv1.EffectClass, bool) {
	if c.registry == nil {
		return janusv1.EffectClass_EFFECT_CLASS_UNSPECIFIED, false
	}
	return c.registry.ClassifyAction(c.participantID, action)
}

// Apply folds one registry event into the projection.
//
// It refuses a transition the lifecycle does not allow, which is what makes the
// projection a check rather than an echo: a log carrying an activation that
// nothing evaluated does not quietly produce an active participant.
func (r *Registry) Apply(seq uint64, wall time.Time, ev *janusv1.RegistryEvent) error {
	if ev.GetParticipantId() == "" || ev.GetVersion() == "" {
		return fmt.Errorf("registry: event at seq %d names no participant version", seq)
	}
	if seq > 0 {
		r.lastSeq = seq
	}

	switch ev.GetKind() {
	case janusv1.RegistryEvent_KIND_REGISTERED:
		if err := r.applyRegistered(seq, ev); err != nil {
			return err
		}
		// Registration is the first thing that establishes standing, so it is
		// where a periodic cadence starts counting for a version nobody has
		// evaluated yet.
		r.stampValidated(ev, wall)
		return nil
	case janusv1.RegistryEvent_KIND_EVALUATED:
		if err := r.applyEvaluated(seq, ev); err != nil {
			return err
		}
		// An evaluation is what a revalidation asks for, so it restarts the
		// clock — whether it passed or not is a separate question the state
		// machine already answers, and a failing evaluation still means
		// somebody looked.
		r.stampValidated(ev, wall)
		return nil
	case janusv1.RegistryEvent_KIND_ACTIVATED:
		return r.applyActivated(seq, ev)
	case janusv1.RegistryEvent_KIND_SUSPENDED:
		return r.applyTerminalish(seq, ev, StateSuspended, canSuspend)
	case janusv1.RegistryEvent_KIND_RETIRED:
		return r.applyTerminalish(seq, ev, StateRetired, canRetire)
	case janusv1.RegistryEvent_KIND_REVALIDATION_REQUIRED:
		return r.applyRevalidationRequired(seq, ev)
	default:
		// A kind this build does not implement is refused rather than skipped.
		// Skipping it would mean an older binary reads a newer log and reports
		// a registry state that is missing whatever the unknown events said —
		// silently, and in the direction of permitting more.
		return fmt.Errorf("registry: event at seq %d has unknown kind %s", seq, ev.GetKind())
	}
}

func (r *Registry) applyRegistered(seq uint64, ev *janusv1.RegistryEvent) error {
	// One event kind, two document types. Which one this is comes from which
	// field carries bytes, and never from a flag a writer could set
	// inconsistently with the payload.
	switch {
	case len(ev.GetTemplate()) > 0 && len(ev.GetManifest()) > 0:
		return fmt.Errorf("registry: event at seq %d carries both a manifest and a template, "+
			"so nothing says which document the version means", seq)
	case len(ev.GetTemplate()) > 0:
		return r.applyTemplateRegistered(seq, ev)
	}
	m, err := DecodeManifest(ev.GetManifest())
	if err != nil {
		return fmt.Errorf("registry: event at seq %d: %w", seq, err)
	}
	if m.Version != ev.GetVersion() {
		return fmt.Errorf("registry: event at seq %d registers %q but the manifest it carries "+
			"declares version %q", seq, ev.GetVersion(), m.Version)
	}
	if m.Identity.ParticipantID != ev.GetParticipantId() {
		return fmt.Errorf("registry: event at seq %d registers participant %q but the manifest "+
			"it carries belongs to %q", seq, ev.GetParticipantId(), m.Identity.ParticipantID)
	}
	addr := ContentAddressOf(ev.GetManifest())
	if ev.GetContentAddress() != "" && ev.GetContentAddress() != addr {
		return fmt.Errorf("registry: event at seq %d records content address %s for bytes that "+
			"hash to %s", seq, shortAddress(ev.GetContentAddress()), shortAddress(addr))
	}

	if _, taken := r.templates[ev.GetParticipantId()]; taken {
		return fmt.Errorf("registry: event at seq %d registers participant %q, which is "+
			"already a template id; the two share a namespace because a version's later "+
			"events say only the id", seq, ev.GetParticipantId())
	}

	byVersion, ok := r.entries[ev.GetParticipantId()]
	if !ok {
		byVersion = map[string]*Entry{}
		r.entries[ev.GetParticipantId()] = byVersion
	}
	if prior, exists := byVersion[m.Version]; exists {
		// The one thing a version may never do is change its mind. Every saga
		// that pinned this string recorded a claim about what the participant
		// was declared to do, and a second registration with different bytes
		// makes every one of those claims ambiguous.
		if prior.ContentAddress != addr {
			return fmt.Errorf("registry: event at seq %d registers %s@%s again with different "+
				"content (%s, was %s); a version that can be edited is not a pin, and every saga "+
				"that pinned it would become unresolvable", seq, ev.GetParticipantId(), m.Version,
				shortAddress(addr), shortAddress(prior.ContentAddress))
		}
		return fmt.Errorf("registry: event at seq %d registers %s@%s a second time",
			seq, ev.GetParticipantId(), m.Version)
	}

	e := &Entry{
		ParticipantID:  m.Identity.ParticipantID,
		Version:        m.Version,
		ContentAddress: addr,
		Manifest:       m,
		Signature:      ev.GetSignature(),
		State:          StateDraft,
		Change:         ev.GetChange(),
		RegisteredSeq:  seq,
		LastSeq:        seq,
	}
	// A change that fired a trigger the predecessor declared is a debt this
	// version carries from birth: it cannot be activated on evidence gathered
	// before the thing that changed.
	e.PendingTriggers = append([]string(nil), ev.GetChange().GetTriggersFired()...)

	byVersion[m.Version] = e
	r.order[e.ParticipantID] = append(r.order[e.ParticipantID], m.Version)
	return nil
}

func (r *Registry) applyEvaluated(seq uint64, ev *janusv1.RegistryEvent) error {
	e, err := r.mutable(seq, ev)
	if err != nil {
		return err
	}
	if err := canEvaluate(e.State); err != nil {
		return fmt.Errorf("%w (%s@%s at seq %d)", err, e.ParticipantID, e.Version, seq)
	}
	report := ev.GetEvaluation()
	if report == nil {
		return fmt.Errorf("registry: event at seq %d evaluates %s@%s but carries no report",
			seq, e.ParticipantID, e.Version)
	}

	// A failing evaluation is recorded and leaves the state alone. It is a fact
	// about the version rather than a transition: a DRAFT that failed is still
	// a DRAFT and still cannot be activated, and an ACTIVE version that fails a
	// re-run needs a human to decide whether to suspend it — that is a judgment
	// with operational consequences, and the registry does not get to make it
	// silently on the strength of a test run.
	e.Evaluation = report
	if report.GetPassed() {
		e.EvaluatedSeq = evidenceEstablishedAt(r, e, report, seq)
		e.PendingTriggers = coveredBy(e.PendingTriggers, report.GetTriggersCovered())
		// A passing run lifts a DRAFT to EVALUATED, and lifts a suspension to
		// the same place: fresh evidence is what the return trip through
		// evaluation exists to put on the record. It does not by itself put the
		// version back in service — activation is a separate, recorded decision
		// somebody has to make. An already ACTIVE version stays active; a
		// re-run that happens to pass is not a reason to take it out.
		if e.State == StateDraft || e.State == StateSuspended {
			e.State = StateEvaluated
		}
	}
	e.LastSeq = seq
	return nil
}

// evidenceEstablishedAt is where in the log the evidence behind a passing report
// was actually established.
//
// For a report somebody ran, that is this event. For an inherited one it is
// wherever the predecessor's was — following the chain, because a version may
// inherit from a version that inherited. A predecessor the fold cannot find
// leaves it at this event, which is the conservative answer: it reads as fresh
// rather than as stale evidence somebody could then be told to go and refresh.
func evidenceEstablishedAt(r *Registry, e *Entry, report *janusv1.EvaluationReport,
	seq uint64) uint64 {

	from := report.GetInheritedFrom()
	if from == "" {
		return seq
	}
	prev, ok := r.resolveEither(e.ParticipantID, from)
	if !ok || prev.EvaluatedSeq == 0 {
		return seq
	}
	return prev.EvaluatedSeq
}

func (r *Registry) applyActivated(seq uint64, ev *janusv1.RegistryEvent) error {
	e, err := r.mutable(seq, ev)
	if err != nil {
		return err
	}
	if err := canActivate(e); err != nil {
		return fmt.Errorf("%w (at seq %d)", err, seq)
	}

	// Activating a successor is the decision to stop using the predecessor.
	// Superseding it here rather than demanding a second event is not a
	// shortcut: it is one decision, and a rule that made an operator record it
	// twice would eventually be a rule under which they recorded it once. The
	// transition is still derived from an event in the log, so a replay reaches
	// the same state.
	if prior, ok := r.activeOf(e); ok && prior.Version != e.Version {
		prior.State = StateSuperseded
		prior.LastSeq = seq
	}

	e.State = StateActive
	e.ActivatedSeq = seq
	e.LastSeq = seq
	return nil
}

func (r *Registry) applyTerminalish(seq uint64, ev *janusv1.RegistryEvent, to State,
	allowed func(State) error) error {

	e, err := r.mutable(seq, ev)
	if err != nil {
		return err
	}
	if err := allowed(e.State); err != nil {
		return fmt.Errorf("%w (%s@%s at seq %d)", err, e.ParticipantID, e.Version, seq)
	}
	if to == StateSuspended && strings.TrimSpace(ev.GetReason()) == "" {
		// The reason is the whole content of a suspension. Without it the log
		// records that somebody stopped a participant and nothing about what
		// would have to be true to start it again.
		return fmt.Errorf("registry: event at seq %d suspends %s@%s with no reason",
			seq, e.ParticipantID, e.Version)
	}
	e.State = to
	e.Reason = ev.GetReason()
	e.LastSeq = seq
	return nil
}

func (r *Registry) applyRevalidationRequired(seq uint64, ev *janusv1.RegistryEvent) error {
	e, err := r.mutable(seq, ev)
	if err != nil {
		return err
	}
	triggers := ev.GetChange().GetTriggersFired()
	if len(triggers) == 0 {
		return fmt.Errorf("registry: event at seq %d requires revalidation of %s@%s but names "+
			"no trigger", seq, e.ParticipantID, e.Version)
	}
	for _, t := range triggers {
		if !containsString(e.PendingTriggers, t) {
			e.PendingTriggers = append(e.PendingTriggers, t)
		}
	}
	sort.Strings(e.PendingTriggers)
	e.LastSeq = seq
	return nil
}

// activeOf returns the currently active version of whatever e is.
//
// A template and a participant live in different maps, and `Active` only reads
// the participant one — so activating a template successor looked up the
// predecessor among participants, found nothing, and superseded nobody. Both
// versions stayed ACTIVE, and since admission requires the pinned version to be
// ACTIVE (admit.go), activating a corrected template did not stop the previous
// shape confining new sagas. Which is precisely what the comment above says
// activation means.
//
// It mirrors `mutable`: the kind is not in the event, so it is read off the
// entry the event resolved to.
func (r *Registry) activeOf(e *Entry) (*Entry, bool) {
	if e.Template != nil {
		return r.ActiveTemplate(e.ParticipantID)
	}
	return r.Active(e.ParticipantID)
}

func (r *Registry) mutable(seq uint64, ev *janusv1.RegistryEvent) (*Entry, error) {
	e, ok := r.Resolve(ev.GetParticipantId(), ev.GetVersion())
	if !ok {
		// A template's later transitions carry no document, so which map the
		// version lives in is only discoverable by looking. Participants are
		// looked at first because they are the overwhelming majority.
		e, ok = r.ResolveTemplate(ev.GetParticipantId(), ev.GetVersion())
	}
	if !ok {
		return nil, fmt.Errorf("registry: event at seq %d acts on %s@%s, which was never registered",
			seq, ev.GetParticipantId(), ev.GetVersion())
	}
	if addr := ev.GetContentAddress(); addr != "" && addr != e.ContentAddress {
		// An event naming a different content address for a version it claims
		// to be acting on is either stale or forged. Either way, acting on it
		// would attach a decision to bytes nobody decided about.
		return nil, fmt.Errorf("registry: event at seq %d names content address %s for %s@%s, "+
			"which is registered as %s", seq, shortAddress(addr), e.ParticipantID, e.Version,
			shortAddress(e.ContentAddress))
	}
	return e, nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ---- reading the log -----------------------------------------------------------

// LoadEvents reads the registry events out of an evidence directory.
//
// Registry events are scattered through the same log as everything else, so
// this walks the segments and keeps the one kind this projection understands.
// It uses the reader's directory scan, which skips a segment that is still
// being created — a registry is read while an appender is running, so that is
// the ordinary case rather than an exotic one.
func LoadEvents(dir string, opts ...evidence.ReadOption) ([]Event, error) {
	var out []Event
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.Kind != evidence.KindRegistry {
			return nil
		}
		// Re-check the record against its own hashes before folding it.
		// Folding unverified bytes would let a tampered log dictate which
		// participants are active — which is the decision the whole gate
		// path rests on.
		if len(rec.Payload) > 0 {
			if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
				return fmt.Errorf("seq %d: payload does not match its recorded hash", h.Seq)
			}
		}
		if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
			return fmt.Errorf("seq %d: chain hash mismatch", h.Seq)
		}
		out = append(out, Event{Seq: h.Seq, Wall: h.TS.Wall(), Payload: rec.Payload})
		return nil
	}, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

// stampValidated records when a version's standing was last established.
func (r *Registry) stampValidated(ev *janusv1.RegistryEvent, wall time.Time) {
	if wall.IsZero() {
		return
	}
	if e, ok := r.resolveEither(ev.GetParticipantId(), ev.GetVersion()); ok {
		e.ValidatedAt = wall
	}
}

// Fold builds a registry from events in log order.
func Fold(events []Event) (*Registry, error) {
	return FoldUntil(events, 0)
}

// FoldUntil builds a registry from events up to and including a sequence.
//
// Passing zero folds everything. Passing the sequence of a SAGA_BEGIN answers
// the question invariant I8 actually asks: was this pin resolvable, and active,
// *when the saga started* — not whether it happens to be active now, which is a
// different and much weaker claim.
func FoldUntil(events []Event, until uint64) (*Registry, error) {
	r := New()
	for _, ev := range events {
		if until > 0 && ev.Seq > until {
			break
		}
		var msg janusv1.RegistryEvent
		if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
			return nil, fmt.Errorf("registry: decode event at seq %d: %w", ev.Seq, err)
		}
		if err := r.Apply(ev.Seq, ev.Wall, &msg); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Replay rebuilds the registry from an evidence directory.
func Replay(dir string, opts ...evidence.ReadOption) (*Registry, error) {
	events, err := LoadEvents(dir, opts...)
	if err != nil {
		return nil, err
	}
	return Fold(events)
}
