// Package saga implements the Janus saga state machine.
//
// The whole package rests on one discipline: Apply is a pure function of
// (current state, next event). No clock, no randomness, no I/O, no network.
// Every nondeterministic input a saga depends on — a model's output, a tool's
// result, a human's approval — has already been turned into a recorded event
// before it reaches here. That is what makes replay trivial rather than
// aspirational (invariant I5): re-running the
// state machine over a recorded event sequence must reproduce the same states,
// and a divergence is a bug rather than a fact of life.
//
// Phase 0 implements the transitions the walking skeleton needs — begin, a PURE
// step, seal, commit — and defines the rest of the machine so that Phase 2
// extends it instead of rewriting it. Transitions that are not yet implemented
// fail loudly rather than being silently ignored.
package saga

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"google.golang.org/protobuf/proto"
)

// Status is the saga lifecycle state.
type Status string

const (
	// StatusCreated means the intent is recorded and participants resolved.
	StatusCreated Status = "CREATED"
	// StatusRunning means steps are executing.
	StatusRunning Status = "RUNNING"
	// StatusGated means the saga is waiting on a validation, policy, frontier,
	// or human decision.
	StatusGated Status = "GATED"
	// StatusSealing means every step is sealed and frontiers are being cleared.
	StatusSealing Status = "SEALING"
	// StatusCommitted is terminal: held effects may be released.
	StatusCommitted Status = "COMMITTED"
	// StatusCompensating means compensations are running in reverse
	// topological order.
	StatusCompensating Status = "COMPENSATING"
	// StatusCompensated is terminal: the saga was undone.
	StatusCompensated Status = "COMPENSATED"
	// StatusQuarantine is terminal until a human intervenes. Janus enters it
	// when automated compensation fails: in a bank a stuck known state beats a
	// guessed clean one.
	StatusQuarantine Status = "QUARANTINE"
)

// StepStatus is the per-step lifecycle.
type StepStatus string

// Step lifecycle states. A step is SEALED once its effect is complete and
// validated, and COMMITTED only when the whole saga commits.
const (
	StepPlanned  StepStatus = "PLANNED"
	StepPrepared StepStatus = "PREPARED"
	StepGated    StepStatus = "GATED"
	StepSealed   StepStatus = "SEALED"
	// StepRefused means the step ran but a gate would not let it through.
	// It is distinct from FAILED because the step itself succeeded, and the
	// distinction decides whether there is anything to undo.
	StepRefused     StepStatus = "REFUSED"
	StepCommitted   StepStatus = "COMMITTED"
	StepFailed      StepStatus = "FAILED"
	StepCompensated StepStatus = "COMPENSATED"
)

// Step is the projected state of one planned unit of work.
type Step struct {
	ID                 string
	Participant        string
	Action             string
	EffectClass        janusv1.EffectClass
	CompensationAction string
	DependsOn          []string
	Status             StepStatus
	// Attempt counts how many times the step has been tried. It starts at one
	// once the step first runs, so Attempt and MaxRetries can be compared
	// directly without an off-by-one.
	Attempt uint32
	// MaxRetries is the budget from the plan. Exhausting it makes the step
	// poison rather than a candidate for another attempt.
	MaxRetries uint32
	// Timeout bounds one attempt, and PreparedAt is when the current attempt
	// started. Both are recorded so that a timeout decision can be made from
	// the log rather than from whenever somebody happened to look.
	Timeout    time.Duration
	PreparedAt time.Time
	// ResultAt is when this attempt's STEP_RESULT was recorded. It is the anchor
	// a PRE_RELEASE deadline counts from (GateOpenedAt): a gate that judges what
	// happened cannot start its clock before there is a result.
	ResultAt time.Time
	Outcome  janusv1.Outcome_Status
	// Touches records which resources the step read or wrote, and when.
	//
	// The mode and the sequence are what make cross-saga commit safety
	// possible: without the mode, every touch would have to be treated as a
	// write and unrelated readers would block each other; without the
	// sequence, there is no way to say which of two sagas reached a resource
	// first, and "first" is the whole basis of the ordering.
	Touches []Touch

	// Compensation tracks the undo of this step, when one is needed.
	Compensation CompensationState
	// CompensatedBy is the id of the step that undid this one, so the log shows
	// which record reversed which.
	CompensatedBy string

	// Child is set when this step delegates its work to a sub-saga
	// rather than carrying it out with a single participant call.
	Child *ChildLink

	// Gates are the requirements this step was admitted under, resolved from
	// the gate policy when the saga began. They live in the projection
	// rather than being looked up when needed, because the policy on disk today
	// is not necessarily the one this saga was admitted under.
	Gates []*janusv1.GateRequirement
	// Facts are the typed values the step declared for its gates to decide on.
	Facts map[string]FactValue
	// Published are the facts this step reported from what it found, once it
	// ran. They are what a later step's gate reads under `result.<id>.<key>`,
	// and they are separate from Facts because the two are worth different
	// amounts: Facts is what the step proposed, Published is what it observed.
	Published map[string]FactValue
	// Answers are the verdicts somebody outside Janus gave on this step's
	// gates — a validator's opinion, a human's approval.
	Answers []GateAnswerRecord
	// Gate is the last verdict recorded against the step.
	Gate GateOutcome
	// PreGatedAttempt is the attempt number the pre-execution gates cleared, or
	// zero if they never have. A step about to make attempt N needs the value N.
	PreGatedAttempt uint32
	// Proposal is what a pre-execution gate escalated on: the facts somebody
	// outside Janus is being asked to answer about, for attempt ProposalAttempt.
	// Under semantics 2 every later verdict on that attempt must be about the
	// same facts, so an answer cannot be counted towards a proposal it was not
	// given for.
	//
	// ProposalAttempt is the marker, not Proposal: a step can escalate on no
	// facts at all, and "asked about nothing" pins as firmly as "asked about
	// 100" — otherwise an approval of a step with no amount could be counted
	// for a pass on a million. Zero is never a live attempt, and semantics 1
	// never sets it.
	Proposal        map[string]FactValue
	ProposalAttempt uint32
	// ProposalSpawn is the sub-saga the escalated proposal would delegate to,
	// attempt-scoped as the prepare will name it, or nil for a proposal that
	// delegates nothing. Under semantics 3 it is part of what was asked about:
	// an approval of a payment is not an approval of that payment handed to a
	// sub-saga that commits on its own. Set only
	// alongside ProposalAttempt, and only under semantics 3.
	ProposalSpawn *ChildLink
}

// ProposalUnderDecision returns the facts a pre-execution gate escalated on
// for the attempt about to be made, and whether there are any.
//
// While it is set, the proposal is not the participant's to change: it is what
// the question was asked about, and it is on the record rather than in the
// memory of whichever process happened to be holding it.
func ProposalUnderDecision(st *Step) (map[string]FactValue, bool) {
	if st.ProposalAttempt == 0 || st.ProposalAttempt != st.Attempt+1 {
		return nil, false
	}
	return st.Proposal, true
}

// ChildLink is what a parent step records about the sub-saga it spawned.
type ChildLink struct {
	SagaID string
	Mode   janusv1.ChildCommitMode
}

// Cascades reports whether the child's fate is bound to the parent's.
func (c *ChildLink) Cascades() bool {
	return c != nil && c.Mode == janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE
}

// ParentLink is what a sub-saga records about the step that spawned it.
type ParentLink struct {
	SagaID string
	StepID string
	Mode   janusv1.ChildCommitMode
}

// Cascades reports whether this saga commits only on its parent's authority.
func (p *ParentLink) Cascades() bool {
	return p != nil && p.Mode == janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE
}

// CompensationState is where a step stands in the undo phase.
type CompensationState string

const (
	// CompNotNeeded means the step left nothing to undo: it never ran, or it
	// was PURE and had no external effect.
	CompNotNeeded CompensationState = ""
	// CompRequired means the step's effect is in the world and must be reversed.
	CompRequired CompensationState = "REQUIRED"
	// CompRunning means the compensating step has been prepared.
	CompRunning CompensationState = "RUNNING"
	// CompDone means the effect has been reversed.
	CompDone CompensationState = "DONE"
	// CompFailed means the reversal failed. This is terminal for the saga: it
	// goes to QUARANTINE rather than continuing to guess.
	CompFailed CompensationState = "FAILED"
	// CompImpossible means the effect cannot be reversed at all, because the
	// step was irreversible by declaration. Reaching this state means a gate
	// let an irreversible effect out and the saga then failed — which is a
	// situation for a human, not for automation.
	CompImpossible CompensationState = "IMPOSSIBLE"
)

// Compensable reports whether this step declares a way to be undone.
func (s *Step) Compensable() bool { return s.CompensationAction != "" }

// State is the saga projection. It is rebuilt from the log rather than stored
// as a second source of truth.
type State struct {
	SagaID   string
	Status   Status
	Mode     string
	IntentID string
	// Intent is the rest of the authorised purpose, which gates decide on.
	Intent IntentDetail
	// GatePolicyVersion is the content address of the gate policy that produced
	// every step's requirement list. It pins the decision to exact bytes rather
	// than to a file that can be edited afterwards.
	GatePolicyVersion string
	// Semantics is the version of these state-machine rules the saga was
	// admitted under, read from SAGA_BEGIN and never inferred. It is what makes
	// "old sagas replay on new versions forever" a property rather than a hope:
	// a fold branches on this, not on what the current build happens to think a
	// transition means.
	Semantics    uint32
	Steps        map[string]*Step
	Order        []string
	LastSeq      uint64
	EventCount   int
	EvidenceRoot []byte
	AbortReason  string
	// QuarantineReason is set when the saga froze because it could not be
	// undone.
	QuarantineReason string
	// Frontiers are the watermarks the saga claimed when it sealed, one per
	// resource it touched. They are recorded so a reader can see what the saga
	// believed about the world at the moment it declared its footprint
	// complete, rather than having to recompute it from a later state.
	Frontiers map[string]uint64
	// Outstanding lists steps whose effects are still in the world at the point
	// the saga was quarantined. It is the handover note to whoever picks it up.
	Outstanding []string
	// Parent is set when this saga is delegated work spawned by another saga's
	// step. Nil means this is a root saga.
	Parent *ParentLink
	// TemplatePin is the saga template this saga is confined to, set only in
	// crystallized mode. Nil for every other saga.
	//
	// It is in the projection because the confinement is enforced *after*
	// admission as well: a step's facts are the model's degrees of freedom and
	// they arrive with the step's result, so whatever checks them has to be able
	// to ask which template this saga pinned — from the log, not from whoever is
	// asking.
	TemplatePin *TemplatePin
	// AuthorizedBy records the parent commit that permitted this saga's commit,
	// so the authority for releasing the effects is in the log rather than in
	// whatever the coordinator remembered at the time.
	AuthorizedBy string
}

// Clone returns a deep copy, so Apply can stay free of aliasing surprises.
func (s State) Clone() State {
	out := s
	out.Steps = make(map[string]*Step, len(s.Steps))
	for id, st := range s.Steps {
		cp := *st
		cp.DependsOn = slices.Clone(st.DependsOn)
		cp.Touches = slices.Clone(st.Touches)
		cp.Gates = cloneGates(st.Gates)
		cp.Facts = maps.Clone(st.Facts)
		cp.Proposal = maps.Clone(st.Proposal)
		cp.Published = maps.Clone(st.Published)
		cp.Gate = st.Gate.clone()
		if st.Answers != nil {
			cp.Answers = make([]GateAnswerRecord, len(st.Answers))
			for i, a := range st.Answers {
				cp.Answers[i] = a.clone()
			}
		}
		if st.Child != nil {
			child := *st.Child
			cp.Child = &child
		}
		if st.ProposalSpawn != nil {
			spawn := *st.ProposalSpawn
			cp.ProposalSpawn = &spawn
		}
		out.Steps[id] = &cp
	}
	out.Intent = s.Intent.clone()
	if s.Parent != nil {
		parent := *s.Parent
		out.Parent = &parent
	}
	out.Order = slices.Clone(s.Order)
	out.EvidenceRoot = slices.Clone(s.EvidenceRoot)
	out.Outstanding = slices.Clone(s.Outstanding)
	out.Frontiers = maps.Clone(s.Frontiers)
	return out
}

// Step returns a step by id.
func (s State) Step(id string) (*Step, bool) {
	st, ok := s.Steps[id]
	return st, ok
}

// TerminalReason is why a saga stopped, or the empty string if it did not stop
// badly.
//
// It lives here rather than in the console because the projection needs it too,
// and the same rule that moved HeldByGate here applies: a predicate about a
// saga's state that two readers compute separately is a predicate that will
// eventually disagree with itself.
func TerminalReason(s State) string {
	switch {
	case s.QuarantineReason != "":
		return s.QuarantineReason
	case s.AbortReason != "":
		return s.AbortReason
	default:
		return ""
	}
}

// TemplatePin names the template version a saga is confined to.
type TemplatePin struct {
	ID      string
	Version string
}

// Terminal reports whether the saga has reached a state it will not leave on
// its own.
func (s State) Terminal() bool {
	switch s.Status {
	case StatusCommitted, StatusCompensated, StatusQuarantine:
		return true
	default:
		return false
	}
}

// Event is one evidence record as the state machine sees it: a kind, a
// sequence number, and an opaque JTP payload.
type Event struct {
	Seq  uint64
	Kind evidence.Kind
	// Wall is the recorded wall-clock time of the event. The state machine uses
	// it only to stamp when an attempt started, so that a later timeout
	// decision is derived from the log rather than from a live clock.
	Wall    time.Time
	Payload []byte
}

// Errors returned by Apply.
var (
	// ErrTransition means the event is not legal in the current state.
	ErrTransition = errors.New("saga: illegal transition")
	// ErrNotAdmitted means a saga was rejected at admission time.
	ErrNotAdmitted = errors.New("saga: not admitted")
	// ErrUnknownStep means an event refers to a step that is not in the plan.
	ErrUnknownStep = errors.New("saga: unknown step")
	// ErrUnsupportedSemantics means a saga was admitted under state-machine
	// rules this build does not implement.
	//
	// It is its own error because the response is different from every other
	// failure here: nothing is wrong with the log, and no retry, repair or
	// rebuild will help. The saga is from the future — written by a newer
	// coordinator — and the only correct action is to run a build that
	// implements those rules. A fold that guessed instead would be re-deciding
	// somebody else's saga under rules it was never admitted under, which is
	// the exact failure this version exists to prevent.
	ErrUnsupportedSemantics = errors.New("saga: unsupported semantics version")
)

// SemanticsVersion is the state-machine rule set this build implements and
// stamps on every saga it admits.
//
// **Bumping it is not a routine act.** It is bumped only when a change makes an
// already-recorded history mean something different — a transition that was
// legal becoming illegal, an admission check gaining teeth, a status being
// reached on different evidence. A change that only adds a new *kind* of
// history, and leaves every recorded one folding exactly as before, is not a
// semantics change and must not bump this: a needless bump splits the corpus in
// two and buys nothing.
//
// The corpus is what catches a bump that should have happened. A change that
// alters what a recorded history means fails a fixture, and the fixture's
// failure is the prompt to decide which of the two this is (see the header of
// corpus.go).
const SemanticsVersion uint32 = 4

// supportedSemantics is every rule set this build can fold.
//
// Version 2 pins what a pre-execution gate escalated on, so the
// answers it collects are about one proposal. Version 3 closes three
// routes around that pin: a step that cleared its gate on no facts may not run
// on some, a proposal's delegation is pinned with its facts, and an answer
// counts only in the phase its requirement is due. Version 4 makes a
// HUMAN requirement a person's: a participant answering one in its own name is
// refused, whatever role it claims, and only the system's expiry of the gate
// after its deadline is recorded there by a non-person. It is deliberately a
// set rather than a `<=` comparison.
// A range would claim this build implements every version below the current
// one, which is a promise about code that does not exist: version 2 arriving
// does not make version 1's branches appear on its own. Membership is asserted
// by whoever writes those branches.
var supportedSemantics = map[uint32]bool{1: true, 2: true, 3: true, 4: true}

// Supports reports whether this build can fold sagas admitted under a version.
func Supports(v uint32) bool { return supportedSemantics[v] }

// Apply folds one event into the state. It never mutates prev.
func Apply(prev State, ev Event) (State, error) {
	next := prev.Clone()
	next.LastSeq = ev.Seq
	next.EventCount++

	switch ev.Kind {
	case evidence.KindSagaBegin:
		return applyBegin(next, ev)
	case evidence.KindStepPrepare:
		return applyStepPrepare(next, ev)
	case evidence.KindStepResult:
		return applyStepResult(next, ev)
	case evidence.KindGateVerdict:
		return applyGateVerdict(next, ev)
	case evidence.KindGateAnswer:
		return applyGateAnswer(next, ev)
	case evidence.KindSealRequest:
		return applySeal(next, ev)
	case evidence.KindCommit:
		return applyCommit(next, ev)
	case evidence.KindAbort:
		return applyAbort(next, ev)
	case evidence.KindCompensate:
		return applyCompensate(next, ev)
	case evidence.KindQuarantine:
		return applyQuarantine(next, ev)

	case evidence.KindDPR, evidence.KindControl, evidence.KindMCPMessage,
		evidence.KindA2AMessage, evidence.KindRecovery, evidence.KindShred,
		evidence.KindClockAttestation,
		// The outbox lifecycle carries a saga id, so these events arrive here,
		// but they belong to the outbox projection (pkg/outbox). The saga state
		// machine deliberately draws no conclusion from them: a saga's status
		// says what was decided, and whether a released effect has yet reached
		// its target is a separate fact with its own record. Folding delivery
		// state into the saga would make the saga's status depend on the
		// reachability of somebody else's endpoint.
		evidence.KindEffectHeld, evidence.KindEffectReleasing,
		evidence.KindEffectDelivered, evidence.KindEffectQuarantined:
		// Evidenced but not state-changing. They still count toward the event
		// total so that replay over the full log lands on the same projection.
		return next, nil

	default:
		return prev, fmt.Errorf("%w: unknown event kind %q", ErrTransition, ev.Kind)
	}
}

func applyBegin(s State, ev Event) (State, error) {
	if s.SagaID != "" {
		return s, fmt.Errorf("%w: SAGA_BEGIN for a saga that already exists", ErrTransition)
	}
	var msg janusv1.SagaBegin
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode SagaBegin: %w", err)
	}
	if msg.GetSagaId() == "" {
		return s, fmt.Errorf("%w: SagaBegin has no saga id", ErrTransition)
	}

	// Absent means 1, and that is a reading of the evidence rather than a
	// default. Every saga recorded before this field existed ran under exactly
	// the rules version 1 names, because version 1 *is* those rules; there is no
	// history for which the zero value is ambiguous.
	s.Semantics = msg.GetSemanticsVersion()
	if s.Semantics == 0 {
		s.Semantics = 1
	}
	if !supportedSemantics[s.Semantics] {
		return s, fmt.Errorf("%w: saga %q was admitted under semantics version %d and this "+
			"build implements %v; it will not be folded under rules it was not admitted "+
			"under", ErrUnsupportedSemantics, msg.GetSagaId(), s.Semantics,
			supportedVersions())
	}

	if p := msg.GetParent(); p != nil {
		switch {
		case p.GetSagaId() == "":
			return s, fmt.Errorf("%w: SagaBegin declares a parent with no saga id", ErrTransition)
		case p.GetStepId() == "":
			return s, fmt.Errorf("%w: SagaBegin declares parent saga %q but not the step that spawned it",
				ErrTransition, p.GetSagaId())
		case p.GetSagaId() == msg.GetSagaId():
			return s, fmt.Errorf("%w: saga %q declares itself as its own parent", ErrTransition, msg.GetSagaId())
		case p.GetCommitMode() == janusv1.ChildCommitMode_CHILD_COMMIT_MODE_UNSPECIFIED:
			// Unspecified cannot default to either value. Defaulting to cascade
			// would promise a reversibility nobody checked at admission;
			// defaulting to autonomous would let a child commit effects its
			// parent believed it still controlled.
			return s, fmt.Errorf("%w: sub-saga %q does not say whether it cascades with its parent "+
				"or commits autonomously", ErrTransition, msg.GetSagaId())
		}
		s.Parent = &ParentLink{
			SagaID: p.GetSagaId(),
			StepID: p.GetStepId(),
			Mode:   p.GetCommitMode(),
		}
	}

	s.SagaID = msg.GetSagaId()
	s.Mode = msg.GetMode()
	s.IntentID = msg.GetIntent().GetIntentId()
	s.Intent = IntentDetail{
		Principal:   msg.GetIntent().GetPrincipal(),
		Originator:  msg.GetIntent().GetOriginator(),
		MandateRef:  msg.GetIntent().GetMandateRef(),
		Scope:       msg.GetIntent().GetScope(),
		Constraints: maps.Clone(msg.GetIntent().GetConstraints()),
	}
	s.GatePolicyVersion = msg.GetGatePolicyVersion()
	if pin := msg.GetTemplatePin(); pin != nil {
		s.TemplatePin = &TemplatePin{ID: pin.GetTemplateId(), Version: pin.GetVersion()}
	}
	s.Status = StatusCreated
	s.Steps = make(map[string]*Step, len(msg.GetPlan()))
	s.Order = make([]string, 0, len(msg.GetPlan()))

	for _, p := range msg.GetPlan() {
		if p.GetStepId() == "" {
			return s, fmt.Errorf("%w: plan contains a step with no id", ErrTransition)
		}
		if _, dup := s.Steps[p.GetStepId()]; dup {
			return s, fmt.Errorf("%w: plan contains step %q twice", ErrTransition, p.GetStepId())
		}
		// Semantics 4: `result.<step>.<key>` names one fact only if a step id
		// cannot contain the separator. With a step "credit.limit" publishing
		// "ok" and a step "credit" publishing "limit.ok", one could shadow the
		// other's finding (the 2026-09-29 audit).
		if s.Semantics >= 4 && strings.Contains(p.GetStepId(), ".") {
			return s, fmt.Errorf("%w: step id %q may not contain '.', which separates a step from "+
				"its finding in result.<step>.<key>", ErrTransition, p.GetStepId())
		}
		s.Steps[p.GetStepId()] = &Step{
			ID:                 p.GetStepId(),
			Participant:        p.GetParticipant(),
			Action:             p.GetAction(),
			MaxRetries:         p.GetMaxRetries(),
			Timeout:            time.Duration(p.GetTimeoutNanos()),
			EffectClass:        p.GetEffectClass(),
			CompensationAction: p.GetCompensationAction(),
			DependsOn:          slices.Clone(p.GetDependsOn()),
			Status:             StepPlanned,
		}
		s.Order = append(s.Order, p.GetStepId())
	}

	for _, g := range msg.GetGatePlan() {
		st, ok := s.Steps[g.GetStepId()]
		if !ok {
			return s, fmt.Errorf("%w: the gate plan covers step %q, which is not in the plan",
				ErrTransition, g.GetStepId())
		}
		if st.Gates != nil {
			return s, fmt.Errorf("%w: the gate plan covers step %q twice", ErrTransition, g.GetStepId())
		}
		st.Gates = cloneGates(g.GetRequire())
		if len(st.Gates) == 0 {
			return s, fmt.Errorf("%w: the gate plan lists step %q with no requirements; a step with "+
				"no gates is left out of the plan rather than listed as exempt",
				ErrTransition, g.GetStepId())
		}
		seen := map[string]bool{}
		for _, r := range st.Gates {
			switch {
			case r.GetId() == "":
				return s, fmt.Errorf("%w: step %q has a gate requirement with no id, so no verdict "+
					"could say it had been decided", ErrTransition, g.GetStepId())
			case seen[r.GetId()]:
				return s, fmt.Errorf("%w: step %q has two gate requirements called %q",
					ErrTransition, g.GetStepId(), r.GetId())
			case r.GetPhase() == janusv1.GatePhase_GATE_PHASE_UNSPECIFIED:
				return s, fmt.Errorf("%w: gate %q on step %q does not say when it is decided",
					ErrTransition, r.GetId(), g.GetStepId())
			}
			seen[r.GetId()] = true
		}
	}

	if err := admit(s); err != nil {
		return s, err
	}
	return s, nil
}

// admit is the admission-time compensability check (invariant I3): a saga is not allowed to start unless every step that touches
// the world declares how it can be undone, or is explicitly classified as
// irreversible so that a gate stands in for compensation.
//
// Doing this at admission rather than at failure time is the point. Discovering
// mid-saga that a step cannot be undone is discovering it too late.
func admit(s State) error {
	for _, id := range s.Order {
		st := s.Steps[id]
		for _, dep := range st.DependsOn {
			if _, ok := s.Steps[dep]; !ok {
				return fmt.Errorf("%w: step %q depends on %q, which is not in the plan", ErrNotAdmitted, id, dep)
			}
		}
		switch st.EffectClass {
		case janusv1.EffectClass_EFFECT_CLASS_UNSPECIFIED:
			return fmt.Errorf("%w: step %q does not declare an effect class", ErrNotAdmitted, id)
		case janusv1.EffectClass_EFFECT_CLASS_PURE:
			// No external effect, so nothing to undo.
		case janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE,
			janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE:
			if !st.Compensable() {
				return fmt.Errorf("%w: step %q is %s but declares no compensation",
					ErrNotAdmitted, id, shortClass(st.EffectClass))
			}
		case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED:
			// Compensation is impossible by definition, so the gate policy is
			// what stands in for it — and a step admitted without one would
			// have neither. This is the second half of invariant I3, and the
			// half that turns "IRREVERSIBLE_GATED" from a label into a
			// constraint: the effect is held until commit, and whether the
			// commit ever comes is a question the gates answer.
			if len(st.Gates) == 0 {
				return fmt.Errorf("%w: step %q is IRREVERSIBLE_GATED and no gate policy covers it, "+
					"so it would have neither a compensation nor anything deciding whether its "+
					"effect may be released", ErrNotAdmitted, id)
			}
			if len(ReleaseGates(st)) == 0 {
				return fmt.Errorf("%w: step %q is IRREVERSIBLE_GATED but every gate covering it is "+
					"decided before it runs; nothing would judge the effect it actually produced",
					ErrNotAdmitted, id)
			}
		case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE:
			// An immediate irreversible effect fires when the step runs, with
			// no commit to hold it back. A saga that cascades with a parent has
			// promised the parent can still withdraw it, and that promise
			// cannot be kept for an effect that is already gone.
			//
			// The same step is admissible in a root saga: there, the party who
			// decides to abort is the same one that decided to run it. A
			// cascade child can be withdrawn by a parent acting on reasons the
			// child never saw, so the two are not the same risk.
			//
			// This is checked before the gate requirement below because it is
			// the more fundamental refusal: a cascade child holding an
			// immediate effect is inadmissible however well gated it is, and
			// telling its author to add a gate would send them down a road that
			// does not lead anywhere.
			if s.Parent.Cascades() {
				return fmt.Errorf("%w: step %q is IRREVERSIBLE_IMMEDIATE, so sub-saga %q cannot cascade "+
					"with parent %q — the parent could not withdraw an effect that has already fired",
					ErrNotAdmitted, id, s.SagaID, s.Parent.SagaID)
			}
			// The effect is in the world the moment the participant returns, so
			// a gate that runs afterwards is a gate on a door already open. The
			// requirement is not merely that gates exist but that at least one
			// of them is decided beforehand.
			if len(PreExecutionGates(st)) == 0 {
				return fmt.Errorf("%w: step %q is IRREVERSIBLE_IMMEDIATE and no gate covering it is "+
					"decided before it runs; its effect cannot be held back afterwards, so a "+
					"gate that judges the result would be judging something already done",
					ErrNotAdmitted, id)
			}
		}
	}
	if err := checkAcyclic(s); err != nil {
		return err
	}
	return nil
}

// checkAcyclic rejects a plan whose dependencies cannot be ordered, since
// compensation runs in reverse topological order and a cycle has none.
func checkAcyclic(s State) error {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[string]int, len(s.Steps))
	var visit func(string, []string) error
	visit = func(id string, path []string) error {
		switch color[id] {
		case black:
			return nil
		case grey:
			return fmt.Errorf("%w: plan has a dependency cycle through %q (%v)", ErrNotAdmitted, id, append(path, id))
		}
		color[id] = grey
		for _, dep := range s.Steps[id].DependsOn {
			if err := visit(dep, append(path, id)); err != nil {
				return err
			}
		}
		color[id] = black
		return nil
	}
	for _, id := range s.Order {
		if err := visit(id, nil); err != nil {
			return err
		}
	}
	return nil
}

func applyStepPrepare(s State, ev Event) (State, error) {
	var msg janusv1.StepPrepare
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode StepPrepare: %w", err)
	}
	// A compensation is a step too, and takes a different path: it undoes a
	// planned step rather than being one.
	if msg.GetCompensates() != "" {
		return applyCompensationPrepare(s, &msg)
	}

	st, ok := s.Steps[msg.GetStepId()]
	if !ok {
		return s, fmt.Errorf("%w: %q", ErrUnknownStep, msg.GetStepId())
	}
	switch s.Status {
	case StatusCreated, StatusRunning:
	default:
		return s, fmt.Errorf("%w: STEP_PREPARE while saga is %s", ErrTransition, s.Status)
	}
	if st.Status != StepPlanned && st.Status != StepFailed {
		return s, fmt.Errorf("%w: STEP_PREPARE for step %q in state %s", ErrTransition, st.ID, st.Status)
	}
	for _, dep := range st.DependsOn {
		if d := s.Steps[dep]; d.Status != StepSealed && d.Status != StepCommitted {
			return s, fmt.Errorf("%w: step %q cannot start while its dependency %q is %s",
				ErrTransition, st.ID, dep, d.Status)
		}
	}

	// A retry has to be inside budget. Without this check a coordinator with a
	// bug, or one that lost track of its own attempts, could retry a step
	// forever — holding the saga's resource frontiers against every other saga
	// while doing so.
	if st.Status == StepFailed {
		if st.Outcome != janusv1.Outcome_STATUS_RETRYABLE_ERROR {
			return s, fmt.Errorf("%w: step %q failed with %s and may not be retried",
				ErrTransition, st.ID, shortOutcome(st.Outcome))
		}
		// Attempt counts attempts made, MaxRetries counts retries allowed, so a
		// step with one retry gets two attempts. Refusing at Attempt >
		// MaxRetries rather than >= is what makes MaxRetries mean what it says.
		if st.Attempt > st.MaxRetries {
			return s, fmt.Errorf("%w: step %q has used all %d of its retries across %d attempts",
				ErrTransition, st.ID, st.MaxRetries, st.Attempt)
		}
	}

	// A step whose policy judges it before it runs may not run until that
	// judgement is on the record for this attempt.
	//
	// This is the check that gives a pre-execution gate teeth. Everything else
	// about gating lives outside the pure core — a policy is read, an
	// expression is evaluated, a verdict is written — and all of it could be
	// skipped by a coordinator with a bug or an instruction it should not have
	// followed. This cannot be skipped: the transition is refused before it is
	// written, so a step that was supposed to be judged first has no legal
	// history in which it ran unjudged.
	if !PreGateCleared(st) {
		return s, fmt.Errorf("%w: step %q has %d gate(s) due before it runs and none has passed for "+
			"attempt %d, so running it now would put its effect in the world ahead of the decision "+
			"that permits it", ErrTransition, st.ID, len(PreExecutionGates(st)), st.Attempt+1)
	}

	facts, err := factsFromProto(msg.GetFacts())
	if err != nil {
		return s, err
	}
	// If a gate has already judged this step, it judged a proposal — and the
	// judgement is only worth anything if what runs is what was judged. A step
	// that cleared its gates showing one amount and then executes with another
	// has not been gated; it has been through a formality.
	//
	// Under semantics 3 "has a gate judged this attempt" is read from the
	// marker the pass set, not from whether the facts it passed on happen to
	// be a map. Under 2, a gate that passed a proposal of no facts left
	// st.Facts nil and this comparison was skipped, so the step could run on
	// 1,000,000 after an approval of nothing.
	judged := st.Facts != nil
	if s.Semantics >= 3 {
		judged = judged || st.PreGatedAttempt == st.Attempt+1
	}
	// Semantics 4: only facts a gate judged for *this* attempt bind it. Before
	// it, st.Facts left over from an earlier attempt's prepare bound a retry of
	// a step no gate had judged, so an ungated step could not correct its
	// facts on retry (the 2026-09-29 audit).
	if s.Semantics >= 4 {
		judged = st.PreGatedAttempt == st.Attempt+1
	}
	if judged && !maps.Equal(st.Facts, facts) {
		return s, fmt.Errorf("%w: step %q is running on facts that differ from the ones its gates "+
			"were shown, so the decision that permitted it was made about something else",
			ErrTransition, st.ID)
	}
	// Semantics 3: a proposal that was escalated is its facts *and* its
	// delegation. An answerer asked about a payment that delegates nothing has
	// not approved the same payment handed to a sub-saga that commits on its
	// own, and before this the delegation lived only in the memory of the
	// daemon holding it, where a re-declaration or a restart could change it.
	if s.Semantics >= 3 && st.ProposalAttempt == st.Attempt+1 &&
		!sameSpawn(st.ProposalSpawn, msg.GetSpawns()) {
		return s, fmt.Errorf("%w: step %q was escalated as a proposal that %s and is running as "+
			"one that %s; the answers recorded for it were given about the first",
			ErrTransition, st.ID, describeSpawn(st.ProposalSpawn), describeSpawn(linkOf(msg.GetSpawns())))
	}

	if spawn := msg.GetSpawns(); spawn != nil {
		if err := recordSpawn(s, st); err != nil {
			return s, err
		}
		child, err := spawnLink(s, st, spawn)
		if err != nil {
			return s, err
		}
		st.Child = child
	}

	st.Facts = facts
	st.Attempt++
	st.Status = StepPrepared
	st.PreparedAt = ev.Wall
	s.Status = StatusRunning
	return s, nil
}

// recordSpawn checks that this step is allowed to delegate its work at all.
func recordSpawn(s State, st *Step) error {
	// A step's effect class is its declaration of what it might later have to
	// undo, and it was admitted on that basis before anybody knew what the
	// sub-saga would contain. A PURE step claims it touches nothing; delegating
	// to a saga that can touch anything makes that claim unverifiable, so the
	// claim is refused rather than quietly widened.
	if st.EffectClass == janusv1.EffectClass_EFFECT_CLASS_PURE {
		return fmt.Errorf("%w: step %q is PURE and may not spawn a sub-saga, because the work it "+
			"delegates is not bounded by anything the plan declared", ErrTransition, st.ID)
	}
	if s.Status == StatusCompensating || s.Terminal() {
		return fmt.Errorf("%w: step %q may not spawn a sub-saga while the saga is %s",
			ErrTransition, st.ID, s.Status)
	}
	return nil
}

// spawnLink validates the declared child and returns the link to record.
func spawnLink(s State, st *Step, spawn *janusv1.ChildSaga) (*ChildLink, error) {
	switch {
	case spawn.GetSagaId() == "":
		return nil, fmt.Errorf("%w: step %q spawns a sub-saga with no saga id", ErrTransition, st.ID)
	case spawn.GetSagaId() == s.SagaID:
		return nil, fmt.Errorf("%w: step %q spawns saga %q, which is the saga it belongs to",
			ErrTransition, st.ID, spawn.GetSagaId())
	case spawn.GetCommitMode() == janusv1.ChildCommitMode_CHILD_COMMIT_MODE_UNSPECIFIED:
		return nil, fmt.Errorf("%w: step %q spawns sub-saga %q without saying whether it cascades",
			ErrTransition, st.ID, spawn.GetSagaId())
	}

	// Two sagas in one family may not share an id, or the log could not say
	// which of them a later event belongs to.
	for _, other := range s.Order {
		if other == st.ID {
			continue
		}
		if c := s.Steps[other].Child; c != nil && c.SagaID == spawn.GetSagaId() {
			return nil, fmt.Errorf("%w: step %q spawns sub-saga %q, which step %q already spawned",
				ErrTransition, st.ID, spawn.GetSagaId(), other)
		}
	}

	if prev := st.Child; prev != nil {
		// This is a retry. It must delegate to a new sub-saga, because the
		// previous one is a saga in its own right that has already run and
		// reached its own conclusion; reusing its id would make the log
		// ambiguous about which attempt an event belongs to.
		if prev.SagaID == spawn.GetSagaId() {
			return nil, fmt.Errorf("%w: step %q is retrying and must spawn a new sub-saga, but names "+
				"%q again", ErrTransition, st.ID, prev.SagaID)
		}
		// The commit mode was the promise made when the step was first
		// admitted. A retry that changed it could turn a withdrawable child
		// into one that commits on its own.
		if prev.Mode != spawn.GetCommitMode() {
			return nil, fmt.Errorf("%w: step %q spawned a %s sub-saga and is retrying with a %s one",
				ErrTransition, st.ID, shortCommitMode(prev.Mode), shortCommitMode(spawn.GetCommitMode()))
		}
	}

	return &ChildLink{SagaID: spawn.GetSagaId(), Mode: spawn.GetCommitMode()}, nil
}

func applyStepResult(s State, ev Event) (State, error) {
	var msg janusv1.StepResult
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode StepResult: %w", err)
	}
	// A result for a compensating step settles the step it undoes, not a step
	// of the plan.
	if target, ok := compensationTargetOf(s, msg.GetStepId()); ok {
		return applyCompensationResult(s, target, msg.GetOutcome().GetStatus())
	}

	st, ok := s.Steps[msg.GetStepId()]
	if !ok {
		return s, fmt.Errorf("%w: %q", ErrUnknownStep, msg.GetStepId())
	}
	if st.Status != StepPrepared {
		return s, fmt.Errorf("%w: STEP_RESULT for step %q in state %s", ErrTransition, st.ID, st.Status)
	}

	published, err := factsFromProto(msg.GetFacts())
	if err != nil {
		return s, err
	}
	st.Published = published

	st.Outcome = msg.GetOutcome().GetStatus()
	// The anchor a PRE_RELEASE deadline counts from (GateOpenedAt). Recorded
	// here because this is the event that puts the step in front of those
	// gates.
	st.ResultAt = ev.Wall
	for _, t := range msg.GetTouches() {
		if t.GetResourceId() == "" {
			return s, fmt.Errorf("%w: step %q reports a touch with no resource id", ErrTransition, st.ID)
		}
		st.Touches = append(st.Touches, Touch{
			Resource: t.GetResourceId(),
			Mode:     t.GetMode(),
			// The evidence sequence of the result that reported the touch is
			// the ordering authority. It comes from the log, so two sagas on
			// different machines still agree on who was first.
			Seq: ev.Seq,
		})
	}

	if st.Outcome != janusv1.Outcome_STATUS_OK {
		st.Status = StepFailed
		return s, nil
	}

	// A PURE step has no external effect, so there is nothing to hold back and
	// it seals immediately. Anything that touches the world waits for a gate,
	// which is what keeps an irreversible effect from escaping before the saga
	// commits (invariant I4). Gates themselves arrive in Phase 3.
	if st.EffectClass == janusv1.EffectClass_EFFECT_CLASS_PURE {
		st.Status = StepSealed
		return s, nil
	}
	st.Status = StepGated
	s.Status = StatusGated
	return s, nil
}

// applyGateAnswer folds an answer from outside Janus into the projection.
//
// The answer does not decide anything by itself — it is an input the next
// verdict reads. What this function enforces is that the input is one the
// policy actually asked for, because everything a composition can check about
// an answer rests on the answer being about the right question.
//
// Each check below closes a way of manufacturing a quorum. Naming a requirement
// the saga was not admitted under would let somebody answer a question nobody
// asked; answering a requirement no human or validator decides would let an
// approval satisfy a schema check; answering twice would let one person be two
// approvers; and answering a step that has already sealed would let an approval
// arrive for something already done.
func applyGateAnswer(s State, ev Event) (State, error) {
	var msg janusv1.GateAnswer
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode GateAnswer: %w", err)
	}
	st, ok := s.Steps[msg.GetStepId()]
	if !ok {
		return s, fmt.Errorf("%w: %q", ErrUnknownStep, msg.GetStepId())
	}

	switch st.Status {
	case StepPlanned, StepFailed, StepGated:
	default:
		return s, fmt.Errorf("%w: an answer arrived for step %q, which is %s and no longer waiting "+
			"on anybody", ErrTransition, st.ID, st.Status)
	}

	req := requirementByID(st, msg.GetRequirementId())
	if req == nil {
		return s, fmt.Errorf("%w: the answer names requirement %q on step %q, which the saga was "+
			"not admitted under", ErrTransition, msg.GetRequirementId(), st.ID)
	}
	if !External(req) {
		return s, fmt.Errorf("%w: requirement %q on step %q is a %s gate, which Janus decides "+
			"itself; an answer to it would be somebody voting on a computation",
			ErrTransition, req.GetId(), st.ID, shortGate(req.GetGate()))
	}

	switch msg.GetVerdict() {
	case janusv1.Verdict_VERDICT_PASS, janusv1.Verdict_VERDICT_FAIL:
	default:
		// An answerer says yes or no. Escalation is what the composition does
		// while it waits for one, not something an answer can express.
		return s, fmt.Errorf("%w: the answer to %q on step %q is neither a yes nor a no",
			ErrTransition, req.GetId(), st.ID)
	}

	actorID, human := actorIdentity(msg.GetActor())
	if actorID == "" {
		return s, fmt.Errorf("%w: the answer to %q on step %q names nobody, so there is no way to "+
			"tell whether it came from somebody entitled to give it",
			ErrTransition, req.GetId(), st.ID)
	}
	// Semantics 4: a HUMAN requirement is answered by a person. Before it the
	// check counted any answer that claimed a role the policy names, so a gated
	// agent -- or the step's own tool -- could satisfy a four-eyes approval by
	// answering in its own name (the 2026-09-29 audit). The one
	// non-person answer a person's gate takes is the system's refusal on the
	// deadline's behalf, and only once that deadline has passed.
	if s.Semantics >= 4 && req.GetGate() == janusv1.GateType_GATE_TYPE_HUMAN && !human {
		expiry := GateAnswerRecord{ActorID: actorID, Verdict: msg.GetVerdict(), Wall: ev.Wall}
		if !IsExpiry(expiry, req, GateOpenedAt(st, PhaseUnderDecision(st))) {
			return s, fmt.Errorf("%w: requirement %q on step %q is answered by a person, and %q "+
				"is a participant; an agent or a tool that could answer a person's approval in "+
				"its own name would be authoring its own permission",
				ErrTransition, req.GetId(), st.ID, actorID)
		}
	}

	// Semantics 3: an answer counts in the phase its requirement is due in.
	// Under 2 an answer to a release requirement was accepted while the step
	// had not yet run, and was then counted when the release gate decided the
	// same attempt -- an approval of what a step produced, given before it had
	// produced anything.
	phase := PhaseUnderDecision(st)
	if s.Semantics >= 3 && req.GetPhase() != phase {
		return s, fmt.Errorf("%w: the answer to %q on step %q is for a %s requirement and the "+
			"step is at %s; an answer given before its question is due would be counted for "+
			"something the answerer never saw", ErrTransition, req.GetId(), st.ID,
			shortPhase(req.GetPhase()), shortPhase(phase))
	}
	// Semantics 3: before a pre-execution gate escalates there is no question,
	// and an answer is bound to the proposal it was asked about. An answer
	// recorded before any proposal was put to it is about nothing, and would be
	// counted for whatever the gate later passed (found in review).
	if s.Semantics >= 3 && phase == janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION {
		if _, asked := ProposalUnderDecision(st); !asked {
			return s, fmt.Errorf("%w: the answer to %q on step %q arrived before any proposal "+
				"was put to it; an answer is about the proposal it was asked about, and there "+
				"was none yet", ErrTransition, req.GetId(), st.ID)
		}
	}

	// The phase, and therefore the attempt being decided, comes from where the
	// step has got to rather than from the message. An answer that could pick
	// its own attempt could approve a future retry in advance.
	want := AttemptUnderDecision(st, phase)
	if msg.GetAttempt() != want {
		return s, fmt.Errorf("%w: the answer to %q on step %q is for attempt %d, and attempt %d is "+
			"the one being decided", ErrTransition, req.GetId(), st.ID, msg.GetAttempt(), want)
	}

	for _, prior := range st.Answers {
		if prior.RequirementID == req.GetId() && prior.Attempt == want && prior.ActorID == actorID {
			return s, fmt.Errorf("%w: %q has already answered %q on step %q for attempt %d; one "+
				"answerer counted twice is a quorum of one wearing two hats",
				ErrTransition, actorID, req.GetId(), st.ID, want)
		}
	}

	st.Answers = append(st.Answers, GateAnswerRecord{
		RequirementID: req.GetId(),
		Attempt:       want,
		ActorID:       actorID,
		Human:         human,
		Verdict:       msg.GetVerdict(),
		Reason:        msg.GetReason(),
		Roles:         slices.Clone(msg.GetRoles()),
		AuthRef:       msg.GetAuthRef(),
		Seq:           ev.Seq,
		Wall:          ev.Wall,
	})
	return s, nil
}

// actorIdentity reduces an actor to the one name separation of duty compares.
func actorIdentity(a *janusv1.Actor) (id string, human bool) {
	if s := a.GetHumanSubject(); s != "" {
		return s, true
	}
	return a.GetParticipant().GetId(), false
}

func requirementByID(st *Step, id string) *janusv1.GateRequirement {
	for _, r := range st.Gates {
		if r.GetId() == id {
			return r
		}
	}
	return nil
}

func shortGate(g janusv1.GateType) string {
	return strings.TrimPrefix(g.String(), "GATE_TYPE_")
}

// applyGateVerdict folds a composite gate decision into the projection.
//
// A step is judged at two moments and the phase is not carried in the message:
// it is implied by where the step has got to. A verdict on a step that has not
// run yet is a judgement on a proposal; a verdict on a step waiting in GATED is
// a judgement on what the step produced. Deriving it from the step's state
// rather than trusting a field means a verdict cannot claim to be the cheap
// kind while being applied as the expensive one.
func applyGateVerdict(s State, ev Event) (State, error) {
	var msg janusv1.GateVerdict
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode GateVerdict: %w", err)
	}
	st, ok := s.Steps[msg.GetStepId()]
	if !ok {
		return s, fmt.Errorf("%w: %q", ErrUnknownStep, msg.GetStepId())
	}
	if msg.GetVerdict() == janusv1.Verdict_VERDICT_UNSPECIFIED {
		return s, fmt.Errorf("%w: gate verdict for step %q is unspecified", ErrTransition, st.ID)
	}

	facts, err := factsFromProto(msg.GetFacts())
	if err != nil {
		return s, err
	}

	switch st.Status {
	case StepPlanned, StepFailed:
		return applyPreExecutionVerdict(s, st, &msg, facts)
	case StepGated:
		return applyReleaseVerdict(s, st, &msg, facts)
	default:
		return s, fmt.Errorf("%w: GATE_VERDICT for step %q in state %s", ErrTransition, st.ID, st.Status)
	}
}

// applyPreExecutionVerdict handles a judgement made before the step runs.
func applyPreExecutionVerdict(s State, st *Step, msg *janusv1.GateVerdict,
	facts map[string]FactValue) (State, error) {

	due := requirementIDs(st, janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION)
	if len(due) == 0 {
		return s, fmt.Errorf("%w: step %q has no gates due before it runs, so there was nothing "+
			"for this verdict to decide", ErrTransition, st.ID)
	}
	if err := coversAll(st, msg, due, "before it runs"); err != nil {
		return s, err
	}

	// Semantics 2: a decision about an attempt is about one proposal. Under 1
	// an escalation on one amount could be followed, after the answers came
	// in, by a pass on another — the answers were bound to the attempt and the
	// attempt was not bound to anything, so an approval given for 100 was
	// counted for 1,000,000.
	if s.Semantics >= 2 {
		if pinned, ok := ProposalUnderDecision(st); ok && !maps.Equal(pinned, facts) {
			return s, fmt.Errorf("%w: the gate on step %q escalated attempt %d on one set of "+
				"facts and this verdict decides it on another; the answers recorded for it "+
				"were given about the first", ErrTransition, st.ID, st.Attempt+1)
		}
		if msg.GetVerdict() == janusv1.Verdict_VERDICT_ESCALATE {
			st.Proposal = facts
			st.ProposalAttempt = st.Attempt + 1
			if s.Semantics >= 3 {
				st.ProposalSpawn = linkOf(msg.GetSpawns())
			}
		}
	}

	st.Gate = outcomeOf(msg)
	switch msg.GetVerdict() {
	case janusv1.Verdict_VERDICT_PASS:
		// The step is still PLANNED: passing a pre-execution gate is permission
		// to run, not a result. What changes is that the attempt about to be
		// made is now one somebody decided to allow, and the facts it was
		// allowed on are pinned so the attempt cannot quietly differ.
		st.Facts = facts
		st.PreGatedAttempt = st.Attempt + 1
		if s.Status == StatusGated {
			s.Status = StatusRunning
		}
	case janusv1.Verdict_VERDICT_FAIL:
		// Refused before running, so there is nothing of this step's to undo —
		// but earlier steps may have left effects behind, which is what
		// beginUnwind works out.
		st.Status = StepRefused
		s = beginUnwind(s, gateReason(msg))
	case janusv1.Verdict_VERDICT_ESCALATE:
		s.Status = StatusGated
	}
	return s, nil
}

// applyReleaseVerdict handles a judgement on what the step produced.
func applyReleaseVerdict(s State, st *Step, msg *janusv1.GateVerdict,
	facts map[string]FactValue) (State, error) {

	due := requirementIDs(st, janusv1.GatePhase_GATE_PHASE_PRE_RELEASE)
	if err := coversAll(st, msg, due, "before its effect is released"); err != nil {
		return s, err
	}
	// A release verdict judges the step that ran. Facts that differ from the
	// ones the step declared would mean the gate was shown something else.
	if len(facts) > 0 && !maps.Equal(st.Facts, facts) {
		return s, fmt.Errorf("%w: the gate on step %q decided on facts the step did not declare",
			ErrTransition, st.ID)
	}

	st.Gate = outcomeOf(msg)
	switch msg.GetVerdict() {
	case janusv1.Verdict_VERDICT_PASS:
		st.Status = StepSealed
		s.Status = StatusRunning
	case janusv1.Verdict_VERDICT_FAIL:
		// Refused, not failed. Whether the refusal leaves anything behind
		// depends on the effect class, which needsCompensation decides.
		st.Status = StepRefused
		s = beginUnwind(s, gateReason(msg))
	case janusv1.Verdict_VERDICT_ESCALATE:
		s.Status = StatusGated
	}
	return s, nil
}

// coversAll refuses a verdict that does not account for every requirement due.
//
// Without it a composite PASS would be cheaper than the checks it claims to
// summarise: a coordinator could evaluate the schema gate, say nothing about
// the risk limit, and record a pass. What this cannot detect is a verdict that
// names every requirement and reports the wrong answer for one — that needs the
// decision re-derived from the recorded facts, which is what pkg/gate's audit
// does. Structure here, meaning there.
func coversAll(st *Step, msg *janusv1.GateVerdict, due []string, when string) error {
	// An escalation is a statement that no decision was reached yet, so it is
	// not required to have covered anything.
	if msg.GetVerdict() == janusv1.Verdict_VERDICT_ESCALATE {
		return nil
	}
	// A refusal needs only one requirement to have refused. Demanding the full
	// set would mean asking a human to approve a payment whose schema is
	// already malformed.
	if msg.GetVerdict() == janusv1.Verdict_VERDICT_FAIL {
		if len(msg.GetDecided()) == 0 {
			return fmt.Errorf("%w: the gate on step %q refuses without naming a requirement that "+
				"refused", ErrTransition, st.ID)
		}
		return knownIDs(st, msg)
	}

	if err := knownIDs(st, msg); err != nil {
		return err
	}
	decided := slices.Clone(msg.GetDecided())
	slices.Sort(decided)
	decided = slices.Compact(decided)
	if !slices.Equal(decided, due) {
		missing := make([]string, 0, len(due))
		for _, id := range due {
			if !slices.Contains(decided, id) {
				missing = append(missing, id)
			}
		}
		return fmt.Errorf("%w: step %q passes %d of the %d gate(s) due %s; %v %s not decided, and a "+
			"step cannot be let through on the checks somebody chose to run",
			ErrTransition, st.ID, len(decided), len(due), when, missing, plural(len(missing)))
	}
	return nil
}

// knownIDs refuses a verdict citing a requirement the step was not admitted
// under, which would otherwise let a coordinator satisfy coverage by inventing
// names.
func knownIDs(st *Step, msg *janusv1.GateVerdict) error {
	for _, id := range msg.GetDecided() {
		if !slices.ContainsFunc(st.Gates, func(r *janusv1.GateRequirement) bool {
			return r.GetId() == id
		}) {
			return fmt.Errorf("%w: the gate on step %q cites requirement %q, which the saga was not "+
				"admitted under", ErrTransition, st.ID, id)
		}
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

func outcomeOf(msg *janusv1.GateVerdict) GateOutcome {
	return GateOutcome{
		Verdict:       msg.GetVerdict(),
		Gate:          msg.GetGate(),
		Reason:        msg.GetReason(),
		PolicyVersion: msg.GetPolicyVersion(),
		DPRRef:        msg.GetDprRef(),
		Decided:       slices.Clone(msg.GetDecided()),
	}
}

func gateReason(msg *janusv1.GateVerdict) string {
	if msg.GetReason() == "" {
		return "gate " + msg.GetGate().String() + " refused"
	}
	return "gate " + msg.GetGate().String() + " refused: " + msg.GetReason()
}

func applySeal(s State, ev Event) (State, error) {
	var msg janusv1.SealRequest
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode SealRequest: %w", err)
	}
	if s.Status != StatusRunning && s.Status != StatusCreated {
		return s, fmt.Errorf("%w: SEAL_REQUEST while saga is %s", ErrTransition, s.Status)
	}
	for _, id := range s.Order {
		if st := s.Steps[id]; st.Status != StepSealed {
			return s, fmt.Errorf("%w: cannot seal while step %q is %s", ErrTransition, id, st.Status)
		}
	}

	// Sealing declares the saga's footprint, so the claims have to cover it.
	// A claim set that misses a resource would seal a footprint smaller than
	// the one the saga actually has, and the commit-safety check downstream
	// would then be asking about the wrong set of resources — passing not
	// because the saga is clear but because nobody looked.
	claimed := make(map[string]struct{}, len(msg.GetFrontiers()))
	for _, c := range msg.GetFrontiers() {
		if c.GetResourceId() == "" {
			return s, fmt.Errorf("%w: SEAL_REQUEST carries a frontier claim with no resource id", ErrTransition)
		}
		claimed[c.GetResourceId()] = struct{}{}
	}
	if len(claimed) > 0 {
		for _, r := range TouchedResources(s) {
			if _, ok := claimed[r]; !ok {
				return s, fmt.Errorf("%w: SEAL_REQUEST does not claim %q, which this saga touched",
					ErrTransition, r)
			}
		}
	}

	s.Status = StatusSealing
	s.Frontiers = make(map[string]uint64, len(msg.GetFrontiers()))
	for _, c := range msg.GetFrontiers() {
		s.Frontiers[c.GetResourceId()] = c.GetLastSealedSeq()
	}
	return s, nil
}

func applyCommit(s State, ev Event) (State, error) {
	var msg janusv1.Commit
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode Commit: %w", err)
	}
	if s.Status != StatusSealing {
		return s, fmt.Errorf("%w: COMMIT while saga is %s (a saga must seal before it commits)", ErrTransition, s.Status)
	}
	if err := checkCommitAuthority(s, msg.GetAuthorizedBy()); err != nil {
		return s, err
	}
	for _, id := range s.Order {
		s.Steps[id].Status = StepCommitted
	}
	s.Status = StatusCommitted
	s.AuthorizedBy = msg.GetAuthorizedBy()
	s.EvidenceRoot = slices.Clone(msg.GetEvidenceRoot())
	return s, nil
}

// checkCommitAuthority decides whether this saga is allowed to commit on the
// authority the commit record claims.
//
// A cascade sub-saga holds effects that belong to its parent's transaction, so
// releasing them without the parent's commit would break the one promise
// cascade makes. The check is deliberately symmetric: a saga that needs no
// authority may not carry one either, because a coordinator that supplies an
// authorisation to the wrong saga has confused two transactions, and the
// failure that follows should be a refused commit rather than a released
// effect nobody meant to release.
func checkCommitAuthority(s State, authorizedBy string) error {
	switch {
	case s.Parent.Cascades():
		if authorizedBy == "" {
			return fmt.Errorf("%w: sub-saga %q cascades with parent %q and may not commit on its own "+
				"authority", ErrTransition, s.SagaID, s.Parent.SagaID)
		}
		if authorizedBy != s.Parent.SagaID {
			return fmt.Errorf("%w: sub-saga %q cascades with parent %q but its commit claims authority "+
				"from %q", ErrTransition, s.SagaID, s.Parent.SagaID, authorizedBy)
		}
	case authorizedBy != "":
		who := "a root saga"
		if s.Parent != nil {
			who = fmt.Sprintf("an autonomous sub-saga of %q", s.Parent.SagaID)
		}
		return fmt.Errorf("%w: saga %q is %s and commits on its own authority, but its commit claims "+
			"authority from %q", ErrTransition, s.SagaID, who, authorizedBy)
	}
	return nil
}

func shortCommitMode(m janusv1.ChildCommitMode) string {
	const prefix = "CHILD_COMMIT_MODE_"
	n := m.String()
	if len(n) > len(prefix) {
		return n[len(prefix):]
	}
	return n
}

func applyAbort(s State, ev Event) (State, error) {
	var msg janusv1.Abort
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode Abort: %w", err)
	}
	if s.Terminal() {
		return s, fmt.Errorf("%w: ABORT of a saga that is already %s", ErrTransition, s.Status)
	}
	s.AbortReason = msg.GetReasonRef()

	// Anything that already touched the world has to be undone; a saga that
	// never got that far is simply finished.
	return beginUnwind(s, msg.GetReasonRef()), nil
}

// Replay folds a sequence of events into a state. This is the definition of
// determinism of record: the same events must always
// produce the same state.
func Replay(events []Event) (State, error) {
	var s State
	for i, ev := range events {
		next, err := Apply(s, ev)
		if err != nil {
			return s, fmt.Errorf("replay event %d (seq %d, %s): %w", i, ev.Seq, ev.Kind, err)
		}
		s = next
	}
	return s, nil
}

func shortClass(c janusv1.EffectClass) string {
	name := c.String()
	const prefix = "EFFECT_CLASS_"
	if len(name) > len(prefix) {
		return name[len(prefix):]
	}
	return name
}

// supportedVersions lists the supported rule sets in order, for an error that
// tells the reader which build they need rather than only that this is not it.
func supportedVersions() []uint32 {
	out := make([]uint32, 0, len(supportedSemantics))
	for v := range supportedSemantics {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}
