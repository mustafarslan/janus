package saga

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"google.golang.org/protobuf/proto"
)

// What the saga projection holds about gates.
//
// The state machine does not decide gate verdicts — pkg/gate does that, from a
// policy, outside the pure core. What lives here is everything the machine has
// to enforce structurally: which requirements a step was admitted under, which
// of them have been decided and for which attempt, and what the last verdict
// was.
//
// The division is the same one that keeps replay honest everywhere else in this
// package. Deciding is nondeterministic — it reads a policy, and later it will
// wait on a human. Recording and enforcing are pure. So the decision arrives as
// an event and the machine's job is to refuse any history in which a step got
// further than its requirements allow.

// FactValue is one typed input a gate reasons about, as the projection holds
// it. It mirrors janusv1.Fact; the projection keeps a plain Go value so that
// cloning a state stays a copy rather than a proto walk.
type FactValue struct {
	Type   janusv1.FactType
	Text   string
	Number int64
	Flag   bool
}

// IntentDetail is the authorised purpose the saga roots in, kept in the
// projection because gates decide on it: a policy that says "only a payments
// mandate may move money" is reading these fields.
type IntentDetail struct {
	Principal   string
	Originator  string
	MandateRef  string
	Scope       string
	Constraints map[string]string
}

func (d IntentDetail) clone() IntentDetail {
	d.Constraints = maps.Clone(d.Constraints)
	return d
}

// GateOutcome is the last gate decision recorded against a step.
type GateOutcome struct {
	Verdict janusv1.Verdict
	Gate    janusv1.GateType
	Reason  string
	// PolicyVersion is the content address of the policy that decided, and
	// DPRRef points at the record holding each individual check's result.
	PolicyVersion string
	DPRRef        string
	// Decided lists the requirement ids the verdict accounted for.
	Decided []string
}

func (g GateOutcome) clone() GateOutcome {
	g.Decided = slices.Clone(g.Decided)
	return g
}

// Recorded reports whether any verdict has been recorded.
func (g GateOutcome) Recorded() bool {
	return g.Verdict != janusv1.Verdict_VERDICT_UNSPECIFIED
}

// GatesFor returns a step's requirements for one phase, in policy order.
func GatesFor(st *Step, phase janusv1.GatePhase) []*janusv1.GateRequirement {
	var out []*janusv1.GateRequirement
	for _, r := range st.Gates {
		if r.GetPhase() == phase {
			out = append(out, r)
		}
	}
	return out
}

// PreExecutionGates returns the requirements decided before the step runs.
func PreExecutionGates(st *Step) []*janusv1.GateRequirement {
	return GatesFor(st, janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION)
}

// ReleaseGates returns the requirements decided on what the step produced.
func ReleaseGates(st *Step) []*janusv1.GateRequirement {
	return GatesFor(st, janusv1.GatePhase_GATE_PHASE_PRE_RELEASE)
}

// requirementIDs lists the ids due in a phase, sorted, for comparing against
// what a verdict claims to have decided.
func requirementIDs(st *Step, phase janusv1.GatePhase) []string {
	var out []string
	for _, r := range GatesFor(st, phase) {
		out = append(out, r.GetId())
	}
	slices.Sort(out)
	return out
}

// PreGateCleared reports whether the step's pre-execution gates have passed for
// the attempt it is about to make.
//
// The answer is per attempt rather than per step. A retry runs the participant
// again, possibly with different arguments, and a gate that cleared the first
// attempt has said nothing about the second — treating one pass as permanent
// would let a step that was refused on its facts sneak through by failing once
// and trying again.
func PreGateCleared(st *Step) bool {
	if len(PreExecutionGates(st)) == 0 {
		return true
	}
	return st.PreGatedAttempt == st.Attempt+1
}

// cloneGates deep-copies a step's requirement list. They are proto messages
// because they are recorded verbatim in SAGA_BEGIN and read back unchanged;
// converting them to Go structs and back would introduce a translation nobody
// needs and a place for the two forms to drift.
func cloneGates(in []*janusv1.GateRequirement) []*janusv1.GateRequirement {
	if in == nil {
		return nil
	}
	out := make([]*janusv1.GateRequirement, 0, len(in))
	for _, r := range in {
		out = append(out, proto.Clone(r).(*janusv1.GateRequirement))
	}
	return out
}

// DescribeFacts renders facts as sorted "key=value" strings, for a message a
// person reads.
func DescribeFacts(in map[string]FactValue) []string { return describeFactValues(in) }

// describeFactValues renders a step's declared facts for the replay corpus, in
// sorted order so a fixture diff shows a changed value rather than a changed
// map iteration.
func describeFactValues(in map[string]FactValue) []string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		v := in[k]
		switch v.Type {
		case janusv1.FactType_FACT_TYPE_TEXT:
			out = append(out, fmt.Sprintf("%s=%q", k, v.Text))
		case janusv1.FactType_FACT_TYPE_NUMBER:
			out = append(out, fmt.Sprintf("%s=%d", k, v.Number))
		case janusv1.FactType_FACT_TYPE_FLAG:
			out = append(out, fmt.Sprintf("%s=%t", k, v.Flag))
		}
	}
	return out
}

// GateAnswerRecord is one answer from outside — a validator's opinion or a
// human's approval — as the projection holds it.
//
// The projection keeps every answer rather than a tally. A quorum is not the
// only thing a policy asks about: separation of duty is a question about *who*
// answered, and an answer from somebody not entitled to give one has to be
// visible in order to be refused. A count would have thrown all of that away.
type GateAnswerRecord struct {
	RequirementID string
	// Attempt is the step attempt this answers. An approval is for one attempt,
	// not for the step.
	Attempt uint32
	// ActorID is the human subject or the participant id, whichever answered.
	ActorID string
	// Human distinguishes a person from a validator participant, because the
	// two are held to different rules.
	Human   bool
	Verdict janusv1.Verdict
	Reason  string
	// Roles are what the authenticating layer asserted the actor holds. Janus
	// checks the claim; it does not establish it (see HumanCheck in gate.proto).
	Roles []string
	// AuthRef points at the authentication evidence.
	AuthRef string
	// Seq is where the answer sits in the log, so two answers can be ordered.
	Seq uint64
	// Wall is when the answer was recorded. It is what makes an expiry
	// checkable rather than asserted: audit compares it against the recorded
	// time the gate's decision window opened, so a coordinator that expired a
	// gate early to make an inconvenient approval unnecessary leaves a finding
	// rather than an ordinary timeout.
	Wall time.Time
}

func (a GateAnswerRecord) clone() GateAnswerRecord {
	a.Roles = slices.Clone(a.Roles)
	return a
}

// HoldsRole reports whether the actor was asserted to hold any of the roles.
// No required roles means the question does not arise.
//
// "Asserted" is load-bearing: these are the roles the answer records, which is
// exactly as trustworthy as whatever wrote it. A
// gate that wants more asks for an established identity, and then compares
// against the roles an assertion proved rather than these.
func (a GateAnswerRecord) HoldsRole(required []string) bool {
	return HoldsAnyRole(a.Roles, required)
}

// HoldsAnyRole is the comparison itself, over whichever set of roles the caller
// has decided to believe. One definition, so that a gate checking established
// roles and a gate checking asserted ones cannot drift into comparing them
// differently.
func HoldsAnyRole(held, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, r := range required {
		if slices.Contains(held, r) {
			return true
		}
	}
	return false
}

// AnswersFor returns the answers recorded against one requirement on one
// attempt, in log order.
func AnswersFor(st *Step, requirementID string, attempt uint32) []GateAnswerRecord {
	var out []GateAnswerRecord
	for _, a := range st.Answers {
		if a.RequirementID == requirementID && a.Attempt == attempt {
			out = append(out, a)
		}
	}
	return out
}

// External reports whether a requirement is decided by somebody outside Janus,
// and therefore waits rather than resolving on the spot.
func External(r *janusv1.GateRequirement) bool {
	switch r.GetGate() {
	case janusv1.GateType_GATE_TYPE_HUMAN, janusv1.GateType_GATE_TYPE_VALIDATOR:
		return true
	default:
		return false
	}
}

// AttemptUnderDecision is the step attempt a gate at this phase is judging.
//
// Before the step runs it is the attempt about to be made; afterwards it is the
// one that was. Both the state machine and the checks derive it the same way,
// from the step's own state, so an answer cannot claim to be about a different
// attempt than the one being decided.
func AttemptUnderDecision(st *Step, phase janusv1.GatePhase) uint32 {
	if phase == janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION {
		return st.Attempt + 1
	}
	return st.Attempt
}

// PhaseUnderDecision is the phase a step is currently being judged at, derived
// from where it has got to.
func PhaseUnderDecision(st *Step) janusv1.GatePhase {
	if st.Status == StepPlanned || st.Status == StepFailed {
		return janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION
	}
	return janusv1.GatePhase_GATE_PHASE_PRE_RELEASE
}

// FactsUnderDecision returns the facts a step's gate is deciding at a phase:
// the proposal an escalation pinned before the step runs, or what the
// step declared when it prepared, at release.
//
// It is what an answerer is shown. Before semantics 2 a step waiting at a
// pre-execution gate had nothing here — the facts were in the escalation's own
// record and nowhere on the projection — so a person approving it, or a
// validator asked about it, saw a question with the numbers blanked out.
func FactsUnderDecision(st *Step, phase janusv1.GatePhase) map[string]FactValue {
	if phase == janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION {
		if pinned, ok := ProposalUnderDecision(st); ok {
			return pinned
		}
		return nil
	}
	return st.Facts
}

// PublishedFactPrefix is the namespace a step's published facts appear under,
// keyed by the step that found them: `result.<step_id>.<key>`.
const PublishedFactPrefix = "result."

// ReservedFactNamespaces are the prefixes Janus derives facts under. A step may
// not declare a fact in any of them.
var ReservedFactNamespaces = []string{"saga.", "step.", "intent.", PublishedFactPrefix}

func reservedNamespace(key string) (string, bool) {
	for _, ns := range ReservedFactNamespaces {
		if strings.HasPrefix(key, ns) {
			return ns, true
		}
	}
	return "", false
}

// factsToProto renders declared facts for recording, in sorted key order so two
// coordinators holding the same facts write the same bytes — which is what lets
// the state machine compare a step's facts against the ones its gate was shown.
func factsToProto(in map[string]FactValue) []*janusv1.Fact {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	out := make([]*janusv1.Fact, 0, len(keys))
	for _, k := range keys {
		v := in[k]
		f := &janusv1.Fact{Key: k}
		switch v.Type {
		case janusv1.FactType_FACT_TYPE_TEXT:
			f.Value = &janusv1.Fact_Text{Text: v.Text}
		case janusv1.FactType_FACT_TYPE_NUMBER:
			f.Value = &janusv1.Fact_Number{Number: v.Number}
		case janusv1.FactType_FACT_TYPE_FLAG:
			f.Value = &janusv1.Fact_Flag{Flag: v.Flag}
		}
		out = append(out, f)
	}
	return out
}

// factsFromProto converts recorded facts into the projection's form, refusing a
// fact that declares no type.
func factsFromProto(in []*janusv1.Fact) (map[string]FactValue, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]FactValue, len(in))
	for _, f := range in {
		if f.GetKey() == "" {
			return nil, fmt.Errorf("%w: a step declares a fact with no name", ErrTransition)
		}
		if _, dup := out[f.GetKey()]; dup {
			return nil, fmt.Errorf("%w: a step declares the fact %q twice, so a gate reading it "+
				"would decide on whichever copy it happened to see", ErrTransition, f.GetKey())
		}
		// Janus derives facts of its own — what the step is, who authorised the
		// saga — under reserved prefixes. A step that could declare a fact in
		// one of those namespaces could tell a gate it was a different step,
		// which is the whole ballgame.
		if ns, reserved := reservedNamespace(f.GetKey()); reserved {
			return nil, fmt.Errorf("%w: the fact %q is in the reserved %q namespace, which only "+
				"Janus may write; a step that could declare it could tell a gate it was some "+
				"other step", ErrTransition, f.GetKey(), ns)
		}
		switch v := f.GetValue().(type) {
		case *janusv1.Fact_Text:
			out[f.GetKey()] = FactValue{Type: janusv1.FactType_FACT_TYPE_TEXT, Text: v.Text}
		case *janusv1.Fact_Number:
			out[f.GetKey()] = FactValue{Type: janusv1.FactType_FACT_TYPE_NUMBER, Number: v.Number}
		case *janusv1.Fact_Flag:
			out[f.GetKey()] = FactValue{Type: janusv1.FactType_FACT_TYPE_FLAG, Flag: v.Flag}
		default:
			// A fact with no value is not an empty string: it is a step
			// declaring a name and saying nothing about it, which a gate would
			// then have to guess at.
			return nil, fmt.Errorf("%w: the fact %q carries no value, so there is nothing for a "+
				"gate to decide on", ErrTransition, f.GetKey())
		}
	}
	return out, nil
}

// FactsFromProto converts facts as they arrive on the wire into the state
// machine's own type.
//
// It is exported because Phase 4 introduced a caller outside this package: a
// participant reporting a step's result over the network sends proto facts, and
// something has to turn them into the values a gate decides on. The conversion
// stays here, next to the one going the other way, so the two cannot drift.
func FactsFromProto(in []*janusv1.Fact) (map[string]FactValue, error) {
	return factsFromProto(in)
}

// FactsToProto converts facts into the form they take on the wire and in the
// log. It is the inverse of FactsFromProto, and exported for the same reason:
// a participant reporting a step's result from another process has to be able
// to put the facts it found on the record.
func FactsToProto(in map[string]FactValue) []*janusv1.Fact {
	return factsToProto(in)
}

// HeldByGate reports whether a step is waiting on somebody outside Janus.
//
// It is the condition WaitingOnGate uses, exported because three callers now
// ask it: the coordinator deciding whether a saga is waiting or stalled, the
// console building its human queue, and the projection telling a connected
// answerer what is outstanding. Three copies of a predicate this load-bearing
// is how a console invites somebody to approve a step no coordinator has
// reached.
//
// The condition is taken from the log rather than inferred: the coordinator
// recorded an escalation against this step, and the step has not since been
// sealed, committed or refused.
func HeldByGate(st *Step) bool {
	return st.Gate.Verdict == janusv1.Verdict_VERDICT_ESCALATE &&
		st.Status != StepSealed && st.Status != StepCommitted && st.Status != StepRefused
}

// GateOpenedAt is when the decision window for a gate at this phase opened.
//
// It is the anchor a deadline counts from, and it
// exists as one function rather than two because the enforcer and the auditor
// must agree. If the process that expires a gate and the process that later
// checks the expiry was genuine anchored differently, every legitimate timeout
// would be reported as a finding — which is the two-vocabularies bug this
// repository has now met twice.
//
// The window opens when the recorded event that put the step in front of that
// gate landed:
//
//   - PRE_EXECUTION: the attempt's STEP_PREPARE, because a pre-execution gate
//     judges a step that has declared what it will do and not yet done it.
//   - PRE_RELEASE: the attempt's STEP_RESULT, because a pre-release gate judges
//     what happened, and the clock cannot start before there is a result.
//
// A zero time means the window has not opened, which a deadline check must
// treat as "not expired" rather than as "expired long ago" — the difference
// between waiting and refusing a gate nobody has reached.
func GateOpenedAt(st *Step, phase janusv1.GatePhase) time.Time {
	if st == nil {
		return time.Time{}
	}
	if phase == janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION {
		return st.PreparedAt
	}
	return st.ResultAt
}

// ExpiryReason is what an expiry answer records, and the prefix by which one is
// recognised.
//
// A prefix rather than a flag on the message: an answer is an ordinary
// GATE_ANSWER, and adding a "this is a timeout" boolean would be a claim a
// caller could make. What makes an expiry an expiry is the three things
// `IsExpiry` checks together, and the reason is for the person reading the log.
const ExpiryReason = "gate deadline elapsed"

// IsExpiry reports whether an answer is the system expiring a gate.
//
// Three conjuncts, and the third is the one that matters:
//
//   - it is not a human's answer, so it did not come through the console's
//     approval path, which always records the authenticated subject;
//   - it is a refusal, because an expiry can only ever refuse; and
//   - the requirement it answers carries a deadline that had actually elapsed
//     by the time the answer was recorded, measured against the recorded moment
//     the gate's decision window opened.
//
// The third is what makes a forged early expiry **inert at decision time**
// rather than merely flagged by audit afterwards. Without it, anybody able to
// append an answer could cancel an approval on demand — which is a denial lever
// even though it cannot approve anything.
func IsExpiry(a GateAnswerRecord, req *janusv1.GateRequirement, openedAt time.Time) bool {
	switch {
	case a.Human:
		return false
	case a.Verdict != janusv1.Verdict_VERDICT_FAIL:
		return false
	case req.GetTimeoutSeconds() == 0:
		return false
	case openedAt.IsZero() || a.Wall.IsZero():
		// A window that never opened cannot have closed. Treating an unknown
		// anchor as "long past" would expire gates nobody had reached.
		return false
	}
	deadline := openedAt.Add(time.Duration(req.GetTimeoutSeconds()) * time.Second)
	return !a.Wall.Before(deadline)
}

// DeadlineElapsed reports whether a gate's deadline has passed by some clock.
//
// Used by the process that decides to expire a gate, which is the one place a
// live clock is read. Every later reading of that decision is a comparison of
// recorded times.
func DeadlineElapsed(req *janusv1.GateRequirement, openedAt, now time.Time) bool {
	if req.GetTimeoutSeconds() == 0 || openedAt.IsZero() {
		return false
	}
	return !now.Before(openedAt.Add(time.Duration(req.GetTimeoutSeconds()) * time.Second))
}
