package gate

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// Asking the log whether its gate decisions were correct.
//
// Recording a decision proves it was made. It does not prove it was made
// correctly, and the difference is the whole reason this file exists. A
// coordinator with a bug — or one following an instruction it should not have —
// can append a verdict that says PASS. The state machine will check that the
// verdict accounts for every requirement due, because that is structural and
// cheap; it cannot check that the answers are right, because checking that
// means evaluating the policy, and the state machine is the one component that
// is not allowed to.
//
// So the check happens here, afterwards, by somebody who does not trust the
// process that wrote the answer. Every input a verdict rested on is in the log:
// the requirements the saga was admitted under, the facts the step declared, the
// state of every other saga at that moment. Audit replays the log to the instant
// before each verdict, re-derives the decision from those inputs, and compares.
// A verdict that does not survive that is a finding, and it is a finding whether
// the coordinator was buggy or lying — which is the property that matters,
// because from the log those two look the same.
//
// Nothing outside the log is needed, including the policy document. The
// requirements travel with the saga, so an auditor with a bundle and this binary
// can answer "did the policy really say yes?" years later, with the policy
// server long since decommissioned.

// FindingKind classifies what is wrong.
type FindingKind string

const (
	// FindingUnsupported means the recorded verdict is not the one the recorded
	// inputs produce. This is the serious one: a step was let through, or
	// stopped, on an answer the policy does not support.
	FindingUnsupported FindingKind = "UNSUPPORTED_VERDICT"
	// FindingUngated means a step got further than its requirements allow with
	// no verdict at all.
	FindingUngated FindingKind = "UNGATED"
	// FindingMismatch means the verdict's own account of itself is
	// inconsistent — the requirements it claims to have decided are not the
	// ones that were due.
	FindingMismatch FindingKind = "COVERAGE_MISMATCH"
	// FindingUnpinned means a saga carries gates but names no policy version,
	// so the requirements cannot be traced to anything.
	FindingUnpinned FindingKind = "POLICY_UNPINNED"
	// FindingEarlyExpiry means a gate was refused on a deadline's behalf before
	// that deadline had passed.
	//
	// This is the check that turns "the system said it timed out" into
	// something checkable rather than asserted. Without it a coordinator could
	// expire a gate early to make an inconvenient approval unnecessary, and the
	// log would show an ordinary timeout.
	//
	// Both times it compares are recorded — the answer's own wall time and the
	// wall time of the event that opened the gate's decision window — so this
	// re-derives to the same answer years later, which is the whole reason the
	// expiry is an event rather than a computation.
	FindingEarlyExpiry FindingKind = "EARLY_EXPIRY"
	// FindingProposalChanged means a step escalated a pre-execution gate on
	// one proposal and a later verdict on the same attempt decided another, so
	// the answers collected in between were counted for something they were
	// not given about.
	//
	// Semantics 2 refuses this history outright. Semantics 1 recorded it as
	// legal, and a version-1 saga goes on folding under version 1's rules
	// forever — so this finding is the only place a swap in an old log is
	// ever named.
	FindingProposalChanged FindingKind = "PROPOSAL_CHANGED"
	// FindingAnswerBeforeDue means an answer to a requirement was recorded
	// while the step was at the other phase -- an approval of what a step
	// produced, given before it had run -- and was then counted when that
	// requirement came due for the same attempt.
	//
	// Semantics 3 refuses it. A version-2 log may hold it legally, and
	// this is where it is named.
	FindingAnswerBeforeDue FindingKind = "ANSWER_BEFORE_DUE"
	// FindingSignature means a recorded answer or result is on behalf of a
	// participant whose manifest -- in this log, at that point -- declares a key,
	// and its signature is missing or does not verify against it.
	//
	// This is the offline half of caller authentication. The daemon checks the
	// signature before it records anything; this checks it again from the log
	// alone, so an auditor does not have to trust that the daemon did.
	FindingSignature FindingKind = "SIGNATURE"
	// FindingNotAPerson means a HUMAN requirement was answered by a participant
	// in its own name -- an agent or a tool standing in for a person -- rather
	// than by a person or by the system expiring the gate after its deadline.
	//
	// Semantics 4 refuses it. A log written under 1 to 3 may hold it,
	// and the check counted it if it claimed the right role; this is where it
	// is named.
	FindingNotAPerson FindingKind = "NOT_A_PERSON"
)

// Finding is one thing wrong with a gate decision in the log.
type Finding struct {
	Kind     FindingKind
	SagaID   string
	StepID   string
	Seq      uint64
	Phase    janusv1.GatePhase
	Detail   string
	Recorded janusv1.Verdict
	Derived  janusv1.Verdict
}

func (f Finding) String() string {
	where := fmt.Sprintf("%s/%s", f.SagaID, f.StepID)
	if f.Seq > 0 {
		where = fmt.Sprintf("%s at seq %d", where, f.Seq)
	}
	return fmt.Sprintf("%s: %s: %s", f.Kind, where, f.Detail)
}

// Report is the outcome of auditing a log.
type Report struct {
	// Verdicts is how many gate decisions were re-derived.
	Verdicts int
	// Sagas is how many sagas were examined.
	Sagas int
	// Signed is how many recorded answers and results carried a participant's
	// signature that verified against the keys its manifest declares.
	Signed int
	// Unsigned is how many recorded answers and results carried no signature:
	// from a participant whose manifest declares no key, a person's answer that
	// names no relayer, or a record no participant can be tied to. Nothing but
	// the daemon vouches for who sent them.
	Unsigned int
	// Findings is what did not hold. Empty means every recorded decision
	// follows from the inputs recorded with it.
	Findings []Finding
}

// OK reports whether the log's gate decisions all hold up.
func (r Report) OK() bool { return len(r.Findings) == 0 }

func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "gate audit: %d verdicts across %d sagas re-derived from the log\n",
		r.Verdicts, r.Sagas)
	if r.Signed > 0 {
		fmt.Fprintf(&b, "  %d answers and results carry a participant's signature that verifies "+
			"against the key its manifest in this log declares\n", r.Signed)
	}
	if r.Unsigned > 0 {
		fmt.Fprintf(&b, "  %d answers and results carry no signature (the participant declares no key, "+
			"a person's answer names no relayer, or no participant can be tied to the record): "+
			"nothing but the daemon vouches for who sent them\n",
			r.Unsigned)
	}
	if len(r.Findings) == 0 {
		b.WriteString("  every recorded verdict follows from the inputs recorded with it\n")
		return b.String()
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  %s\n", f)
	}
	return b.String()
}

// timed is one event with the saga it belongs to, so a global walk can keep
// every saga's projection in step with the others.
type timed struct {
	sagaID string
	ev     saga.Event
}

// Audit re-derives every gate decision in an evidence directory.
func Audit(dir string) (Report, error) {
	byID, err := loadBySaga(dir)
	if err != nil {
		return Report{}, err
	}

	var all []timed
	for id, events := range byID {
		for _, e := range events {
			all = append(all, timed{sagaID: id, ev: e})
		}
	}
	// The global sequence is the ordering authority — the same one the frontier
	// index uses — so re-deriving a verdict sees exactly the world its
	// coordinator saw, and not the world as it later became.
	sort.SliceStable(all, func(i, j int) bool { return all[i].ev.Seq < all[j].ev.Seq })

	rep := Report{Sagas: len(byID)}
	sigs, err := newSignatureAudit(dir, byID)
	if err != nil {
		return rep, err
	}
	states := map[string]saga.State{}
	asked := map[string]map[string]saga.FactValue{}

	for _, t := range all {
		outcome, findings := sigs.check(states, t)
		switch outcome {
		case sigVerified:
			rep.Signed++
		case sigUnsigned:
			rep.Unsigned++
		}
		rep.Findings = append(rep.Findings, findings...)
		switch t.ev.Kind {
		case evidence.KindStepPrepare:
			rep.Findings = append(rep.Findings, auditPreparedOnNothing(states, t)...)
		case evidence.KindGateAnswer:
			rep.Findings = append(rep.Findings, auditAnswerPhase(states, t)...)
			rep.Findings = append(rep.Findings, auditNotAPerson(states, t)...)
		}
		if t.ev.Kind == evidence.KindGateVerdict {
			n, findings := auditVerdict(states, t)
			rep.Verdicts += n
			rep.Findings = append(rep.Findings, findings...)
			rep.Findings = append(rep.Findings, auditProposal(states, asked, t)...)
		}
		next, err := saga.Apply(states[t.sagaID], t.ev)
		if err != nil {
			return rep, fmt.Errorf("saga %q does not replay at seq %d: %w", t.sagaID, t.ev.Seq, err)
		}
		states[t.sagaID] = next
	}

	rep.Findings = append(rep.Findings, auditReachedStates(states)...)
	sortFindings(rep.Findings)
	return rep, nil
}

// auditProposal checks that every pre-execution verdict on an attempt decides
// the proposal that attempt was escalated on, if it was escalated at all.
//
// It keeps its own record of what was asked rather than reading the
// projection's, because a version-1 fold never recorded one — and version-1
// logs are the ones this check exists for.
func auditProposal(states map[string]saga.State, asked map[string]map[string]saga.FactValue,
	t timed) []Finding {

	msg, err := decodeVerdict(t.ev.Payload)
	if err != nil {
		return nil // auditVerdict has already reported it
	}
	st, ok := states[t.sagaID].Step(msg.GetStepId())
	if !ok || saga.PhaseUnderDecision(st) != janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION {
		return nil
	}
	key := fmt.Sprintf("%s\x00%s\x00%d", t.sagaID, st.ID, st.Attempt+1)
	facts := FactsFromProto(msg.GetFacts())
	first, seen := asked[key]
	if !seen {
		if msg.GetVerdict() == janusv1.Verdict_VERDICT_ESCALATE {
			asked[key] = facts
		}
		return nil
	}
	if maps.Equal(first, facts) {
		return nil
	}
	return []Finding{{
		Kind: FindingProposalChanged, SagaID: t.sagaID, StepID: st.ID, Seq: t.ev.Seq,
		Phase:    janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION,
		Recorded: msg.GetVerdict(),
		Detail: fmt.Sprintf("attempt %d was escalated on %s and this verdict decides it on %s; "+
			"the answers recorded in between were given about the first",
			st.Attempt+1, strings.Join(saga.DescribeFacts(first), " "),
			strings.Join(saga.DescribeFacts(facts), " ")),
	}}
}

// auditPreparedOnNothing names the history semantics 3 refuses as route (b)
// around the approval binding: a pre-execution gate passed a proposal of no
// facts, and the step then prepared on some. Under semantics 2 the fold
// compared a prepare with the judged facts only if the pass had left a map
// behind, so the approval of nothing was counted for whatever the step ran on.
func auditPreparedOnNothing(states map[string]saga.State, t timed) []Finding {
	s := states[t.sagaID]
	if s.Semantics >= 3 {
		return nil // the fold refuses it; a log that holds it does not replay
	}
	var msg janusv1.StepPrepare
	if err := proto.Unmarshal(t.ev.Payload, &msg); err != nil {
		return nil // the replay reports an undecodable event
	}
	st, ok := s.Step(msg.GetStepId())
	if !ok || st.PreGatedAttempt != st.Attempt+1 || st.Facts != nil || len(msg.GetFacts()) == 0 {
		return nil
	}
	return []Finding{{
		Kind: FindingProposalChanged, SagaID: t.sagaID, StepID: st.ID, Seq: t.ev.Seq,
		Phase: janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION,
		Detail: fmt.Sprintf("attempt %d was let through by a gate shown no facts and runs on %s; "+
			"any answer counted for that gate was given about a step that stated nothing",
			st.Attempt+1, strings.Join(saga.DescribeFacts(FactsFromProto(msg.GetFacts())), " ")),
	}}
}

// auditAnswerPhase names route (d) around the approval binding in a version-2
// log: an answer to a requirement recorded while the step was at the other phase.
func auditAnswerPhase(states map[string]saga.State, t timed) []Finding {
	s := states[t.sagaID]
	if s.Semantics >= 3 {
		return nil
	}
	var msg janusv1.GateAnswer
	if err := proto.Unmarshal(t.ev.Payload, &msg); err != nil {
		return nil
	}
	st, ok := s.Step(msg.GetStepId())
	if !ok {
		return nil
	}
	at := saga.PhaseUnderDecision(st)
	// A pre-execution answer before the gate escalated: answered before any
	// proposal was put to it. Semantics 2 records the escalation's pin, so it
	// can be told; semantics 1 recorded none, and is not judged on it.
	if s.Semantics == 2 && at == janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION {
		if _, asked := saga.ProposalUnderDecision(st); !asked {
			return []Finding{{
				Kind: FindingAnswerBeforeDue, SagaID: t.sagaID, StepID: st.ID, Seq: t.ev.Seq,
				Phase: at, Recorded: msg.GetVerdict(),
				Detail: fmt.Sprintf("the answer to %q was recorded before the gate put any "+
					"proposal to it; it was counted for whatever the gate later decided",
					msg.GetRequirementId()),
			}}
		}
	}
	for _, req := range st.Gates {
		if req.GetId() != msg.GetRequirementId() || req.GetPhase() == at {
			continue
		}
		return []Finding{{
			Kind: FindingAnswerBeforeDue, SagaID: t.sagaID, StepID: st.ID, Seq: t.ev.Seq,
			Phase: req.GetPhase(), Recorded: msg.GetVerdict(),
			Detail: fmt.Sprintf("the answer to %q, a %s requirement, was recorded while the "+
				"step was at %s; it was given before the question it answers was due",
				req.GetId(), req.GetPhase(), at),
		}}
	}
	return nil
}

// auditNotAPerson names a person's gate answered by a participant, in a log
// written before semantics 4 refused it.
func auditNotAPerson(states map[string]saga.State, t timed) []Finding {
	s := states[t.sagaID]
	if s.Semantics >= 4 {
		return nil
	}
	var msg janusv1.GateAnswer
	if err := proto.Unmarshal(t.ev.Payload, &msg); err != nil || msg.GetActor().GetHumanSubject() != "" {
		return nil
	}
	st, ok := s.Step(msg.GetStepId())
	if !ok {
		return nil
	}
	for _, req := range st.Gates {
		if req.GetId() != msg.GetRequirementId() || req.GetGate() != janusv1.GateType_GATE_TYPE_HUMAN {
			continue
		}
		who := msg.GetActor().GetParticipant().GetId()
		rec := saga.GateAnswerRecord{ActorID: who, Verdict: msg.GetVerdict(), Wall: t.ev.Wall}
		if saga.IsExpiry(rec, req, saga.GateOpenedAt(st, saga.PhaseUnderDecision(st))) {
			return nil
		}
		return []Finding{{
			Kind: FindingNotAPerson, SagaID: t.sagaID, StepID: st.ID, Seq: t.ev.Seq,
			Phase: req.GetPhase(), Recorded: msg.GetVerdict(),
			Detail: fmt.Sprintf("the person's requirement %q was answered by participant %q in its "+
				"own name; whatever role it claimed, no person gave this answer", req.GetId(), who),
		}}
	}
	return nil
}

// auditVerdict re-derives one recorded decision.
func auditVerdict(states map[string]saga.State, t timed) (int, []Finding) {
	s := states[t.sagaID]
	msg, err := decodeVerdict(t.ev.Payload)
	if err != nil {
		return 0, []Finding{{
			Kind: FindingUnsupported, SagaID: t.sagaID, Seq: t.ev.Seq,
			Detail: fmt.Sprintf("the verdict does not decode: %v", err),
		}}
	}
	st, ok := s.Step(msg.GetStepId())
	if !ok {
		return 0, []Finding{{
			Kind: FindingUnsupported, SagaID: t.sagaID, StepID: msg.GetStepId(), Seq: t.ev.Seq,
			Detail: "the verdict names a step the saga does not have",
		}}
	}

	// The phase is implied by where the step had got to, which is how the state
	// machine reads it too. A verdict cannot be audited as the cheap kind while
	// having been applied as the expensive one.
	phase := saga.PhaseUnderDecision(st)

	early := auditExpiries(t.sagaID, st, phase)

	due := saga.GatesFor(st, phase)
	if len(due) == 0 {
		// Nothing was due, so there was nothing to get wrong. This is the
		// ordinary case for a step with no requirements at all.
		return 0, nil
	}

	// A pre-execution verdict judges a proposal the step has not recorded yet,
	// so the facts come from the verdict. A release verdict judges what ran, so
	// they come from the step — and the state machine has already refused any
	// verdict whose facts disagreed with it.
	declared := st.Facts
	if phase == janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION {
		declared = FactsFromProto(msg.GetFacts())
	}

	derived := Decide(phase, Input{
		Saga:     s,
		Step:     st,
		Declared: declared,
		Index:    indexAsOf(states),
	})

	out := early
	if derived.Verdict != msg.GetVerdict() {
		out = append(out, Finding{
			Kind: FindingUnsupported, SagaID: t.sagaID, StepID: st.ID, Seq: t.ev.Seq, Phase: phase,
			Recorded: msg.GetVerdict(), Derived: derived.Verdict,
			Detail: fmt.Sprintf("the log records %s but the requirements the saga was admitted "+
				"under produce %s on the facts recorded with it: %s",
				shortVerdict(msg.GetVerdict()), shortVerdict(derived.Verdict), derived.Reason),
		})
	}

	if f, bad := compareCoverage(msg, derived, t, st, phase); bad {
		out = append(out, f)
	}
	if s.GatePolicyVersion == "" {
		out = append(out, Finding{
			Kind: FindingUnpinned, SagaID: t.sagaID, StepID: st.ID, Seq: t.ev.Seq, Phase: phase,
			Detail: "the saga carries gate requirements but names no policy version, so nothing " +
				"ties them to a policy anybody approved",
		})
	}
	return 1, out
}

// compareCoverage checks the verdict's account of which requirements it decided
// against the ones re-derivation actually consulted.
func compareCoverage(msg *janusv1.GateVerdict, derived Decision, t timed,
	st *saga.Step, phase janusv1.GatePhase) (Finding, bool) {

	recorded := slices.Clone(msg.GetDecided())
	slices.Sort(recorded)
	want := slices.Clone(derived.Decided)
	slices.Sort(want)
	if slices.Equal(recorded, want) {
		return Finding{}, false
	}
	// A refusal short-circuits, so the two lists differ legitimately when the
	// recorded run stopped at a different check than this one did. That is only
	// benign if the recorded set is a prefix of what was due, in order.
	if msg.GetVerdict() != janusv1.Verdict_VERDICT_PASS && isSubset(recorded, want) {
		return Finding{}, false
	}
	return Finding{
		Kind: FindingMismatch, SagaID: t.sagaID, StepID: st.ID, Seq: t.ev.Seq, Phase: phase,
		Recorded: msg.GetVerdict(), Derived: derived.Verdict,
		Detail: fmt.Sprintf("the verdict claims to have decided %v; re-deriving it consults %v",
			recorded, want),
	}, true
}

func isSubset(small, large []string) bool {
	for _, s := range small {
		if !slices.Contains(large, s) {
			return false
		}
	}
	return true
}

// auditReachedStates catches the omissions a per-verdict check cannot see: a
// step that got somewhere it should not have reached without one.
func auditReachedStates(states map[string]saga.State) []Finding {
	var out []Finding
	ids := make([]string, 0, len(states))
	for id := range states {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	for _, sagaID := range ids {
		s := states[sagaID]
		for _, stepID := range s.Order {
			st := s.Steps[stepID]
			if len(saga.PreExecutionGates(st)) > 0 && st.Attempt > 0 && st.PreGatedAttempt == 0 {
				out = append(out, Finding{
					Kind: FindingUngated, SagaID: sagaID, StepID: stepID,
					Phase: janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION,
					Detail: fmt.Sprintf("the step ran %d time(s) and no gate ever passed it, though "+
						"%s due before it runs", st.Attempt,
						quantity(len(saga.PreExecutionGates(st)), "gate is")),
				})
			}
			sealed := st.Status == saga.StepSealed || st.Status == saga.StepCommitted
			if sealed && len(saga.ReleaseGates(st)) > 0 &&
				st.Gate.Verdict != janusv1.Verdict_VERDICT_PASS {
				out = append(out, Finding{
					Kind: FindingUngated, SagaID: sagaID, StepID: stepID,
					Phase:  janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
					Detail: "the step sealed without a passing release verdict",
				})
			}
		}
	}
	return out
}

// indexAsOf builds the cross-saga view as it stood at this point in the walk.
func indexAsOf(states map[string]saga.State) *saga.Index {
	ix := saga.NewIndex()
	for _, s := range states {
		ix.Add(s)
	}
	return ix
}

// loadBySaga reads every saga's events out of an evidence directory.
func loadBySaga(dir string) (map[string][]saga.Event, error) {
	states, err := saga.ReplayAll(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]saga.Event, len(states))
	for id := range states {
		events, err := saga.LoadEvents(dir, id)
		if err != nil {
			return nil, err
		}
		out[id] = events
	}
	return out, nil
}

func decodeVerdict(payload []byte) (*janusv1.GateVerdict, error) {
	var msg janusv1.GateVerdict
	if err := proto.Unmarshal(payload, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func shortVerdict(v janusv1.Verdict) string {
	return strings.TrimPrefix(v.String(), "VERDICT_")
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].SagaID != f[j].SagaID {
			return f[i].SagaID < f[j].SagaID
		}
		if f[i].Seq != f[j].Seq {
			return f[i].Seq < f[j].Seq
		}
		return f[i].StepID < f[j].StepID
	})
}

// auditExpiries checks that every gate refused on a deadline's behalf was
// refused after that deadline had actually passed.
//
// This is step four of the human-gate timeout design, and the one worth
// insisting on. The
// composition already refuses to *treat* an early answer as an expiry, so a
// forged one does not skip an approval — but it still sits in the log looking
// like a system decision, and an audit that could not tell would report nothing.
//
// It compares two recorded times and reads no clock: the answer's own wall time
// against the wall time of the event that opened the gate's decision window. So
// it re-derives to the same finding years afterwards, which is the property the
// whole audit rests on.
//
// The anchor comes from `saga.GateOpenedAt`, the same function the enforcer
// uses. Two implementations of the anchor would make every legitimate expiry a
// finding — or, worse, make a real early expiry look fine.
func auditExpiries(sagaID string, st *saga.Step, phase janusv1.GatePhase) []Finding {
	openedAt := saga.GateOpenedAt(st, phase)
	if openedAt.IsZero() {
		return nil
	}
	var out []Finding
	for _, req := range saga.GatesFor(st, phase) {
		if req.GetTimeoutSeconds() == 0 {
			continue
		}
		deadline := openedAt.Add(time.Duration(req.GetTimeoutSeconds()) * time.Second)
		for _, a := range st.Answers {
			switch {
			case a.RequirementID != req.GetId():
				continue
			case a.Human, a.Verdict != janusv1.Verdict_VERDICT_FAIL:
				// A person's refusal is not an expiry and is not this check's
				// business.
				continue
			case a.Reason != saga.ExpiryReason:
				// Some other participant refusing, which the composition judges
				// on its own terms.
				continue
			case a.Wall.IsZero():
				out = append(out, Finding{
					Kind: FindingEarlyExpiry, SagaID: sagaID, StepID: st.ID,
					Seq: a.Seq, Phase: phase,
					Detail: fmt.Sprintf("requirement %q was refused on a deadline's behalf by "+
						"an answer with no recorded time, so nothing says whether the deadline "+
						"had passed", req.GetId()),
				})
			case a.Wall.Before(deadline):
				out = append(out, Finding{
					Kind: FindingEarlyExpiry, SagaID: sagaID, StepID: st.ID,
					Seq: a.Seq, Phase: phase,
					Detail: fmt.Sprintf("requirement %q was refused on a deadline's behalf at "+
						"%s, %s before the deadline it cites; the gate opened at %s with a "+
						"timeout of %s",
						req.GetId(), a.Wall.Format(time.RFC3339),
						deadline.Sub(a.Wall).Round(time.Second), openedAt.Format(time.RFC3339),
						time.Duration(req.GetTimeoutSeconds())*time.Second),
				})
			}
		}
	}
	return out
}
