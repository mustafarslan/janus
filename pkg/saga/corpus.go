// Replay corpus.
//
// Criterion S2 asks for 100% replay determinism on a fixture corpus in CI, and
// the important word is *corpus*: the guarantee is not that today's saga
// replays, but that every saga anyone has ever written still replays the same
// way after every future change.
//
// A fixture is a recorded history plus the projection it produced. Replaying it
// must reproduce that projection exactly. When it does not, one of two things
// has happened, and they need opposite responses:
//
//   - The state machine has a bug, and the fixture caught it.
//   - The semantics changed deliberately, and the fixture is now out of date.
//
// The second is legitimate but must never be silent, because "just regenerate
// the fixtures" is how a determinism guarantee quietly stops meaning anything.
// Regenerating is therefore an explicit act (JANUS_UPDATE_FIXTURES=1) that shows
// up as a reviewable diff of what the change did to recorded history.
//
// Since semantics were versioned there is a third outcome, and it is the one Phase 7 asks for:
//
//   - The semantics changed deliberately, and every saga already recorded must
//     go on meaning what it meant.
//
// That is not a regeneration. Regenerating rewrites what an old history is
// expected to produce, which is precisely the claim "old sagas replay forever"
// denies. The response instead is to add a member to `supportedSemantics`,
// branch on `s.Semantics` inside the apply functions the change touches, and
// leave every existing fixture's expectation exactly as it stands — its history
// carries the old version, so the new branch never runs on it.
//
// Telling the second case from the third is a judgement, and it is the one the
// corpus exists to force somebody to make. A failing fixture is not a nuisance;
// it is the question "did this change what an already-recorded saga means?"
// arriving at the only moment it can still be answered honestly.

package saga

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
)

// Fixture is one recorded saga history and the projection it must produce.
type Fixture struct {
	// Name identifies the fixture and its file.
	Name string `json:"name"`
	// Description says what shape of history this is and why it is worth
	// keeping, so a future reader knows whether a change to it matters.
	Description string `json:"description"`
	// Events is the history, in order.
	Events []FixtureEvent `json:"events"`
	// Expect is the projection replaying the history must produce.
	Expect FixtureState `json:"expect"`
}

// FixtureEvent is one event, stored in a form a person can read and edit.
type FixtureEvent struct {
	Seq  uint64 `json:"seq"`
	Kind string `json:"kind"`
	Wall string `json:"wall,omitempty"`
	// Payload is the JTP message as JSON. Storing it as JSON rather than as
	// base64 protobuf is deliberate: a fixture nobody can read is a fixture
	// nobody will check, and the point of the corpus is that a diff to it is
	// reviewable.
	Payload json.RawMessage `json:"payload"`
}

// FixtureState is the projection a fixture expects, in a comparable form.
type FixtureState struct {
	SagaID           string            `json:"saga_id"`
	Status           string            `json:"status"`
	Mode             string            `json:"mode,omitempty"`
	IntentID         string            `json:"intent_id,omitempty"`
	LastSeq          uint64            `json:"last_seq"`
	EventCount       int               `json:"event_count"`
	AbortReason      string            `json:"abort_reason,omitempty"`
	QuarantineReason string            `json:"quarantine_reason,omitempty"`
	Outstanding      []string          `json:"outstanding,omitempty"`
	Frontiers        map[string]uint64 `json:"frontiers,omitempty"`
	// Parent and AuthorizedBy record a sub-saga's place in a family: who
	// spawned it, and whose commit permitted its own.
	Parent       string `json:"parent,omitempty"`
	AuthorizedBy string `json:"authorized_by,omitempty"`
	// GatePolicy is the policy version the saga was admitted under. It is part
	// of the contract because a saga's requirements come from it: a change that
	// stopped recording it would leave every recorded verdict citing nothing.
	GatePolicy string `json:"gate_policy,omitempty"`
	// Semantics is the state-machine rule set the saga was admitted under, and
	// it is in the *expectation* rather than only in the events on purpose.
	//
	// Fixtures 01-20 predate the field entirely: their SAGA_BEGIN carries no
	// semantics_version, and the `"semantics": 1` here is the assertion that a
	// history recorded before the field existed still folds as version 1. That
	// is the backward-compatibility claim of semantics versioning, written down
	// once per recorded history rather than argued once in prose.
	Semantics uint32        `json:"semantics,omitempty"`
	Steps     []FixtureStep `json:"steps"`
}

// FixtureStep is one step's expected state.
type FixtureStep struct {
	ID            string   `json:"id"`
	Status        string   `json:"status"`
	Attempt       uint32   `json:"attempt,omitempty"`
	Outcome       string   `json:"outcome,omitempty"`
	Compensation  string   `json:"compensation,omitempty"`
	CompensatedBy string   `json:"compensated_by,omitempty"`
	Touches       []string `json:"touches,omitempty"`
	// Child names the sub-saga this step delegated to, and how it commits.
	Child string `json:"child,omitempty"`
	// Gates lists the requirements the step was admitted under, as
	// "id@PHASE", and Gate is the last verdict recorded against it. Both are
	// part of the contract: a step that quietly stopped carrying its
	// requirements would still replay to the same status, and would have
	// stopped being gated.
	Gates []string `json:"gates,omitempty"`
	Gate  string   `json:"gate,omitempty"`
	// Facts is what the step declared for its gates to decide on, sorted.
	Facts []string `json:"facts,omitempty"`
	// Published is what the step reported from what it found, sorted. It is
	// part of the contract because a later step's gate decides on it.
	Published []string `json:"published,omitempty"`
	// Proposal is what a pre-execution gate escalated on, as
	// "attempt N: facts". Semantics 1 never recorded one, so it is empty in
	// every fixture written before semantics 2 and they fold unchanged.
	Proposal string `json:"proposal,omitempty"`
	// ProposalSpawn is the delegation a semantics-3 escalation pinned with
	// its facts; absent for one that delegates nothing, so every
	// fixture written before it reads the same.
	ProposalSpawn string `json:"proposal_spawn,omitempty"`
	// Answers are the verdicts somebody outside gave, as
	// "requirement@attempt actor=VERDICT", in log order.
	Answers []string `json:"answers,omitempty"`
}

// Snapshot renders a projection in the fixture's comparable form.
//
// It deliberately captures the fields whose meaning is part of the contract and
// omits derived detail, so that an internal refactor does not churn every
// fixture while a semantic change still shows up.
func Snapshot(s State) FixtureState {
	out := FixtureState{
		SagaID:           s.SagaID,
		Status:           string(s.Status),
		Mode:             s.Mode,
		IntentID:         s.IntentID,
		LastSeq:          s.LastSeq,
		EventCount:       s.EventCount,
		AbortReason:      s.AbortReason,
		QuarantineReason: s.QuarantineReason,
		Outstanding:      s.Outstanding,
		Frontiers:        s.Frontiers,
		AuthorizedBy:     s.AuthorizedBy,
		GatePolicy:       s.GatePolicyVersion,
		Semantics:        s.Semantics,
	}
	if s.Parent != nil {
		out.Parent = fmt.Sprintf("%s/%s:%s", s.Parent.SagaID, s.Parent.StepID, shortCommitMode(s.Parent.Mode))
	}
	for _, id := range s.Order {
		st := s.Steps[id]
		fs := FixtureStep{
			ID:            st.ID,
			Status:        string(st.Status),
			Attempt:       st.Attempt,
			Compensation:  string(st.Compensation),
			CompensatedBy: st.CompensatedBy,
		}
		if st.Outcome != 0 {
			fs.Outcome = shortOutcome(st.Outcome)
		}
		if st.Child != nil {
			fs.Child = fmt.Sprintf("%s:%s", st.Child.SagaID, shortCommitMode(st.Child.Mode))
		}
		for _, t := range st.Touches {
			mode := "R"
			if t.IsWrite() {
				mode = "W"
			}
			fs.Touches = append(fs.Touches, fmt.Sprintf("%s:%s@%d", t.Resource, mode, t.Seq))
		}
		for _, g := range st.Gates {
			fs.Gates = append(fs.Gates, fmt.Sprintf("%s@%s", g.GetId(),
				strings.TrimPrefix(g.GetPhase().String(), "GATE_PHASE_")))
		}
		if st.Gate.Recorded() {
			fs.Gate = fmt.Sprintf("%s via %s",
				strings.TrimPrefix(st.Gate.Verdict.String(), "VERDICT_"),
				strings.TrimPrefix(st.Gate.Gate.String(), "GATE_TYPE_"))
		}
		fs.Facts = describeFactValues(st.Facts)
		fs.Published = describeFactValues(st.Published)
		if st.ProposalSpawn != nil {
			fs.ProposalSpawn = describeSpawn(st.ProposalSpawn)
		}
		if st.ProposalAttempt != 0 {
			fs.Proposal = fmt.Sprintf("attempt %d: %s", st.ProposalAttempt,
				strings.Join(describeFactValues(st.Proposal), " "))
		}
		for _, a := range st.Answers {
			fs.Answers = append(fs.Answers, fmt.Sprintf("%s@%d %s=%s",
				a.RequirementID, a.Attempt, a.ActorID,
				strings.TrimPrefix(a.Verdict.String(), "VERDICT_")))
		}
		out.Steps = append(out.Steps, fs)
	}
	return out
}

// Diff describes how two snapshots disagree, in terms a reader can act on.
func (f FixtureState) Diff(other FixtureState) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	if f.Status != other.Status {
		add("status: expected %s, replay produced %s", f.Status, other.Status)
	}
	if f.SagaID != other.SagaID {
		add("saga id: expected %q, replay produced %q", f.SagaID, other.SagaID)
	}
	if f.LastSeq != other.LastSeq {
		add("last sequence: expected %d, replay produced %d", f.LastSeq, other.LastSeq)
	}
	if f.EventCount != other.EventCount {
		add("event count: expected %d, replay produced %d", f.EventCount, other.EventCount)
	}
	if f.QuarantineReason != other.QuarantineReason {
		add("quarantine reason: expected %q, replay produced %q", f.QuarantineReason, other.QuarantineReason)
	}
	if strings.Join(f.Outstanding, ",") != strings.Join(other.Outstanding, ",") {
		add("outstanding: expected %v, replay produced %v", f.Outstanding, other.Outstanding)
	}
	if f.Parent != other.Parent {
		add("parent: expected %q, replay produced %q", f.Parent, other.Parent)
	}
	if f.AuthorizedBy != other.AuthorizedBy {
		add("commit authority: expected %q, replay produced %q", f.AuthorizedBy, other.AuthorizedBy)
	}
	if f.GatePolicy != other.GatePolicy {
		add("gate policy: expected %q, replay produced %q", f.GatePolicy, other.GatePolicy)
	}
	if f.Semantics != other.Semantics {
		add("semantics version: expected %d, replay produced %d — this history was admitted "+
			"under one rule set and folded under another", f.Semantics, other.Semantics)
	}

	byID := map[string]FixtureStep{}
	for _, st := range other.Steps {
		byID[st.ID] = st
	}
	for _, want := range f.Steps {
		got, ok := byID[want.ID]
		if !ok {
			add("step %s: expected in the projection, replay did not produce it", want.ID)
			continue
		}
		if want.Status != got.Status {
			add("step %s status: expected %s, replay produced %s", want.ID, want.Status, got.Status)
		}
		if want.Attempt != got.Attempt {
			add("step %s attempts: expected %d, replay produced %d", want.ID, want.Attempt, got.Attempt)
		}
		if want.Compensation != got.Compensation {
			add("step %s compensation: expected %q, replay produced %q",
				want.ID, want.Compensation, got.Compensation)
		}
		if strings.Join(want.Touches, ",") != strings.Join(got.Touches, ",") {
			add("step %s touches: expected %v, replay produced %v", want.ID, want.Touches, got.Touches)
		}
		if want.Child != got.Child {
			add("step %s sub-saga: expected %q, replay produced %q", want.ID, want.Child, got.Child)
		}
		if strings.Join(want.Gates, ",") != strings.Join(got.Gates, ",") {
			add("step %s gates: expected %v, replay produced %v", want.ID, want.Gates, got.Gates)
		}
		if want.Gate != got.Gate {
			add("step %s gate verdict: expected %q, replay produced %q", want.ID, want.Gate, got.Gate)
		}
		if strings.Join(want.Facts, ",") != strings.Join(got.Facts, ",") {
			add("step %s facts: expected %v, replay produced %v", want.ID, want.Facts, got.Facts)
		}
		if strings.Join(want.Published, ",") != strings.Join(got.Published, ",") {
			add("step %s published: expected %v, replay produced %v",
				want.ID, want.Published, got.Published)
		}
		if want.ProposalSpawn != got.ProposalSpawn {
			add("step %s pinned delegation: expected %q, replay produced %q",
				want.ID, want.ProposalSpawn, got.ProposalSpawn)
		}
		if want.Proposal != got.Proposal {
			add("step %s proposal: expected %q, replay produced %q",
				want.ID, want.Proposal, got.Proposal)
		}
		if strings.Join(want.Answers, ",") != strings.Join(got.Answers, ",") {
			add("step %s answers: expected %v, replay produced %v",
				want.ID, want.Answers, got.Answers)
		}
	}
	for _, got := range other.Steps {
		found := false
		for _, want := range f.Steps {
			if want.ID == got.ID {
				found = true
				break
			}
		}
		if !found {
			add("step %s: replay produced it, the fixture does not expect it", got.ID)
		}
	}
	return out
}

// LoadFixtures reads every fixture in a directory, sorted by name so a corpus
// run is reproducible.
func LoadFixtures(dir string) ([]Fixture, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Fixture
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var f Fixture
		if err := json.Unmarshal(blob, &f); err != nil {
			return nil, fmt.Errorf("parse fixture %s: %w", e.Name(), err)
		}
		if f.Name == "" {
			f.Name = strings.TrimSuffix(e.Name(), ".json")
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Save writes a fixture as indented JSON.
func (f Fixture) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, f.Name+".json"), append(blob, '\n'), 0o640)
}

// Replayable converts a fixture's stored events into replayable ones.
func (f Fixture) Replayable() ([]Event, error) {
	out := make([]Event, 0, len(f.Events))
	for i, fe := range f.Events {
		payload, err := payloadFromJSON(evidence.Kind(fe.Kind), fe.Payload)
		if err != nil {
			return nil, fmt.Errorf("fixture %s event %d: %w", f.Name, i, err)
		}
		e := Event{Seq: fe.Seq, Kind: evidence.Kind(fe.Kind), Payload: payload}
		if fe.Wall != "" {
			w, perr := time.Parse(time.RFC3339Nano, fe.Wall)
			if perr != nil {
				return nil, fmt.Errorf("fixture %s event %d: bad wall time: %w", f.Name, i, perr)
			}
			e.Wall = w
		}
		out = append(out, e)
	}
	return out, nil
}

// Verify replays the fixture and reports how the result differs from what it
// expects. An empty result means the fixture still holds.
func (f Fixture) Verify() ([]string, error) {
	events, err := f.Replayable()
	if err != nil {
		return nil, err
	}
	state, err := Replay(events)
	if err != nil {
		return nil, fmt.Errorf("fixture %s did not replay: %w", f.Name, err)
	}
	return f.Expect.Diff(Snapshot(state)), nil
}
