// Package console is the operator's view of a Janus deployment: what the sagas
// are doing, what is waiting for a person, and what the evidence says.
//
// It is a view. That word is doing real work here, and three things follow from
// it.
//
// # It holds nothing
//
// Every request re-reads the evidence directory and re-derives what it shows.
// There is no cache, no database, no projection maintained on the side. A
// console with its own copy of the truth is a second system of record that will
// eventually disagree with the first, and the disagreement will
// surface as an operator acting on a screen that was right ten minutes ago. It
// costs a full read per request, which is affordable at this phase and will
// need revisiting when it is not.
//
// # It decides nothing
//
// The queue is derived by running the same gate composition the coordinator
// runs — `gate.Decide` over the requirements recorded in the saga's own
// SAGA_BEGIN — rather than by a second implementation of "what is this step
// waiting for". A console that computed its own answer would be a second gate
// engine, and the interesting failure is not that it disagrees with the
// coordinator but that it agrees convincingly while being wrong.
//
// # An approval through it is an ordinary recorded input
//
// When somebody approves from the console, the console appends a GATE_ANSWER —
// the same event a validator or any other channel produces — and stops. It does
// not decide the gate, does not advance the saga, and has no privileged path of
// any kind. The coordinator reads the answer and composes the verdict, and the
// separation-of-duty rule that refuses a self-approval is the same code in the
// same place.
//
// What the console cannot do is establish who somebody is. It takes the
// approver's identity from the authenticating layer in front of it and records
// the claim as a claim. With nothing in front of it, it is read-only — because
// the alternative is a console that asserts identities on people's behalf,
// which moves the trust boundary without moving the wording of the compliance
// report.
package console

import (
	"context"
	"fmt"
	"sort"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Console answers questions about one evidence directory.
type Console struct {
	dir string
	// projection is an optional read-only view of the projection tables. With
	// one, the overview and the queue are answered from it instead of by
	// replaying every saga in the directory; without one, nothing changes.
	//
	// A console never folds. It holds no writer lock and never advances
	// `last_event_seq` — the daemon that owns the log owns the projection too.
	// What it does instead is say which sequence it is showing.
	projection *projection.Store
	// keys are the writer public keys search checks segment signatures
	// against. Empty means signatures are not checked, and the search result
	// says so rather than implying otherwise.
	keys keys.PublicKeySet
	// blobs is where an approver's assertion is stored, content-addressed, so
	// that auth_ref points at the proof rather than describing it.
	blobs cas.Store
	// recorder is where a composed answer is sent. Nil means this console owns
	// the evidence directory and appends to it itself, which is how it worked
	// before there was a daemon to ask.
	recorder    AnswerRecorder
	credentials CredentialRecorder
}

// AnswerRecorder appends an answer somewhere this process does not own.
//
// It exists because one process writes an evidence directory, so a
// console running alongside a coordinator has no way to append at all. Before
// Phase 4 the honest response was to tell the person to try again later.
// Now the console hands the answer to whoever owns the log.
//
// It is deliberately the *only* thing that is delegated. Every refusal in
// answer.go still happens here, against this console's own reading of the log:
// an approval to a requirement the saga was not admitted under is meaningless
// wherever it is appended, and a console that shipped its refusals to the
// server would be a console that could be talked out of them by a server.
type AnswerRecorder interface {
	RecordAnswer(ctx context.Context, answer *janusv1.GateAnswer) (evidence.Ref, error)
}

// WithBlobs gives this console somewhere to put an approver's assertion.
//
// Without one, an approval carrying an assertion is refused rather than
// recorded with the proof left out: an auth_ref that points at nothing is worse
// than an approval that admits it established nothing.
func (c *Console) WithBlobs(store cas.Store) *Console {
	c.blobs = store
	return c
}

// WithRecorder points this console's approvals at a process that owns the log.
//
// A recorder that also enrols credentials is used for both. The two are
// separate interfaces because they are separate authorities: an implementation
// may reasonably take answers and refuse registrations.
func (c *Console) WithRecorder(r AnswerRecorder) *Console {
	c.recorder = r
	if e, ok := r.(CredentialRecorder); ok {
		c.credentials = e
	}
	return c
}

// CredentialRecorder appends a credential registration for a console that does
// not own the log.
//
// Deliberately narrower than "records identity trust". Trusting an OIDC issuer
// key is not something a console may delegate, or do: a caller that could add a
// trusted issuer could mint tokens establishing any role it liked. Issuer trust
// is an operator action, out of band.
type CredentialRecorder interface {
	RegisterCredential(ctx context.Context, credentialID, subject string,
		publicKeySPKI []byte) (evidence.Ref, error)
}

// Open returns a console over an evidence directory. It does not open the
// directory: every call reads it afresh.
func Open(dir string) *Console { return &Console{dir: dir} }

// WithProjection points the overview and the queue at the projected tables.
//
// It is deliberately only those two. A saga's detail page needs the whole
// projection of that saga — its gates, its recorded answers, the facts each
// requirement was decided on — and that comes from replaying the saga, because
// a page that showed a gate's standing from a column would be a second opinion
// about what a gate means. And every refusal in answer.go keeps reading the log
// directly: those are decisions, not display.
func (c *Console) WithProjection(store *projection.Store) *Console {
	c.projection = store
	return c
}

// Dir is the evidence directory being viewed.
func (c *Console) Dir() string { return c.dir }

// ---- the saga list -------------------------------------------------------------

// SagaRow is one saga as it appears in a list.
type SagaRow struct {
	SagaID    string `json:"saga_id"`
	Status    string `json:"status"`
	Mode      string `json:"mode,omitempty"`
	IntentID  string `json:"intent_id,omitempty"`
	Principal string `json:"principal,omitempty"`
	Steps     int    `json:"steps"`
	Done      int    `json:"steps_done"`
	// Waiting counts steps held by a gate that escalated rather than deciding.
	Waiting int `json:"waiting"`
	// Held counts irreversible effects the outbox is still holding.
	Held       int    `json:"held_effects"`
	LastSeq    uint64 `json:"last_seq"`
	EventCount int    `json:"event_count"`
	// Parent is set for a sub-saga, so a reader can see delegated work as
	// delegated rather than as an orphan.
	Parent string `json:"parent,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Overview is the front page: every saga, plus the counts that decide whether
// anybody needs to do anything.
type Overview struct {
	Dir string `json:"dir"`
	// Sagas are ordered by the sequence they last moved at, most recent first:
	// a console is read by somebody asking what is happening now.
	Sagas   []SagaRow `json:"sagas"`
	Waiting int       `json:"waiting"`
	// Quarantined counts sagas in QUARANTINE. It is emphatically not a count of
	// frozen effects, and the two are independent: nothing drives a saga to
	// QUARANTINE when one of its effects freezes, so the usual shape is a
	// COMMITTED saga with an effect nobody can deliver. This number was the only
	// one on the page and was rendered as "quarantined", under which three
	// frozen effects showed as nothing at all.
	Quarantined int `json:"quarantined"`
	// QuarantinedEffects counts frozen effects across every saga -- the
	// /quarantine work list, as a number. It is separate from HeldEffects
	// rather than part of it: a frozen effect stops being pending, so it leaves
	// that count when it freezes.
	QuarantinedEffects int `json:"quarantined_effects"`
	HeldEffects        int `json:"held_effects"`
	Participants       int `json:"participants"`
	// AsOf is the evidence sequence this page reflects, and Projected says
	// whether it came from the projection or from reading the log.
	//
	// It is on the page rather than implied. A projection is behind the log by
	// however long it has been since the daemon last folded, and a console that
	// rendered without saying when would be making a claim about now that it
	// cannot support. When the log is read directly this is the highest sequence
	// seen, which is "now" and says so.
	AsOf      uint64 `json:"as_of"`
	Projected bool   `json:"projected"`
}

// Overview reads the directory and summarises it.
func (c *Console) Overview() (Overview, error) {
	if c.projection != nil {
		return c.projectedOverview()
	}
	v, err := c.view()
	if err != nil {
		return Overview{}, err
	}
	out := Overview{Dir: c.dir, Participants: len(v.registry.Participants())}

	for _, s := range v.sagas {
		row := SagaRow{
			SagaID:     s.SagaID,
			Status:     string(s.Status),
			Mode:       s.Mode,
			IntentID:   s.IntentID,
			Principal:  s.Intent.Principal,
			Steps:      len(s.Order),
			LastSeq:    s.LastSeq,
			EventCount: s.EventCount,
			Reason:     saga.TerminalReason(s),
		}
		if s.Parent != nil {
			row.Parent = s.Parent.SagaID
		}
		for _, id := range s.Order {
			st := s.Steps[id]
			if st.Status == saga.StepCommitted || st.Status == saga.StepCompensated ||
				st.Status == saga.StepRefused {
				row.Done++
			}
			if saga.HeldByGate(st) {
				row.Waiting++
			}
		}
		row.Held = len(outbox.PendingFor(v.outbox, s.SagaID))

		out.Waiting += row.Waiting
		out.HeldEffects += row.Held
		if s.Status == saga.StatusQuarantine {
			out.Quarantined++
		}
		out.Sagas = append(out.Sagas, row)
	}
	out.QuarantinedEffects = len(outbox.Quarantined(v.outbox))

	sort.SliceStable(out.Sagas, func(i, j int) bool {
		return out.Sagas[i].LastSeq > out.Sagas[j].LastSeq
	})
	for _, s := range v.sagas {
		if s.LastSeq > out.AsOf {
			out.AsOf = s.LastSeq
		}
	}
	return out, nil
}

// projectedOverview answers the same question from the projection tables.
//
// Every number here was folded by the same state machines the replay above
// runs — `saga.Apply` for a saga's standing, `saga.HeldByGate` for whether a
// step is waiting, `outbox.Apply` for how many effects are held. What changed is
// that they were folded once by the daemon rather than once per page view.
func (c *Console) projectedOverview() (Overview, error) {
	ctx := context.Background()
	rows, asOf, err := c.projection.Overview(ctx)
	if err != nil {
		return Overview{}, err
	}
	participants, err := c.projection.ParticipantCount(ctx)
	if err != nil {
		return Overview{}, err
	}
	out := Overview{Dir: c.dir, Participants: participants, AsOf: asOf, Projected: true}
	for _, r := range rows {
		out.Sagas = append(out.Sagas, SagaRow{
			SagaID:     r.SagaID,
			Status:     r.Status,
			Mode:       r.Mode,
			IntentID:   r.IntentID,
			Principal:  r.Principal,
			Steps:      r.Steps,
			Done:       r.Done,
			Waiting:    r.Waiting,
			Held:       r.Held,
			LastSeq:    r.LastSeq,
			EventCount: r.EventCount,
			Reason:     r.Reason,
			Parent:     r.Parent,
		})
		out.Waiting += r.Waiting
		out.HeldEffects += r.Held
		out.QuarantinedEffects += r.Quarantined
		if r.Status == string(saga.StatusQuarantine) {
			out.Quarantined++
		}
	}
	return out, nil
}

// ---- one saga ------------------------------------------------------------------

// StepView is one step, with everything a person looking at a stuck saga wants
// in front of them.
type StepView struct {
	StepID       string   `json:"step_id"`
	Participant  string   `json:"participant"`
	Manifest     string   `json:"manifest_version,omitempty"`
	Action       string   `json:"action"`
	EffectClass  string   `json:"effect_class"`
	Status       string   `json:"status"`
	Attempt      uint32   `json:"attempt"`
	MaxRetries   uint32   `json:"max_retries,omitempty"`
	DependsOn    []string `json:"depends_on,omitempty"`
	Compensation string   `json:"compensation,omitempty"`
	CompState    string   `json:"compensation_state,omitempty"`
	Child        string   `json:"child_saga,omitempty"`
	ChildMode    string   `json:"child_mode,omitempty"`

	// Gates are the requirements the step was admitted under, with the standing
	// of each one as it is now.
	Gates []GateView `json:"gates,omitempty"`
	// Verdict is the last composed decision recorded against the step.
	Verdict string `json:"verdict,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Facts are what the step declared for its gates to decide on, and
	// Published what it reported once it ran.
	Facts     map[string]string `json:"facts,omitempty"`
	Published map[string]string `json:"published,omitempty"`
	// Touches are the resources the step read or wrote.
	Touches []TouchView `json:"touches,omitempty"`
	// Effects are the outbox entries this step produced.
	Effects []EffectView `json:"effects,omitempty"`
}

// GateView is one requirement and where it stands.
type GateView struct {
	RequirementID string `json:"requirement_id"`
	Gate          string `json:"gate"`
	Phase         string `json:"phase"`
	// Verdict is what this requirement evaluates to right now, re-derived from
	// the recorded inputs by the same code the coordinator uses.
	Verdict string `json:"verdict,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Detail describes what the requirement asks for.
	Detail string `json:"detail,omitempty"`
	// Answers are the opinions and approvals recorded against it.
	Answers []AnswerView `json:"answers,omitempty"`
	// External marks a requirement decided by somebody outside Janus, which is
	// the difference between a gate that will resolve itself and one that is
	// waiting for a person.
	External bool `json:"external"`
	// Human marks the subset a person can answer from this console.
	Human bool `json:"human"`
	// StepUp marks a requirement that demands a fresh, phishing-resistant proof
	// of presence bound to this approval. The approval page asks the browser
	// for one only where it is wanted: prompting for a security key at every
	// approval trains people to tap through it, which is how a step-up becomes
	// a formality.
	StepUp bool `json:"step_up,omitempty"`
}

// AnswerView is one recorded answer.
type AnswerView struct {
	Actor   string   `json:"actor"`
	Human   bool     `json:"human"`
	Verdict string   `json:"verdict"`
	Reason  string   `json:"reason,omitempty"`
	Roles   []string `json:"roles,omitempty"`
	AuthRef string   `json:"auth_ref,omitempty"`
	Attempt uint32   `json:"attempt"`
	Seq     uint64   `json:"seq"`
}

// TouchView is one resource the step read or wrote.
type TouchView struct {
	ResourceID string `json:"resource_id"`
	Mode       string `json:"mode"`
	Seq        uint64 `json:"seq"`
}

// EffectView is one outbox entry.
type EffectView struct {
	EffectID string `json:"effect_id"`
	State    string `json:"state"`
	Target   string `json:"target,omitempty"`
	Action   string `json:"action,omitempty"`
	IdemKey  string `json:"idem_key,omitempty"`
	Attempts uint32 `json:"attempts,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// SagaDetail is one saga's topology and standing.
type SagaDetail struct {
	SagaRow
	MandateRef    string     `json:"mandate_ref,omitempty"`
	Scope         string     `json:"scope,omitempty"`
	Originator    string     `json:"originator,omitempty"`
	PolicyVersion string     `json:"gate_policy_version,omitempty"`
	Pins          []PinView  `json:"manifest_pins,omitempty"`
	Steps         []StepView `json:"steps"`
	// Frontiers are the resource watermarks the saga claimed when it sealed.
	Frontiers map[string]uint64 `json:"frontiers,omitempty"`
	// Outstanding lists steps whose effects are still in the world, for a saga
	// that quarantined.
	Outstanding []string `json:"outstanding,omitempty"`
	Children    []string `json:"children,omitempty"`
}

// PinView is one participant pin, resolved against the registry as it stood
// when the saga began.
type PinView struct {
	Participant string `json:"participant"`
	Version     string `json:"version"`
	// State is the manifest version's standing at the sequence this saga began,
	// not now. "what was this participant allowed to do then" is the question a
	// pin exists to answer.
	State string `json:"state,omitempty"`
	// Unresolved is set when the registry has no such version at all, which
	// means nothing in the log says what the participant was declared to do.
	Unresolved bool `json:"unresolved,omitempty"`
}

// ErrNoSaga means the directory holds no such saga.
var ErrNoSaga = fmt.Errorf("console: no such saga")

// Saga returns one saga's detail.
func (c *Console) Saga(sagaID string) (SagaDetail, error) {
	v, err := c.view()
	if err != nil {
		return SagaDetail{}, err
	}
	s, ok := v.byID[sagaID]
	if !ok {
		return SagaDetail{}, fmt.Errorf("%w: %s", ErrNoSaga, sagaID)
	}

	out := SagaDetail{
		SagaRow: SagaRow{
			SagaID: s.SagaID, Status: string(s.Status), Mode: s.Mode,
			IntentID: s.IntentID, Principal: s.Intent.Principal,
			Steps: len(s.Order), LastSeq: s.LastSeq, EventCount: s.EventCount,
			Reason: saga.TerminalReason(s),
		},
		MandateRef:    s.Intent.MandateRef,
		Scope:         s.Intent.Scope,
		Originator:    s.Intent.Originator,
		PolicyVersion: s.GatePolicyVersion,
		Frontiers:     s.Frontiers,
		Outstanding:   s.Outstanding,
	}
	if s.Parent != nil {
		out.Parent = s.Parent.SagaID
	}
	for _, other := range v.sagas {
		if other.Parent != nil && other.Parent.SagaID == s.SagaID {
			out.Children = append(out.Children, other.SagaID)
		}
	}
	out.Pins = v.pinsFor(s)

	for _, id := range s.Order {
		st := s.Steps[id]
		sv := StepView{
			StepID:       st.ID,
			Participant:  st.Participant,
			Action:       st.Action,
			EffectClass:  registry.ShortClass(st.EffectClass),
			Status:       string(st.Status),
			Attempt:      st.Attempt,
			MaxRetries:   st.MaxRetries,
			DependsOn:    st.DependsOn,
			Compensation: st.CompensationAction,
			Facts:        renderFacts(st.Facts),
			Published:    renderFacts(st.Published),
			Verdict:      shortVerdict(st.Gate.Verdict),
			Reason:       st.Gate.Reason,
		}
		if st.Compensation != saga.CompNotNeeded {
			sv.CompState = string(st.Compensation)
		}
		if st.Child != nil {
			sv.Child = st.Child.SagaID
			sv.ChildMode = shortChildMode(st.Child.Mode)
		}
		for _, pin := range out.Pins {
			if pin.Participant == st.Participant {
				sv.Manifest = pin.Version
			}
		}
		for _, t := range st.Touches {
			sv.Touches = append(sv.Touches, TouchView{
				ResourceID: t.Resource, Mode: shortMode(t.Mode), Seq: t.Seq,
			})
		}
		for _, e := range outbox.EffectsFor(v.outbox, s.SagaID) {
			if e.StepID == st.ID {
				sv.Effects = append(sv.Effects, effectView(e))
			}
		}
		sv.Gates = v.gatesFor(s, st)
		out.Steps = append(out.Steps, sv)

		if st.Status == saga.StepCommitted || st.Status == saga.StepCompensated ||
			st.Status == saga.StepRefused {
			out.Done++
		}
		if saga.HeldByGate(st) {
			out.Waiting++
		}
		out.Held += len(sv.Effects)
	}
	return out, nil
}

// ---- the queue -----------------------------------------------------------------

// QueueItem is one step waiting on somebody outside Janus.
type QueueItem struct {
	SagaID      string `json:"saga_id"`
	StepID      string `json:"step_id"`
	Participant string `json:"participant"`
	Action      string `json:"action"`
	EffectClass string `json:"effect_class"`
	Attempt     uint32 `json:"attempt"`
	Phase       string `json:"phase"`
	// Initiator is the principal the saga was raised for. A gate with
	// separation of duty refuses an approval from them, so it is shown rather
	// than left for somebody to discover at the refusal.
	Initiator  string            `json:"initiator,omitempty"`
	IntentID   string            `json:"intent_id,omitempty"`
	MandateRef string            `json:"mandate_ref,omitempty"`
	Scope      string            `json:"scope,omitempty"`
	Facts      map[string]string `json:"facts,omitempty"`
	// Outstanding are the external requirements that have not resolved.
	Outstanding []GateView `json:"outstanding"`
	// WaitingSince is when the step's current attempt was prepared.
	WaitingSince time.Time `json:"waiting_since,omitempty"`
	// Answerable is true when a person can answer at least one of the
	// outstanding requirements from this console. A step waiting on validator
	// participants is shown, because an operator needs to know why nothing is
	// moving, and it is not something a person can sign off.
	Answerable bool `json:"answerable"`
}

// QueueBoard is the approval queue together with the point in the log it
// reflects.
//
// The sequence is part of the answer rather than metadata about it. A queue read
// from a projection is a list of what was waiting as of a sequence, and a person
// deciding whether to approve a payment should be able to see that rather than
// infer it — the more so because a projection that is behind produces a queue
// with a row *missing*, which is invisible unless the page says when it was
// built.
type QueueBoard struct {
	Items []QueueItem `json:"items"`
	AsOf  uint64      `json:"as_of"`
	// Projected says the shortlist came from the projection. When false the
	// queue was built by replaying every saga, and AsOf is the highest sequence
	// that replay saw — which is "now".
	Projected bool `json:"projected"`
}

// Queue lists everything waiting on a human or a validator, oldest first.
//
// "Waiting" is taken from the log rather than inferred: a step is in the queue
// when the coordinator recorded an escalation against it and the step has not
// since been sealed, committed or refused. That is the same condition
// saga.WaitingOnGate uses. Deriving it any other way would let the console
// invite somebody to approve a step no coordinator has actually reached.
func (c *Console) Queue() (QueueBoard, error) {
	v, err := c.queueView()
	if err != nil {
		return QueueBoard{}, err
	}
	board := QueueBoard{AsOf: v.asOf, Projected: v.projected}
	if !v.projected {
		for _, s := range v.sagas {
			if s.LastSeq > board.AsOf {
				board.AsOf = s.LastSeq
			}
		}
	}
	var out []QueueItem
	for _, s := range v.sagas {
		for _, id := range s.Order {
			st := s.Steps[id]
			if !saga.HeldByGate(st) {
				continue
			}
			item := QueueItem{
				SagaID:      s.SagaID,
				StepID:      st.ID,
				Participant: st.Participant,
				Action:      st.Action,
				EffectClass: registry.ShortClass(st.EffectClass),
				Attempt:     saga.AttemptUnderDecision(st, saga.PhaseUnderDecision(st)),
				Phase:       shortPhase(saga.PhaseUnderDecision(st)),
				Initiator:   s.Intent.Principal,
				IntentID:    s.IntentID,
				MandateRef:  s.Intent.MandateRef,
				Scope:       s.Intent.Scope,
				// What the approver is being asked about. Before it runs that
				// is the pinned proposal, not st.Facts, which is empty until
				// the step prepares.
				Facts:        renderFacts(saga.FactsUnderDecision(st, saga.PhaseUnderDecision(st))),
				WaitingSince: st.PreparedAt,
			}
			for _, g := range v.gatesFor(s, st) {
				if !g.External || g.Verdict == shortVerdict(janusv1.Verdict_VERDICT_PASS) {
					continue
				}
				item.Outstanding = append(item.Outstanding, g)
				if g.Human {
					item.Answerable = true
				}
			}
			if len(item.Outstanding) == 0 {
				// Held by something that is not waiting on a person — a
				// contended resource, most often. It belongs on the saga page,
				// not in a queue of things somebody can act on.
				continue
			}
			out = append(out, item)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].WaitingSince.Before(out[j].WaitingSince)
	})
	board.Items = out
	return board, nil
}

// queueView is the read the approval queue needs.
//
// With a projection it asks which sagas have a step stopped at a gate — a
// shortlist — and replays only those, in one pass over the log. Without one it
// is the full read, unchanged.
//
// What the projection is trusted for and what it is not is the whole design
// here. It chooses *which* sagas to look at; it says nothing about what any gate
// is waiting for. That is decided by `gate.Decide` over the projections this
// replays, the same composition the coordinator runs, because a queue built from
// a column would be a second opinion about what a gate means. The consequence is
// worth stating plainly: a projection that is behind produces a queue that is
// missing a row, never a queue with a wrong row on it — and the page carries the
// sequence, so a missing row reads as staleness rather than as absence.
func (c *Console) queueView() (*view, error) {
	if c.projection == nil {
		return c.view()
	}
	ctx := context.Background()
	ids, asOf, err := c.projection.SagasHeldAtAGate(ctx)
	if err != nil {
		return nil, err
	}
	byID, err := saga.ReplaySome(c.dir, ids)
	if err != nil {
		return nil, fmt.Errorf("console: replay the sagas waiting at a gate: %w", err)
	}
	v := &view{byID: byID, index: saga.NewIndex(), asOf: asOf, projected: true}
	for _, s := range byID {
		v.sagas = append(v.sagas, s)
		v.index.Add(s)
	}
	sort.SliceStable(v.sagas, func(i, j int) bool { return v.sagas[i].SagaID < v.sagas[j].SagaID })

	// The registry is still read from the log. The queue renders a step's
	// effect class from the manifest it was pinned to, and this is a page
	// somebody acts on — see the pin resolution in pinsFor, which asks the
	// registry as of the sequence the saga began.
	if v.registryEvents, err = registry.LoadEvents(c.dir); err != nil {
		return nil, fmt.Errorf("console: read registry: %w", err)
	}
	if v.registry, err = registry.Fold(v.registryEvents); err != nil {
		return nil, fmt.Errorf("console: fold registry: %w", err)
	}
	if v.begins, err = loadBegins(c.dir); err != nil {
		return nil, fmt.Errorf("console: read saga pins: %w", err)
	}
	return v, nil
}

// ---- the quarantine work list ---------------------------------------------------

// QuarantineItem is one frozen effect, with what a person needs to reconcile it.
type QuarantineItem struct {
	EffectID string `json:"effect_id"`
	SagaID   string `json:"saga_id"`
	StepID   string `json:"step_id,omitempty"`
	Target   string `json:"target,omitempty"`
	Action   string `json:"action,omitempty"`
	// IdemKey is the key the target was asked to deduplicate on. It is what
	// somebody reconciling by hand searches the target's own records for, so it
	// is on the row rather than a click away.
	IdemKey string `json:"idem_key,omitempty"`
	// Attempts is how many times delivery was announced, not how many times it
	// succeeded. An effect can be frozen having possibly landed; see
	// MayHaveLanded, which is why this number and not a success count.
	Attempts uint32 `json:"attempts"`
	// MayHaveLanded says the effect could already be in the world. It changes
	// what reconciliation means -- check the target before retrying, rather than
	// assume nothing happened -- so it is on the row.
	MayHaveLanded bool   `json:"may_have_landed"`
	Reason        string `json:"reason,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	// SagaStatus is where the effect's saga stands, and it is on the row
	// because the answer is usually COMMITTED. Nothing drives a saga to
	// QUARANTINE when one of its effects freezes, so a reader who assumed the
	// saga would look wrong needs to see that it does not.
	SagaStatus string `json:"saga_status,omitempty"`
	Principal  string `json:"principal,omitempty"`
	IntentID   string `json:"intent_id,omitempty"`
	// HeldSince is when the effect was first held, and is named for what it is
	// rather than for the page it appears on. It is not when the effect froze:
	// the log records no wall clock for the freeze beyond the event's own
	// timestamp, and a field called "frozen since" carrying "held since" is the
	// kind of label this page was built to stop shipping.
	HeldSince time.Time `json:"held_since,omitempty"`
}

// QuarantineBoard is every frozen effect in the deployment, and the point in the
// log it reflects.
type QuarantineBoard struct {
	Items []QuarantineItem `json:"items"`
	AsOf  uint64           `json:"as_of"`
	// Projected says the shortlist of sagas came from the projection. What is
	// on the list never does.
	Projected bool `json:"projected"`
}

// Quarantine lists every frozen effect, oldest first.
//
// This page was once missing. Quarantine was
// produced and an effect was visible on its own saga's page, so nothing was
// hidden — but only from somebody who already knew which saga to open, and the
// saga is very often COMMITTED, which is not a saga anybody is looking at. The
// operator's question is cross-saga: what is frozen, anywhere.
//
// It is read-only, and that is a decision rather than an omission. Releasing a
// frozen effect from a page built on a shortlist would be exactly the release
// path that is ruled out — the projection would have chosen what to act on. A
// release belongs where the log is the input, with the commit authority read
// from it.
//
// With a projection the shortlist says which sagas hold something frozen and the
// effects are replayed from the log for those sagas alone. Without one the whole
// outbox is replayed, unchanged.
func (c *Console) Quarantine() (QuarantineBoard, error) {
	v, err := c.quarantineView()
	if err != nil {
		return QuarantineBoard{}, err
	}
	board := QuarantineBoard{AsOf: v.asOf, Projected: v.projected}
	if !v.projected {
		for _, s := range v.sagas {
			if s.LastSeq > board.AsOf {
				board.AsOf = s.LastSeq
			}
		}
	}
	for _, e := range outbox.Quarantined(v.outbox) {
		item := QuarantineItem{
			EffectID:      e.ID,
			SagaID:        e.SagaID,
			StepID:        e.StepID,
			Target:        e.Target,
			Action:        e.Action,
			IdemKey:       e.IdemKey,
			Attempts:      e.Attempts,
			MayHaveLanded: e.MayHaveLanded(),
			Reason:        e.QuarantineReason,
			LastError:     e.LastError,
			HeldSince:     e.FirstHeldAt,
		}
		// The saga is looked up rather than required. An effect whose saga is
		// not in the replayed set still belongs on the list: the effect is what
		// is frozen, and dropping the row because its context is missing would
		// hide the thing this page exists to show.
		if s, ok := v.byID[e.SagaID]; ok {
			item.SagaStatus = string(s.Status)
			item.Principal = s.Intent.Principal
			item.IntentID = s.IntentID
		}
		board.Items = append(board.Items, item)
	}
	sort.SliceStable(board.Items, func(i, j int) bool {
		return board.Items[i].HeldSince.Before(board.Items[j].HeldSince)
	})
	return board, nil
}

// quarantineView is the read the quarantine list needs: the outbox, plus the
// sagas the frozen effects belong to.
//
// The registry is deliberately not loaded. The queue renders a step's effect
// class from the manifest it was pinned to because it is a page somebody acts
// on; this one shows what a target was asked to do and what it said, all of
// which is in the outbox events themselves.
func (c *Console) quarantineView() (*view, error) {
	if c.projection == nil {
		return c.view()
	}
	ctx := context.Background()
	ids, asOf, err := c.projection.SagasWithQuarantinedEffects(ctx)
	if err != nil {
		return nil, err
	}
	byID, err := saga.ReplaySome(c.dir, ids)
	if err != nil {
		return nil, fmt.Errorf("console: replay the sagas holding a frozen effect: %w", err)
	}
	v := &view{byID: byID, index: saga.NewIndex(), asOf: asOf, projected: true}
	for _, s := range byID {
		v.sagas = append(v.sagas, s)
		v.index.Add(s)
	}
	sort.SliceStable(v.sagas, func(i, j int) bool { return v.sagas[i].SagaID < v.sagas[j].SagaID })

	// The effects themselves come from the log, for the shortlisted sagas only.
	// This is the half the projection is not trusted with: it named the sagas,
	// and `outbox.Apply` over the real events decides what is frozen on them. A
	// saga the shortlist names in error contributes nothing, because there is
	// no quarantined effect in its log to find.
	events, err := outbox.LoadEventsFor(c.dir, ids)
	if err != nil {
		return nil, fmt.Errorf("console: read the outbox: %w", err)
	}
	if v.outbox, err = outbox.Replay(events); err != nil {
		return nil, fmt.Errorf("console: replay the outbox: %w", err)
	}
	return v, nil
}

// ---- the shared read -----------------------------------------------------------

// view is one consistent read of the directory: every saga, the outbox, and the
// registry, plus the cross-saga index a frontier gate needs.
//
// They are read together because they are read together by the thing being
// modelled. A queue built from sagas read at one moment and a registry read at
// another could show a step waiting on a participant that the same page reports
// as retired.
type view struct {
	sagas    []saga.State
	byID     map[string]saga.State
	outbox   outbox.State
	registry *registry.Registry
	index    *saga.Index
	// registryEvents are kept so a pin can be resolved as of the sequence a
	// saga began rather than as of now.
	registryEvents []registry.Event
	// begins is what each saga's SAGA_BEGIN said: its pins and where it began.
	begins map[string]beginRecord
	// asOf is the sequence this read reflects, and projected says whether the
	// saga set came from the projection rather than from replaying everything.
	asOf      uint64
	projected bool
}

func (c *Console) view() (*view, error) {
	byID, err := saga.ReplayAll(c.dir)
	if err != nil {
		return nil, fmt.Errorf("console: read sagas: %w", err)
	}
	v := &view{byID: byID, index: saga.NewIndex()}
	for _, s := range byID {
		v.sagas = append(v.sagas, s)
		v.index.Add(s)
	}
	sort.SliceStable(v.sagas, func(i, j int) bool { return v.sagas[i].SagaID < v.sagas[j].SagaID })

	events, err := outbox.LoadEvents(c.dir)
	if err != nil {
		return nil, fmt.Errorf("console: read outbox: %w", err)
	}
	if v.outbox, err = outbox.Replay(events); err != nil {
		return nil, fmt.Errorf("console: replay outbox: %w", err)
	}

	if v.registryEvents, err = registry.LoadEvents(c.dir); err != nil {
		return nil, fmt.Errorf("console: read registry: %w", err)
	}
	if v.registry, err = registry.Fold(v.registryEvents); err != nil {
		return nil, fmt.Errorf("console: fold registry: %w", err)
	}

	if v.begins, err = loadBegins(c.dir); err != nil {
		return nil, fmt.Errorf("console: read saga pins: %w", err)
	}
	return v, nil
}

// gatesFor renders a step's requirements with the standing of each.
//
// The verdicts come from gate.Decide — the same composition the coordinator
// runs, over the requirements recorded in the saga's own SAGA_BEGIN. The
// console does not have a second opinion about what a gate means.
func (v *view) gatesFor(s saga.State, st *saga.Step) []GateView {
	if len(st.Gates) == 0 {
		return nil
	}
	phase := saga.PhaseUnderDecision(st)
	decision := gate.Decide(phase, gate.Input{
		Saga: s, Step: st, Declared: saga.FactsUnderDecision(st, phase), Index: v.index,
	})
	byReq := map[string]gate.Result{}
	for _, r := range decision.Results {
		byReq[r.RequirementID] = r
	}

	out := make([]GateView, 0, len(st.Gates))
	for _, req := range st.Gates {
		g := GateView{
			RequirementID: req.GetId(),
			Gate:          shortGate(req.GetGate()),
			Phase:         shortPhase(req.GetPhase()),
			Detail:        describeRequirement(req),
			External:      saga.External(req),
			Human:         req.GetGate() == janusv1.GateType_GATE_TYPE_HUMAN,
			StepUp:        req.GetHuman().GetRequireStepUp(),
		}
		switch r, evaluated := byReq[req.GetId()]; {
		case evaluated:
			g.Verdict = shortVerdict(r.Verdict)
			g.Reason = r.Reason
		case req.GetPhase() != phase:
			// Due at the other phase. Saying so beats leaving it blank, which
			// reads as "passed".
			g.Reason = "not yet due: decided " + shortPhase(req.GetPhase())
		default:
			// Due now, but the composition stopped before reaching it: an
			// earlier requirement is waiting, and evaluating the rest would
			// record answers to questions that may not be asked. An approval
			// can still be given against it — answers arrive in any order and
			// the composition folds whatever is there when it next runs.
			g.Reason = "not reached: an earlier requirement in this phase is still waiting"
		}
		for _, a := range st.Answers {
			if a.RequirementID != req.GetId() {
				continue
			}
			g.Answers = append(g.Answers, AnswerView{
				Actor: a.ActorID, Human: a.Human, Verdict: shortVerdict(a.Verdict),
				Reason: a.Reason, Roles: a.Roles, AuthRef: a.AuthRef,
				Attempt: a.Attempt, Seq: a.Seq,
			})
		}
		out = append(out, g)
	}
	return out
}

// pinsFor resolves a saga's manifest pins against the registry as it stood when
// the saga began.
func (v *view) pinsFor(s saga.State) []PinView {
	begin := v.begins[s.SagaID]
	pins := begin.Pins
	if len(pins) == 0 {
		return nil
	}
	// Folded to the sequence the saga began at, because that is the question a
	// pin asks: what did the registry say *then*. A participant suspended
	// afterwards does not retroactively make this saga's steps unresolvable.
	asOf, err := registry.FoldUntil(v.registryEvents, begin.Seq)
	if err != nil {
		asOf = v.registry
	}

	names := make([]string, 0, len(pins))
	for p := range pins {
		names = append(names, p)
	}
	sort.Strings(names)

	out := make([]PinView, 0, len(names))
	for _, p := range names {
		pv := PinView{Participant: p, Version: pins[p]}
		if e, ok := asOf.Resolve(p, pins[p]); ok {
			pv.State = string(e.State)
		} else {
			pv.Unresolved = true
		}
		out = append(out, pv)
	}
	return out
}

// heldByGate reports whether a step is sitting on an escalated gate. It is the
// same condition saga.WaitingOnGate applies, widened to every step rather than
// the first.

func effectView(e *outbox.Effect) EffectView {
	out := EffectView{
		EffectID: e.ID, State: string(e.State), Target: e.Target,
		Action: e.Action, IdemKey: e.IdemKey, Attempts: e.Attempts,
	}
	switch {
	case e.QuarantineReason != "":
		out.Reason = e.QuarantineReason
	case e.LastError != "":
		out.Reason = e.LastError
	}
	return out
}

func renderFacts(in map[string]saga.FactValue) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = factString(v)
	}
	return out
}
