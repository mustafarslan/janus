package retention

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// LegalHold freezes disposal for a matter, regardless of what the schedule says.
//
// A hold is scoped rather than global: an investigation into one customer
// should not stop the disposal of everything else, and a regulator asking about
// one saga should not force a bank to keep unrelated personal data past its
// permitted maximum.
type LegalHold struct {
	ID string `json:"id"`
	// Matter names the litigation, investigation, or supervisory request.
	Matter string `json:"matter"`
	// PlacedBy and PlacedAt record who froze disposal and when. A hold is a
	// deliberate act by an accountable person, not a configuration flag.
	PlacedBy string    `json:"placed_by"`
	PlacedAt time.Time `json:"placed_at"`
	// ReleasedAt, when set, ends the hold.
	ReleasedAt *time.Time `json:"released_at,omitempty"`
	ReleasedBy string     `json:"released_by,omitempty"`
	// Scope selects what is frozen. An empty Scope freezes everything, which is
	// occasionally what a supervisor demands.
	Scope Scope `json:"scope"`
}

// Active reports whether the hold applies at time t.
func (h LegalHold) Active(t time.Time) bool {
	if t.Before(h.PlacedAt) {
		return false
	}
	return h.ReleasedAt == nil || t.Before(*h.ReleasedAt)
}

// Scope narrows a legal hold. Every non-empty field must match.
type Scope struct {
	SagaIDs  []string `json:"saga_ids,omitempty"`
	Subjects []string `json:"subjects,omitempty"`
	Classes  []Class  `json:"classes,omitempty"`
	Tenants  []string `json:"tenants,omitempty"`
}

// Matches reports whether a record falls inside the scope.
func (s Scope) Matches(r Record) bool {
	if len(s.SagaIDs) > 0 && !slices.Contains(s.SagaIDs, r.SagaID) {
		return false
	}
	if len(s.Subjects) > 0 && !slices.Contains(s.Subjects, r.Subject) {
		return false
	}
	if len(s.Classes) > 0 && !slices.Contains(s.Classes, r.Class) {
		return false
	}
	if len(s.Tenants) > 0 && !slices.Contains(s.Tenants, r.Tenant) {
		return false
	}
	return true
}

// Empty reports whether the scope selects everything.
func (s Scope) Empty() bool {
	return len(s.SagaIDs) == 0 && len(s.Subjects) == 0 && len(s.Classes) == 0 && len(s.Tenants) == 0
}

// Record is what the engine reasons about: enough to select a policy and match
// a hold, and nothing else. The engine never sees payload content.
type Record struct {
	Class        Class
	Jurisdiction string
	Tenant       string
	SagaID       string
	// Subject is the data subject, for personal-data records.
	Subject string
	// CreatedAt starts the retention clock.
	CreatedAt time.Time
}

// Decision is the engine's answer about one record.
type Decision struct {
	Record Record `json:"-"`
	// Disposable is the only field a caller should act on.
	Disposable bool `json:"disposable"`
	// Mode says what disposal would do, when disposal is permitted.
	Mode DisposalMode `json:"mode"`
	// Reason explains the answer in the terms a compliance officer would use.
	Reason string `json:"reason"`
	// Policy is the rule that governed the decision.
	Policy Policy `json:"policy"`
	// EligibleAt is when the record becomes disposable, if it is not yet.
	EligibleAt time.Time `json:"eligible_at,omitempty"`
	// HeldBy lists the legal holds blocking disposal.
	HeldBy []string `json:"held_by,omitempty"`
}

// Engine answers retention questions against a schedule and a set of holds.
type Engine struct {
	mu       sync.RWMutex
	schedule Schedule
	holds    map[string]LegalHold
}

// NewEngine returns an engine over a validated schedule.
func NewEngine(s Schedule) (*Engine, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &Engine{schedule: s, holds: map[string]LegalHold{}}, nil
}

// Schedule returns the schedule in force.
func (e *Engine) Schedule() Schedule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.schedule
}

// LoadHolds installs a folded set of legal holds.
//
// This is the only way holds get into an engine, and that is the point.
// There is deliberately no PlaceHold or
// ReleaseHold here any more: they existed, they mutated a map, and a hold
// placed through them ceased to exist when the process did. Placing and
// releasing are `retention.Recorder` methods now — they append to the log — and
// an engine's holds come from `FoldHolds`, so an engine that was never given a
// fold has no holds rather than a stale set.
func (e *Engine) LoadHolds(h Holds) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.holds = make(map[string]LegalHold, len(h.byID))
	for id, v := range h.byID {
		e.holds[id] = v
	}
}

// Holds returns every hold the engine knows about, sorted by id.
func (e *Engine) Holds() []LegalHold {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]LegalHold, 0, len(e.holds))
	for _, h := range e.holds {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Evaluate decides whether a record may be disposed of at time now.
//
// The order of the checks is the order of authority. A legal hold outranks the
// schedule, the minimum retention outranks the maximum, and a record with no
// maximum is simply kept. Nothing here ever answers "dispose" by default.
func (e *Engine) Evaluate(r Record, now time.Time) (Decision, error) {
	e.mu.RLock()
	schedule := e.schedule
	holds := make([]LegalHold, 0, len(e.holds))
	for _, h := range e.holds {
		holds = append(holds, h)
	}
	e.mu.RUnlock()

	policy, err := schedule.Lookup(r.Class, r.Jurisdiction)
	if err != nil {
		return Decision{Record: r}, err
	}
	d := Decision{Record: r, Policy: policy, Mode: policy.Mode}

	// A legal hold freezes disposal even after the maximum has passed. This is
	// the one rule that can require keeping data a data-protection regime would
	// otherwise say must go, and it is why holds are scoped and auditable.
	var held []string
	for _, h := range holds {
		if h.Active(now) && h.Scope.Matches(r) {
			held = append(held, h.ID)
		}
	}
	if len(held) > 0 {
		sort.Strings(held)
		d.HeldBy = held
		d.Reason = "frozen by legal hold " + strings.Join(held, ", ")
		return d, nil
	}

	if policy.Mode == DisposeNone {
		d.Reason = "policy keeps this class indefinitely"
		if policy.Authority != "" {
			d.Reason += " (" + policy.Authority + ")"
		}
		return d, nil
	}

	minUntil := r.CreatedAt.Add(time.Duration(policy.MinRetention))
	if now.Before(minUntil) {
		d.EligibleAt = minUntil
		d.Reason = fmt.Sprintf("inside the minimum retention of %s, which ends %s",
			policy.MinRetention, minUntil.UTC().Format(time.RFC3339))
		return d, nil
	}

	if policy.MaxRetention == 0 {
		d.Reason = "past the minimum retention, but the policy sets no maximum, so the record is kept"
		return d, nil
	}

	maxUntil := r.CreatedAt.Add(time.Duration(policy.MaxRetention))
	if now.Before(maxUntil) {
		d.EligibleAt = maxUntil
		d.Reason = fmt.Sprintf("past the minimum but inside the maximum retention of %s, which ends %s",
			policy.MaxRetention, maxUntil.UTC().Format(time.RFC3339))
		return d, nil
	}

	d.Disposable = true
	d.EligibleAt = maxUntil
	d.Reason = fmt.Sprintf("past the maximum retention of %s and under no legal hold", policy.MaxRetention)
	return d, nil
}

// DisposalRecord is the payload of the event written when evidence is disposed
// of. Disposal that leaves no trace turns a gap in the record into an
// unanswerable question: was there nothing here, or was something removed?
type DisposalRecord struct {
	// Class, Jurisdiction, and Subject identify what went, without reproducing
	// the content that was the reason for disposing of it.
	Class        Class  `json:"class"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
	Tenant       string `json:"tenant,omitempty"`
	Subject      string `json:"subject,omitempty"`
	SagaID       string `json:"saga_id,omitempty"`

	// Mode is what was actually done.
	Mode DisposalMode `json:"mode"`
	// Count is how many records the operation covered.
	Count int `json:"count"`
	// Refs identifies the disposed artefacts, so the gap is locatable.
	Refs []string `json:"refs,omitempty"`

	// Policy and Authority say under what rule this was permitted.
	PolicyClass  Class  `json:"policy_class"`
	Authority    string `json:"authority,omitempty"`
	MinRetention string `json:"min_retention"`
	MaxRetention string `json:"max_retention,omitempty"`

	// ApprovedBy names the accountable person. Automated disposal still runs
	// under someone's authority, and the record should say whose.
	ApprovedBy string    `json:"approved_by"`
	DisposedAt time.Time `json:"disposed_at"`
	Reason     string    `json:"reason"`
}

// Payload renders the disposal record for the evidence log. Struct field order
// is fixed, so the encoding is stable and safe to hash into the chain.
func (d DisposalRecord) Payload() ([]byte, error) { return json.Marshal(d) }

// NewDisposalRecord builds a disposal record from a decision that permitted it.
func NewDisposalRecord(d Decision, refs []string, approvedBy string, at time.Time) (DisposalRecord, error) {
	if !d.Disposable {
		return DisposalRecord{}, fmt.Errorf("retention: refusing to record a disposal the policy did not permit: %s", d.Reason)
	}
	if approvedBy == "" {
		return DisposalRecord{}, fmt.Errorf("retention: a disposal needs an accountable approver")
	}
	rec := DisposalRecord{
		Class:        d.Record.Class,
		Jurisdiction: d.Record.Jurisdiction,
		Tenant:       d.Record.Tenant,
		Subject:      d.Record.Subject,
		SagaID:       d.Record.SagaID,
		Mode:         d.Mode,
		Count:        len(refs),
		Refs:         refs,
		PolicyClass:  d.Policy.Class,
		Authority:    d.Policy.Authority,
		MinRetention: d.Policy.MinRetention.String(),
		ApprovedBy:   approvedBy,
		DisposedAt:   at.UTC(),
		Reason:       d.Reason,
	}
	if d.Policy.MaxRetention > 0 {
		rec.MaxRetention = d.Policy.MaxRetention.String()
	}
	return rec, nil
}
