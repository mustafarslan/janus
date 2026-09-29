package retention

import (
	"context"
	"fmt"
	"sort"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"google.golang.org/protobuf/proto"
)

// A legal hold is a record in the log, not an entry in a map.
//
// It was the second: `Engine.holds` was in-memory, so a hold placed by an
// accountable person for a named matter ceased silently when the process
// restarted, and nothing anywhere said it had ever existed. For a configuration
// flag that would be a limitation. For a litigation hold it is an incident —
// the deployment resumes destroying the records a court told it to keep, and
// discovers this, if ever, from the other side.
//
// So placing and releasing are events, folded like everything else (Janus's own
// administration is evidence too). The two facts a lawyer
// needs are when destruction stopped and when it was allowed to resume, and
// both are now answerable about the past rather than only about now.
//
// Disposal itself remains unbuilt.
// This is the half that could land independently, because a hold is an evidence
// kind and a fold rather than a disposal mechanism, and because what a hold
// freezes today is `janus-tier erase`, which is built and irreversible.

// Recorder appends legal-hold decisions to the log.
type Recorder struct {
	app *evidence.Appender
	by  evidence.ParticipantRef
}

// NewRecorder returns a recorder for legal-hold events.
func NewRecorder(app *evidence.Appender, by evidence.ParticipantRef) *Recorder {
	return &Recorder{app: app, by: by}
}

// Place records a legal hold.
//
// The hold is validated against the current fold before it is written, so the
// log cannot come to contain two placements of one id — the same rule
// `Runner.record` keeps for saga events, and for the same reason: a log that
// can only contain legal history is one a reader never has to reconcile.
func (r *Recorder) Place(ctx context.Context, dir string, h LegalHold) error {
	held, err := FoldHolds(dir)
	if err != nil {
		return err
	}
	if err := held.place(h); err != nil {
		return err
	}
	return r.append(ctx, &janusv1.LegalHoldEvent{
		Kind:     janusv1.LegalHoldEvent_KIND_PLACED,
		HoldId:   h.ID,
		Matter:   h.Matter,
		Actor:    h.PlacedBy,
		SagaIds:  h.Scope.SagaIDs,
		Subjects: h.Scope.Subjects,
		Classes:  classStrings(h.Scope.Classes),
		Tenants:  h.Scope.Tenants,
	})
}

// Release ends a legal hold, recording who allowed disposal to resume and why.
func (r *Recorder) Release(ctx context.Context, dir, id, releasedBy, reason string, at time.Time) error {
	held, err := FoldHolds(dir)
	if err != nil {
		return err
	}
	if err := held.release(id, releasedBy, at); err != nil {
		return err
	}
	return r.append(ctx, &janusv1.LegalHoldEvent{
		Kind:   janusv1.LegalHoldEvent_KIND_RELEASED,
		HoldId: id,
		Actor:  releasedBy,
		Reason: reason,
	})
}

// append writes one hold event.
//
// Request.Subject is deliberately left empty even for a hold scoped to a
// subject. Setting it would seal the payload under that subject's data
// encryption key, so `janus-tier erase` on the subject would destroy the hold
// that was protecting them — unreadable at exactly the moment it mattered.
// Registry events are excluded from encryption for the same reason: a record
// about the administration of the system is not a record about a person, even
// when it names one.
func (r *Recorder) append(ctx context.Context, event *janusv1.LegalHoldEvent) error {
	payload, err := proto.Marshal(event)
	if err != nil {
		return fmt.Errorf("retention: encoding the legal-hold event: %w", err)
	}
	_, err = r.app.Append(ctx, evidence.Request{
		Kind: evidence.KindLegalHold, Participant: r.by, Payload: payload,
	})
	return err
}

// Holds is the folded set of legal holds.
type Holds struct {
	byID map[string]LegalHold
}

// FoldHolds rebuilds every legal hold from an evidence directory.
//
// This is what makes a hold survive a restart, and it is the whole of the
// change: the engine's decision logic was always right, and only its source of
// truth was wrong.
func FoldHolds(dir string, opts ...evidence.ReadOption) (Holds, error) {
	h := Holds{byID: map[string]LegalHold{}}
	if err := evidence.Walk(dir, func(hdr evidence.EventHeader, rec segment.Record) error {
		if hdr.Kind != evidence.KindLegalHold {
			return nil
		}
		// The same verification every fold in this repository does before
		// trusting a payload. A hold decides whether evidence may be destroyed;
		// reading it from unverified bytes would let a tampered log lift one.
		if len(rec.Payload) > 0 {
			if got := evidence.HashPayload(rec.Payload); got != hdr.PayloadHash {
				return fmt.Errorf("seq %d: payload does not match its recorded hash", hdr.Seq)
			}
		}
		if want := evidence.ComputeChainHash(rec.Prev, hdr.PayloadHash, rec.Header); want != rec.Chain {
			return fmt.Errorf("seq %d: chain hash mismatch", hdr.Seq)
		}
		var ev janusv1.LegalHoldEvent
		if err := proto.Unmarshal(rec.Payload, &ev); err != nil {
			return fmt.Errorf("seq %d: decode LegalHoldEvent: %w", hdr.Seq, err)
		}
		return h.apply(&ev, hdr.TS.Wall())
	}, opts...); err != nil {
		return Holds{}, err
	}
	return h, nil
}

// apply folds one recorded hold event.
func (h *Holds) apply(ev *janusv1.LegalHoldEvent, at time.Time) error {
	switch ev.GetKind() {
	case janusv1.LegalHoldEvent_KIND_PLACED:
		return h.place(LegalHold{
			ID:       ev.GetHoldId(),
			Matter:   ev.GetMatter(),
			PlacedBy: ev.GetActor(),
			PlacedAt: at,
			Scope: Scope{
				SagaIDs:  ev.GetSagaIds(),
				Subjects: ev.GetSubjects(),
				Classes:  classesFrom(ev.GetClasses()),
				Tenants:  ev.GetTenants(),
			},
		})
	case janusv1.LegalHoldEvent_KIND_RELEASED:
		return h.release(ev.GetHoldId(), ev.GetActor(), at)
	default:
		return fmt.Errorf("retention: legal-hold event %q says neither placed nor released",
			ev.GetHoldId())
	}
}

func (h *Holds) place(v LegalHold) error {
	if v.ID == "" {
		return fmt.Errorf("retention: a legal hold needs an id")
	}
	if v.Matter == "" || v.PlacedBy == "" {
		return fmt.Errorf("retention: legal hold %s needs a matter and a person placing it", v.ID)
	}
	if v.PlacedAt.IsZero() {
		return fmt.Errorf("retention: legal hold %s needs a placement time", v.ID)
	}
	if h.byID == nil {
		h.byID = map[string]LegalHold{}
	}
	if _, exists := h.byID[v.ID]; exists {
		return fmt.Errorf("retention: legal hold %s already exists", v.ID)
	}
	h.byID[v.ID] = v
	return nil
}

func (h *Holds) release(id, releasedBy string, at time.Time) error {
	if releasedBy == "" {
		return fmt.Errorf("retention: releasing hold %s requires the person releasing it", id)
	}
	v, ok := h.byID[id]
	if !ok {
		return fmt.Errorf("retention: no legal hold %s", id)
	}
	if v.ReleasedAt != nil {
		return fmt.Errorf("retention: legal hold %s was already released at %s",
			id, v.ReleasedAt.Format(time.RFC3339))
	}
	v.ReleasedAt = &at
	v.ReleasedBy = releasedBy
	h.byID[id] = v
	return nil
}

// All returns every hold ever placed, released or not, sorted by id.
//
// Released holds are kept rather than dropped: "this was held until March" is
// the fact that explains why records outlived their ceiling, and a set that
// forgot it would leave nobody able to say why.
func (h Holds) All() []LegalHold {
	out := make([]LegalHold, 0, len(h.byID))
	for _, v := range h.byID {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Active returns the holds in force at t.
func (h Holds) Active(t time.Time) []LegalHold {
	var out []LegalHold
	for _, v := range h.All() {
		if v.Active(t) {
			out = append(out, v)
		}
	}
	return out
}

// Covering returns the active holds that freeze a record.
func (h Holds) Covering(r Record, t time.Time) []LegalHold {
	var out []LegalHold
	for _, v := range h.Active(t) {
		if v.Scope.Empty() || v.Scope.Matches(r) {
			out = append(out, v)
		}
	}
	return out
}

// CoveringSubject returns the active holds that freeze a data subject.
//
// Its own method rather than a Record with only the subject set, because a
// scope that names sagas or classes and not this subject must not be read as
// covering them: `Scope.Matches` takes an unset field as "any", which is right
// for a record being considered for disposal and wrong for the question
// `janus-tier erase` asks, which is about one person and nothing else.
func (h Holds) CoveringSubject(subject string, t time.Time) []LegalHold {
	var out []LegalHold
	for _, v := range h.Active(t) {
		if v.Scope.Empty() {
			// An unscoped hold freezes everything, which is occasionally what a
			// supervisor demands, and it freezes this subject too.
			out = append(out, v)
			continue
		}
		for _, s := range v.Scope.Subjects {
			if s == subject {
				out = append(out, v)
				break
			}
		}
	}
	return out
}

func classStrings(cs []Class) []string {
	if len(cs) == 0 {
		return nil
	}
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, string(c))
	}
	return out
}

func classesFrom(ss []string) []Class {
	if len(ss) == 0 {
		return nil
	}
	out := make([]Class, 0, len(ss))
	for _, s := range ss {
		out = append(out, Class(s))
	}
	return out
}
