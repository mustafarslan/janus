package registry

import (
	"context"
	"fmt"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/template"
	"google.golang.org/protobuf/proto"
)

// Writing to the registry.
//
// The ordering is the same one the saga runner uses and for the same reason:
// check the transition against the projection, append the event and wait for it
// to be durable, and only then advance the projection. A transition the
// lifecycle rejects is never written, so the log contains only legal history
// and a fold over it can never fail. A transition whose append fails never
// advances the projection, so the projection can never claim a participant is
// active on the strength of an event that did not survive.

// Recorder appends registry events and keeps a projection in step with them.
//
// It is not safe for concurrent use by multiple goroutines. A registry has one
// writer in the deployments this phase targets, and pretending otherwise would
// mean a lock that makes the check-then-append pair look atomic when the log
// behind it is shared with other writers anyway.
type Recorder struct {
	app   *evidence.Appender
	by    evidence.ParticipantRef
	reg   *Registry
	trust TrustStore
}

// NewRecorder returns a recorder writing under the given operator identity.
//
// The trust store may be nil, in which case manifests are registered
// unverified. That is a deliberate escape hatch for a development registry, and
// it is visible in the record: the registration event carries whatever
// signature it was given, and audit reports every manifest whose principal has
// no trusted key rather than passing it silently.
func NewRecorder(app *evidence.Appender, by evidence.ParticipantRef, reg *Registry, trust TrustStore) *Recorder {
	if reg == nil {
		reg = New()
	}
	return &Recorder{app: app, by: by, reg: reg, trust: trust}
}

// Registry returns the projection the recorder maintains.
func (r *Recorder) Registry() *Registry { return r.reg }

// Register enters a manifest as DRAFT.
//
// When the participant already has a registered version, the change record is
// computed here from the two manifests rather than supplied by the caller. A
// registrant that got to describe its own change could call a new model a typo
// fix and skip the revalidation its predecessor demanded.
func (r *Recorder) Register(ctx context.Context, m *Manifest, sig *janusv1.ManifestSignature) (*Entry, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	canonical, err := m.Canonical()
	if err != nil {
		return nil, err
	}
	if r.trust != nil {
		if err := Verify(canonical, m.Identity.Principal, sig, r.trust); err != nil {
			return nil, err
		}
	}

	ev := &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  m.Identity.ParticipantID,
		Version:        m.Version,
		ContentAddress: ContentAddressOf(canonical),
		Manifest:       canonical,
		Signature:      sig,
		By:             actorOf(r.by),
	}
	if prev, ok := r.latestOf(m.Identity.ParticipantID); ok {
		ev.Change = Diff(prev.Manifest, m)
	}

	if err := r.append(ctx, ev); err != nil {
		return nil, err
	}
	e, _ := r.reg.Resolve(m.Identity.ParticipantID, m.Version)
	return e, nil
}

// Evaluate attaches a conformance report.
func (r *Recorder) Evaluate(ctx context.Context, participantID, version string,
	report *janusv1.EvaluationReport) error {

	e, ok := r.reg.resolveEither(participantID, version)
	if !ok {
		return fmt.Errorf("registry: %s@%s is not registered", participantID, version)
	}
	return r.append(ctx, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_EVALUATED,
		ParticipantId:  participantID,
		Version:        version,
		ContentAddress: e.ContentAddress,
		Evaluation:     report,
		By:             actorOf(r.by),
	})
}

// InheritEvaluation carries a predecessor's evidence forward for a change that
// fired no revalidation trigger.
//
// This is a recorded event rather than an implicit rule, because "this version
// was never separately evaluated" is exactly the fact somebody reviewing an
// inventory needs to see. The event says which version the evidence came from
// and carries no checks of its own — copying the predecessor's check results
// would read as though they had been run against these bytes.
func (r *Recorder) InheritEvaluation(ctx context.Context, participantID, version string) error {
	e, ok := r.reg.resolveEither(participantID, version)
	if !ok {
		return fmt.Errorf("registry: %s@%s is not registered", participantID, version)
	}
	if e.Change == nil {
		return fmt.Errorf("registry: %s@%s has no predecessor to inherit an evaluation from",
			participantID, version)
	}
	if len(e.PendingTriggers) > 0 {
		return fmt.Errorf("registry: %s@%s changed %v, which fired %v; that is precisely the "+
			"case where the predecessor's evidence does not carry over", participantID, version,
			e.Change.GetChanged(), e.PendingTriggers)
	}
	prev, ok := r.reg.resolveEither(participantID, e.Change.GetFromVersion())
	if !ok {
		return fmt.Errorf("registry: %s@%s claims to follow %s, which is not registered",
			participantID, version, e.Change.GetFromVersion())
	}
	if prev.Evaluation == nil || !prev.Evaluation.GetPassed() {
		return fmt.Errorf("registry: %s@%s has no passing evaluation to inherit",
			participantID, e.Change.GetFromVersion())
	}

	return r.append(ctx, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_EVALUATED,
		ParticipantId:  participantID,
		Version:        version,
		ContentAddress: e.ContentAddress,
		Evaluation: &janusv1.EvaluationReport{
			Passed:         true,
			InheritedFrom:  prev.Version,
			HarnessVersion: prev.Evaluation.GetHarnessVersion(),
		},
		By: actorOf(r.by),
	})
}

// Activate makes a version the one new sagas pin.
func (r *Recorder) Activate(ctx context.Context, participantID, version string) error {
	e, ok := r.reg.resolveEither(participantID, version)
	if !ok {
		return fmt.Errorf("registry: %s@%s is not registered", participantID, version)
	}
	return r.append(ctx, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_ACTIVATED,
		ParticipantId:  participantID,
		Version:        version,
		ContentAddress: e.ContentAddress,
		By:             actorOf(r.by),
	})
}

// Suspend stops a version for cause.
func (r *Recorder) Suspend(ctx context.Context, participantID, version, reason string) error {
	e, ok := r.reg.resolveEither(participantID, version)
	if !ok {
		return fmt.Errorf("registry: %s@%s is not registered", participantID, version)
	}
	return r.append(ctx, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_SUSPENDED,
		ParticipantId:  participantID,
		Version:        version,
		ContentAddress: e.ContentAddress,
		Reason:         reason,
		By:             actorOf(r.by),
	})
}

// Retire ends a version permanently.
func (r *Recorder) Retire(ctx context.Context, participantID, version, reason string) error {
	e, ok := r.reg.resolveEither(participantID, version)
	if !ok {
		return fmt.Errorf("registry: %s@%s is not registered", participantID, version)
	}
	return r.append(ctx, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_RETIRED,
		ParticipantId:  participantID,
		Version:        version,
		ContentAddress: e.ContentAddress,
		Reason:         reason,
		By:             actorOf(r.by),
	})
}

// RequireRevalidation records that a version owes fresh evidence for reasons
// nothing in the log implies — a calendar review coming due, a supervisor
// asking for one (SS1/23 periodic revalidation).
//
// Change-driven revalidation does not come through here: it is derived from the
// registration event's change record, so that a crash between two appends
// cannot leave a version owing a revalidation nobody recorded.
func (r *Recorder) RequireRevalidation(ctx context.Context, participantID, version string,
	triggers []string, reason string) error {

	e, ok := r.reg.resolveEither(participantID, version)
	if !ok {
		return fmt.Errorf("registry: %s@%s is not registered", participantID, version)
	}
	return r.append(ctx, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REVALIDATION_REQUIRED,
		ParticipantId:  participantID,
		Version:        version,
		ContentAddress: e.ContentAddress,
		Change:         &janusv1.ChangeRecord{TriggersFired: triggers},
		Reason:         reason,
		By:             actorOf(r.by),
	})
}

// append validates the transition, records it durably, and only then advances
// the projection.
func (r *Recorder) append(ctx context.Context, ev *janusv1.RegistryEvent) error {
	// Fold into a copy first, so a refused transition never reaches the log and
	// a rejected event never leaves the projection half-changed.
	if err := r.dryRun(ev); err != nil {
		return err
	}

	payload, err := proto.Marshal(ev)
	if err != nil {
		return fmt.Errorf("registry: encode event: %w", err)
	}
	ref, err := r.app.Append(ctx, evidence.Request{
		Kind:        evidence.KindRegistry,
		Participant: r.by,
		Payload:     payload,
		Labels:      map[string]string{"participant": ev.GetParticipantId()},
	})
	if err != nil {
		return fmt.Errorf("registry: record %s for %s@%s: %w", ev.GetKind(),
			ev.GetParticipantId(), ev.GetVersion(), err)
	}
	return r.reg.Apply(ref.Seq, ref.Wall, ev)
}

// dryRun checks a transition against a throwaway fold of the current state.
//
// Applying to the live projection and rolling back on failure would be smaller
// code and one bad afternoon away from a partial mutation surviving a refusal.
func (r *Recorder) dryRun(ev *janusv1.RegistryEvent) error {
	// The rehearsal's clock is irrelevant: dryRun decides whether a transition
	// is legal, and nothing about legality depends on when it happened. The
	// real time comes from the appender's ref when the event is recorded.
	return r.snapshot().Apply(r.reg.LastSeq()+1, time.Time{}, ev)
}

// snapshot copies the projection so a transition can be tried against it.
//
// It copies entries rather than re-folding, because the recorder does not keep
// the events it wrote. Manifests are immutable once registered, so sharing
// those pointers is safe; everything a transition mutates is copied.
func (r *Recorder) snapshot() *Registry {
	out := New()
	out.lastSeq = r.reg.lastSeq
	for id, byVersion := range r.reg.entries {
		copied := make(map[string]*Entry, len(byVersion))
		for v, e := range byVersion {
			clone := *e
			clone.PendingTriggers = append([]string(nil), e.PendingTriggers...)
			copied[v] = &clone
		}
		out.entries[id] = copied
		out.order[id] = append([]string(nil), r.reg.order[id]...)
	}
	// Templates are copied the same way. Missing them here meant a transition on
	// a template was dry-run against a registry that had never heard of it, so
	// every evaluate and activate after a template registration was refused —
	// by the *rehearsal*, not by the state machine, which is the kind of
	// disagreement that reads as a bug in the thing being rehearsed.
	for id, byVersion := range r.reg.templates {
		copied := make(map[string]*Entry, len(byVersion))
		for v, e := range byVersion {
			clone := *e
			clone.PendingTriggers = append([]string(nil), e.PendingTriggers...)
			copied[v] = &clone
		}
		out.templates[id] = copied
		out.templateOrder[id] = append([]string(nil), r.reg.templateOrder[id]...)
	}
	return out
}

// latestOf returns the most recently registered version of a participant.
func (r *Recorder) latestOf(participantID string) (*Entry, bool) {
	versions := r.reg.order[participantID]
	if len(versions) == 0 {
		return nil, false
	}
	e := r.reg.entries[participantID][versions[len(versions)-1]]
	return e, true
}

// latestTemplateOf is latestOf for the other map. A template is a second
// document type in the same event stream and lives in its own map, so
// every reader of `order`/`entries` needs a twin or a template silently has no
// predecessor -- which is how the audit once passed over templates and
// how activating a successor superseded nobody.
func (r *Recorder) latestTemplateOf(templateID string) (*Entry, bool) {
	versions := r.reg.templateOrder[templateID]
	if len(versions) == 0 {
		return nil, false
	}
	e := r.reg.templates[templateID][versions[len(versions)-1]]
	return e, true
}

func actorOf(p evidence.ParticipantRef) *janusv1.Actor {
	return &janusv1.Actor{
		Participant: &janusv1.ParticipantRef{
			Id:              p.ID,
			ManifestVersion: p.ManifestVersion,
			Principal:       p.Principal,
		},
	}
}

// RegisterTemplate enters a saga template as DRAFT.
//
// It signs and content-addresses the template the same way a manifest is, and
// for the same reason: a template confines what later sagas may do, so an
// unsigned one would be a confinement anybody could write. The trust store is
// consulted against the template's own declared principal, exactly as it is for
// a manifest's.
func (r *Recorder) RegisterTemplate(ctx context.Context, t *template.Template,
	sig *janusv1.ManifestSignature) (*Entry, error) {

	if err := r.childTemplatesExist(t); err != nil {
		return nil, err
	}
	canonical, err := template.Encode(t)
	if err != nil {
		return nil, err
	}
	if r.trust != nil {
		if err := Verify(canonical, t.Principal, sig, r.trust); err != nil {
			return nil, err
		}
	}
	ev := &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  t.TemplateID,
		Version:        t.Version,
		ContentAddress: ContentAddressOf(canonical),
		Template:       canonical,
		Signature:      sig,
		By:             actorOf(r.by),
	}
	if prev, ok := r.latestTemplateOf(t.TemplateID); ok {
		ev.Change = DiffTemplate(prev.Template, t)
	}
	if err := r.append(ctx, ev); err != nil {
		return nil, err
	}
	e, _ := r.reg.ResolveTemplate(t.TemplateID, t.Version)
	return e, nil
}

// childTemplatesExist refuses a template whose steps name a child template the
// registry does not hold.
//
// Here rather than in the fold, and the distinction matters. The fold has to
// replay every log it is given, including one an adversary appended to directly;
// a fold that refused would make such a log unreplayable and take the audit down
// with it, which is the opposite of what the audit is for. This is the same rule
// `Manifest.Validate` states for itself: fail when somebody registers the
// document, not when a saga pins it at three in the morning.
//
// The consequence is an ordering — leaves first, then the parent that names
// them. That is the cost of `ChildTemplate` being checked rather than believed,
// stated here rather than left for an operator to find out from a
// refusal.
func (r *Recorder) childTemplatesExist(t *template.Template) error {
	for _, step := range t.Steps {
		if step.ChildTemplate == "" {
			continue
		}
		if step.ChildTemplate == t.TemplateID {
			return fmt.Errorf("registry: template %s@%s says step %q delegates to itself; a "+
				"template that confines its own children to its own shape describes a tree "+
				"with no bottom", t.TemplateID, t.Version, step.StepID)
		}
		if len(r.reg.TemplateVersions(step.ChildTemplate)) == 0 {
			return fmt.Errorf("registry: template %s@%s says step %q confines its children to "+
				"template %q, which is not registered; a child template is registered before "+
				"the parent that names it, because a constraint naming a document nobody "+
				"holds constrains nothing", t.TemplateID, t.Version, step.StepID,
				step.ChildTemplate)
		}
	}
	return nil
}
