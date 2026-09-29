package registry

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/template"
	"google.golang.org/protobuf/proto"
)

// Asking the log whether its registry holds up.
//
// The registry decides what a participant is allowed to be: which actions
// exist, what each one does to the world, and therefore which gates apply. A
// registry service with a bug — or one doing what somebody told it to — can
// record an activation nothing evaluated, a change record that understates what
// changed, or a second version of a pinned string with different content. Each
// of those looks exactly like an honest record from the inside.
//
// So the check happens here, afterwards, from the log alone. Every input is
// recorded: the manifest bytes, the signature, the evaluation report, the
// change record, and the pins every saga recorded when it began. Audit re-folds
// the registry, recomputes what should have been derived, and compares. It also
// crosses the two logs — a saga's pins against the registry as it stood at the
// sequence that saga began — because "the manifest version is resolvable at
// replay time" (invariant I8) is a claim about a moment, not about now.
//
// Nothing outside the log is needed except the trust store, which by design
// travels separately: a signature checked against keys carried in the same
// artifact proves nothing.

// FindingKind classifies what is wrong.
type FindingKind string

const (
	// FindingContentMismatch means a recorded content address does not match
	// the bytes recorded beside it. Every pin to that version resolves to
	// something other than what the registry says it resolves to.
	FindingContentMismatch FindingKind = "CONTENT_MISMATCH"
	// FindingVersionReused means one version string was registered twice with
	// different content. This is the failure that makes pinning decorative.
	FindingVersionReused FindingKind = "VERSION_REUSED"
	// FindingSignatureUnverified means a manifest's signature does not verify
	// under a key trusted for its principal.
	FindingSignatureUnverified FindingKind = "SIGNATURE_UNVERIFIED"
	// FindingActivatedWithoutEvaluation means a version was made active without
	// passing conformance evidence covering what it changed.
	FindingActivatedWithoutEvaluation FindingKind = "ACTIVATED_WITHOUT_EVALUATION"
	// FindingChangeUnderstated means the recorded change record does not match
	// the diff of the two manifests it sits between — the way a registrant
	// dodges the revalidation its predecessor demanded.
	FindingChangeUnderstated FindingKind = "CHANGE_UNDERSTATED"
	// FindingIllegalTransition means the log contains a lifecycle transition
	// that is not legal from where the version stood.
	FindingIllegalTransition FindingKind = "ILLEGAL_TRANSITION"
	// FindingPinUnresolvable means a saga pinned a manifest version that was
	// not registered, or not active, when the saga began (invariant I8).
	FindingPinUnresolvable FindingKind = "PIN_UNRESOLVABLE"
	// FindingEffectClassMismatch means a step ran under a different effect
	// class than the manifest it pinned declares for that action — the
	// difference between a gated wire and an ungated one.
	FindingEffectClassMismatch FindingKind = "EFFECT_CLASS_MISMATCH"
	// FindingChildTemplateUnresolvable means a template step confines its
	// children to a template the registry does not hold. The recorder
	// refuses to write one, so a log containing it was appended to directly.
	//
	// It is fail-closed — no child can ever be admitted under that step, because
	// admission resolves the same reference — so this is not a safety hole. It
	// is reported because a step that refuses every spawn reads to an operator
	// as the daemon misbehaving, and the audit is where "this log says something
	// the recorder would not have written" belongs.
	FindingChildTemplateUnresolvable FindingKind = "CHILD_TEMPLATE_UNRESOLVABLE"
	// FindingParentEvidencePredatesChild means a template is ACTIVE on evidence
	// established before a template it delegates to changed shape.
	// Its report covers a tree one of whose branches no longer looks like that.
	FindingParentEvidencePredatesChild FindingKind = "PARENT_EVIDENCE_PREDATES_CHILD"
)

// Finding is one thing wrong with the registry as the log records it.
type Finding struct {
	Kind          FindingKind
	ParticipantID string
	Version       string
	SagaID        string
	StepID        string
	Seq           uint64
	Detail        string
}

func (f Finding) String() string {
	where := f.ParticipantID
	if f.Version != "" {
		where += "@" + f.Version
	}
	if f.SagaID != "" {
		where = fmt.Sprintf("%s (%s/%s)", where, f.SagaID, f.StepID)
	}
	if where == "" {
		where = "registry"
	}
	if f.Seq > 0 {
		where = fmt.Sprintf("%s at seq %d", where, f.Seq)
	}
	return fmt.Sprintf("%s: %s: %s", f.Kind, where, f.Detail)
}

// Report is the outcome of auditing a log's registry.
type Report struct {
	// Events is how many registry events were folded.
	Events int
	// Versions is how many manifest versions the log registers.
	Versions int
	// Pins is how many saga-to-manifest pins were resolved against the
	// registry as it stood when each saga began.
	Pins int
	// Templates is how many template versions the log registers. Counted
	// separately from Versions because they are a second document type in the
	// same event stream, and because a reader has to be able to see
	// that this audit looked at them at all — it used to skip every one in
	// silence.
	Templates int
	// Unchecked counts manifests and templates whose signature could not be
	// checked because no key is trusted for their principal. It is reported as
	// a number rather than as findings: with no trust store at all, every
	// document is unchecked, and a page of identical findings would bury the
	// real ones.
	Unchecked int
	// TemplateEvaluationsHandAssembled counts template EVALUATED events whose
	// report does not carry the template harness's version string, so
	// it was assembled by somebody rather than produced by re-reading the runs
	// the template names. Not a finding: a manifest evaluation may be
	// hand-assembled too, and a deployment may hold templates evaluated before
	// the harness existed. Reported because the alternative is the audit
	// passing over it, which is the symptom this count exists to prevent.
	TemplateEvaluationsHandAssembled int
	Findings                         []Finding
}

// OK reports whether the log's registry holds up.
func (r Report) OK() bool { return len(r.Findings) == 0 }

func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "registry audit: %d events, %d manifest version(s), %d template version(s), "+
		"%d saga pin(s) re-derived from the log\n", r.Events, r.Versions, r.Templates, r.Pins)
	if r.Unchecked > 0 {
		fmt.Fprintf(&b, "  %d signature(s) not checked: no trusted key for the "+
			"principal that signed them\n", r.Unchecked)
	}
	if r.TemplateEvaluationsHandAssembled > 0 {
		fmt.Fprintf(&b, "  %d template evaluation(s) assembled by hand: the report does not "+
			"carry %s, so nothing re-read the runs the template names\n",
			r.TemplateEvaluationsHandAssembled, template.HarnessVersion)
	}
	if len(r.Findings) == 0 {
		if r.Events == 0 {
			b.WriteString("  the log records no registry events, so nothing in it pins a " +
				"manifest to a declaration\n")
			return b.String()
		}
		b.WriteString("  every lifecycle transition, change record and saga pin follows from " +
			"the log\n")
		return b.String()
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  %s\n", f)
	}
	return b.String()
}

// Audit re-derives the registry from an evidence directory.
//
// The trust store may be nil, in which case signatures are counted as unchecked
// rather than reported as findings.
func Audit(dir string, trust TrustStore) (Report, error) {
	records, err := walk(dir)
	if err != nil {
		return Report{}, err
	}
	return auditRecords(records, trust)
}

// record is one event this audit cares about, in log order.
type record struct {
	seq uint64
	// wall is the recorded time, carried so the folded registry gets the same
	// revalidation anchor an ordinary reader would.
	wall    time.Time
	kind    evidence.Kind
	payload []byte
}

// auditRecords runs the audit over already-loaded records, so a test can hand
// it a history it constructed rather than one it had to write to disk.
func auditRecords(records []record, trust TrustStore) (Report, error) {
	var rep Report
	reg := New()

	for _, rec := range records {
		switch rec.kind {
		case evidence.KindRegistry:
			rep.Events++
			auditRegistryEvent(&rep, reg, rec, trust)
		case evidence.KindSagaBegin:
			auditSagaBegin(&rep, reg, rec)
		case evidence.KindStepPrepare:
			auditStepPrepare(&rep, reg, rec)
		}
	}

	for _, id := range reg.Participants() {
		rep.Versions += len(reg.Versions(id))
	}
	// Counted, because the totals line is how a reader judges whether the audit
	// saw what they think it saw — and it used to report a log full of
	// templates as holding none.
	for _, id := range reg.Templates() {
		rep.Templates += len(reg.TemplateVersions(id))
	}
	auditChildrenReshapedUnderTheirParents(&rep, reg)
	sort.SliceStable(rep.Findings, func(i, j int) bool { return rep.Findings[i].Seq < rep.Findings[j].Seq })
	return rep, nil
}

func auditRegistryEvent(rep *Report, reg *Registry, rec record, trust TrustStore) {
	var ev janusv1.RegistryEvent
	if err := proto.Unmarshal(rec.payload, &ev); err != nil {
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingIllegalTransition, Seq: rec.seq,
			Detail: fmt.Sprintf("registry event does not decode: %v", err),
		})
		return
	}

	if ev.GetKind() == janusv1.RegistryEvent_KIND_REGISTERED {
		// Checked before folding: the fold refuses a second registration of a
		// version under different bytes, and that refusal is the single most
		// serious thing this audit can find — every saga that pinned the string
		// becomes ambiguous — so it is named rather than left as "illegal".
		// resolveEither and registeredBytes, not Resolve and GetManifest: a
		// template lives in the other map and carries its document in the other
		// field, so asking the participant map about a template found nothing
		// and this check never ran for one. Asking with the wrong bytes would
		// be worse than not asking — every template registration would hash to
		// the empty address and report itself as reused.
		if prior, ok := reg.resolveEither(ev.GetParticipantId(), ev.GetVersion()); ok &&
			prior.ContentAddress != ContentAddressOf(registeredBytes(&ev)) {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingVersionReused, ParticipantID: ev.GetParticipantId(),
				Version: ev.GetVersion(), Seq: rec.seq,
				Detail: fmt.Sprintf("registered again with different content (%s, was %s); every "+
					"saga that pinned this version resolves to two different declarations",
					shortAddress(ContentAddressOf(registeredBytes(&ev))),
					shortAddress(prior.ContentAddress)),
			})
			return
		}
		auditRegistration(rep, reg, rec.seq, &ev, trust)
	}
	if ev.GetKind() == janusv1.RegistryEvent_KIND_EVALUATED {
		countHandAssembled(rep, reg, &ev)
	}
	if ev.GetKind() == janusv1.RegistryEvent_KIND_ACTIVATED {
		// Checked before folding, because the fold refuses the transition and
		// the refusal alone would not say what was missing.
		if e, ok := reg.resolveEither(ev.GetParticipantId(), ev.GetVersion()); ok {
			if err := canActivate(e); err != nil {
				rep.Findings = append(rep.Findings, Finding{
					Kind: FindingActivatedWithoutEvaluation, ParticipantID: ev.GetParticipantId(),
					Version: ev.GetVersion(), Seq: rec.seq, Detail: err.Error(),
				})
			}
		}
	}

	if err := reg.Apply(rec.seq, rec.wall, &ev); err != nil {
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingIllegalTransition, ParticipantID: ev.GetParticipantId(),
			Version: ev.GetVersion(), Seq: rec.seq, Detail: err.Error(),
		})
	}
}

// countHandAssembled counts template evaluations no harness produced.
//
// Item 55's own "what to do if it goes wrong" is the symptom this makes visible:
// *"a registry whose templates all carry identical evaluation reports with the
// same HarnessVersion string and TriggersCovered naming every trigger there is.
// That is not coverage, it is a constant, and registry.Audit cannot tell the
// difference."* It can now, for the half that is mechanical — the harness stamps
// its own version string, so a report that does not carry it was assembled by
// hand.
//
// A count rather than findings, the way `Unchecked` is. `Recorder.Evaluate`
// accepts any report for a manifest too, and requiring a harness for one
// document and not the other would be a rule with no argument behind it; a
// deployment may legitimately have templates evaluated before the harness existed.
// What must not happen is the audit passing over it in silence.
//
// An *inherited* evaluation (the path for a change that fired no trigger)
// is counted or not according to what it inherited: `InheritEvaluation` copies
// the predecessor's `HarnessVersion` forward, so a version inheriting from a
// harness-produced verdict is not counted and one inheriting from a typed string
// is. That is the right answer for the line this number prints — if nothing ever
// re-read the runs, nothing re-read them, and carrying the fact forward is what
// an inheritance is for.
//
// It does not check the converse. A report *carrying* the harness version was
// not necessarily produced by the harness — anyone who can append can copy the
// string — and saying otherwise would be the same overclaim in the other
// direction. What the string buys is that a hand-assembled report has to lie on
// purpose rather than merely omit.
func countHandAssembled(rep *Report, reg *Registry, ev *janusv1.RegistryEvent) {
	if _, isTemplate := reg.ResolveTemplate(ev.GetParticipantId(), ev.GetVersion()); !isTemplate {
		return
	}
	if ev.GetEvaluation().GetHarnessVersion() != template.HarnessVersion {
		rep.TemplateEvaluationsHandAssembled++
	}
}

// registeredBytes returns the document a registration carries, whichever kind
// it is. Exactly one of the two is set on a registration; the fold refuses an
// event with both.
func registeredBytes(ev *janusv1.RegistryEvent) []byte {
	if len(ev.GetTemplate()) > 0 {
		return ev.GetTemplate()
	}
	return ev.GetManifest()
}

// auditTemplateRegistration checks a template registration the way
// auditRegistration checks a manifest one, as far as the vocabulary reaches.
//
// The signature half is the same question and gets the same answer: a template
// is signed by a principal and `Verify` takes canonical bytes, so nothing here
// is template-specific except which document is canonicalised.
//
// The change half is **not** the same question, and is answered with a diff of
// its own rather than approximated with the manifest one. `Diff` compares models,
// prompts and effect classes; a template's shape is a different vocabulary with
// different triggers, and running the manifest diff over two templates would
// find its nine scalar fields equal because neither document has them, and fire
// nothing for the step that moved.
func auditTemplateRegistration(rep *Report, reg *Registry, seq uint64,
	ev *janusv1.RegistryEvent, trust TrustStore) {

	t, err := template.Decode(ev.GetTemplate())
	if err != nil {
		// The fold reports this too; returning here avoids saying it twice.
		return
	}

	switch {
	case trust == nil || !trust.Knows(t.Principal):
		rep.Unchecked++
	default:
		if err := Verify(ev.GetTemplate(), t.Principal, ev.GetSignature(), trust); err != nil {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingSignatureUnverified, ParticipantID: t.TemplateID,
				Version: t.Version, Seq: seq, Detail: err.Error(),
			})
		}
	}

	// Resolved against the registry as it stood *before* this event, which is
	// the same rule the recorder applies: a child template is registered before
	// the parent that names it.
	for _, step := range t.Steps {
		if step.ChildTemplate == "" {
			continue
		}
		if len(reg.TemplateVersions(step.ChildTemplate)) == 0 {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingChildTemplateUnresolvable, ParticipantID: t.TemplateID,
				Version: t.Version, Seq: seq,
				Detail: fmt.Sprintf("step %q confines its children to template %q, which no "+
					"earlier event registers; RegisterTemplate refuses this, so the event was "+
					"appended without it", step.StepID, step.ChildTemplate),
			})
		}
	}

	auditTemplateChangeRecord(rep, reg, seq, ev, t)
}

// auditTemplateChangeRecord recomputes the change record from the two templates
// rather than believing the one the registrant wrote.
//
// This is the same discipline `auditChangeRecord` applies to manifests, and it
// is the reason a diff belongs in code rather than in a registration form: a
// registrant who could describe its own change could call a step swapped for a
// different participant a rename, and inherit an evaluation that never saw it.
func auditTemplateChangeRecord(rep *Report, reg *Registry, seq uint64,
	ev *janusv1.RegistryEvent, t *template.Template) {

	prev, ok := previousTemplateOf(reg, t.TemplateID)
	if !ok {
		if ev.GetChange() != nil {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingChangeUnderstated, ParticipantID: t.TemplateID,
				Version: t.Version, Seq: seq,
				Detail: fmt.Sprintf("carries a change record naming predecessor %q, but this is "+
					"the template's first registered version",
					ev.GetChange().GetFromVersion()),
			})
		}
		return
	}

	want := DiffTemplate(prev.Template, t)
	got := ev.GetChange()
	switch {
	case got == nil:
		if len(want.GetChanged()) == 0 {
			// Two identical shapes under different version numbers. The
			// recorder writes an empty record rather than none, but a log from
			// before template change records has none at all and nothing was understated.
			return
		}
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingChangeUnderstated, ParticipantID: t.TemplateID,
			Version: t.Version, Seq: seq,
			Detail: fmt.Sprintf("supersedes %s and records no change record; the change against "+
				"%v would have fired %v", prev.Version, want.GetChanged(), want.GetTriggersFired()),
		})
	case got.GetFromVersion() != want.GetFromVersion(),
		!slices.Equal(got.GetChanged(), want.GetChanged()),
		!slices.Equal(got.GetTriggersFired(), want.GetTriggersFired()):
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingChangeUnderstated, ParticipantID: t.TemplateID,
			Version: t.Version, Seq: seq,
			Detail: fmt.Sprintf("records a change from %q of %v firing %v; the two templates "+
				"differ in %v, which fires %v", got.GetFromVersion(), got.GetChanged(),
				got.GetTriggersFired(), want.GetChanged(), want.GetTriggersFired()),
		})
	}
}

// previousTemplateOf returns the most recently registered version of a template.
func previousTemplateOf(reg *Registry, templateID string) (*Entry, bool) {
	versions := reg.templateOrder[templateID]
	if len(versions) == 0 {
		return nil, false
	}
	return reg.templates[templateID][versions[len(versions)-1]], true
}

// auditRegistration checks everything about a registration that the fold takes
// on trust: the signature, and whether the change record describes the change.
func auditRegistration(rep *Report, reg *Registry, seq uint64, ev *janusv1.RegistryEvent,
	trust TrustStore) {

	// Which document this registers decides everything below, and the previous
	// version of this function did not ask. It began with DecodeManifest, which
	// fails on a template event because the manifest field is empty, and
	// returned — under a comment saying "the fold reports this too", which is
	// true of a malformed manifest and false of a well-formed template: the
	// fold takes the template path and succeeds. So every template registration
	// passed through this audit with its signature unchecked and nothing said.
	if len(ev.GetTemplate()) > 0 {
		auditTemplateRegistration(rep, reg, seq, ev, trust)
		return
	}

	m, err := DecodeManifest(ev.GetManifest())
	if err != nil {
		// The fold reports this too; returning here avoids saying it twice.
		return
	}
	if addr := ContentAddressOf(ev.GetManifest()); addr != ev.GetContentAddress() {
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingContentMismatch, ParticipantID: m.Identity.ParticipantID,
			Version: m.Version, Seq: seq,
			Detail: fmt.Sprintf("the event records content address %s for bytes that hash to %s",
				shortAddress(ev.GetContentAddress()), shortAddress(addr)),
		})
	}

	switch {
	case trust == nil || !trust.Knows(m.Identity.Principal):
		rep.Unchecked++
	default:
		if err := Verify(ev.GetManifest(), m.Identity.Principal, ev.GetSignature(), trust); err != nil {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingSignatureUnverified, ParticipantID: m.Identity.ParticipantID,
				Version: m.Version, Seq: seq, Detail: err.Error(),
			})
		}
	}

	// The change record decides whether a revalidation was owed, so a
	// registrant that writes its own is a registrant that can excuse itself.
	// Recomputing the diff from the two manifests is the whole check.
	prev, ok := previousOf(reg, m.Identity.ParticipantID)
	if !ok {
		if ev.GetChange() != nil {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingChangeUnderstated, ParticipantID: m.Identity.ParticipantID,
				Version: m.Version, Seq: seq,
				Detail: fmt.Sprintf("carries a change record naming predecessor %q, but this is "+
					"the participant's first registered version",
					ev.GetChange().GetFromVersion()),
			})
		}
		return
	}

	want := Diff(prev.Manifest, m)
	got := ev.GetChange()
	switch {
	case got == nil:
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingChangeUnderstated, ParticipantID: m.Identity.ParticipantID,
			Version: m.Version, Seq: seq,
			Detail: fmt.Sprintf("supersedes %s and records no change record; the change against "+
				"%v would have fired %v", prev.Version, want.GetChanged(), want.GetTriggersFired()),
		})
	case got.GetFromVersion() != want.GetFromVersion(),
		!slices.Equal(got.GetChanged(), want.GetChanged()),
		!slices.Equal(got.GetTriggersFired(), want.GetTriggersFired()):
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingChangeUnderstated, ParticipantID: m.Identity.ParticipantID,
			Version: m.Version, Seq: seq,
			Detail: fmt.Sprintf("records a change from %q of %v firing %v; the two manifests "+
				"differ in %v, which fires %v", got.GetFromVersion(), got.GetChanged(),
				got.GetTriggersFired(), want.GetChanged(), want.GetTriggersFired()),
		})
	}
}

// previousOf returns the most recently registered version of a participant.
func previousOf(reg *Registry, participantID string) (*Entry, bool) {
	versions := reg.order[participantID]
	if len(versions) == 0 {
		return nil, false
	}
	return reg.entries[participantID][versions[len(versions)-1]], true
}

// auditSagaBegin crosses the saga log against the registry as it stood at this
// sequence.
func auditSagaBegin(rep *Report, reg *Registry, rec record) {
	if len(reg.Participants()) == 0 {
		// A log with no registry in it pins nothing to anything. Reporting a
		// finding per saga would say the same thing hundreds of times; the
		// report says it once, as a count of zero registry events.
		return
	}
	var begin janusv1.SagaBegin
	if err := proto.Unmarshal(rec.payload, &begin); err != nil {
		return
	}

	for _, step := range begin.GetPlan() {
		participant := step.GetParticipant()
		version, pinned := begin.GetManifestPins()[participant]
		rep.Pins++
		if !pinned {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingPinUnresolvable, ParticipantID: participant, SagaID: begin.GetSagaId(),
				StepID: step.GetStepId(), Seq: rec.seq,
				Detail: "the saga records no manifest version for this participant, so nothing " +
					"says which declaration the step ran under (I8)",
			})
			continue
		}
		e, ok := reg.Resolve(participant, version)
		if !ok {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingPinUnresolvable, ParticipantID: participant, Version: version,
				SagaID: begin.GetSagaId(), StepID: step.GetStepId(), Seq: rec.seq,
				Detail: "pinned a manifest version the registry had never registered at this point",
			})
			continue
		}
		if e.State != StateActive {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingPinUnresolvable, ParticipantID: participant, Version: version,
				SagaID: begin.GetSagaId(), StepID: step.GetStepId(), Seq: rec.seq,
				Detail: fmt.Sprintf("the saga began against a version that was %s at the time",
					e.State),
			})
			continue
		}
		if want, known := e.Manifest.EffectClassOf(step.GetAction()); !known {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingEffectClassMismatch, ParticipantID: participant, Version: version,
				SagaID: begin.GetSagaId(), StepID: step.GetStepId(), Seq: rec.seq,
				Detail: fmt.Sprintf("plans action %q, which %s@%s does not declare",
					step.GetAction(), participant, version),
			})
		} else if want != step.GetEffectClass() {
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingEffectClassMismatch, ParticipantID: participant, Version: version,
				SagaID: begin.GetSagaId(), StepID: step.GetStepId(), Seq: rec.seq,
				Detail: fmt.Sprintf("plans %q as %s; the pinned manifest registers it as %s",
					step.GetAction(), ShortClass(step.GetEffectClass()), ShortClass(want)),
			})
		}
	}
}

// auditStepPrepare checks the class a step actually ran under.
//
// The plan is what a saga intended; a STEP_PREPARE is what happened. A step
// that prepared under a class its own plan did not declare is how a gate gets
// skipped after admission has already passed.
func auditStepPrepare(rep *Report, reg *Registry, rec record) {
	if len(reg.Participants()) == 0 {
		return
	}
	var prep janusv1.StepPrepare
	if err := proto.Unmarshal(rec.payload, &prep); err != nil {
		return
	}
	ref := prep.GetParticipant()
	if ref.GetId() == "" || ref.GetManifestVersion() == "" {
		return
	}
	e, ok := reg.Resolve(ref.GetId(), ref.GetManifestVersion())
	if !ok {
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingPinUnresolvable, ParticipantID: ref.GetId(),
			Version: ref.GetManifestVersion(), SagaID: prep.GetSagaId(),
			StepID: prep.GetStepId(), Seq: rec.seq,
			Detail: "the step ran under a manifest version the registry had never registered",
		})
		return
	}
	want, known := e.Manifest.EffectClassOf(prep.GetAction())
	if !known {
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingEffectClassMismatch, ParticipantID: ref.GetId(),
			Version: ref.GetManifestVersion(), SagaID: prep.GetSagaId(),
			StepID: prep.GetStepId(), Seq: rec.seq,
			Detail: fmt.Sprintf("ran action %q, which the pinned manifest does not declare",
				prep.GetAction()),
		})
		return
	}
	if want != prep.GetEffectClass() {
		rep.Findings = append(rep.Findings, Finding{
			Kind: FindingEffectClassMismatch, ParticipantID: ref.GetId(),
			Version: ref.GetManifestVersion(), SagaID: prep.GetSagaId(),
			StepID: prep.GetStepId(), Seq: rec.seq,
			Detail: fmt.Sprintf("ran %q as %s; the pinned manifest registers it as %s",
				prep.GetAction(), ShortClass(prep.GetEffectClass()), ShortClass(want)),
		})
	}
}

// walk reads the events an audit needs out of an evidence directory, in log
// order, verifying each record against its own hashes on the way past.
func walk(dir string) ([]record, error) {
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return nil, err
	}
	var out []record
	for _, id := range ids {
		path := segment.Path(dir, id)
		insp, err := segment.Inspect(path)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", path, err)
		}
		if insp.Torn {
			return nil, fmt.Errorf("segment %d ends in an incomplete record; recover the log "+
				"before auditing it", id)
		}
		for i, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				return nil, fmt.Errorf("segment %d record %d: %w", id, i, err)
			}
			switch h.Kind {
			case evidence.KindRegistry, evidence.KindSagaBegin, evidence.KindStepPrepare:
			default:
				continue
			}
			if len(rec.Payload) > 0 {
				if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
					return nil, fmt.Errorf("segment %d seq %d: payload does not match its "+
						"recorded hash", id, h.Seq)
				}
			}
			if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
				return nil, fmt.Errorf("segment %d seq %d: chain hash mismatch", id, h.Seq)
			}
			out = append(out, record{seq: h.Seq, wall: h.TS.Wall(), kind: h.Kind, payload: rec.Payload})
		}
	}
	return out, nil
}

// auditChildrenReshapedUnderTheirParents names a parent template still admitting
// sagas on evidence that predates a reshape of a template it delegates to.
//
// # Why this runs after the fold rather than per event
//
// Every other check here asks about one document against its own predecessor,
// and can be made as the event goes past. This asks about two documents against
// each other, and the answer changes when *either* moves — so the only moment it
// is well defined is once the whole log has been read.
//
// # What makes it a finding rather than a count
//
// The parent is ACTIVE, which means `AdmitFor` is admitting sagas under it right
// now, and admission confines each of their children to the template this parent
// names. So a saga beginning today is confined to a shape the parent's evidence
// never covered. That is the same category as an understated change record, not
// the same category as a signature nobody could check.
//
// # Why one hop is enough
//
// The harness's `children_match_declared` compares a template's source runs against
// the plans of the sub-sagas those runs *actually spawned*, which are its
// immediate children. A grandparent's evidence says "my source runs spawned
// parent-shaped children"; it says nothing about grandchild shape, because
// nothing in it looked. Evidence is per edge, so a finding per edge is complete
// — and a transitive rule is not needed to *observe*
// this, only to enforce it.
func auditChildrenReshapedUnderTheirParents(rep *Report, reg *Registry) {
	for _, parentID := range reg.Templates() {
		parent, active := reg.ActiveTemplate(parentID)
		if !active {
			// A superseded or draft parent admits nothing, so nobody is being
			// confined to a shape on the strength of its evidence. Naming it
			// would be reporting history.
			continue
		}
		for _, step := range parent.Template.Steps {
			if step.ChildTemplate == "" {
				continue
			}
			for _, child := range reg.TemplateVersions(step.ChildTemplate) {
				if !reshapedAfter(child, parent.EvaluatedSeq) {
					continue
				}
				// Seq is the *child's* activation, not the parent's evidence:
				// that is the event that made the finding true, and findings
				// sort by Seq so it lands where a reader looking at the child's
				// activation would expect it.
				rep.Findings = append(rep.Findings, Finding{
					Kind: FindingParentEvidencePredatesChild, ParticipantID: parentID,
					Version: parent.Version, Seq: child.ActivatedSeq,
					Detail: fmt.Sprintf("is active on evidence established at seq %d, and "+
						"step %q confines its children to %s, whose version %s changed shape "+
						"and was activated at seq %d; sagas admitted under this template are "+
						"confined to a branch shape its evaluation never saw. Re-evaluating "+
						"this version does not fix it -- the harness matches its source runs' "+
						"children against the active child template, which is what changed -- "+
						"and inheriting carries the same evidence forward. It needs a new "+
						"version extracted from runs whose children have the new shape",
						parent.EvaluatedSeq, step.StepID, step.ChildTemplate, child.Version,
						child.ActivatedSeq),
				})
			}
		}
	}
}

// reshapedAfter reports whether a child version changed *shape* and was put in
// service after the parent's evidence was established.
//
// The shape filter is what keeps this from firing on the recommended
// path. A child version whose only change was a slot's observed values
// growing fires no trigger, inherits its predecessor's evidence and activates —
// and the parent's evidence is not stale, because the branch still has the same
// shape. Comparing sequences alone would report it, and a finding that fires on
// the recommended path is one people learn to ignore.
//
// `TriggersFired` rather than a re-diff: the record is in the log, `Audit`
// already recomputes it against the two documents (auditTemplateChangeRecord),
// and reading it here is reading a fact that has been checked rather than
// deriving a second opinion that could disagree with the first.
//
// **Activation, not evaluation, and the coupling is worth naming.** The harness's
// `sourceRuns` resolves a declared child through `ActiveTemplate`, so the
// harness compared the parent's source runs against whichever child version was
// *active* when the parent's evidence was established — and activation is the
// event that changes that. Anyone changing `sourceRuns` to resolve a child some
// other way has to change this anchor with it, or the finding quietly stops
// lining up with what the harness actually saw.
func reshapedAfter(child *Entry, parentEvidenceSeq uint64) bool {
	if child.ActivatedSeq == 0 || child.ActivatedSeq <= parentEvidenceSeq {
		return false
	}
	return containsString(child.Change.GetTriggersFired(), TriggerShapeChange)
}
