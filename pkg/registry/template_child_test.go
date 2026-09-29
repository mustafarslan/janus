package registry_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/template"
)

// A template naming a child template nobody holds is refused at registration.
//
// At the recorder rather than in the fold, and the distinction is load-bearing:
// the fold has to replay every log it is given, including one an adversary
// appended to directly, and a fold that refused would make such a log
// unreplayable and take the audit down with it. `Manifest.Validate` states the
// same rule for itself — fail when somebody registers the document, not when a
// saga pins it at three in the morning.
//
// The consequence is an ordering: leaves first, then the parent that names them.
func TestATemplateMayNotNameAChildTemplateNobodyHolds(t *testing.T) {
	rec, signer, _ := newRecorder(t)
	ctx := context.Background()

	parent := testTemplate()
	parent.TemplateID = "tpl_parent"
	parent.Steps[0].ChildTemplate = "tpl_settle"
	sig, err := registry.SignTemplate(parent, signer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rec.RegisterTemplate(ctx, parent, sig)
	if err == nil {
		t.Fatal("a template was registered naming a child template the registry does not " +
			"hold; the constraint names a document nobody has, so it constrains nothing")
	}
	if !strings.Contains(err.Error(), "tpl_settle") || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("the refusal does not say which document is missing: %v", err)
	}

	// Register the child first and the same parent goes through. Without this
	// leg the check above passes for a rule that refused every child reference.
	//
	// The child is still DRAFT when the parent is accepted, deliberately:
	// registration is the ordering, activation is admission's question, and
	// requiring ACTIVE here would make a template pair impossible to register
	// at all -- neither can be evaluated before it exists.
	child := testTemplate()
	child.TemplateID = "tpl_settle"
	childSig, err := registry.SignTemplate(child, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, child, childSig); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, parent, sig); err != nil {
		t.Fatalf("a parent registered after the child it names was refused: %v", err)
	}

}

// A template whose step delegates to itself is refused.
//
// Not a cycle check in general -- two templates can still name each other, and
// refusing that would need a graph walk the registry does not do. This is the
// one case that is unambiguous and cheap: a template confining its own children
// to its own shape describes a tree with no bottom, and every saga under it
// would spawn another of the same shape forever.
func TestATemplateMayNotDelegateToItself(t *testing.T) {
	rec, signer, _ := newRecorder(t)

	tpl := testTemplate()
	tpl.Steps[0].ChildTemplate = tpl.TemplateID
	sig, err := registry.SignTemplate(tpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rec.RegisterTemplate(context.Background(), tpl, sig)
	if err == nil {
		t.Fatal("a template declared itself as its own children's template")
	}
	if !strings.Contains(err.Error(), "no bottom") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// The child reference is part of the shape, so changing it owes fresh evidence.
//
// A new field on `template.Step` that `Changed` does not enumerate is a change
// that fires nothing -- which is exactly the defect once found in
// `applyTemplateRegistered`, one layer up. This is the assertion that says the
// field was added to the diff and not only to the document.
func TestChangingAChildTemplateOwesAFreshEvaluation(t *testing.T) {
	rec, signer, _ := newRecorder(t)
	ctx := context.Background()

	for _, id := range []string{"tpl_settle", "tpl_settle_v2"} {
		c := testTemplate()
		c.TemplateID = id
		sig, err := registry.SignTemplate(c, signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rec.RegisterTemplate(ctx, c, sig); err != nil {
			t.Fatal(err)
		}
	}

	first := testTemplate()
	first.TemplateID = "tpl_parent"
	first.Steps[0].ChildTemplate = "tpl_settle"
	sig, err := registry.SignTemplate(first, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, first, sig); err != nil {
		t.Fatal(err)
	}

	second := testTemplate()
	second.TemplateID = "tpl_parent"
	second.Version = "2.0.0"
	second.Steps[0].ChildTemplate = "tpl_settle_v2"
	sig2, err := registry.SignTemplate(second, signer)
	if err != nil {
		t.Fatal(err)
	}
	e, err := rec.RegisterTemplate(ctx, second, sig2)
	if err != nil {
		t.Fatal(err)
	}

	if got := e.Change.GetChanged(); len(got) != 1 || got[0] != "steps.st_wire.child_template" {
		t.Fatalf("the change record names %v, want the child reference", got)
	}
	if got := e.PendingTriggers; len(got) != 1 || got[0] != registry.TriggerShapeChange {
		t.Fatalf("repointing a step's children at another template left pending triggers "+
			"%v, want %v", got, []string{registry.TriggerShapeChange})
	}
}

// A log whose template names a child nobody registered is a finding.
//
// `RegisterTemplate` refuses to write one, so such an event was appended
// directly — which is what the adversarial suite points the audit at. It is fail-closed
// already: admission resolves the same reference, so no child can ever be
// admitted under that step. It is reported anyway, because a step that refuses
// every spawn reads to an operator as the daemon misbehaving, and "this log says
// something the recorder would not have written" is the audit's question.
func TestTheAuditNamesATemplateWhoseChildReferenceResolvesToNothing(t *testing.T) {
	app, dir, signer, trust := honestLog(t)

	tpl := testTemplate()
	tpl.Steps[0].ChildTemplate = "tpl_settle"
	canonical, err := template.Encode(tpl)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := registry.SignTemplate(tpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  tpl.TemplateID,
		Version:        tpl.Version,
		ContentAddress: registry.ContentAddressOf(canonical),
		Template:       canonical,
		Signature:      sig,
	})

	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Kind == registry.FindingChildTemplateUnresolvable &&
			strings.Contains(f.Detail, "tpl_settle") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a template confining its children to a document the log does not hold "+
			"audits clean:\n%s", rep)
	}
}
