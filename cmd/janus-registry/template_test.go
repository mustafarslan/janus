package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/template"
	"google.golang.org/protobuf/proto"
)

// The CLI is the whole point here: `Extract` and `RegisterTemplate`
// were library calls, so crystallized mode was built, enforced, and unusable by
// anyone not compiling this repository. These tests drive the command functions
// the way the binary does — flags, files, signing — because that glue is what
// makes crystallized mode usable and nothing else touches it.

// threeRuns writes three committed sagas of one shape into an evidence
// directory, and returns their ids.
func threeRuns(t *testing.T, dir string) []string {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"sg_a", "sg_b", "sg_c"}
	amounts := []string{"100", "250", "900"}
	for i, id := range ids {
		events := []saga.FixtureEvent{
			{Kind: "SAGA_BEGIN", Payload: []byte(`{"saga_id":"` + id + `","mode":"supervised",` +
				`"intent":{"intent_id":"in_` + id + `","principal":"pr_bank"},` +
				`"plan":[{"step_id":"st_pay","participant":"tool_payments",` +
				`"action":"payments.wire","effect_class":"EFFECT_CLASS_COMPENSABLE",` +
				`"compensation_action":"payments.refund"}]}`)},
			{Kind: "STEP_PREPARE", Payload: []byte(`{"saga_id":"` + id + `","step_id":"st_pay",` +
				`"facts":[{"key":"amount","number":` + amounts[i] + `}]}`)},
			{Kind: "STEP_RESULT", Payload: []byte(`{"saga_id":"` + id + `","step_id":"st_pay",` +
				`"outcome":{"status":"STATUS_OK"}}`)},
			{Kind: "GATE_VERDICT", Payload: []byte(`{"saga_id":"` + id + `","step_id":"st_pay",` +
				`"verdict":"VERDICT_PASS"}`)},
			{Kind: "SEAL_REQUEST", Payload: []byte(`{"saga_id":"` + id + `"}`)},
			{Kind: "COMMIT", Payload: []byte(`{"saga_id":"` + id + `"}`)},
		}
		replayable, err := saga.Fixture{Name: id, Events: events}.Replayable()
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range replayable {
			if e.Kind == evidence.KindCommit {
				root, err := saga.EvidenceRoot(dir, id)
				if err != nil {
					t.Fatal(err)
				}
				var c janusv1.Commit
				if err := proto.Unmarshal(e.Payload, &c); err != nil {
					t.Fatal(err)
				}
				c.EvidenceRoot = root
				if e.Payload, err = proto.Marshal(&c); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := app.Append(t.Context(), evidence.Request{
				Kind: e.Kind, SagaID: id, Payload: e.Payload,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return ids
}

// TestTheTemplateCommandsExtractAndRegister is the path an operator takes.
func TestTheTemplateCommandsExtractAndRegister(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "evidence")
	ids := threeRuns(t, dir)

	doc := filepath.Join(work, "tpl.json")
	if err := templateExtract([]string{
		"-evidence", dir, "-id", "tpl_wire", "-version", "1.0.0",
		"-principal", "pr_bank", "-risk", "2",
		"-sagas", strings.Join(ids, ","), "-out", doc,
	}); err != nil {
		t.Fatalf("extract: %v", err)
	}

	blob, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	var tpl template.Template
	if err := json.Unmarshal(blob, &tpl); err != nil {
		t.Fatalf("the document extract wrote is not readable: %v", err)
	}
	if tpl.Provenance.Runs != 3 || len(tpl.Slots) != 1 {
		t.Fatalf("extracted %d run(s) and %d slot(s): %+v", tpl.Provenance.Runs,
			len(tpl.Slots), tpl)
	}

	// Extract must not have registered anything. The judgement about whether
	// those runs are representative belongs to a person reading the document,
	// and a command that registered what it extracted would make it trivial to
	// crystallise whatever a handful of recent runs happened to do.
	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Templates()) != 0 {
		t.Fatalf("extract registered %v; it prints and stops", reg.Templates())
	}

	keyPath := filepath.Join(work, "writer.key")
	if _, err := keys.LoadOrCreate(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := templateRegister([]string{"-evidence", dir, "-key", keyPath, doc}); err != nil {
		t.Fatalf("register: %v", err)
	}

	if reg, err = registry.Replay(dir); err != nil {
		t.Fatal(err)
	}
	e, ok := reg.ResolveTemplate("tpl_wire", "1.0.0")
	if !ok {
		t.Fatal("the template is not in the registry after register")
	}
	if e.State != registry.StateDraft {
		t.Errorf("a freshly registered template is %s; it confines nothing until it is "+
			"evaluated and activated", e.State)
	}
}

// TestTemplateRegisterRefusesAnUnsignedDocument: a template confines every saga
// that pins it, so one nobody signed would be a confinement on nobody's
// authority.
func TestTemplateRegisterRefusesAnUnsignedDocument(t *testing.T) {
	work := t.TempDir()
	doc := filepath.Join(work, "tpl.json")
	if err := os.WriteFile(doc, []byte(`{}`), 0o640); err != nil {
		t.Fatal(err)
	}
	err := templateRegister([]string{"-evidence", filepath.Join(work, "e"), doc})
	if err == nil {
		t.Fatal("an unsigned template was registered")
	}
	if !strings.Contains(err.Error(), "-key") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// TestTemplateExtractRefusesWithoutARiskTier.
//
// There is no default that is right for a shape nobody has looked at: the tier
// is what a deployment decides how much evidence to demand from.
func TestTemplateExtractRefusesWithoutARiskTier(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "evidence")
	ids := threeRuns(t, dir)
	err := templateExtract([]string{
		"-evidence", dir, "-id", "tpl_wire", "-version", "1.0.0",
		"-principal", "pr_bank", "-sagas", strings.Join(ids, ","),
	})
	if err == nil {
		t.Fatal("a template was extracted with no risk tier")
	}
	if !strings.Contains(err.Error(), "risk") {
		t.Errorf("the refusal does not name the missing flag: %v", err)
	}
}

// -child names a template the registry has to hold and have active.
//
// The flag is a claim about what a sub-saga is confined to, and a claim naming
// a document nobody has constrains nothing. Resolving it here rather
// than passing the string through means the extractor gets a shape to match the
// runs against, which is the whole point of checking the claim instead of
// recording it.
func TestTemplateExtractRefusesAChildTemplateTheRegistryDoesNotHold(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "evidence")
	ids := threeRuns(t, dir)
	err := templateExtract([]string{
		"-evidence", dir, "-id", "tpl_wire", "-version", "1.0.0", "-risk", "2",
		"-principal", "pr_bank", "-sagas", strings.Join(ids, ","),
		"-child", "st_wire=tpl_settle",
	})
	if err == nil {
		t.Fatal("a step was confined to a child template no version of which is active")
	}
	if !strings.Contains(err.Error(), "tpl_settle") {
		t.Errorf("the refusal does not name the template: %v", err)
	}

	// And a malformed pair is refused before anything is read, because
	// "st_wire" alone would silently become a step with no child.
	err = templateExtract([]string{
		"-evidence", dir, "-id", "tpl_wire", "-version", "1.0.0", "-risk", "2",
		"-principal", "pr_bank", "-sagas", strings.Join(ids, ","),
		"-child", "st_wire",
	})
	if err == nil || !strings.Contains(err.Error(), "step=templateID") {
		t.Fatalf("a -child value that is not a pair was not refused as one: %v", err)
	}
}

// The whole path, end to end: extract, register, evaluate, activate.
//
// Item 38 closed with the claim that "the ordinary `evaluate` and `activate`
// verbs work on it unchanged, because a template is a registry entry". That
// sentence was standing in for a control. `evaluate` resolved through the
// participant map and told an operator a registered template was "not
// registered"; `activate` wrote the event and then **segfaulted** reading the
// result back, so an operator saw a crash and could not tell whether the
// activation had happened. Neither had ever been run against a template.
func TestATemplateGoesFromExtractionToActiveThroughTheCLI(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "evidence")
	ids := threeRuns(t, dir)
	doc := filepath.Join(work, "tpl.json")

	if err := templateExtract([]string{
		"-evidence", dir, "-id", "tpl_wire", "-version", "1.0.0", "-risk", "2",
		"-principal", "pr_bank", "-sagas", strings.Join(ids, ","), "-out", doc,
	}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	keyPath := filepath.Join(work, "writer.key")
	if _, err := keys.LoadOrCreate(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := templateRegister([]string{"-evidence", dir, "-key", keyPath, doc}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// resolve used to say a registered template "is not in the log".
	if err := resolve([]string{"-evidence", dir, "tpl_wire", "1.0.0"}); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// The manifest verb points at the template one rather than claiming the
	// document is missing.
	err := evaluate([]string{"-evidence", dir, "-sandbox", "x", "tpl_wire", "1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "template evaluate") {
		t.Fatalf("the manifest evaluate verb does not say where a template is evaluated: %v", err)
	}

	if err := templateEvaluate([]string{"-evidence", dir, "tpl_wire", "1.0.0"}); err != nil {
		t.Fatalf("template evaluate: %v", err)
	}
	if err := transition([]string{"-evidence", dir, "tpl_wire", "1.0.0"}, "activate"); err != nil {
		t.Fatalf("activate: %v", err)
	}

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := reg.ResolveTemplate("tpl_wire", "1.0.0")
	if !ok || e.State != registry.StateActive {
		t.Fatalf("the template did not reach ACTIVE (resolved %t)", ok)
	}
	// `resolve` with no version goes through the active lookup, which is the
	// other reader that only ever asked the participant map.
	if err := resolve([]string{"-evidence", dir, "tpl_wire"}); err != nil {
		t.Fatalf("resolve with no version: %v", err)
	}

	// And the verdict on the record is the harness's, with the triggers it
	// actually covered rather than a string somebody typed.
	if got := e.Evaluation.GetHarnessVersion(); got != template.HarnessVersion {
		t.Fatalf("the recorded evaluation names harness %q, want %q", got,
			template.HarnessVersion)
	}
	if len(e.Evaluation.GetTriggersCovered()) == 0 {
		t.Fatal("the recorded evaluation covers no trigger, so it could not clear a reshape")
	}
}

// A template edited after extraction cannot be activated through the CLI.
//
// This is what the harness buys end to end: before it, the document registered
// was never compared with the runs it names, so the review step `extract` forces
// could be followed by an edit nobody would see again.
func TestAnEditedTemplateFailsConformanceAndCannotBeActivated(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "evidence")
	ids := threeRuns(t, dir)
	doc := filepath.Join(work, "tpl.json")

	if err := templateExtract([]string{
		"-evidence", dir, "-id", "tpl_wire", "-version", "1.0.0", "-risk", "2",
		"-principal", "pr_bank", "-sagas", strings.Join(ids, ","), "-out", doc,
	}); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	var tpl template.Template
	if err := json.Unmarshal(blob, &tpl); err != nil {
		t.Fatal(err)
	}
	tpl.Steps[0].Participant = "tool_elsewhere"
	edited, err := json.MarshalIndent(&tpl, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(doc, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(work, "writer.key")
	if _, err := keys.LoadOrCreate(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := templateRegister([]string{"-evidence", dir, "-key", keyPath, doc}); err != nil {
		t.Fatal(err)
	}
	err = templateEvaluate([]string{"-evidence", dir, "tpl_wire", "1.0.0"})
	if err == nil {
		t.Fatal("a template repointed at another participant after extraction passed " +
			"conformance against the runs it claims to describe")
	}
	if !strings.Contains(err.Error(), "cannot be activated") {
		t.Fatalf("the failure does not say what it costs: %v", err)
	}
	// The failing verdict is on the record, and it is what refuses activation.
	if err := transition([]string{"-evidence", dir, "tpl_wire", "1.0.0"}, "activate"); err == nil {
		t.Fatal("a template that failed conformance was activated")
	}
}
