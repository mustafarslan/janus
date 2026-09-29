package template_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/template"
	"google.golang.org/protobuf/proto"
)

// TestExtractingFromARealLog is the path the CLI takes, and the one every unit
// test above skips: the runs come out of an evidence directory rather than being
// handed to the extractor as structs.
//
// It exercises `saga.BeginOf` and `saga.ReplaySome` together, which is how
// `janus-registry template extract` reads its input, and it is the only test
// that would notice if a saga's recorded plan and its projection stopped lining
// up.
func TestExtractingFromARealLog(t *testing.T) {
	ctx := context.Background()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}

	ev := func(kind, payload string) saga.FixtureEvent {
		return saga.FixtureEvent{Kind: kind, Payload: []byte(payload)}
	}
	ids := []string{"sg_a", "sg_b", "sg_c"}
	for i, id := range ids {
		amounts := []string{"100", "250", "900"}
		events := []saga.FixtureEvent{
			ev("SAGA_BEGIN", `{"saga_id":"`+id+`","mode":"supervised",`+
				`"intent":{"intent_id":"in_`+id+`","principal":"pr_bank"},`+
				`"plan":[{"step_id":"st_pay","participant":"tool_payments",`+
				`"action":"payments.wire","effect_class":"EFFECT_CLASS_COMPENSABLE",`+
				`"compensation_action":"payments.refund"}]}`),
			// Declared at prepare, which is where the state machine binds them
			// and where a pre-execution gate decides against them. A result's
			// facts are what a step *published*, which is a different set.
			ev("STEP_PREPARE", `{"saga_id":"`+id+`","step_id":"st_pay",`+
				`"facts":[{"key":"amount","number":`+amounts[i]+`}]}`),
			ev("STEP_RESULT", `{"saga_id":"`+id+`","step_id":"st_pay",`+
				`"outcome":{"status":"STATUS_OK"}}`),
			ev("GATE_VERDICT", `{"saga_id":"`+id+`","step_id":"st_pay","verdict":"VERDICT_PASS"}`),
			ev("SEAL_REQUEST", `{"saga_id":"`+id+`"}`),
			ev("COMMIT", `{"saga_id":"`+id+`"}`),
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
			if _, err := app.Append(ctx, evidence.Request{
				Kind: e.Kind, SagaID: id, Payload: e.Payload,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	states, err := saga.ReplaySome(dir, ids)
	if err != nil {
		t.Fatal(err)
	}
	runs := make([]template.Run, 0, len(ids))
	for _, id := range ids {
		begin, err := saga.BeginOf(dir, id)
		if err != nil {
			t.Fatalf("reading the beginning of %s: %v", id, err)
		}
		if begin.GetMode() != "supervised" {
			t.Fatalf("%s was recorded in mode %q", id, begin.GetMode())
		}
		runs = append(runs, template.Run{State: states[id], Begin: begin})
	}

	tpl, err := template.Extract("tpl_from_log", "1.0.0", "pr_bank", 2, runs, nil)
	if err != nil {
		t.Fatalf("extracting from a real log: %v", err)
	}
	if len(tpl.Steps) != 1 || tpl.Steps[0].StepID != "st_pay" {
		t.Fatalf("the extracted shape is %+v", tpl.Steps)
	}
	if len(tpl.Slots) != 1 || tpl.Slots[0].Name != "amount" || tpl.Slots[0].Kind != "NUMBER" {
		t.Fatalf("the extracted slots are %+v", tpl.Slots)
	}
	if len(tpl.Slots[0].Observed) != 3 {
		t.Errorf("the amount slot observed %v; three runs used three values",
			tpl.Slots[0].Observed)
	}
	// Provenance an auditor can follow back into this log.
	for i, root := range tpl.Provenance.EvidenceRoots {
		if root == "" {
			t.Errorf("saga %s contributed no evidence root", tpl.Provenance.SagaIDs[i])
		}
	}

	// And the shape it produced matches the plans it came from.
	begin, err := saga.BeginOf(dir, "sg_a")
	if err != nil {
		t.Fatal(err)
	}
	if err := template.Match(tpl, begin.GetPlan()); err != nil {
		t.Errorf("a template does not match the plan it was extracted from: %v", err)
	}
	if !strings.Contains(tpl.Provenance.ExtractedFrom, "supervised") {
		t.Errorf("provenance says the runs were %q", tpl.Provenance.ExtractedFrom)
	}
}
