package saga_test

import (
	"encoding/json"
	"os"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

const fixtureDir = "testdata/fixtures"

// TestReplayCorpus is replay determinism as a standing gate: every saga history ever
// recorded still replays to the projection it produced when it was recorded.
//
// A failure here means one of two things, and they need opposite responses. If
// the state machine has a bug, the fixture caught it and the code is wrong. If
// the semantics changed on purpose, the fixture is out of date and regenerating
// it is correct — but only as a deliberate act, because "just regenerate the
// fixtures" is how a determinism guarantee quietly stops meaning anything.
func TestReplayCorpus(t *testing.T) {
	fixtures, err := saga.LoadFixtures(fixtureDir)
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("the corpus is empty, so this gate proves nothing")
	}
	t.Logf("replaying %d fixtures", len(fixtures))

	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			diffs, err := f.Verify()
			if err != nil {
				t.Fatalf("%s: %v", f.Name, err)
			}
			if len(diffs) == 0 {
				return
			}
			for _, d := range diffs {
				t.Errorf("  %s", d)
			}
			t.Fatalf("%s no longer replays to the projection it recorded (%s).\n"+
				"Three things this can be, and they have different answers.\n"+
				"  1. The state machine is wrong and the fixture caught it. Fix the code.\n"+
				"  2. What a projection *records* changed, and no recorded history means\n"+
				"     anything different. Regenerate: `make corpus-update`, then read the\n"+
				"     diff — it shows exactly what the change did to recorded history.\n"+
				"  3. What an already-recorded history *means* changed. Do not regenerate:\n"+
				"     that rewrites the past. Bump saga.SemanticsVersion, add the new\n"+
				"     version to supportedSemantics, and branch on s.Semantics so this\n"+
				"     fixture goes on folding under the rules it was admitted under.",
				f.Name, f.Description)
		})
	}
}

// TestCorpusReplaysIdentically: replaying twice must agree, or determinism is
// accidental rather than structural.
func TestCorpusReplaysIdentically(t *testing.T) {
	fixtures, err := saga.LoadFixtures(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		events, err := f.Replayable()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		first, err := saga.Replay(events)
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		for i := range 10 {
			again, err := saga.Replay(events)
			if err != nil {
				t.Fatalf("%s replay %d: %v", f.Name, i, err)
			}
			if d := saga.Diff(first, again); len(d) > 0 {
				t.Fatalf("%s replay %d diverged: %v", f.Name, i, d)
			}
		}
	}
}

// TestPrefixesOfEveryFixtureAlsoReplay: a coordinator that crashes partway
// through resumes from a prefix, so every prefix has to be a legal history in
// its own right. A state machine that only worked on complete histories would
// fail exactly when a crash made it matter.
func TestPrefixesOfEveryFixtureAlsoReplay(t *testing.T) {
	fixtures, err := saga.LoadFixtures(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		events, err := f.Replayable()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		for n := 1; n <= len(events); n++ {
			prefix := events[:n]
			first, err := saga.Replay(prefix)
			if err != nil {
				t.Fatalf("%s: the first %d events do not replay: %v", f.Name, n, err)
			}
			again, err := saga.Replay(prefix)
			if err != nil {
				t.Fatal(err)
			}
			if d := saga.Diff(first, again); len(d) > 0 {
				t.Fatalf("%s: prefix of %d events replayed differently twice: %v", f.Name, n, d)
			}
		}
	}
}

// ---- fixture generation -----------------------------------------------------

// TestGenerateFixtures writes the corpus. It only does anything when
// JANUS_UPDATE_FIXTURES is set, so regenerating is always a deliberate act that
// produces a reviewable diff.
func TestGenerateFixtures(t *testing.T) {
	if os.Getenv("JANUS_UPDATE_FIXTURES") == "" {
		t.Skip("set JANUS_UPDATE_FIXTURES=1 to regenerate the corpus")
	}
	for _, b := range corpusBuilders() {
		f := buildFixture(t, b)
		if err := f.Save(fixtureDir); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", f.Name)
	}
}

// TestCorpusCoversEveryBuilder: a builder added without regenerating would mean
// a shape the corpus claims to cover but does not.
func TestCorpusCoversEveryBuilder(t *testing.T) {
	fixtures, err := saga.LoadFixtures(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, f := range fixtures {
		have[f.Name] = true
	}
	for _, b := range corpusBuilders() {
		if !have[b.name] {
			t.Errorf("no fixture on disk for %q; run JANUS_UPDATE_FIXTURES=1 go test ./pkg/saga/", b.name)
		}
	}
	if len(fixtures) != len(corpusBuilders()) {
		t.Errorf("corpus has %d fixtures but %d builders; a stale fixture would be replayed forever "+
			"against semantics nobody maintains", len(fixtures), len(corpusBuilders()))
	}
}

type builder struct {
	name        string
	description string
	events      func() []recorded
}

type recorded struct {
	kind evidence.Kind
	msg  proto.Message
}

func buildFixture(t *testing.T, b builder) saga.Fixture {
	t.Helper()
	f := saga.Fixture{Name: b.name, Description: b.description}

	var events []saga.Event
	for i, r := range b.events() {
		seq := uint64(i + 1)
		payload := mustMarshal(t, r.msg)
		readable, err := saga.PayloadToJSON(r.kind, payload)
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		f.Events = append(f.Events, saga.FixtureEvent{
			Seq: seq, Kind: string(r.kind), Payload: json.RawMessage(readable),
		})
		events = append(events, saga.Event{Seq: seq, Kind: r.kind, Payload: payload})
	}

	state, err := saga.Replay(events)
	if err != nil {
		t.Fatalf("%s: the fixture's own history does not replay: %v", b.name, err)
	}
	f.Expect = saga.Snapshot(state)
	return f
}

// corpusBuilders is the set of histories the corpus keeps. Each one is a shape
// worth never regressing on, not an arbitrary sample.
func corpusBuilders() []builder {
	compensable := func(id string, deps ...string) *janusv1.PlannedStep {
		return &janusv1.PlannedStep{
			StepId: id, EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: id + ".undo", DependsOn: deps,
		}
	}
	pure := func(id string, deps ...string) *janusv1.PlannedStep {
		return &janusv1.PlannedStep{
			StepId: id, EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, DependsOn: deps,
		}
	}
	ok := &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK}

	return append([]builder{
		{
			name:        "01-pure-commit",
			description: "the simplest complete saga: one PURE step, sealed and committed",
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg", Intent: &janusv1.Intent{IntentId: "in"}, Mode: "supervised",
						Plan: []*janusv1.PlannedStep{pure("read")},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "read"}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "read", Outcome: ok}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
		{
			name:        "02-gated-effect-commit",
			description: "an effectful step waits for a gate before sealing, then commits",
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg", Plan: []*janusv1.PlannedStep{compensable("pay")},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "pay"}},
					{evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg", StepId: "pay", Outcome: ok,
						Touches: []*janusv1.ResourceTouch{
							{ResourceId: "acct:1", Mode: janusv1.ResourceTouch_MODE_WRITE},
						},
					}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "pay",
						Gate: janusv1.GateType_GATE_TYPE_POLICY, Verdict: janusv1.Verdict_VERDICT_PASS,
					}},
					{evidence.KindSealRequest, &janusv1.SealRequest{
						SagaId:    "sg",
						Frontiers: []*janusv1.FrontierClaim{{ResourceId: "acct:1", LastSealedSeq: 3}},
					}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
		{
			name:        "03-chain-compensated",
			description: "a three-step chain undone in reverse topological order",
			events: func() []recorded {
				out := []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg",
						Plan: []*janusv1.PlannedStep{
							compensable("pay"), compensable("book", "pay"), compensable("notify", "book"),
						},
					}},
				}
				for _, id := range []string{"pay", "book", "notify"} {
					out = append(out,
						recorded{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: id}},
						recorded{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: id, Outcome: ok}},
						recorded{evidence.KindGateVerdict, &janusv1.GateVerdict{
							SagaId: "sg", StepId: id, Verdict: janusv1.Verdict_VERDICT_PASS,
						}})
				}
				out = append(out, recorded{evidence.KindCompensate, &janusv1.Compensate{
					SagaId: "sg", ReasonRef: "customer withdrew",
				}})
				for _, id := range []string{"notify", "book", "pay"} {
					out = append(out,
						recorded{evidence.KindStepPrepare, &janusv1.StepPrepare{
							SagaId: "sg", StepId: id + "~undo", Compensates: id,
						}},
						recorded{evidence.KindStepResult, &janusv1.StepResult{
							SagaId: "sg", StepId: id + "~undo", Outcome: ok,
						}})
				}
				return out
			},
		},
		{
			name:        "04-failed-compensation-quarantine",
			description: "a compensation fails, so the saga freezes rather than leaving a hole in the undo",
			events: func() []recorded {
				out := []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg",
						Plan:   []*janusv1.PlannedStep{compensable("pay"), compensable("book", "pay")},
					}},
				}
				for _, id := range []string{"pay", "book"} {
					out = append(out,
						recorded{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: id}},
						recorded{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: id, Outcome: ok}},
						recorded{evidence.KindGateVerdict, &janusv1.GateVerdict{
							SagaId: "sg", StepId: id, Verdict: janusv1.Verdict_VERDICT_PASS,
						}})
				}
				out = append(out,
					recorded{evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}},
					recorded{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "book~undo", Compensates: "book",
					}},
					recorded{evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg", StepId: "book~undo",
						Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_TERMINAL_ERROR},
					}})
				return out
			},
		},
		{
			name:        "05-irreversible-quarantine",
			description: "an irreversible effect escaped and the saga then failed, so nothing can undo it",
			events: func() []recorded {
				facts := []*janusv1.Fact{flagFact("approved", true)}
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId:            "sg",
						GatePolicyVersion: fixturePolicy,
						Plan: []*janusv1.PlannedStep{{
							StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
						}},
						GatePlan: []*janusv1.StepGates{stepGates("wire", "wires",
							policyGate("approval", "PRE_RELEASE", "approved == true",
								"a wire needs an approval on the record"))},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "wire", Facts: facts,
					}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"approval"},
						Facts:   facts,
					}},
					{evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}},
				}
			},
		},
		{
			name:        "06-retry-then-succeed",
			description: "a step fails retryably, is retried inside its budget, and then succeeds",
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg",
						Plan: []*janusv1.PlannedStep{{
							StepId: "flaky", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, MaxRetries: 2,
						}},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "flaky"}},
					{evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg", StepId: "flaky",
						Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_RETRYABLE_ERROR},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "flaky"}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "flaky", Outcome: ok}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
		{
			name:        "07-parallel-branches",
			description: "two independent branches run and commit; neither blocks the other",
			events: func() []recorded {
				out := []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg",
						Plan: []*janusv1.PlannedStep{
							pure("a1"), pure("b1"), pure("a2", "a1"), pure("b2", "b1"),
						},
					}},
				}
				// Interleaved deliberately: the projection must not depend on
				// which branch happened to go first.
				for _, id := range []string{"a1", "b1", "b2", "a2"} {
					out = append(out,
						recorded{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: id}},
						recorded{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: id, Outcome: ok}})
				}
				out = append(out,
					recorded{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					recorded{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}})
				return out
			},
		},
		{
			name:        "08-abort-before-effects",
			description: "a saga aborted before anything effectful ran needs no compensation",
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg", Plan: []*janusv1.PlannedStep{pure("read"), compensable("pay", "read")},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "read"}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "read", Outcome: ok}},
					{evidence.KindAbort, &janusv1.Abort{SagaId: "sg", ReasonRef: "policy refused"}},
				}
			},
		},
		{
			name: "09-gate-failure-unwinds",
			description: "a gate refuses a compensable step that had already executed, so both it and " +
				"the step before it are undone, in reverse order",
			events: func() []recorded {
				bookFacts := []*janusv1.Fact{numberFact("amount_minor", 250000)}
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId:            "sg",
						GatePolicyVersion: fixturePolicy,
						Plan:              []*janusv1.PlannedStep{compensable("pay"), compensable("book", "pay")},
						GatePlan: []*janusv1.StepGates{
							stepGates("book", "bookings", limitGate("booking-limit", "amount_minor", 100000)),
						},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "pay"}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "pay", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "pay", Verdict: janusv1.Verdict_VERDICT_PASS,
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "book", Facts: bookFacts,
					}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "book", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "book",
						Gate:    janusv1.GateType_GATE_TYPE_RISK_LIMIT,
						Verdict: janusv1.Verdict_VERDICT_FAIL,
						Reason:  "amount_minor is 250000, over the limit of 100000",
						Decided: []string{"booking-limit"},
						Facts:   bookFacts,
					}},
					// "book" ran and was then refused, so its effect is live and
					// must be reversed before the step it depended on.
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "book~undo", Compensates: "book",
					}},
					{evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg", StepId: "book~undo", Outcome: ok,
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "pay~undo", Compensates: "pay",
					}},
					{evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg", StepId: "pay~undo", Outcome: ok,
					}},
				}
			},
		},
		{
			name: "10-gate-stops-irreversible",
			description: "a gate refuses an irreversible effect, which was therefore never released; " +
				"the saga has nothing to undo and must not quarantine for a gate doing its job",
			events: func() []recorded {
				facts := []*janusv1.Fact{flagFact("approved", false)}
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId:            "sg",
						GatePolicyVersion: fixturePolicy,
						Plan: []*janusv1.PlannedStep{{
							StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
						}},
						GatePlan: []*janusv1.StepGates{stepGates("wire", "wires",
							policyGate("approval", "PRE_RELEASE", "approved == true",
								"a wire needs an approval on the record"))},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "wire", Facts: facts,
					}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_POLICY,
						Verdict: janusv1.Verdict_VERDICT_FAIL,
						Reason:  "a wire needs an approval on the record — \"approved == true\" does not hold",
						Decided: []string{"approval"},
						Facts:   facts,
					}},
				}
			},
		},
		{
			name:        "11-diamond-compensated",
			description: "a diamond dependency undone in reverse order, where the join must go first",
			events: func() []recorded {
				out := []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg",
						Plan: []*janusv1.PlannedStep{
							compensable("root"),
							compensable("left", "root"),
							compensable("right", "root"),
							compensable("join", "left", "right"),
						},
					}},
				}
				for _, id := range []string{"root", "left", "right", "join"} {
					out = append(out,
						recorded{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: id}},
						recorded{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: id, Outcome: ok}},
						recorded{evidence.KindGateVerdict, &janusv1.GateVerdict{
							SagaId: "sg", StepId: id, Verdict: janusv1.Verdict_VERDICT_PASS,
						}})
				}
				out = append(out, recorded{evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}})
				for _, id := range []string{"join", "right", "left", "root"} {
					out = append(out,
						recorded{evidence.KindStepPrepare, &janusv1.StepPrepare{
							SagaId: "sg", StepId: id + "~undo", Compensates: id,
						}},
						recorded{evidence.KindStepResult, &janusv1.StepResult{
							SagaId: "sg", StepId: id + "~undo", Outcome: ok,
						}})
				}
				return out
			},
		},

		// Sub-sagas. A family spans two sagas and a fixture records
		// one, so the parent's history and the child's are kept separately.
		// What each one has to pin down is its own half of the contract: the
		// parent that it recorded the delegation, the child that it committed
		// on borrowed authority rather than its own.
		{
			name:        "12-subsaga-parent-cascade",
			description: "a parent delegates a step to a cascade sub-saga, then seals and commits",
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg", Intent: &janusv1.Intent{IntentId: "in"},
						Plan: []*janusv1.PlannedStep{compensable("delegate")},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "delegate",
						Spawns: &janusv1.ChildSaga{
							SagaId:     "sg_child",
							CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
						},
					}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "delegate", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "delegate", Verdict: janusv1.Verdict_VERDICT_PASS,
					}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
		{
			name:        "13-subsaga-child-commits-on-parent-authority",
			description: "a cascade sub-saga commits carrying its parent's authorisation, never its own",
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg_child", Intent: &janusv1.Intent{IntentId: "in_child"},
						Plan: []*janusv1.PlannedStep{compensable("charge")},
						Parent: &janusv1.ParentSaga{
							SagaId: "sg", StepId: "delegate",
							CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
						},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg_child", StepId: "charge"}},
					{evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg_child", StepId: "charge", Outcome: ok,
					}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg_child", StepId: "charge", Verdict: janusv1.Verdict_VERDICT_PASS,
					}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg_child"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg_child", AuthorizedBy: "sg"}},
				}
			},
		},
		{
			name: "14-subsaga-autonomous-parent-unwinds",
			description: "a parent unwinds after delegating to an autonomous sub-saga, so it " +
				"compensates with its own declared action rather than recalling the child",
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg", Intent: &janusv1.Intent{IntentId: "in"},
						Plan: []*janusv1.PlannedStep{compensable("delegate")},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "delegate",
						Spawns: &janusv1.ChildSaga{
							SagaId:     "sg_child",
							CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS,
						},
					}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "delegate", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "delegate", Verdict: janusv1.Verdict_VERDICT_PASS,
					}},
					{evidence.KindAbort, &janusv1.Abort{SagaId: "sg", ReasonRef: "operator cancelled"}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "delegate~undo", Compensates: "delegate",
					}},
					{evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg", StepId: "delegate~undo", Outcome: ok,
					}},
				}
			},
		},
		{
			name: "21-semantics-pinned-at-admission",
			description: "a saga whose SAGA_BEGIN states the state-machine rules it was " +
				"admitted under, which is what every saga written from now on looks like",
			// Fixtures 01-20 are the other half of this, and the more important
			// half: none of their histories carries the field, and each expects
			// `"semantics": 1` anyway. Together the two say the thing versioning
			// claims — an explicit pin is honoured, and a history recorded
			// before the pin existed goes on folding under the rules it was
			// actually admitted under, forever.
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId: "sg", Intent: &janusv1.Intent{IntentId: "in"}, Mode: "supervised",
						Plan: []*janusv1.PlannedStep{pure("read")},
						// A literal 1, deliberately, and never
						// saga.SemanticsVersion. A fixture's history is a
						// *recorded* history: tying it to the constant would
						// mean the next bump silently rewrote this saga's
						// SAGA_BEGIN from 1 to 2 on the next `make
						// corpus-update`, which is precisely the rewriting of
						// the past versioning exists to forbid. Version 2 gets its
						// own fixture; this one stays admitted under 1 forever.
						SemanticsVersion: 1,
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "read"}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "read", Outcome: ok}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
	}, append(gateBuilders(ok), externalGateBuilders(ok)...)...)
}

// ---- gate fixtures ------------------------------------------------------------

// fixturePolicy stands in for a real policy version in the corpus.
//
// The fixtures record the pin rather than the policy: what the state machine
// enforces is that a saga carries the requirements it was admitted under and is
// judged against exactly those, and it enforces that without ever reading a
// policy document. Putting a real hash here would tie the corpus to whatever
// example policy the repository happens to ship, so a change to that file would
// churn recorded history that the change did not affect.
const fixturePolicy = "blake3:" +
	"0000000000000000000000000000000000000000000000000000000000000000"

func policyGate(id, phase, expr, desc string) *janusv1.GateRequirement {
	return &janusv1.GateRequirement{
		Id:    id,
		Gate:  janusv1.GateType_GATE_TYPE_POLICY,
		Phase: janusv1.GatePhase(janusv1.GatePhase_value["GATE_PHASE_"+phase]),
		Check: &janusv1.GateRequirement_Policy{
			Policy: &janusv1.PolicyCheck{Expr: expr, Description: desc},
		},
	}
}

func limitGate(id, fact string, max int64) *janusv1.GateRequirement {
	return &janusv1.GateRequirement{
		Id:    id,
		Gate:  janusv1.GateType_GATE_TYPE_RISK_LIMIT,
		Phase: janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
		Check: &janusv1.GateRequirement_RiskLimit{
			RiskLimit: &janusv1.RiskLimitCheck{
				Thresholds: []*janusv1.RiskLimitCheck_Threshold{{Fact: fact, Max: max}},
			},
		},
	}
}

func stepGates(stepID, ruleID string, require ...*janusv1.GateRequirement) *janusv1.StepGates {
	return &janusv1.StepGates{StepId: stepID, RuleId: ruleID, Require: require}
}

func numberFact(key string, n int64) *janusv1.Fact {
	return &janusv1.Fact{Key: key, Value: &janusv1.Fact_Number{Number: n}}
}

func flagFact(key string, b bool) *janusv1.Fact {
	return &janusv1.Fact{Key: key, Value: &janusv1.Fact_Flag{Flag: b}}
}

// gateBuilders are the histories that exist because of gates: the shapes where
// a gate decides something the rest of the machine then has to respect.
func gateBuilders(ok *janusv1.Outcome) []builder {
	wire := func() *janusv1.PlannedStep {
		return &janusv1.PlannedStep{
			StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}
	}
	return []builder{
		{
			name: "15-pre-execution-gate-refuses",
			description: "a gate refuses a step before it runs, so the participant is never called " +
				"and there is nothing to undo",
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId:            "sg",
						GatePolicyVersion: fixturePolicy,
						Plan: []*janusv1.PlannedStep{{
							StepId:      "send",
							EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE,
						}},
						GatePlan: []*janusv1.StepGates{stepGates("send", "outbound",
							policyGate("recipient-allowed", "PRE_EXECUTION",
								"recipient in [\"ops@example.com\"]",
								"outbound mail may only go to a listed recipient"))},
					}},
					// No STEP_PREPARE: the refusal lands while the step is still
					// PLANNED, which is the whole point of a pre-execution gate.
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "send",
						Gate:    janusv1.GateType_GATE_TYPE_POLICY,
						Verdict: janusv1.Verdict_VERDICT_FAIL,
						Reason:  "recipient is not on the list",
						Decided: []string{"recipient-allowed"},
						Facts: []*janusv1.Fact{
							{Key: "recipient", Value: &janusv1.Fact_Text{Text: "attacker@example.com"}},
						},
					}},
				}
			},
		},
		{
			name: "16-both-phases-then-commit",
			description: "an irreversible effect is judged before it runs and again before release, " +
				"on the same facts both times, and only then commits",
			events: func() []recorded {
				facts := []*janusv1.Fact{numberFact("amount_minor", 250000), flagFact("approved", true)}
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId:            "sg",
						GatePolicyVersion: fixturePolicy,
						Plan:              []*janusv1.PlannedStep{wire()},
						GatePlan: []*janusv1.StepGates{stepGates("wire", "wires",
							policyGate("approval", "PRE_EXECUTION", "approved == true",
								"a wire needs an approval on the record"),
							limitGate("wire-limit", "amount_minor", 1000000))},
					}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"approval"},
						Facts:   facts,
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "wire", Facts: facts,
					}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"wire-limit"},
						Facts:   facts,
					}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
	}
}

// ---- fixtures for gates somebody outside decides -----------------------------

func humanGate(id, phase string, quorum uint32, sod bool, roles ...string) *janusv1.GateRequirement {
	return &janusv1.GateRequirement{
		Id:    id,
		Gate:  janusv1.GateType_GATE_TYPE_HUMAN,
		Phase: janusv1.GatePhase(janusv1.GatePhase_value["GATE_PHASE_"+phase]),
		Check: &janusv1.GateRequirement_Human{
			Human: &janusv1.HumanCheck{Roles: roles, Quorum: quorum, SeparationOfDuty: sod},
		},
	}
}

func validatorGate(id string, quorum uint32, escalate bool, validators ...string) *janusv1.GateRequirement {
	return &janusv1.GateRequirement{
		Id:    id,
		Gate:  janusv1.GateType_GATE_TYPE_VALIDATOR,
		Phase: janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
		Check: &janusv1.GateRequirement_Validator{
			Validator: &janusv1.ValidatorCheck{
				Validators: validators, Quorum: quorum, EscalateOnDisagreement: escalate,
			},
		},
	}
}

func humanAnswer(person, reqID string, v janusv1.Verdict, roles ...string) *janusv1.GateAnswer {
	return &janusv1.GateAnswer{
		SagaId: "sg", StepId: "wire", RequirementId: reqID, Attempt: 1,
		Actor:   &janusv1.Actor{HumanSubject: person},
		Verdict: v, Roles: roles, AuthRef: "auth:" + person,
	}
}

func validatorAnswer(who, reqID string, v janusv1.Verdict, reason string) *janusv1.GateAnswer {
	return &janusv1.GateAnswer{
		SagaId: "sg", StepId: "wire", RequirementId: reqID, Attempt: 1,
		Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: who}},
		Verdict: v, Reason: reason,
	}
}

// externalGateBuilders are the histories where the gate's answer comes from
// somebody who is not the agent being gated.
func externalGateBuilders(ok *janusv1.Outcome) []builder {
	// The saga is initiated on bob's authority throughout, so separation of
	// duty has something concrete to be about.
	begin := func(gates ...*janusv1.GateRequirement) *janusv1.SagaBegin {
		return &janusv1.SagaBegin{
			SagaId:            "sg",
			GatePolicyVersion: fixturePolicy,
			Intent: &janusv1.Intent{
				IntentId: "in", Principal: "bob", MandateRef: "m-1",
			},
			Plan: []*janusv1.PlannedStep{{
				StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			}},
			GatePlan: []*janusv1.StepGates{stepGates("wire", "wires", gates...)},
		}
	}
	ran := func() []recorded {
		return []recorded{
			{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire"}},
			{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Outcome: ok}},
		}
	}

	return []builder{
		{
			name: "17-human-approval-releases",
			description: "an irreversible effect waits for a person, is approved by somebody other " +
				"than the principal it was initiated for, and only then commits",
			events: func() []recorded {
				out := []recorded{{evidence.KindSagaBegin,
					begin(humanGate("approval", "PRE_RELEASE", 1, true, "credit-officer"))}}
				out = append(out, ran()...)
				return append(out,
					recorded{evidence.KindGateAnswer, humanAnswer("alice", "approval",
						janusv1.Verdict_VERDICT_PASS, "credit-officer")},
					recorded{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Reason:  "approved by alice",
						Decided: []string{"approval"},
					}},
					recorded{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					recorded{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}})
			},
		},
		{
			name: "18-self-approval-refused",
			description: "the principal the saga was initiated for approves their own payment; " +
				"four eyes means the gate refuses rather than quietly waiting for somebody else",
			events: func() []recorded {
				out := []recorded{{evidence.KindSagaBegin,
					begin(humanGate("approval", "PRE_RELEASE", 1, true, "credit-officer"))}}
				out = append(out, ran()...)
				return append(out,
					// bob is the intent principal, and holds the role. The role
					// is not the problem; being the initiator is.
					recorded{evidence.KindGateAnswer, humanAnswer("bob", "approval",
						janusv1.Verdict_VERDICT_PASS, "credit-officer")},
					recorded{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_HUMAN,
						Verdict: janusv1.Verdict_VERDICT_FAIL,
						Reason: "\"bob\" approved a saga initiated on their own authority, and this " +
							"gate requires the approver not be the initiator",
						Decided: []string{"approval"},
					}})
			},
		},
		{
			name: "19-validator-disagreement-escalates",
			description: "two independent validators disagree, so the step is held for a human " +
				"rather than the majority carrying it",
			events: func() []recorded {
				out := []recorded{{evidence.KindSagaBegin,
					begin(validatorGate("second-opinion", 2, true, "val_a", "val_b"))}}
				out = append(out, ran()...)
				return append(out,
					recorded{evidence.KindGateAnswer, validatorAnswer("val_a", "second-opinion",
						janusv1.Verdict_VERDICT_PASS, "")},
					recorded{evidence.KindGateAnswer, validatorAnswer("val_b", "second-opinion",
						janusv1.Verdict_VERDICT_FAIL, "the counterparty is not on the mandate")},
					recorded{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_VALIDATOR,
						Verdict: janusv1.Verdict_VERDICT_ESCALATE,
						Reason:  "the validators disagree, so this needs a human",
					}})
			},
		},
		{
			name: "20-relative-threshold-on-a-published-fact",
			description: "a payment is judged against a fraction of a balance another step went " +
				"and read, which the paying step never gets to state",
			events: func() []recorded {
				return []recorded{
					{evidence.KindSagaBegin, &janusv1.SagaBegin{
						SagaId:            "sg",
						GatePolicyVersion: fixturePolicy,
						Intent:            &janusv1.Intent{IntentId: "in", Principal: "bob"},
						Plan: []*janusv1.PlannedStep{
							{StepId: "balance", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
							{StepId: "wire", DependsOn: []string{"balance"},
								EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED},
						},
						GatePlan: []*janusv1.StepGates{stepGates("wire", "wires",
							policyGate("within-share", "PRE_RELEASE",
								"amount_minor <= 10 percent of result.balance.available_minor",
								"a single payment may not exceed a tenth of the balance"))},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "balance"}},
					// The balance step publishes what it found. A PURE step
					// seals on its result, so the finding is settled before the
					// payment is judged against it.
					{evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg", StepId: "balance", Outcome: ok,
						Facts: []*janusv1.Fact{numberFact("available_minor", 10000000)},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg", StepId: "wire",
						Facts: []*janusv1.Fact{numberFact("amount_minor", 250000)},
					}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"within-share"},
						Facts:   []*janusv1.Fact{numberFact("amount_minor", 250000)},
					}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
		{
			name: "22-an-approval-is-about-the-proposal-it-was-asked-about",
			description: "a person approves a wire before it runs; the proposal the question was " +
				"asked about is pinned at the escalation, and the pass, the prepare and the " +
				"release are all about that same amount (semantics 2)",
			events: func() []recorded {
				amount := []*janusv1.Fact{numberFact("amount_minor", 100)}
				b := begin(humanGate("pre-approval", "PRE_EXECUTION", 1, true, "credit-officer"),
					limitGate("wire-limit", "amount_minor", 1000000))
				// A literal 2, for the reason fixture 21 carries a literal 1:
				// this is a recorded history, and the constant moves.
				b.SemanticsVersion = 2
				return []recorded{
					{evidence.KindSagaBegin, b},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_HUMAN,
						Verdict: janusv1.Verdict_VERDICT_ESCALATE,
						Reason:  "waiting for approval from an approver holding one of credit-officer",
						Facts:   amount,
					}},
					{evidence.KindGateAnswer, humanAnswer("alice", "pre-approval",
						janusv1.Verdict_VERDICT_PASS, "credit-officer")},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"pre-approval"},
						Facts:   amount,
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire", Facts: amount}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"wire-limit"},
						Facts:   amount,
					}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
		{
			name: "23-an-approval-of-nothing-ran-on-an-amount-under-semantics-2",
			description: "a wire escalates having proposed no facts, a person approves it, the " +
				"gate passes on nothing, and the step prepares on 250,000. Legal under " +
				"semantics 2, refused under 3; kept so a " +
				"version-2 log holding it goes on folding exactly as it did",
			events: func() []recorded {
				amount := []*janusv1.Fact{numberFact("amount_minor", 250000)}
				b := begin(humanGate("pre-approval", "PRE_EXECUTION", 1, true, "credit-officer"),
					limitGate("wire-limit", "amount_minor", 1000000))
				// A recorded history: the literal is the version it was written under.
				b.SemanticsVersion = 2
				return []recorded{
					{evidence.KindSagaBegin, b},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_HUMAN,
						Verdict: janusv1.Verdict_VERDICT_ESCALATE,
						Reason:  "waiting for approval from an approver holding one of credit-officer",
					}},
					{evidence.KindGateAnswer, humanAnswer("alice", "pre-approval",
						janusv1.Verdict_VERDICT_PASS, "credit-officer")},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"pre-approval"},
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire", Facts: amount}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"wire-limit"},
						Facts:   amount,
					}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
		{
			name: "24-an-approval-pins-its-proposal-and-its-delegation",
			description: "fixture 22's approval under semantics 3: the escalation pins the " +
				"amount and that the wire delegates nothing, and the pass, the prepare and " +
				"the release are all about that proposal",
			events: func() []recorded {
				amount := []*janusv1.Fact{numberFact("amount_minor", 100)}
				b := begin(humanGate("pre-approval", "PRE_EXECUTION", 1, true, "credit-officer"),
					limitGate("wire-limit", "amount_minor", 1000000))
				b.SemanticsVersion = 3
				return []recorded{
					{evidence.KindSagaBegin, b},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_HUMAN,
						Verdict: janusv1.Verdict_VERDICT_ESCALATE,
						Reason:  "waiting for approval from an approver holding one of credit-officer",
						Facts:   amount,
					}},
					{evidence.KindGateAnswer, humanAnswer("alice", "pre-approval",
						janusv1.Verdict_VERDICT_PASS, "credit-officer")},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"pre-approval"},
						Facts:   amount,
					}},
					{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire", Facts: amount}},
					{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Outcome: ok}},
					{evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg", StepId: "wire",
						Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
						Verdict: janusv1.Verdict_VERDICT_PASS,
						Decided: []string{"wire-limit"},
						Facts:   amount,
					}},
					{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
					{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
				}
			},
		},
		{
			name: "25-a-participant-approved-for-a-person-under-semantics-3",
			description: "a wire's person approval before it runs is answered by a participant in " +
				"its own name, claiming the role, and the saga commits. Legal under semantics 3, " +
				"refused under 4; kept so a version-3 log holding it folds as it did",
			events: func() []recorded {
				amount := []*janusv1.Fact{numberFact("amount_minor", 100)}
				b := begin(humanGate("pre-approval", "PRE_EXECUTION", 1, false, "credit-officer"),
					limitGate("wire-limit", "amount_minor", 1000000))
				b.SemanticsVersion = 3
				self := validatorAnswer("ag_intake", "pre-approval", janusv1.Verdict_VERDICT_PASS, "approved")
				self.Roles = []string{"credit-officer"}
				return approvedWire(b, amount, self)
			},
		},
		{
			name:        "26-a-persons-approval-is-given-by-a-person",
			description: "fixture 25 under semantics 4: the person's approval is given by a person",
			events: func() []recorded {
				amount := []*janusv1.Fact{numberFact("amount_minor", 100)}
				b := begin(humanGate("pre-approval", "PRE_EXECUTION", 1, false, "credit-officer"),
					limitGate("wire-limit", "amount_minor", 1000000))
				b.SemanticsVersion = 4
				return approvedWire(b, amount, humanAnswer("alice", "pre-approval",
					janusv1.Verdict_VERDICT_PASS, "credit-officer"))
			},
		},
	}
}

// approvedWire is a wire escalated for a pre-execution approval on `amount`,
// answered by `answer`, passed, run, released and committed.
func approvedWire(b *janusv1.SagaBegin, amount []*janusv1.Fact, answer *janusv1.GateAnswer) []recorded {
	return []recorded{
		{evidence.KindSagaBegin, b},
		{evidence.KindGateVerdict, &janusv1.GateVerdict{
			SagaId: "sg", StepId: "wire", Gate: janusv1.GateType_GATE_TYPE_HUMAN,
			Verdict: janusv1.Verdict_VERDICT_ESCALATE,
			Reason:  "waiting for approval from an approver holding one of credit-officer",
			Facts:   amount,
		}},
		{evidence.KindGateAnswer, answer},
		{evidence.KindGateVerdict, &janusv1.GateVerdict{
			SagaId: "sg", StepId: "wire", Gate: janusv1.GateType_GATE_TYPE_COMPOSITE,
			Verdict: janusv1.Verdict_VERDICT_PASS, Decided: []string{"pre-approval"}, Facts: amount,
		}},
		{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire", Facts: amount}},
		{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK}}},
		{evidence.KindGateVerdict, &janusv1.GateVerdict{
			SagaId: "sg", StepId: "wire", Gate: janusv1.GateType_GATE_TYPE_COMPOSITE,
			Verdict: janusv1.Verdict_VERDICT_PASS, Decided: []string{"wire-limit"}, Facts: amount,
		}},
		{evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}},
		{evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}},
	}
}
