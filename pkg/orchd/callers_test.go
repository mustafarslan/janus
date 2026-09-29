package orchd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/callersig"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"
)

// Before this the daemon took every caller at its
// word, and the proof test -- "a client holding the agent's
// key answers as ag_credit_policy" -- would have passed. These are that test
// and its neighbours.

// participantKey derives a participant's signing key from its name, so a test
// can say "the agent's key" and mean one thing.
func participantKey(who string) callersig.Signer {
	seed := sha256.Sum256([]byte("test-key:" + who))
	return callersig.Signer{Participant: who, Key: ed25519.NewKeyFromSeed(seed[:])}
}

func pubOf(s callersig.Signer) string {
	return callersig.EncodeKey(s.Key.Public().(ed25519.PublicKey))
}

// keyedParticipants registers, each declaring its own key: the payments tool,
// the credit validator, the console that relays people's answers, and an agent
// -- the party with a reason to lie.
func keyedParticipants(t *testing.T, dir string, writer *keys.Signer) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	trust := registry.TrustStore{}
	trust.Trust(testPrincipal, writer.Public())
	reg := registry.New()
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: testPrincipal, Kind: "SYSTEM",
	}, reg, trust)
	ctx := context.Background()

	simple := func(id, kind, action string) *registry.Manifest {
		return &registry.Manifest{
			Version:  "1.0.0",
			Identity: registry.Identity{ParticipantID: id, Kind: kind, Principal: testPrincipal},
			Runtime:  registry.Runtime{ModelID: "none", PromptBundleHash: "blake3:" + id},
			Actions:  []registry.Action{{Name: action, EffectClass: "PURE"}},
			Risk:     registry.Risk{Tier: 2},
			Jurisdiction: registry.Jurisdiction{
				DeployableIn: []string{"EU"}, DataResidency: "EU",
			},
		}
	}
	payments := paymentsManifest()
	for _, m := range []struct {
		m       *registry.Manifest
		doubles *registry.Doubles
	}{
		{payments, paymentsDoubles()},
		{simple("ag_credit_policy", "VALIDATOR", "credit.assess"),
			registry.NewDoubles("v").With("credit.assess", registry.Double{})},
		{simple("sys_console", "SYSTEM", "console.relay"),
			registry.NewDoubles("c").With("console.relay", registry.Double{})},
		{simple("sys_batch", "SYSTEM", "batch.run"),
			registry.NewDoubles("b").With("batch.run", registry.Double{})},
		{simple("ag_intake", "AGENT", "intake.read"),
			registry.NewDoubles("a").With("intake.read", registry.Double{})},
	} {
		id := m.m.Identity.ParticipantID
		m.m.Identity.PublicKeys = []string{pubOf(participantKey(id))}
		sig, err := registry.Sign(m.m, writer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rec.Register(ctx, m.m, sig); err != nil {
			t.Fatalf("registering %s: %v", id, err)
		}
		report, err := registry.Evaluate(ctx, m.m, m.doubles)
		if err != nil || !report.GetPassed() {
			t.Fatalf("%s does not pass its own conformance: %v", id, err)
		}
		if err := rec.Evaluate(ctx, id, "1.0.0", report); err != nil {
			t.Fatal(err)
		}
		if err := rec.Activate(ctx, id, "1.0.0"); err != nil {
			t.Fatal(err)
		}
	}
}

// signedServer is a daemon whose participants declare keys, with a policy that
// asks the credit validator and then a person before a notice is released.
func signedServer(t *testing.T, opts func(*orchd.Options)) (*orchd.Server, string) {
	t.Helper()
	s, dir, _ := signedServerWithWriter(t, opts)
	return s, dir
}

func signedServerWithWriter(t *testing.T, opts func(*orchd.Options)) (*orchd.Server, string, *keys.Signer) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	writer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyedParticipants(t, dir, writer)
	p := &gate.Policy{ID: "orchd.signed", Rules: []gate.Rule{{
		ID: "notices", Match: gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
		Require: []gate.Requirement{{
			ID: "credit-opinion", Gate: gate.GateValidator, Phase: gate.PhasePreRelease,
			Validator: &gate.ValidatorSpec{Validators: []string{"ag_credit_policy"}},
		}, {
			ID: "four-eyes", Gate: gate.GateHuman, Phase: gate.PhasePreRelease,
			Human: &gate.HumanSpec{Roles: []string{"credit-officer"}, Quorum: 1},
		}},
	}}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	o := orchd.Options{
		Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone, Policy: p,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	}
	if opts != nil {
		opts(&o)
	}
	s, err := orchd.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir, writer
}

func signedBegin(t *testing.T, s *orchd.Server) {
	t.Helper()
	begin := &janusv1.SagaBegin{
		SagaId: notifySaga, Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in_notify", Principal: testPrincipal,
			Originator: "human:desk@bank", MandateRef: "mandate:payments", Scope: "notify"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_notify", Participant: "tool_payments", Action: "notify.email",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
	if _, err := s.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{
		Begin: begin, Signature: participantKey("tool_payments").Sign(callersig.Begin(begin)),
	}); err != nil {
		t.Fatalf("beginning a saga signed by its own participant: %v", err)
	}
}

// runToTheGate prepares and completes the notice, signed by the payments tool,
// so it waits at its release gates.
func runToTheGate(t *testing.T, s *orchd.Server) uint32 {
	t.Helper()
	pay := participantKey("tool_payments")
	resp, err := s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
		SagaId: notifySaga, StepId: "st_notify",
		Signature: pay.Sign(callersig.Prepare(notifySaga, "st_notify", nil, nil)),
	})
	if err != nil || resp.GetStatus() != janusv1.PrepareStatus_PREPARE_STATUS_PREPARED {
		t.Fatalf("a signed declaration did not prepare: %v %s", err, resp.GetStatus())
	}
	res := &janusv1.StepResult{
		SagaId: notifySaga, StepId: "st_notify", Attempt: resp.GetAttempt(),
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}
	res.Signature = pay.Sign(callersig.Result(res))
	if _, err := s.CompleteStep(context.Background(), &janusv1.CompleteStepRequest{Result: res}); err != nil {
		t.Fatalf("a signed result was refused: %v", err)
	}
	return resp.GetAttempt()
}

func validatorAnswer(attempt uint32) *janusv1.GateAnswer {
	return &janusv1.GateAnswer{
		SagaId: notifySaga, StepId: "st_notify", RequirementId: "credit-opinion", Attempt: attempt,
		Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: "ag_credit_policy"}},
		Verdict: janusv1.Verdict_VERDICT_PASS, Reason: "within the mandate",
	}
}

func answer(s *orchd.Server, a *janusv1.GateAnswer) error {
	_, err := s.RecordAnswer(context.Background(), &janusv1.RecordAnswerRequest{Answer: a})
	return err
}

// TestAnAgentCannotAnswerAsTheValidator is the proof test: a client
// holding the agent's key answers as ag_credit_policy.
func TestAnAgentCannotAnswerAsTheValidator(t *testing.T) {
	s, dir := signedServer(t, nil)
	defer func() { _ = s.Close() }()
	signedBegin(t, s)
	attempt := runToTheGate(t, s)

	forged := validatorAnswer(attempt)
	agent := participantKey("ag_intake")
	for name, sig := range map[string]*janusv1.ParticipantSignature{
		"unsigned": nil,
		"signed by the agent as the validator": callersig.Signer{Participant: "ag_credit_policy",
			Key: agent.Key}.Sign(callersig.Answer(forged)),
		"signed by the agent as itself": agent.Sign(callersig.Answer(forged)),
	} {
		forged.Signature = sig
		err := answer(s, forged)
		if c := status.Code(err); c != codes.PermissionDenied && c != codes.Unauthenticated {
			t.Errorf("%s: an answer claiming to be ag_credit_policy's was told %v", name, err)
		}
	}
	st, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(st.Steps["st_notify"].Answers); n != 0 {
		t.Fatalf("%d forged answer(s) reached the log", n)
	}

	honest := validatorAnswer(attempt)
	honest.Signature = participantKey("ag_credit_policy").Sign(callersig.Answer(honest))
	if err := answer(s, honest); err != nil {
		t.Fatalf("the validator's own signed answer was refused: %v", err)
	}
	st, err = saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	got := st.Steps["st_notify"].Answers
	if len(got) != 1 || got[0].ActorID != "ag_credit_policy" {
		t.Fatalf("the validator's answer was not recorded: %+v", got)
	}
}

// TestTheSignatureIsKeptWithTheAnswer: an auditor checks the validator's answer
// from the log, not from the daemon's say-so.
func TestTheSignatureIsKeptWithTheAnswer(t *testing.T) {
	s, dir := signedServer(t, nil)
	defer func() { _ = s.Close() }()
	signedBegin(t, s)
	a := validatorAnswer(runToTheGate(t, s))
	a.Signature = participantKey("ag_credit_policy").Sign(callersig.Answer(a))
	if err := answer(s, a); err != nil {
		t.Fatal(err)
	}
	events, err := saga.LoadEvents(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	var recorded *janusv1.GateAnswer
	var result *janusv1.StepResult
	for _, e := range events {
		switch e.Kind {
		case evidence.KindGateAnswer:
			recorded = mustAnswer(t, e.Payload)
		case evidence.KindStepResult:
			result = mustResult(t, e.Payload)
		}
	}
	declared := []string{pubOf(participantKey("ag_credit_policy"))}
	if err := callersig.Verify(recorded.GetSignature(), "ag_credit_policy", declared,
		callersig.Answer(recorded)); err != nil {
		t.Fatalf("the recorded answer's signature does not verify from the log: %v", err)
	}
	if err := callersig.Verify(result.GetSignature(), "tool_payments",
		[]string{pubOf(participantKey("tool_payments"))}, callersig.Result(result)); err != nil {
		t.Fatalf("the recorded result's signature does not verify from the log: %v", err)
	}
}

// TestAnAgentCannotRecordAPersonsApproval: a person's answer is relayed by a
// participant allowed to relay one. An agent that could write "alice approved"
// in its own name would be authoring its own permission.
func TestAnAgentCannotRecordAPersonsApproval(t *testing.T) {
	s, _ := signedServer(t, func(o *orchd.Options) { o.HumanRelayers = []string{"sys_console"} })
	defer func() { _ = s.Close() }()
	signedBegin(t, s)
	attempt := runToTheGate(t, s)
	person := func() *janusv1.GateAnswer {
		return &janusv1.GateAnswer{
			SagaId: notifySaga, StepId: "st_notify", RequirementId: "four-eyes", Attempt: attempt,
			Actor:   &janusv1.Actor{HumanSubject: "person:alice@bank"},
			Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
			AuthRef: "oidc:session-1",
		}
	}
	forged := person()
	forged.Signature = participantKey("ag_intake").Sign(callersig.Answer(forged))
	if err := answer(s, forged); status.Code(err) != codes.PermissionDenied ||
		!strings.Contains(err.Error(), "relayed by \"ag_intake\"") {
		t.Fatalf("an agent relayed a person's approval and was told %v", err)
	}
	honest := person()
	honest.Signature = participantKey("sys_console").Sign(callersig.Answer(honest))
	if err := answer(s, honest); err != nil {
		t.Fatalf("the console's relay of a person's approval was refused: %v", err)
	}
}

// TestOnlyTheStepsParticipantReportsItsResult: the agent completing the
// payments tool's step.
func TestOnlyTheStepsParticipantReportsItsResult(t *testing.T) {
	s, _ := signedServer(t, nil)
	defer func() { _ = s.Close() }()
	signedBegin(t, s)
	pay := participantKey("tool_payments")
	resp, err := s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
		SagaId: notifySaga, StepId: "st_notify",
		Signature: pay.Sign(callersig.Prepare(notifySaga, "st_notify", nil, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := &janusv1.StepResult{
		SagaId: notifySaga, StepId: "st_notify", Attempt: resp.GetAttempt(),
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}
	res.Signature = callersig.Signer{Participant: "tool_payments",
		Key: participantKey("ag_intake").Key}.Sign(callersig.Result(res))
	if _, err := s.CompleteStep(context.Background(), &janusv1.CompleteStepRequest{Result: res}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the agent reported the payments tool's result with its own key and was told %v", err)
	}
	res.Signature = nil
	if _, err := s.CompleteStep(context.Background(), &janusv1.CompleteStepRequest{Result: res}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("an unsigned result for a participant that declares a key was told %v", err)
	}
}

// TestOnlyTheStepsParticipantDeclaresIt: the declaration is what a gate judges.
func TestOnlyTheStepsParticipantDeclaresIt(t *testing.T) {
	s, _ := signedServer(t, nil)
	defer func() { _ = s.Close() }()
	signedBegin(t, s)
	facts := []*janusv1.Fact{{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: 5}}}
	_, err := s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
		SagaId: notifySaga, StepId: "st_notify", Facts: facts,
		Signature: participantKey("ag_intake").Sign(callersig.Prepare(notifySaga, "st_notify", facts, nil)),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the agent declared the payments tool's step and was told %v", err)
	}
}

// TestASagaIsBegunInItsOwnPrincipalsName: a begin signed by a participant not
// in the plan, or naming a principal the signer does not act for, is refused.
func TestASagaIsBegunInItsOwnPrincipalsName(t *testing.T) {
	s, _ := signedServer(t, func(o *orchd.Options) { o.RequireCallerSignatures = true })
	defer func() { _ = s.Close() }()
	begin := &janusv1.SagaBegin{
		SagaId: notifySaga, Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in_notify", Principal: testPrincipal,
			Originator: "human:desk@bank", MandateRef: "mandate:payments", Scope: "notify"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_notify", Participant: "tool_payments", Action: "notify.email",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
	for name, sig := range map[string]*janusv1.ParticipantSignature{
		"unsigned, with signatures required": nil,
		"by a participant not in the plan":   participantKey("ag_intake").Sign(callersig.Begin(begin)),
	} {
		_, err := s.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{Begin: begin, Signature: sig})
		if c := status.Code(err); c != codes.PermissionDenied && c != codes.Unauthenticated {
			t.Errorf("a saga begun %s was told %v", name, err)
		}
	}
	other := cloneBegin(begin)
	other.Intent.Principal = "pr_somebody_else"
	_, err := s.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{
		Begin: other, Signature: participantKey("tool_payments").Sign(callersig.Begin(other)),
	})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "another principal's name") {
		t.Fatalf("a saga in another principal's name, signed by a participant acting for %q, "+
			"was told %v", testPrincipal, err)
	}
}

func mustAnswer(t *testing.T, payload []byte) *janusv1.GateAnswer {
	t.Helper()
	var a janusv1.GateAnswer
	if err := gproto.Unmarshal(payload, &a); err != nil {
		t.Fatal(err)
	}
	return &a
}

func mustResult(t *testing.T, payload []byte) *janusv1.StepResult {
	t.Helper()
	var r janusv1.StepResult
	if err := gproto.Unmarshal(payload, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func cloneBegin(b *janusv1.SagaBegin) *janusv1.SagaBegin {
	return gproto.Clone(b).(*janusv1.SagaBegin)
}

// personsAnswer is alice's approval of the notice, relayed by `relayer`.
func personsAnswer(attempt uint32, relayer string) *janusv1.GateAnswer {
	a := &janusv1.GateAnswer{
		SagaId: notifySaga, StepId: "st_notify", RequirementId: "four-eyes", Attempt: attempt,
		Actor:   &janusv1.Actor{HumanSubject: "person:alice@bank"},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
		AuthRef: "oidc:session-1",
	}
	a.Signature = participantKey(relayer).Sign(callersig.Answer(a))
	return a
}

// TestOnlyANamedRelayerCarriesAPersonsAnswer: with relayers named, a SYSTEM
// participant that is not one of them is refused -- being a system is not
// being the console. (Separate from the kind check, which would otherwise mask
// this one: the agent in the test above fails both.)
func TestOnlyANamedRelayerCarriesAPersonsAnswer(t *testing.T) {
	s, _ := signedServer(t, func(o *orchd.Options) { o.HumanRelayers = []string{"sys_console"} })
	defer func() { _ = s.Close() }()
	signedBegin(t, s)
	err := answer(s, personsAnswer(runToTheGate(t, s), "sys_batch"))
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "only from [sys_console]") {
		t.Fatalf("a SYSTEM participant not named as a relayer carried a person's answer: %v", err)
	}
}

// TestAnAgentIsNeverARelayer: with no relayers named but signatures required, a
// person's answer must still be relayed by a SYSTEM or HUMAN participant.
func TestAnAgentIsNeverARelayer(t *testing.T) {
	s, _ := signedServer(t, func(o *orchd.Options) { o.RequireCallerSignatures = true })
	defer func() { _ = s.Close() }()
	signedBegin(t, s)
	attempt := runToTheGate(t, s)
	err := answer(s, personsAnswer(attempt, "ag_intake"))
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "a participant of kind AGENT") {
		t.Fatalf("an agent relayed a person's answer and was told %v", err)
	}
	if err := answer(s, personsAnswer(attempt, "sys_batch")); err != nil {
		t.Fatalf("a SYSTEM participant's relay, with no relayers named, was refused: %v", err)
	}
}

// TestAKeylessParticipantMustSignWhenTheDaemonRequiresIt: a manifest that
// declares no key has nothing to check a signature against, and a daemon run
// with RequireCallerSignatures refuses its unsigned calls rather than taking
// them on trust.
func TestAKeylessParticipantMustSignWhenTheDaemonRequiresIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	writer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, writer) // tool_payments, declaring no key
	for _, require := range []bool{false, true} {
		s, err := orchd.New(orchd.Options{
			Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone,
			Policy: preApprovalPolicy(t), RequireCallerSignatures: require,
			Participant: evidence.ParticipantRef{
				ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.GetSaga(context.Background(), &janusv1.GetSagaRequest{SagaId: notifySaga})
		begun := err == nil
		if !begun {
			beginGatedPlan(t, s, context.Background())
		}
		_, err = s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
			SagaId: notifySaga, StepId: "st_notify",
		})
		switch {
		case !require && err != nil:
			t.Errorf("without the requirement, a keyless participant's unsigned declaration was "+
				"refused: %v", err)
		case require && status.Code(err) != codes.Unauthenticated:
			t.Errorf("with signatures required, a keyless participant's unsigned declaration "+
				"was told %v", err)
		}
		_ = s.Close()
	}
}

// TestASagaIsCheckedAgainstTheManifestItPinned: the payments tool rotates its
// key in version 1.0.1. A saga admitted against 1.0.0 goes on accepting 1.0.0's
// key and not 1.0.1's -- so a rotation does not strand work in flight, and a key
// declared later cannot sign for work admitted under the earlier one.
func TestASagaIsCheckedAgainstTheManifestItPinned(t *testing.T) {
	s, dir, writer := signedServerWithWriter(t, nil)
	signedBegin(t, s) // pins tool_payments@1.0.0
	_ = s.Close()

	rotated := callersig.Signer{Participant: "tool_payments",
		Key: participantKey("tool_payments-after-rotation").Key}
	rotateTo(t, dir, writer, rotated)

	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone, Policy: preApprovalPolicy(t),
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	prep := func(signer callersig.Signer) error {
		_, err := s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
			SagaId: notifySaga, StepId: "st_notify",
			Signature: signer.Sign(callersig.Prepare(notifySaga, "st_notify", nil, nil)),
		})
		return err
	}
	if err := prep(rotated); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a key first declared in 1.0.1 signed for a saga pinned to 1.0.0: %v", err)
	}
	if err := prep(participantKey("tool_payments")); err != nil {
		t.Fatalf("the key 1.0.0 declares was refused for a saga pinned to 1.0.0: %v", err)
	}

	// The audit applies the same rule from the log: the result, signed after
	// the rotation with 1.0.0's key, verifies against the version the saga
	// pinned rather than the one active by then.
	st, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	res := &janusv1.StepResult{
		SagaId: notifySaga, StepId: "st_notify", Attempt: st.Steps["st_notify"].Attempt,
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}
	res.Signature = participantKey("tool_payments").Sign(callersig.Result(res))
	if _, err := s.CompleteStep(context.Background(), &janusv1.CompleteStepRequest{Result: res}); err != nil {
		t.Fatalf("the result signed with the pinned version's key: %v", err)
	}
	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.Kind == gate.FindingSignature {
			t.Fatalf("the audit judged a pinned saga's result against a later version's key: %s", f)
		}
	}
	if rep.Signed != 1 {
		t.Fatalf("%d signatures checked, want the one result", rep.Signed)
	}
}

// rotateTo registers and activates tool_payments@1.0.1, declaring a new key,
// which supersedes 1.0.0.
func rotateTo(t *testing.T, dir string, writer *keys.Signer, key callersig.Signer) {
	t.Helper()
	events, err := registry.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Fold(events)
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	trust := registry.TrustStore{}
	trust.Trust(testPrincipal, writer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: testPrincipal, Kind: "SYSTEM",
	}, reg, trust)
	ctx := context.Background()
	m := paymentsManifest()
	m.Version = "1.0.1"
	m.Identity.PublicKeys = []string{pubOf(key)}
	sig, err := registry.Sign(m, writer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Register(ctx, m, sig); err != nil {
		t.Fatalf("registering 1.0.1: %v", err)
	}
	report, err := registry.Evaluate(ctx, m, paymentsDoubles())
	if err != nil || !report.GetPassed() {
		t.Fatalf("1.0.1 does not pass its conformance: %v", err)
	}
	if err := rec.Evaluate(ctx, "tool_payments", "1.0.1", report); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tool_payments", "1.0.1"); err != nil {
		t.Fatalf("activating 1.0.1: %v", err)
	}
}

// TestTheGoClientSignsAsItsParticipants: the client every Go caller uses --
// the console, the MCP proxy, the chaos harness -- signs what it sends, so a
// daemon that checks signatures accepts it over the wire.
func TestTheGoClientSignsAsItsParticipants(t *testing.T) {
	s, dir := signedServer(t, func(o *orchd.Options) {
		o.RequireCallerSignatures = true
		o.HumanRelayers = []string{"sys_console"}
	})
	defer func() { _ = s.Close() }()
	conn := clientConn(t, s)
	ctx := context.Background()

	payments := orchd.NewClient(conn).WithSigners(participantKey("tool_payments"))
	begin := &janusv1.SagaBegin{
		SagaId: notifySaga, Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in_notify", Principal: testPrincipal,
			Originator: "human:desk@bank", MandateRef: "mandate:payments", Scope: "notify"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_notify", Participant: "tool_payments", Action: "notify.email",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
	if _, err := payments.BeginSaga(ctx, begin); err != nil {
		t.Fatalf("begin: %v", err)
	}
	resp, err := payments.PrepareStep(ctx, notifySaga, "st_notify", nil, nil)
	if err != nil || resp.GetStatus() != janusv1.PrepareStatus_PREPARE_STATUS_PREPARED {
		t.Fatalf("prepare: %v %s", err, resp.GetStatus())
	}
	if _, err := payments.CompleteStep(ctx, &janusv1.StepResult{
		SagaId: notifySaga, StepId: "st_notify", Attempt: resp.GetAttempt(),
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}); err != nil {
		t.Fatalf("complete: %v", err)
	}

	validator := orchd.NewClient(conn).WithSigners(participantKey("ag_credit_policy"))
	if _, err := validator.RecordAnswer(ctx, validatorAnswer(resp.GetAttempt())); err != nil {
		t.Fatalf("the validator's client answer: %v", err)
	}
	console := orchd.NewClient(conn).WithSigners(participantKey("sys_console")).As("sys_console")
	person := personsAnswer(resp.GetAttempt(), "sys_console")
	person.Signature = nil // the client signs it
	if _, err := console.RecordAnswer(ctx, person); err != nil {
		t.Fatalf("the console's client relaying a person's answer: %v", err)
	}
	st, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(st.Steps["st_notify"].Answers); n != 2 {
		t.Fatalf("%d answer(s) recorded, want the validator's and the person's", n)
	}
}

// TestTheAuditChecksSignaturesFromTheLogAlone: the daemon checked each
// signature before recording it; the audit checks them again from the log, so
// an auditor need not trust the daemon did. A forged record written straight
// into the log -- a person's approval "relayed by the console" but signed with
// the agent's key -- is named.
func TestTheAuditChecksSignaturesFromTheLogAlone(t *testing.T) {
	s, dir, writer := signedServerWithWriter(t, nil)
	signedBegin(t, s)
	a := validatorAnswer(runToTheGate(t, s))
	a.Signature = participantKey("ag_credit_policy").Sign(callersig.Answer(a))
	if err := answer(s, a); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Signed != 2 {
		t.Fatalf("an honest signed log audited with %d signatures checked and findings:\n%s", rep.Signed, rep)
	}

	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	forged := personsAnswer(a.GetAttempt(), "sys_console")
	forged.Signature = callersig.Signer{Participant: "sys_console",
		Key: participantKey("ag_intake").Key}.Sign(callersig.Answer(forged))
	payload, err := gproto.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind: evidence.KindGateAnswer, SagaID: notifySaga, StepID: "st_notify",
		Participant: evidence.ParticipantRef{ID: "ag_orchd", Principal: testPrincipal, Kind: "AGENT"},
		Payload:     payload,
	}); err != nil {
		t.Fatal(err)
	}
	_ = app.Close()

	rep, err = gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep.Findings {
		found = found || (f.Kind == gate.FindingSignature && strings.Contains(f.Detail, `"sys_console"`))
	}
	if !found {
		t.Fatalf("a person's approval signed with the agent's key, written straight into the log, "+
			"was not named by the audit:\n%s", rep)
	}
}

// TestAnAnswerIsFromAParticipantOrAPersonNotBoth: found in review. The fold counts an actor that names a person as that person, even if
// it names a participant too; the check read the participant and verified the
// agent's own signature, so an agent signing as itself recorded "alice
// approved". An actor naming both is refused.
func TestAnAnswerIsFromAParticipantOrAPersonNotBoth(t *testing.T) {
	s, dir := signedServer(t, func(o *orchd.Options) { o.HumanRelayers = []string{"sys_console"} })
	defer func() { _ = s.Close() }()
	signedBegin(t, s)
	a := &janusv1.GateAnswer{
		SagaId: notifySaga, StepId: "st_notify", RequirementId: "four-eyes",
		Attempt: runToTheGate(t, s),
		Actor: &janusv1.Actor{
			Participant:  &janusv1.ParticipantRef{Id: "ag_intake"},
			HumanSubject: "person:alice@bank",
		},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"}, AuthRef: "oidc:x",
	}
	a.Signature = participantKey("ag_intake").Sign(callersig.Answer(a))
	if err := answer(s, a); status.Code(err) == codes.OK {
		t.Fatal("an agent recorded a person's approval by naming itself and the person, " +
			"signed with its own key")
	}
	st, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(st.Steps["st_notify"].Answers); n != 0 {
		t.Fatalf("%d answer(s) reached the log", n)
	}
}

// TestTheAuditNamesAPersonsAnswerAnAgentRecorded: the same forgeries, written
// straight into the log past the daemon -- an actor naming the agent and a
// person, and a person's answer relayed by an agent -- are named by the audit
// from the log alone.
func TestTheAuditNamesAPersonsAnswerAnAgentRecorded(t *testing.T) {
	// Each case isolates one check: the actor naming both is a SYSTEM
	// participant, which the relayer-kind check would let through, and the
	// agent relay names only a person, which the both-named check would.
	for name, c := range map[string]struct {
		signer string
		forge  func(*janusv1.GateAnswer)
	}{
		"an actor naming both": {"sys_batch", func(a *janusv1.GateAnswer) {
			a.Actor.Participant = &janusv1.ParticipantRef{Id: "sys_batch"}
		}},
		"relayed by an agent": {"ag_intake", func(*janusv1.GateAnswer) {}},
	} {
		s, dir, writer := signedServerWithWriter(t, nil)
		signedBegin(t, s)
		attempt := runToTheGate(t, s)
		_ = s.Close()
		a := personsAnswer(attempt, c.signer)
		c.forge(a)
		a.Signature = participantKey(c.signer).Sign(callersig.Answer(a))
		app, err := evidence.Open(evidence.Options{Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := gproto.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.Append(context.Background(), evidence.Request{
			Kind: evidence.KindGateAnswer, SagaID: notifySaga, StepID: "st_notify",
			Participant: evidence.ParticipantRef{ID: "ag_orchd", Principal: testPrincipal, Kind: "AGENT"},
			Payload:     payload,
		}); err != nil {
			t.Fatal(err)
		}
		_ = app.Close()
		rep, err := gate.Audit(dir)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, f := range rep.Findings {
			found = found || f.Kind == gate.FindingSignature
		}
		if !found {
			t.Errorf("%s: a person's approval an agent recorded passed the audit:\n%s", name, rep)
		}
	}
}

// TestNoParticipantApprovesForAPerson is the 2026-09-29 audit's attack, in the
// strictest configuration the paper names: signatures required, the console
// the only relayer. The gated agent, and the step's own tool, answer the
// four-eyes requirement in their own names, signed with their own keys and
// claiming the role. Under semantics 4 neither counts.
func TestNoParticipantApprovesForAPerson(t *testing.T) {
	for _, who := range []string{"ag_intake", "tool_payments"} {
		s, dir := signedServer(t, func(o *orchd.Options) {
			o.RequireCallerSignatures = true
			o.HumanRelayers = []string{"sys_console"}
		})
		signedBegin(t, s)
		attempt := runToTheGate(t, s)
		v := validatorAnswer(attempt)
		v.Signature = participantKey("ag_credit_policy").Sign(callersig.Answer(v))
		if err := answer(s, v); err != nil {
			t.Fatal(err)
		}
		a := &janusv1.GateAnswer{
			SagaId: notifySaga, StepId: "st_notify", RequirementId: "four-eyes", Attempt: attempt,
			Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: who}},
			Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
			Reason: "approved",
		}
		a.Signature = participantKey(who).Sign(callersig.Answer(a))
		if err := answer(s, a); err == nil || !strings.Contains(err.Error(), "is answered by a person") {
			t.Errorf("%s approved a person's requirement in its own name and was told %v", who, err)
		}
		st, err := saga.ReplaySaga(dir, notifySaga)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Steps["st_notify"].Status; got == saga.StepCommitted || st.Status == saga.StatusCommitted {
			t.Errorf("%s: the notice committed on an approval no person gave", who)
		}
		_ = s.Close()
	}
}

// suspend suspends a participant's version in the log, as an operator would on
// learning its key was compromised.
func suspend(t *testing.T, dir string, writer *keys.Signer, who string) {
	t.Helper()
	events, err := registry.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Fold(events)
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: testPrincipal, Kind: "SYSTEM",
	}, reg, nil)
	if err := rec.Suspend(context.Background(), who, "1.0.0", "key compromised"); err != nil {
		t.Fatal(err)
	}
}

// TestASuspendedValidatorCannotBeAnsweredFor is the audit's M-1: the validator
// declares a key, is suspended because the key was compromised, and an unsigned
// PASS in its name followed -- accepted in the default configuration, because
// "no active version" read as "no key to check".
func TestASuspendedValidatorCannotBeAnsweredFor(t *testing.T) {
	s, dir, writer := signedServerWithWriter(t, nil)
	signedBegin(t, s)
	attempt := runToTheGate(t, s)
	_ = s.Close()
	suspend(t, dir, writer, "ag_credit_policy")
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone, Policy: preApprovalPolicy(t),
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for name, sig := range map[string]*janusv1.ParticipantSignature{
		"unsigned":                nil,
		"signed with its old key": participantKey("ag_credit_policy").Sign(callersig.Answer(validatorAnswer(attempt))),
	} {
		a := validatorAnswer(attempt)
		a.Signature = sig
		if err := answer(s, a); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: an answer in the name of a suspended validator was told %v", name, err)
		}
	}
}

// TestASuspendedRelayerRelaysNothing: the same for the participant that relays
// a person's answer.
func TestASuspendedRelayerRelaysNothing(t *testing.T) {
	s, dir, writer := signedServerWithWriter(t, nil)
	signedBegin(t, s)
	attempt := runToTheGate(t, s)
	_ = s.Close()
	suspend(t, dir, writer, "sys_console")
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone, Policy: preApprovalPolicy(t),
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := answer(s, personsAnswer(attempt, "sys_console")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a person's answer relayed by a suspended console was told %v", err)
	}
}

// TestTheAuditNamesAnAnswerFromASuspendedParticipant: the same answer written
// straight into the log past the daemon is named from the log alone.
func TestTheAuditNamesAnAnswerFromASuspendedParticipant(t *testing.T) {
	s, dir, writer := signedServerWithWriter(t, nil)
	signedBegin(t, s)
	attempt := runToTheGate(t, s)
	_ = s.Close()
	suspend(t, dir, writer, "ag_credit_policy")
	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: writer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := gproto.Marshal(validatorAnswer(attempt))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind: evidence.KindGateAnswer, SagaID: notifySaga, StepID: "st_notify",
		Participant: evidence.ParticipantRef{ID: "ag_orchd", Principal: testPrincipal, Kind: "AGENT"},
		Payload:     payload,
	}); err != nil {
		t.Fatal(err)
	}
	_ = app.Close()
	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep.Findings {
		found = found || (f.Kind == gate.FindingSignature && strings.Contains(f.Detail, "no active version"))
	}
	if !found {
		t.Fatalf("an unsigned answer in a suspended validator's name passed the audit:\n%s", rep)
	}
}
