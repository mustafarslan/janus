package main

// Running the chaos suite against a hosted coordinator.
//
// The suite's own property does not change: a saga's outcome must not depend on
// how many times its coordinator died. What changes is where the coordinator
// lives. In hosted mode the child process is a janus-orchd server plus a client
// of it, the participants answer over gRPC, and the SIGKILL takes both down
// together — which is what a crash in a deployment does.
//
// The seam this is really testing is the new one. In-process, a step's outcome
// is produced and appended in the same call, so there is no window. Hosted,
// there is: the client sends a result, the daemon appends it, the daemon
// acknowledges. A kill anywhere in there leaves the client not knowing whether
// its report landed, and the only correct behaviour is to send it again. That
// retry is the interesting path, and it runs on every restart here — the driver
// re-reads the projection and reports whatever is still outstanding, which for
// a step whose result did land is a duplicate the daemon has to absorb.
//
// Two things this mode does not cover, and both are stated rather than worked
// around:
//
//   - Scenarios that need an answerer or a deliverer injected — the outbox,
//     rogue-step, four-eyes and self-approval scenarios — are not hosted. They
//     need a way to carry a validator's answer and a target's delivery over the
//     wire, which is 4b and 4c's work, not something to smuggle in behind a
//     test harness.
//   - Sub-sagas are not hosted: the hosted program implements no Spawner, and
//     spawning over the wire needs a vocabulary this phase has not designed.
//
// So `-hosted` runs the scenarios that translate honestly and says how many it
// ran. It is an addition to the suite, not a replacement for it.

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// runHostedChild drives one scenario through a daemon it starts itself.
func runHostedChild(dir, name string) error {
	sc, ok := scenarioByName(name)
	if !ok {
		return fmt.Errorf("unknown scenario %q", name)
	}
	if sc.hosted == nil {
		return fmt.Errorf("scenario %q cannot be hosted", name)
	}
	plan := *sc.hosted
	members := append([]hostedMember{{prog: plan.prog, spawns: plan.spawns}}, plan.also...)
	begins := make([]*janusv1.SagaBegin, 0, len(members))
	for _, m := range members {
		begins = append(begins, pinnedBegin(m.prog.begin))
	}

	// The first run of a scenario has no directory yet: the in-process child
	// gets one as a side effect of opening the log, and this one reads the log
	// before it opens it.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	// The registry is written before the daemon opens the directory, because
	// the daemon holds the writer lock for as long as it runs. A deployment
	// registers participants with the registry CLI the same way, and doing it
	// here rather than teaching the daemon a back door is the point.
	// One registration for the whole family: a participant that appears in both
	// the parent's plan and the child's has to declare the actions of both, or
	// admitting the second saga refuses it for an action the first never
	// mentioned.
	if err := ensureManifests(dir, begins); err != nil {
		return fmt.Errorf("registering the scenario's participants: %w", err)
	}

	signer, err := keys.LoadOrCreate(dir + "/orchd.key")
	if err != nil {
		return err
	}
	dsn, err := scopedDSN(context.Background(), dir)
	if err != nil {
		return err
	}
	srv, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: engine.Policy(),
		Participant: participant,
		// With -projection, this crash point's frontier gates are answered from
		// the projection tables rather than by replaying the log — so the process
		// being killed is one holding a projection, and the one that restarts
		// resumes from a last_event_seq another process wrote.
		ProjectionDSN: dsn,
		// The ticker is off unless the scenario asks for it. Background work
		// would otherwise make what the kill interrupted depend on a timer
		// rather than on the transition under test.
		//
		// One scenario asks for it, because for that one the ticker is the
		// thing being killed: a gate expiry is recorded by the daemon and
		// nothing else, so a chaos run with the ticker off would be
		// testing a deadline that never arrives.
		TickInterval: tickFor(plan),
	})
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	conn, stop := serveInProcess(srv)
	defer stop()
	cl := orchd.NewClient(conn)

	// The deliverer connects the way a janus-mcpd would: it opens the stream,
	// says which targets it serves, and waits to be told. Nothing about the
	// release path changes for it being a test ledger.
	if plan.target != "" {
		stopDelivering, err := serveDeliverer(context.Background(), cl,
			plan.target, plan.newDeliverer(dir))
		if err != nil {
			return err
		}
		defer stopDelivering()
	}

	report := func(sagaID string) {
		state, err := saga.ReplaySaga(dir, sagaID)
		if err != nil {
			return
		}
		digest, derr := digestOf(state)
		if derr != nil {
			return
		}
		fmt.Printf("ack %s %d %s\n", state.SagaID, state.EventCount, digest)
	}
	return driveHosted(context.Background(), cl, begins, members, plan, dir, report)
}

// driveHosted plays the scenario's script against the service.
//
// It is written as a client with no memory, for the same reason the coordinator
// is: after a kill the next process starts from the projection and nothing
// else. Every iteration asks what is outstanding and answers exactly one thing,
// so the parent's kill can land between any two.
func driveHosted(ctx context.Context, cl *orchd.Client, begins []*janusv1.SagaBegin,
	members []hostedMember, plan hostedPlan, dir string, report func(string)) error {

	for _, b := range begins {
		if _, err := cl.BeginSaga(ctx, b); err != nil {
			// AlreadyExists is the ordinary case on every run but the first:
			// this process is resuming a saga its predecessor started. Treating
			// it as a failure would make recovery impossible by construction.
			if status.Code(err) != codes.AlreadyExists {
				return fmt.Errorf("beginning %s: %w", b.GetSagaId(), err)
			}
		}
	}
	// Capture the effect before the saga is driven, and re-send it on every
	// restart: holding the same effect twice is a success that changed nothing,
	// so the client does not have to remember whether it already did.
	if plan.holdFor != nil {
		effect := plan.holdFor(dir)
		if _, err := cl.HoldEffect(ctx, effect); err != nil {
			return fmt.Errorf("holding the effect for %s: %w", effect.GetSagaId(), err)
		}
	}
	report(begins[0].GetSagaId())

	// The bound is generous and is a bound: a driver that could loop forever
	// would turn a coordinator bug into a hung test rather than a failure.
	for range 4000 {
		var acted, pending bool
		for i, b := range begins {
			sagaID := b.GetSagaId()
			p, err := cl.GetSaga(ctx, sagaID)
			if err != nil {
				return fmt.Errorf("reading %s: %w", sagaID, err)
			}
			if terminalProjection(p) {
				continue
			}
			pending = true
			did, err := answerOne(ctx, cl, sagaID, p, members[i], plan)
			if err != nil {
				return err
			}
			if did {
				acted = true
				report(sagaID)
				break
			}
		}
		if !pending {
			return nil
		}
		if !acted {
			// Nothing outstanding anywhere and something is still running.
			//
			// For a scenario with a ticker that is the ordinary state, not a
			// stall: the saga is held at a gate whose deadline the daemon has
			// not reached yet, and the only thing that can move it is the
			// daemon. Waiting is what a deployment does, so the driver waits.
			//
			// For every other scenario it means a gate is waiting for somebody
			// the hosted driver cannot be, which is a scenario that should not
			// have been marked hostable — and that stays an error, because a
			// driver that waited on it would hang instead of saying so.
			if plan.tick > 0 {
				select {
				case <-time.After(plan.tick):
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return fmt.Errorf("no saga in %v has anything for a participant to do and "+
				"none is finished", sagaIDs(begins))
		}
	}
	return fmt.Errorf("the family %v did not settle within the driver's bound", sagaIDs(begins))
}

func sagaIDs(begins []*janusv1.SagaBegin) []string {
	out := make([]string, 0, len(begins))
	for _, b := range begins {
		out = append(out, b.GetSagaId())
	}
	return out
}

// answerOne reports exactly one outstanding step or compensation.
func answerOne(ctx context.Context, cl *orchd.Client, sagaID string,
	p *janusv1.SagaProjection, member hostedMember, plan hostedPlan) (bool, error) {

	prog := member.prog

	// Gates first. A step held by a gate is not going to move for any
	// participant, and answering is the only thing that unblocks it.
	for _, st := range p.GetSteps() {
		for _, pg := range st.GetPendingGates() {
			answered, err := answerGate(ctx, cl, sagaID, st.GetStepId(), pg, plan.answerers)
			if answered || err != nil {
				return answered, err
			}
		}
	}

	for _, st := range p.GetSteps() {
		switch {
		case st.GetAwaitingParticipant() && st.GetStatus() != janusv1.StepState_STEP_STATE_PREPARED:
			// Claim the step and say what it will do. The declaration is what
			// its pre-execution gate decides on, so it goes with the request to
			// prepare rather than with the result.
			//
			// The condition is "not prepared" rather than "planned" because a
			// step that failed retryably and still has budget is also the
			// participant's turn again, and it sits in FAILED until the next
			// attempt is prepared. Matching on PLANNED alone leaves a retrying
			// saga going round forever, reporting a result for an attempt that
			// was never started.
			resp, err := cl.PrepareStep(ctx, sagaID, st.GetStepId(),
				saga.FactsToProto(prog.Facts(st.GetStepId(), st.GetAttempt())),
				member.spawns[st.GetStepId()])
			if err != nil {
				return true, fmt.Errorf("preparing %s/%s: %w", sagaID, st.GetStepId(), err)
			}
			switch resp.GetStatus() {
			case janusv1.PrepareStatus_PREPARE_STATUS_PREPARED:
				return true, nil
			case janusv1.PrepareStatus_PREPARE_STATUS_UNAVAILABLE:
				// The claim was refused because the saga moved while it was
				// being made — which is what happens when a step's own
				// pre-execution gate turns it down: the step is refused, the
				// saga starts unwinding, and by the time the answer comes back
				// there is nothing here to run. That is the rogue-step scenario
				// working, not a failure, and the next pass picks up the
				// compensations.
				return true, nil
			default:
				return true, fmt.Errorf("preparing %s/%s: %s — %s", sagaID, st.GetStepId(),
					resp.GetStatus(), resp.GetReason())
			}
		case st.GetAwaitingParticipant():
			out := prog.Run(st.GetStepId(), st.GetAttempt())
			return true, complete(ctx, cl, &janusv1.StepResult{
				SagaId: sagaID, StepId: st.GetStepId(), Attempt: st.GetAttempt(),
				Outcome: &janusv1.Outcome{Status: out.Status},
				Touches: out.Touches,
				Facts:   saga.FactsToProto(out.Published),
			})
		case st.GetAwaitingCompensation():
			return true, complete(ctx, cl, &janusv1.StepResult{
				SagaId: sagaID, StepId: st.GetStepId() + "~undo",
				Outcome: &janusv1.Outcome{Status: prog.Undo(st.GetStepId())},
			})
		}
	}
	return false, nil
}

// complete sends a result and retries it once the way a participant would.
//
// The retry is the point of hosting the suite at all. A daemon killed between
// its append and its acknowledgement leaves the client unable to tell whether
// the result landed, and the only safe move is to send it again — so the
// service has to absorb the duplicate rather than record a second account of
// one attempt. That is what already_recorded is for, and it is exercised here
// on every restart rather than only in a unit test.
func complete(ctx context.Context, cl *orchd.Client, res *janusv1.StepResult) error {
	_, err := cl.CompleteStep(ctx, res)
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.Unavailable {
		time.Sleep(10 * time.Millisecond)
		_, err = cl.CompleteStep(ctx, res)
	}
	if err != nil {
		return fmt.Errorf("reporting %s/%s: %w", res.GetSagaId(), res.GetStepId(), err)
	}
	return nil
}

func terminalProjection(p *janusv1.SagaProjection) bool {
	switch p.GetStatus() {
	case janusv1.SagaState_SAGA_STATE_COMMITTED,
		janusv1.SagaState_SAGA_STATE_COMPENSATED,
		janusv1.SagaState_SAGA_STATE_QUARANTINE:
		return true
	}
	return false
}

// ---- the registry the daemon admits against --------------------------------

// pinnedBegin returns the plan with a manifest pin per participant.
//
// The scenarios were written before the registry existed and pin nothing, and
// the daemon refuses an unpinned plan (I8). Filling the pins here rather than
// relaxing the daemon is the direction that keeps the check real: what is
// admitted is a plan that names exactly which declaration it is relying on.
func pinnedBegin(begin *janusv1.SagaBegin) *janusv1.SagaBegin {
	out, _ := proto.Clone(begin).(*janusv1.SagaBegin)
	if out.ManifestPins == nil {
		out.ManifestPins = map[string]string{}
	}
	for _, step := range out.GetPlan() {
		out.ManifestPins[step.GetParticipant()] = manifestVersion
	}
	return out
}

const manifestVersion = "1.0.0"

// ensureManifests registers and activates a manifest for every participant the
// plan names, unless one is already active from a previous run of this child.
//
// The manifests are synthesised from the plan, which is the one thing that
// would be dishonest if this were a deployment: there, the manifest is what the
// participant declares and the plan is checked against it. Here the plan is the
// only description of the participant that exists. What the check still catches
// is a plan that contradicts *itself* across a restart — and, more to the
// point, it means the daemon's admission path runs for real rather than being
// switched off for the harness.
func ensureManifests(dir string, begins []*janusv1.SagaBegin) error {
	events, err := registry.LoadEvents(dir)
	if err != nil {
		return err
	}
	reg, err := registry.Fold(events)
	if err != nil {
		return err
	}

	missing := map[string]bool{}
	for _, begin := range begins {
		for _, step := range begin.GetPlan() {
			if _, ok := reg.Resolve(step.GetParticipant(), manifestVersion); !ok {
				missing[step.GetParticipant()] = true
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}

	signer, err := keys.LoadOrCreate(dir + "/registry.key")
	if err != nil {
		return err
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 64 << 10,
	})
	if err != nil {
		return err
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust(participant.Principal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: participant.Principal, Kind: "SYSTEM",
	}, reg, trust)

	ctx := context.Background()
	for id := range missing {
		m, doubles := manifestFor(id, begins)
		sig, err := registry.Sign(m, signer)
		if err != nil {
			return err
		}
		if _, err := rec.Register(ctx, m, sig); err != nil {
			return fmt.Errorf("registering %s: %w", id, err)
		}
		rep, err := registry.Evaluate(ctx, m, doubles)
		if err != nil {
			return fmt.Errorf("evaluating %s: %w", id, err)
		}
		if !rep.GetPassed() {
			return fmt.Errorf("the synthesised manifest for %s does not pass its own "+
				"conformance:\n%s", id, registry.ReportText(rep))
		}
		if err := rec.Evaluate(ctx, id, manifestVersion, rep); err != nil {
			return err
		}
		if err := rec.Activate(ctx, id, manifestVersion); err != nil {
			return err
		}
	}
	return nil
}

// manifestFor builds the declaration a participant would have published, from
// the only description of it that this suite has: the plan.
func manifestFor(participantID string, begins []*janusv1.SagaBegin) (
	*registry.Manifest, *registry.Doubles) {

	m := &registry.Manifest{
		Version: manifestVersion,
		Identity: registry.Identity{
			ParticipantID: participantID, Kind: "TOOL", Principal: participant.Principal,
		},
		Runtime: registry.Runtime{ModelID: "none", PromptBundleHash: "blake3:chaos"},
		Risk: registry.Risk{
			Tier:                 1,
			RevalidationTriggers: []string{registry.TriggerModelChange, registry.TriggerActionChange},
		},
		Jurisdiction: registry.Jurisdiction{DeployableIn: []string{"EU"}, DataResidency: "EU"},
	}
	doubles := registry.NewDoubles("chaos-sandbox/" + participantID)

	declared := map[string]bool{}
	for _, step := range allSteps(begins) {
		if step.GetParticipant() != participantID || declared[step.GetAction()] {
			continue
		}
		declared[step.GetAction()] = true
		action := registry.Action{
			Name:        step.GetAction(),
			EffectClass: effectClassName(step.GetEffectClass()),
		}
		// A PURE action delivers nothing, so it cannot deliver anything twice
		// and the registry refuses an idempotency recipe on one. That refusal
		// is right and the synthesised manifest has to respect it rather than
		// declare a key for something that never leaves.
		if action.EffectClass != "PURE" {
			action.Idempotency = &registry.Idempotency{KeyRecipe: "saga_id,step_id"}
		}
		if undo := step.GetCompensationAction(); undo != "" {
			action.Compensation = &registry.Compensation{
				Action: undo, MaxDelaySeconds: 3600,
				ResidualEffects: "none in the sandbox",
			}
			if !declared[undo] {
				declared[undo] = true
				m.Actions = append(m.Actions, registry.Action{
					Name: undo, EffectClass: "REVERSIBLE",
					Compensation: &registry.Compensation{Action: step.GetAction()},
					Idempotency:  &registry.Idempotency{KeyRecipe: "saga_id,step_id"},
				})
				// The inverse has to be demonstrable, not merely claimed: a
				// conformance run that took the word of the manifest would be
				// paperwork.
				doubles = doubles.With(undo, registry.Double{
					Deltas: map[string]int64{"ledger": 1},
				})
			}
		}
		m.Actions = append(m.Actions, action)
		switch action.EffectClass {
		case "PURE":
			doubles = doubles.With(action.Name, registry.Double{})
		default:
			doubles = doubles.With(action.Name, registry.Double{
				Deltas: map[string]int64{"ledger": -1},
			})
		}
	}
	return m, doubles
}

func effectClassName(c janusv1.EffectClass) string {
	switch c {
	case janusv1.EffectClass_EFFECT_CLASS_PURE:
		return "PURE"
	case janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE:
		return "REVERSIBLE"
	case janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE:
		return "COMPENSABLE"
	case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED:
		return "IRREVERSIBLE_GATED"
	default:
		return "IRREVERSIBLE_IMMEDIATE"
	}
}

// serveInProcess runs the daemon over an in-memory listener.
//
// A real port would be the more faithful thing and is the wrong trade here: the
// suite runs many children at once and a bound port turns a correctness suite
// into a scheduling problem. What is being tested is the service boundary —
// serialisation, status codes, the retry — and bufconn carries all of it.
func serveInProcess(s *orchd.Server) (*grpc.ClientConn, func()) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	janusv1.RegisterOrchestratorServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(fmt.Sprintf("in-process dial: %v", err))
	}
	return conn, func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// serveDeliverer connects a deliverer to the daemon and answers what it is sent.
//
// It returns once the stream is registered, so a scenario cannot race ahead of
// its own deliverer and see an effect refused for want of one.
func serveDeliverer(ctx context.Context, cl *orchd.Client, target string,
	d outbox.Deliverer) (func(), error) {

	ctx, cancel := context.WithCancel(ctx)
	stream, err := cl.DeliverEffects(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := stream.Send(&janusv1.DeliverEffectsRequest{
		Message: &janusv1.DeliverEffectsRequest_Register{
			Register: &janusv1.DelivererRegistration{Targets: []string{target}},
		},
	}); err != nil {
		cancel()
		return nil, err
	}

	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			receipt := &janusv1.DeliveryReceipt{EffectId: msg.GetEffectId()}
			r, derr := d.Deliver(ctx, outbox.Effect{
				ID: msg.GetEffectId(), SagaID: msg.GetSagaId(), StepID: msg.GetStepId(),
				Target: msg.GetTarget(), Action: msg.GetAction(), IdemKey: msg.GetIdemKey(),
				Class: msg.GetEffectClass(), PayloadHash: msg.GetPayloadHash(),
				PayloadRef: msg.GetPayloadRef(),
			})
			switch {
			case derr != nil:
				receipt.Error = derr.Error()
				receipt.Retryable = r.Retryable
			default:
				receipt.Ref, receipt.Hash = r.Ref, r.Hash
				receipt.Duplicate, receipt.Retryable = r.Duplicate, r.Retryable
				receipt.Message = r.Message
			}
			if err := stream.Send(&janusv1.DeliverEffectsRequest{
				Message: &janusv1.DeliverEffectsRequest_Receipt{Receipt: receipt},
			}); err != nil {
				return
			}
		}
	}()
	return cancel, nil
}

// answerGate records one outstanding answer, as the party whose turn it is.
//
// The party is chosen by how many answers the requirement already has rather
// than by anything this process remembers. That is what makes it correct across
// a kill: a driver that restarted mid-quorum and started again from the first
// party would be asking somebody who has already answered, which the state
// machine refuses — correctly, and in a way that would look like a bug here.
func answerGate(ctx context.Context, cl *orchd.Client, sagaID, stepID string,
	pg *janusv1.PendingGate, answerers []answerSet) (bool, error) {

	idx := int(pg.GetAnswersRecorded())
	if idx >= len(answerers) {
		// Nobody left to answer as. For a scenario that is meant to be refused
		// this is the expected resting place, so it is not an error here — the
		// driver's own "nothing to do and not terminal" check is what reports a
		// saga that is genuinely stuck.
		return false, nil
	}
	answer := answerers[idx].Answer(stepID, pg.GetAttempt(), pg.GetRequirementId())
	if answer == nil {
		return false, nil
	}
	answer.SagaId, answer.StepId = sagaID, stepID
	answer.RequirementId, answer.Attempt = pg.GetRequirementId(), pg.GetAttempt()
	if _, err := cl.RecordAnswer(ctx, answer); err != nil {
		return true, fmt.Errorf("answering %s/%s/%s: %w",
			sagaID, stepID, pg.GetRequirementId(), err)
	}
	return true, nil
}

// allSteps is every step in a family's plans, in order.
func allSteps(begins []*janusv1.SagaBegin) []*janusv1.PlannedStep {
	var out []*janusv1.PlannedStep
	for _, b := range begins {
		out = append(out, b.GetPlan()...)
	}
	return out
}
