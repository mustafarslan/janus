package orchd_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/registry"
)

// The tests in this file exist because everything else about the projection is
// checked in pkg/projection, against the store directly. That leaves the wiring
// -- `orchd.Options.ProjectionDSN`, the `projection.Open`, the closure over
// `app.Stats().LastSeq` that supplies the head -- compile-checked and never run.
//
// This repository has shipped that shape before and it is written down as
// something to watch for: `janus-tier -jurisdiction` was a declaration nothing
// read back. A flag whose
// effect no test observes is the same thing.

// pgSchema gives a test its own schema in the projection database and returns a
// DSN scoped to it.
func pgSchema(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("JANUS_PG_DSN")
	if dsn == "" {
		if os.Getenv("JANUS_PG_REQUIRED") != "" {
			t.Fatal("JANUS_PG_REQUIRED is set but JANUS_PG_DSN is not, so the orchd " +
				"projection wiring would have gone untested")
		}
		t.Skip("set JANUS_PG_DSN to exercise the projection-backed daemon")
	}
	ctx := context.Background()
	schema := "o_" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(t.Name()))
	if len(schema) > 60 {
		schema = schema[:60]
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to %s: %v", dsn, err)
	}
	for _, q := range []string{`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`, `CREATE SCHEMA ` + schema} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_ = admin.Close(ctx)
	t.Cleanup(func() {
		a, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return
		}
		_, _ = a.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		_ = a.Close(ctx)
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "options=-c%20search_path%3D" + schema
}

// frontierPolicy puts a frontier gate in front of any irreversible effect, which
// is what makes the daemon consult the cross-saga index at all: `needsIndex`
// skips the work entirely when no frontier requirement is due, so a policy
// without one would exercise none of this.
func frontierPolicy(t *testing.T) *gate.Policy {
	t.Helper()
	p := &gate.Policy{
		ID: "orchd.projection.test",
		Rules: []gate.Rule{{
			ID:    "irreversible-checks-the-frontier",
			Match: gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
			Require: []gate.Requirement{{
				ID: "notify-frontier", Gate: gate.GateFrontier, Phase: gate.PhasePreRelease,
				Frontier: &gate.FrontierSpec{},
			}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func newFrontierServer(t *testing.T, dsn string) (*orchd.Server, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		Policy:        frontierPolicy(t),
		ProjectionDSN: dsn,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatalf("starting the daemon (projection=%q): %v", dsn, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

// runNotify drives the gated saga to the point where its PRE_RELEASE gates are
// decided, and returns the saga as the daemon reports it.
func runNotify(t *testing.T, s *orchd.Server) *janusv1.SagaProjection {
	t.Helper()
	ctx := context.Background()
	beginGatedPlan(t, s, ctx)
	prepareStep(t, s, notifySaga, "st_notify")
	step := stepOf(t, getSaga(t, s, notifySaga), "st_notify")
	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify", Attempt: step.GetAttempt(),
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			Touches: []*janusv1.ResourceTouch{
				{ResourceId: "acct:1", Mode: janusv1.ResourceTouch_MODE_WRITE},
			},
		},
	}); err != nil {
		t.Fatalf("completing the step: %v", err)
	}
	return getSaga(t, s, notifySaga)
}

// TestAProjectionBackedDaemonDecidesAsAReplayBackedOneDoes runs the same saga
// through two daemons that differ only in how the frontier gate gets its index,
// and requires the same outcome.
//
// It also checks the thing that makes the comparison meaningful: that the
// projection was actually written. Two daemons agreeing proves nothing if the
// second one quietly fell back to replaying the log, and a flag that is accepted
// and ignored is exactly the failure this file exists to catch.
func TestAProjectionBackedDaemonDecidesAsAReplayBackedOneDoes(t *testing.T) {
	dsn := pgSchema(t)

	projected, _ := newFrontierServer(t, dsn)
	replayed, _ := newFrontierServer(t, "")

	withProjection := runNotify(t, projected)
	withReplay := runNotify(t, replayed)

	if a, b := withProjection.GetStatus(), withReplay.GetStatus(); a != b {
		t.Errorf("the projection-backed daemon reached %s, the replay-backed one %s", a, b)
	}
	if withReplay.GetStatus() != janusv1.SagaState_SAGA_STATE_COMMITTED {
		t.Fatalf("the replay-backed daemon reached %s, so this test is not comparing "+
			"two daemons that got past the frontier gate", withReplay.GetStatus())
	}

	pa := stepOf(t, withProjection, "st_notify")
	pb := stepOf(t, withReplay, "st_notify")
	if pa.GetStatus() != pb.GetStatus() {
		t.Errorf("step status: projection-backed %s, replay-backed %s",
			pa.GetStatus(), pb.GetStatus())
	}
	if a, b := len(pa.GetPendingGates()), len(pb.GetPendingGates()); a != b {
		t.Errorf("pending gates: projection-backed %d, replay-backed %d", a, b)
	}

	// Did the daemon actually use it? The rows are the evidence.
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var sagas, touches int
	var head int64
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM sagas`).Scan(&sagas); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM resource_touches`).Scan(&touches); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx,
		`SELECT last_event_seq FROM projection_meta WHERE only_row`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if sagas == 0 || head == 0 {
		t.Fatalf("the daemon was given a projection and never folded into it "+
			"(%d sagas, last_event_seq %d); the flag is a declaration nothing reads",
			sagas, head)
	}
	if touches == 0 {
		t.Error("the projection holds no resource touches, so the frontier query it " +
			"answers could only ever have found nothing")
	}
	t.Logf("projection holds %d sagas and %d touches, folded to sequence %d", sagas, touches, head)
}

// TestADaemonWithAnUnreachableProjectionRefusesToStart.
//
// Starting anyway and falling back to replaying the log would be the friendly
// behaviour and the wrong one: an operator who asked for a projection and got a
// daemon that silently did something else has a deployment whose performance
// characteristics are not the ones they configured, and no way to notice.
func TestADaemonWithAnUnreachableProjectionRefusesToStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		Policy: frontierPolicy(t),
		// A port nothing is listening on, with a short timeout so the test does
		// not wait out the default.
		ProjectionDSN: "postgres://janus:janus@127.0.0.1:1/janus?connect_timeout=2",
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err == nil {
		_ = s.Close()
		t.Fatal("the daemon started with a projection it cannot reach")
	}
	if !strings.Contains(err.Error(), "projection") {
		t.Errorf("the error does not say the projection was the problem: %v", err)
	}
}

// serverOn starts a daemon over an existing directory, optionally backed by a
// projection. It is `newFrontierServer` without the fresh directory, so a test
// can stop a daemon, change the log underneath it, and start another one on the
// same evidence and the same projection.
func serverOn(t *testing.T, dir string, signer *keys.Signer, dsn string) *orchd.Server {
	t.Helper()
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		Policy:        frontierPolicy(t),
		ProjectionDSN: dsn,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatalf("starting the daemon on %s: %v", dir, err)
	}
	return s
}

// suspendPayments withdraws the active manifest version, the way an operator
// would: through the registry, against the log, with no daemon running. One
// process owns an evidence directory, so this cannot be done to a
// live daemon and the daemon has no RPC for it — which is why the test below
// stops and restarts rather than suspending underneath a running server.
func suspendPayments(t *testing.T, dir string, signer *keys.Signer) {
	t.Helper()
	ctx := context.Background()
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust(testPrincipal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "ag_operator", Principal: testPrincipal, Kind: "AGENT", ManifestVersion: "1.0.0",
	}, reg, trust)
	if err := rec.Suspend(ctx, "tool_payments", "1.0.0", "an incident"); err != nil {
		t.Fatalf("suspending the manifest: %v", err)
	}
}

func beginWire(t *testing.T, s *orchd.Server, sagaID string) error {
	t.Helper()
	_, err := s.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{
		Begin: &janusv1.SagaBegin{
			SagaId: sagaID,
			Mode:   "supervised",
			Intent: &janusv1.Intent{
				IntentId: "in_" + sagaID, Principal: testPrincipal,
				Originator: "human:desk@bank", MandateRef: "mandate:payments",
				Scope: "move money",
			},
			Plan: []*janusv1.PlannedStep{{
				StepId: "st_wire", Participant: "tool_payments", Action: "payments.wire",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
				// Declared, because admission refuses a COMPENSABLE step that
				// names no undo and that no policy rule covers -- nothing would
				// decide whether its effect may happen and nothing could reverse
				// it afterwards.
				CompensationAction: "payments.refund",
			}},
			ManifestPins: map[string]string{"tool_payments": "1.0.0"},
		},
	})
	return err
}

// TestASuspensionBetweenSagasIsSeen is the reason admission re-reads the
// registry at all.
//
// `admitAgainstRegistry` names the failure in its own comment: a manifest can be
// suspended between one saga and the next, so a cached registry would admit a
// plan against a version that had been withdrawn — which is precisely the check
// it is. Moving that read onto a projection is only safe if the projection is
// not that cache, and the way it is not is the staleness contract: it must have
// reached the head of the log before it may answer.
//
// So: admit a saga, suspend the version, admit again, and require the refusal.
// The daemon is restarted around the suspension because one process owns an
// evidence directory and there is no RPC to suspend through — but the
// *projection* survives the restart, which is what makes this a real test. A
// projector that resumed from `last_event_seq` and did not catch up would still
// be holding the registry from before the suspension, and would admit.
func TestASuspensionBetweenSagasIsSeen(t *testing.T) {
	dsn := pgSchema(t)

	for _, backing := range []struct {
		name string
		dsn  string
	}{{"projection", dsn}, {"replay", ""}} {
		t.Run(backing.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "evidence")
			signer, err := keys.Generate()
			if err != nil {
				t.Fatal(err)
			}
			registerManifest(t, dir, signer)

			first := serverOn(t, dir, signer, backing.dsn)
			if err := beginWire(t, first, "sg_before"); err != nil {
				t.Fatalf("the saga was refused while its manifest was active: %v", err)
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}

			suspendPayments(t, dir, signer)

			second := serverOn(t, dir, signer, backing.dsn)
			defer func() { _ = second.Close() }()
			err = beginWire(t, second, "sg_after")
			if err == nil {
				t.Fatal("a saga was admitted against a manifest version that had been " +
					"suspended; the registry read is answering about the past")
			}
			t.Logf("refused as it should be: %v", err)

			// ResolveParticipant reads the registry through the same path and
			// returns a whole Entry rather than a yes/no — the manifest, its
			// declared actions, its standing. On a projection-backed daemon that
			// Entry is folded from the projected event stream, and nothing else
			// in this suite ever makes it do so.
			resolved, err := second.ResolveParticipant(context.Background(),
				&janusv1.ResolveParticipantRequest{
					ParticipantId: "tool_payments", Version: "1.0.0",
				})
			if err != nil {
				t.Fatalf("resolving a suspended version should report it, not fail: %v", err)
			}
			if got := resolved.GetState(); got != "SUSPENDED" {
				t.Errorf("resolve reports state %q for a suspended version, want SUSPENDED", got)
			}
			// And the Entry has to carry the manifest's substance, not just a
			// state: a resolve that returned the right label and an empty
			// declaration would satisfy the check above and tell a caller
			// nothing.
			var found bool
			for _, a := range resolved.GetActions() {
				if a.GetName() == "payments.wire" {
					found = true
					if a.GetEffectClass() != janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE {
						t.Errorf("payments.wire resolves as %s, the manifest declares COMPENSABLE",
							a.GetEffectClass())
					}
				}
			}
			if !found {
				t.Errorf("the resolved entry declares no payments.wire action; it carries a "+
					"state and not a manifest: %v", resolved.GetActions())
			}
		})
	}
}

// TestTheDaemonFoldsWithNothingReading is the acceptance test for folding unprompted.
//
// Until 6c the projection only ever advanced because something in this process
// asked it a question — a frontier gate, an admission — so a console in another
// process would have shown a world that stopped at the last admission. A console
// cannot fold for itself: it holds no writer lock and is not the writer.
//
// So the daemon folds on an interval. This drives a saga, reads *nothing*
// through the daemon afterwards, and requires the projection to catch up anyway.
// Without the ticker the head stays where the last gate decision left it.
func TestTheDaemonFoldsWithNothingReading(t *testing.T) {
	dsn := pgSchema(t)
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		Policy:        frontierPolicy(t),
		ProjectionDSN: dsn,
		// Fast, because this is a test and not a deployment.
		TickInterval: 50 * time.Millisecond,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	// A saga that runs to completion. Its own gate decisions fold the projection
	// as far as the last one, and the events after that — the commit, the seal —
	// are what only the ticker will pick up.
	runNotify(t, s)

	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	head := func() int64 {
		var n int64
		if err := conn.QueryRow(context.Background(),
			`SELECT last_event_seq FROM projection_meta WHERE only_row`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Nothing is asked of the daemon from here on. Whatever moves the head moves
	// it on the daemon's own initiative.
	logHead := int64(0)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h := head(); h > 0 {
			logHead = h
			var behind int
			if err := conn.QueryRow(context.Background(),
				`SELECT count(*) FROM sagas WHERE terminal`).Scan(&behind); err != nil {
				t.Fatal(err)
			}
			if behind > 0 {
				// The saga reached a terminal state *and* the projection knows
				// it, with nothing having asked. That is the property.
				t.Logf("the daemon folded to sequence %d unprompted", logHead)
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the projection never caught up on the daemon's own initiative; it sits at "+
		"sequence %d and no committed saga has reached it", logHead)
}

// TestAConsoleReadsWhileTheDaemonFolds is the rule "reading needs no lock"
// under the conditions that would break it.
//
// An earlier version of this test lived in pkg/console and could not fail: a
// console never calls CatchUp, so there was no code path by which it could take
// the lock, and breaking it would have meant adding code. What was untested was
// the case that matters — a *live* daemon whose ticker is folding while a
// console reads the same store, concurrently rather than one after the other.
// If the lock were taken on Open rather than on the fold, or if a reader had to
// wait behind a fold, this is where it would show.
func TestAConsoleReadsWhileTheDaemonFolds(t *testing.T) {
	dsn := pgSchema(t)
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	daemon, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		Policy:        frontierPolicy(t),
		ProjectionDSN: dsn,
		// Folding hard, so a reader that had to wait for the lock would wait
		// often enough to notice.
		TickInterval: time.Millisecond,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = daemon.Close() }()
	runNotify(t, daemon)

	// The console's own store, on the same schema, while the daemon holds the
	// writer lock and its ticker is folding.
	reader, err := projection.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("a console could not open a store the daemon is folding: %v", err)
	}
	defer reader.Close()

	c := console.Open(dir).WithProjection(reader)
	deadline := time.Now().Add(2 * time.Second)
	reads := 0
	for time.Now().Before(deadline) {
		if _, err := c.Overview(); err != nil {
			t.Fatalf("the console could not read the overview while the daemon folded: %v", err)
		}
		if _, err := c.Queue(); err != nil {
			t.Fatalf("the console could not read the queue while the daemon folded: %v", err)
		}
		reads++
		if reads >= 50 {
			break
		}
	}
	if reads < 50 {
		t.Fatalf("only %d reads completed in two seconds; a console reading a store being "+
			"folded should not be waiting on anything", reads)
	}

	// And it took nothing: the daemon is still the writer, so its own fold still
	// works after all that reading.
	if _, err := daemon.ResolveParticipant(context.Background(),
		&janusv1.ResolveParticipantRequest{ParticipantId: "tool_payments", Version: "1.0.0"}); err != nil {
		t.Errorf("the daemon lost its own store to a reader: %v", err)
	}
}

// TestTheTickerCanBeTurnedOff. A negative interval is a documented option, and
// an option nothing tests is a flag that may or may not do what it says.
func TestTheTickerCanBeTurnedOff(t *testing.T) {
	dsn := pgSchema(t)
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		Policy:        frontierPolicy(t),
		ProjectionDSN: dsn,
		TickInterval:  -1,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	// The daemon still works: the in-process readers fold for themselves and
	// never depended on the ticker.
	runNotify(t, s)

	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	head := func() int64 {
		var n int64
		if err := conn.QueryRow(context.Background(),
			`SELECT last_event_seq FROM projection_meta WHERE only_row`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := head()
	if before == 0 {
		t.Fatal("nothing was folded at all, so this test cannot tell a stopped ticker " +
			"from a broken projection")
	}
	time.Sleep(300 * time.Millisecond)
	if after := head(); after != before {
		t.Errorf("the projection advanced from %d to %d with the ticker turned off",
			before, after)
	}
}

// TestACrystallizedSagaWorksThroughTheProjection.
//
// Phase 6b's equivalence tests use a template-free history, and no
// projection-backed daemon had ever admitted a crystallized saga — so if the
// projected registry stream mishandled template events in any way, nothing would
// have said so.
//
// It also transplants 6b's suspend-between-sagas rhythm onto templates, which is
// the property the whole lifecycle reuse was for: a template withdrawn between
// one saga and the next must stop the next one.
func TestACrystallizedSagaWorksThroughTheProjection(t *testing.T) {
	dsn := pgSchema(t)
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	registerTemplateInLog(t, dir, signer, true)

	first := serverOn(t, dir, signer, dsn)
	if _, err := first.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{
		Begin: crystallizedPlan("notify.email"),
	}); err != nil {
		t.Fatalf("a projection-backed daemon refused a valid crystallized saga: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// Withdraw the template, the way an operator would: through the registry,
	// against the log, with no daemon running.
	suspendTemplate(t, dir, signer)

	second := serverOn(t, dir, signer, dsn)
	defer func() { _ = second.Close() }()
	begin := crystallizedPlan("notify.email")
	begin.SagaId = "sg_crystal_after"
	begin.Intent.IntentId = "in_after"
	_, err = second.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{Begin: begin})
	if err == nil {
		t.Fatal("a saga was confined to a template that had been withdrawn; the projection " +
			"is answering about the past")
	}
	if !strings.Contains(err.Error(), "SUSPENDED") {
		t.Errorf("the refusal does not say the template was withdrawn: %v", err)
	}
}

func suspendTemplate(t *testing.T, dir string, signer *keys.Signer) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust(testPrincipal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "ag_operator", Principal: testPrincipal, Kind: "AGENT", ManifestVersion: "1.0.0",
	}, reg, trust)
	if err := rec.Suspend(context.Background(), "tpl_notify", "1.0.0",
		"the shape was wrong"); err != nil {
		t.Fatalf("suspending the template: %v", err)
	}
}
