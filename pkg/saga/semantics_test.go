package saga_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// TestEverySagaThisBuildAdmitsCarriesItsSemanticsVersion.
//
// The pin is worthless if the daemon does not write it. This asserts on the
// **recorded SAGA_BEGIN**, not on the folded state, because the folded state
// says 1 either way — absent is read as 1 — so a test that checked
// `State.Semantics` would pass just as happily against a coordinator that
// records nothing. The bytes in the log are the thing under test.
//
// It goes through `Runner.Begin` with a message that does not set the field, so
// it also fixes that the stamp is the runner's job rather than the caller's.
// Every SAGA_BEGIN in production goes through that one method; a pin each call
// site had to remember would be set by the ones somebody thought of.
func TestEverySagaThisBuildAdmitsCarriesItsSemanticsVersion(t *testing.T) {
	app, dir, _ := newLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag_1"})

	if _, err := r.Begin(ctx, &janusv1.SagaBegin{
		SagaId: "sg_pinned",
		Intent: &janusv1.Intent{IntentId: "in"},
		Plan: []*janusv1.PlannedStep{
			{StepId: "read", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	var found bool
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.Kind != evidence.KindSagaBegin {
			return nil
		}
		var msg janusv1.SagaBegin
		if err := proto.Unmarshal(rec.Payload, &msg); err != nil {
			return err
		}
		found = true
		if msg.GetSemanticsVersion() != saga.SemanticsVersion {
			t.Errorf("the recorded SAGA_BEGIN carries semantics version %d; this build "+
				"admits under %d, and a saga whose log does not say which rules it was "+
				"admitted under can only be guessed at later",
				msg.GetSemanticsVersion(), saga.SemanticsVersion)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("no SAGA_BEGIN in the log, so this test asserted nothing")
	}
}

// TestACallerCannotDeclareItsOwnSemantics.
//
// A caller naming a version would be claiming the rules the code folding its
// saga implements, which is not a thing a caller can know. Here it claims 99 —
// a version nothing implements — and the log must not end up carrying it,
// because a SAGA_BEGIN nobody can fold is a saga that can never be read again.
//
// Two mechanisms stop that and this is indifferent to which one acts, because
// both are correct. The stamp overwrites the claim; and failing that,
// `Runner.record` validates every event through `Apply` before appending, so a
// coordinator cannot write history it could not itself fold. The second is
// pre-existing and this change gets it for free — worth knowing, because it
// means the refusal does not rest on the stamp alone.
//
// What this cannot test, honestly, is a caller declaring a *supported* version
// other than the current one. There is one supported version, so no such value
// exists. When there are two, the case to add is a caller declaring 1 while the
// build admits under 2 — that is where the stamp is the only thing acting, and
// where a missing one would be invisible to everything here.
func TestACallerCannotDeclareItsOwnSemantics(t *testing.T) {
	app, dir, _ := newLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag_1"})

	msg := &janusv1.SagaBegin{
		SagaId:           "sg_liar",
		Intent:           &janusv1.Intent{IntentId: "in"},
		Plan:             []*janusv1.PlannedStep{{StepId: "read", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE}},
		SemanticsVersion: 99,
	}
	if _, err := r.Begin(ctx, msg); err != nil {
		// Legitimate, and the second mechanism acting: with no stamp,
		// `record`'s validation refuses to append a SAGA_BEGIN this build
		// cannot fold. The claim never reached the log, which is the whole
		// claim here, so there is nothing further to assert.
		if errors.Is(err, saga.ErrUnsupportedSemantics) {
			return
		}
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	// The caller's own message must not have been mutated under it: Begin works
	// on a copy, because a runner that rewrote its argument would surprise a
	// caller that reused the message for anything else.
	if msg.GetSemanticsVersion() != 99 {
		t.Errorf("Begin mutated the caller's message (now %d); it should stamp a copy",
			msg.GetSemanticsVersion())
	}

	// Asserted on the recorded bytes rather than on the folded state, and the
	// difference decides whether this means anything: a fold reads 1 whether
	// the field was stamped or absent, so a check on `State.Semantics` would
	// pass just as happily against a coordinator that records nothing.
	if got := recordedSemantics(t, dir); got != saga.SemanticsVersion {
		t.Errorf("the recorded SAGA_BEGIN carries semantics version %d; the caller asked "+
			"for 99 and this build admits under %d, so the caller's claim reached the log",
			got, saga.SemanticsVersion)
	}
}

// recordedSemantics reads the semantics version out of the one SAGA_BEGIN in a
// log, failing if there is not exactly one.
func recordedSemantics(t *testing.T, dir string) uint32 {
	t.Helper()
	var got []uint32
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.Kind != evidence.KindSagaBegin {
			return nil
		}
		var msg janusv1.SagaBegin
		if err := proto.Unmarshal(rec.Payload, &msg); err != nil {
			return err
		}
		got = append(got, msg.GetSemanticsVersion())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("found %d SAGA_BEGIN records, want exactly 1; this asserted nothing", len(got))
	}
	return got[0]
}

// TestASagaFromTheFutureIsRefusedRatherThanGuessedAt.
//
// The whole point of the pin is what happens when it names rules this build does
// not have. Folding it anyway would apply today's reading to a history admitted
// under different rules — silently, and producing a projection that looks
// entirely ordinary. That is the failure this exists to prevent, so the fold
// refuses and says which versions it does implement.
func TestASagaFromTheFutureIsRefusedRatherThanGuessedAt(t *testing.T) {
	payload, err := proto.Marshal(&janusv1.SagaBegin{
		SagaId: "sg_future",
		Intent: &janusv1.Intent{IntentId: "in"},
		Plan: []*janusv1.PlannedStep{
			{StepId: "read", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
		},
		SemanticsVersion: 99,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = saga.Replay([]saga.Event{{Seq: 1, Kind: evidence.KindSagaBegin, Payload: payload}})
	if err == nil {
		t.Fatal("a saga admitted under semantics 99 folded under this build's rules and " +
			"produced an ordinary-looking projection; nothing would ever have said so")
	}
	if !errors.Is(err, saga.ErrUnsupportedSemantics) {
		t.Fatalf("refused, but not as an unsupported semantics version: %v", err)
	}
	// The error has to name what this build does implement. "Unsupported" alone
	// leaves an operator holding a log they cannot read and no idea which
	// binary reads it.
	if !strings.Contains(err.Error(), "[1 2 3 4]") {
		t.Errorf("the refusal does not say which versions this build implements: %v", err)
	}
}

// TestAHistoryRecordedBeforeThePinStillFoldsAsVersionOne.
//
// This is the backward-compatibility claim, isolated. The corpus makes it
// twenty times over — none of fixtures 01-20 carries the field and every one of
// them expects `"semantics": 1` — but those fixtures assert many things at once,
// and this asserts only the one.
//
// Absent is read as 1 rather than refused, and that is a reading of the
// evidence rather than a lenience: version 1 *is* the rules every one of those
// sagas ran under, because this PR named the rules that already existed.
func TestAHistoryRecordedBeforeThePinStillFoldsAsVersionOne(t *testing.T) {
	payload, err := proto.Marshal(&janusv1.SagaBegin{
		SagaId: "sg_legacy",
		Intent: &janusv1.Intent{IntentId: "in"},
		Plan: []*janusv1.PlannedStep{
			{StepId: "read", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
		},
		// No SemanticsVersion: the shape of every SAGA_BEGIN ever written
		// before this field existed.
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := saga.Replay([]saga.Event{{Seq: 1, Kind: evidence.KindSagaBegin, Payload: payload}})
	if err != nil {
		t.Fatalf("a history from before the field existed no longer folds: %v", err)
	}
	if s.Semantics != 1 {
		t.Errorf("a SAGA_BEGIN with no semantics version folded as %d, want 1; every log "+
			"written before this field existed ran under exactly version 1's rules",
			s.Semantics)
	}
	if !saga.Supports(s.Semantics) {
		t.Error("this build does not claim to support version 1, which it implements")
	}
}

// TestASagaCannotBeBegunUnderRulesThisBuildDoesNotHave: BeginUnder takes a
// version from whoever read the parent, and a version nothing here can fold
// must not reach the log, where it would be found unreadable afterwards.
func TestASagaCannotBeBegunUnderRulesThisBuildDoesNotHave(t *testing.T) {
	app, dir, _ := newLog(t)
	r := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag"})
	_, err := r.BeginUnder(context.Background(), &janusv1.SagaBegin{
		SagaId: "sg_future", Intent: &janusv1.Intent{IntentId: "in"},
		Plan: []*janusv1.PlannedStep{
			{StepId: "read", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
		},
	}, 99)
	if !errors.Is(err, saga.ErrUnsupportedSemantics) {
		t.Fatalf("a saga was begun under version 99: %v", err)
	}
	if _, err := saga.ReplaySaga(dir, "sg_future"); err == nil {
		t.Fatal("the refused SAGA_BEGIN is in the log anyway")
	}
}
