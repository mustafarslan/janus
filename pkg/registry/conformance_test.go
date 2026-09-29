package registry_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/registry"
)

// honestDoubles model a payments participant that behaves the way its manifest
// says it does: a wire moves money, a refund moves it back, quoting changes
// nothing, and everything deduplicates and enforces its limits.
func honestDoubles() *registry.Doubles {
	return registry.NewDoubles("payments-sandbox/honest").
		With("payments.wire", registry.Double{Deltas: map[string]int64{"balance": -100}}).
		With("payments.refund", registry.Double{Deltas: map[string]int64{"balance": 100}}).
		With("notify.email", registry.Double{Deltas: map[string]int64{"sent": 1}}).
		With("payments.quote", registry.Double{})
}

func checkNamed(t *testing.T, rep *janusv1.EvaluationReport, action, name string) *janusv1.EvaluationReport_Check {
	t.Helper()
	for _, c := range rep.GetChecks() {
		if c.GetAction() == action && c.GetName() == name {
			return c
		}
	}
	t.Fatalf("the report has no %s check for %s; it has %d checks", name, action, len(rep.GetChecks()))
	return nil
}

func TestAnHonestParticipantPassesConformance(t *testing.T) {
	rep, err := registry.Evaluate(context.Background(), wireManifest(), honestDoubles())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.GetPassed() {
		t.Fatalf("an honest participant failed conformance:\n%s", registry.ReportText(rep))
	}

	// The irreversible action is reported as unchecked rather than as passed.
	// A report that says "checked" about something it did not check is worse
	// than no report.
	skipped := checkNamed(t, rep, "notify.email", registry.CheckCompensationRestore)
	if !skipped.GetSkipped() {
		t.Fatal("an irreversible action was reported as having demonstrated an inverse")
	}
}

// TestAFalseReversibleClaimFails is the evil-auditor case
// "registering a participant with a false REVERSIBLE
// claim". The class permits optimistic execution, so believing it wrongly means
// an effect that stays in the world after the saga unwinds.
func TestAFalseReversibleClaimFails(t *testing.T) {
	m := wireManifest()
	// payments.refund claims REVERSIBLE — a perfect undo. The double gives it a
	// re-wire that only returns 90 of every 100, which is what a participant
	// with a fee looks like.
	sb := honestDoubles().With("payments.wire", registry.Double{Deltas: map[string]int64{"balance": -90}})

	rep, err := registry.Evaluate(context.Background(), m, sb)
	if err != nil {
		t.Fatal(err)
	}
	if rep.GetPassed() {
		t.Fatalf("a participant whose undo does not undo passed conformance:\n%s",
			registry.ReportText(rep))
	}
	c := checkNamed(t, rep, "payments.refund", registry.CheckCompensationRestore)
	if c.GetPassed() {
		t.Fatal("the compensation check passed on a compensation that left the world changed")
	}
	if !strings.Contains(c.GetDetail(), "balance") {
		t.Fatalf("the finding does not say what was left behind: %q", c.GetDetail())
	}
}

// TestAnActionThatWritesCannotClaimToBePure guards the class with no gates at
// all. A PURE step is evidenced and otherwise unimpeded, so "this only reads"
// is the most valuable claim in the manifest to check.
func TestAnActionThatWritesCannotClaimToBePure(t *testing.T) {
	sb := honestDoubles().With("payments.quote", registry.Double{
		Deltas: map[string]int64{"quotes_issued": 1},
	})
	rep, err := registry.Evaluate(context.Background(), wireManifest(), sb)
	if err != nil {
		t.Fatal(err)
	}
	if rep.GetPassed() {
		t.Fatalf("an action declared PURE changed the world and passed:\n%s", registry.ReportText(rep))
	}
	if c := checkNamed(t, rep, "payments.quote", registry.CheckPurity); c.GetPassed() {
		t.Fatal("the purity check passed on an action that wrote")
	}
}

// TestADuplicateDeliveryThatLandsTwiceFails checks the participant's half of
// exactly-once. Janus delivers at least once; if the receiver does not absorb
// the retry, a retried wire is a second wire.
func TestADuplicateDeliveryThatLandsTwiceFails(t *testing.T) {
	sb := honestDoubles().With("notify.email", registry.Double{
		Deltas:             map[string]int64{"sent": 1},
		IgnoresIdempotency: true,
	})
	rep, err := registry.Evaluate(context.Background(), wireManifest(), sb)
	if err != nil {
		t.Fatal(err)
	}
	if rep.GetPassed() {
		t.Fatalf("a participant that applies a redelivered effect twice passed:\n%s",
			registry.ReportText(rep))
	}
	if c := checkNamed(t, rep, "notify.email", registry.CheckIdempotency); c.GetPassed() {
		t.Fatal("the idempotency check passed on a participant that ignores the key")
	}
}

// TestALimitTheParticipantDoesNotEnforceFails. The manifest claims both that
// the gate caps the amount and that the participant does; only one of those is
// being checked anywhere else.
func TestALimitTheParticipantDoesNotEnforceFails(t *testing.T) {
	sb := honestDoubles().With("payments.wire", registry.Double{
		Deltas:           map[string]int64{"balance": -100},
		AcceptsOverLimit: true,
	})
	rep, err := registry.Evaluate(context.Background(), wireManifest(), sb)
	if err != nil {
		t.Fatal(err)
	}
	if rep.GetPassed() {
		t.Fatalf("a participant that accepted an over-limit amount passed:\n%s",
			registry.ReportText(rep))
	}
	c := checkNamed(t, rep, "payments.wire", registry.CheckLimits)
	if c.GetPassed() {
		t.Fatal("the limit check passed on a participant that does not enforce its limit")
	}
	if !strings.Contains(c.GetDetail(), "10001") {
		t.Fatalf("the finding does not say what was accepted: %q", c.GetDetail())
	}
}

// TestAnUnmodelledActionIsReportedAsUnobservable. A check that cannot fail is
// not evidence, and saying so is the difference between a report and a rubber
// stamp.
func TestAnUnmodelledActionIsReportedAsUnobservable(t *testing.T) {
	sb := registry.NewDoubles("payments-sandbox/empty")
	rep, err := registry.Evaluate(context.Background(), wireManifest(), sb)
	if err != nil {
		t.Fatal(err)
	}
	c := checkNamed(t, rep, "notify.email", registry.CheckIdempotency)
	if !c.GetSkipped() {
		t.Fatalf("a duplicate delivery against a sandbox that models no effect was reported as "+
			"a result: %q", c.GetDetail())
	}
}

// TestTheReportSaysWhatItRanAgainst. A conformance verdict is only as
// meaningful as the doubles behind it, and whose doubles they were.
func TestTheReportSaysWhatItRanAgainst(t *testing.T) {
	rep, err := registry.Evaluate(context.Background(), wireManifest(), honestDoubles())
	if err != nil {
		t.Fatal(err)
	}
	if rep.GetSandbox() != "payments-sandbox/honest" {
		t.Fatalf("the report names sandbox %q", rep.GetSandbox())
	}
	if rep.GetHarnessVersion() != registry.HarnessVersion {
		t.Fatalf("the report names harness %q", rep.GetHarnessVersion())
	}
}

// TestEvaluationIsDeterministic. The report goes into the evidence log, so two
// runs over the same manifest have to produce the same bytes or replay diverges.
func TestEvaluationIsDeterministic(t *testing.T) {
	first, err := registry.Evaluate(context.Background(), wireManifest(), honestDoubles())
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.Evaluate(context.Background(), wireManifest(), honestDoubles())
	if err != nil {
		t.Fatal(err)
	}
	if registry.ReportText(first) != registry.ReportText(second) {
		t.Fatalf("two runs disagreed:\n%s\n---\n%s", registry.ReportText(first),
			registry.ReportText(second))
	}
}
