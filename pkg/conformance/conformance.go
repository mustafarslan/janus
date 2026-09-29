// Package conformance checks that an integration built on Janus actually got
// the guarantees Janus offers.
//
// It is the other half of Phase 4's exit gate, and it exists before the
// reference app on purpose: an app written first and described afterwards is an
// app that defines what conformance means, which makes the suite a restatement
// of whatever was built rather than a bar it had to clear.
//
// # What it checks, and what it deliberately does not
//
// It reads an evidence directory and nothing else. It does not know how the
// integration works, which language it is written in, or whether it went
// through janus-mcpd, the Python SDK, or something nobody has written yet —
// which is exactly what "the conformance suite passes for both adapters"
// requires. Two adapters that produce the same evidence are equally conformant,
// and an adapter that produces different evidence is a different integration
// however similar its source looks.
//
// The checks are the invariants, re-derived from the log by the same code that
// enforces them: the chain and signatures (I2), replay determinism (I5), the
// gate decisions (I3), the outbox's release authority (I1, I4), and the
// registry pins (I8). Nothing here is a second implementation of any of them.
//
// # Why an expectation is required
//
// Every one of those checks passes on an empty log. A suite that can be
// satisfied by an integration doing nothing measures nothing, so a run has to
// say what the integration was asked to do — which sagas, which steps, which
// outcome — and the suite refuses to run without it. That is the check the
// others rest on: the guarantees are only interesting about work that happened.
package conformance

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Expectation is what an integration was asked to do.
//
// It is written by whoever ran the integration, not derived from what the log
// happens to contain. Deriving it would make the suite agree with itself.
type Expectation struct {
	// Integration names what produced this evidence, for the report.
	Integration string            `json:"integration"`
	Sagas       []SagaExpectation `json:"sagas"`
}

// SagaExpectation is one saga the integration was supposed to produce.
type SagaExpectation struct {
	SagaID string `json:"saga_id"`
	// Status is the terminal state it was supposed to reach: COMMITTED,
	// COMPENSATED or QUARANTINE.
	Status string            `json:"status"`
	Steps  []StepExpectation `json:"steps"`
}

// StepExpectation is one step, as the integration declared it.
//
// The effect class is here because it is the field an adapter is most likely to
// get wrong and least likely to notice: every gate matches on it, so a step
// that reaches the log as PURE when the integration meant COMPENSABLE is a step
// no rule applied to.
type StepExpectation struct {
	StepID      string `json:"step_id"`
	Participant string `json:"participant"`
	Action      string `json:"action"`
	EffectClass string `json:"effect_class"`
	Status      string `json:"status"`
}

// Options configures a run.
type Options struct {
	// Keys are the writer keys the log is checked against. Without them the
	// signature check cannot run, and the report says so rather than passing.
	Keys keys.PublicKeySet
	// Trust is the manifest-signing trust store for the registry audit.
	Trust registry.TrustStore
	// AllowUnsealedTail permits the final segment to have no footer, which is
	// the normal state of a log whose writer is still running.
	AllowUnsealedTail bool
}

// Check is one thing the suite asked of the evidence.
type Check struct {
	Name string `json:"name"`
	// Invariant is the plan's name for what this defends, or empty for a check
	// that is about the integration rather than about Janus.
	Invariant string `json:"invariant,omitempty"`
	Passed    bool   `json:"passed"`
	Detail    string `json:"detail,omitempty"`
}

// Report is the outcome of a run.
type Report struct {
	Integration string  `json:"integration"`
	Checks      []Check `json:"checks"`
	Passed      bool    `json:"passed"`
}

// ErrNothingExpected means the run was asked to check an integration that was
// not asked to do anything.
var ErrNothingExpected = errors.New("conformance: the expectation is empty")

// Run checks an evidence directory against an expectation.
func Run(dir string, want Expectation, opts Options) (*Report, error) {
	if len(want.Sagas) == 0 {
		return nil, fmt.Errorf("%w: every check below passes on a log with nothing in it, "+
			"so a run has to say what the integration was asked to do", ErrNothingExpected)
	}

	report := &Report{Integration: want.Integration}
	states, replayErr := saga.ReplayAll(dir)

	report.add(checkChain(dir, opts))
	report.add(checkReplay(dir, states, replayErr))
	report.add(checkExpectedSagas(states, want))
	report.add(checkExpectedSteps(states, want))
	report.add(checkGates(dir))
	report.add(checkOutbox(dir, states))
	report.add(checkPins(dir, opts.Trust))

	report.Passed = true
	for _, c := range report.Checks {
		if !c.Passed {
			report.Passed = false
		}
	}
	return report, nil
}

func (r *Report) add(c Check) { r.Checks = append(r.Checks, c) }

// String renders the report the way an operator reads it: what was asked, what
// held, and for anything that did not, why.
func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "conformance: %s\n\n", r.Integration)
	for _, c := range r.Checks {
		mark := "ok  "
		if !c.Passed {
			mark = "FAIL"
		}
		name := c.Name
		if c.Invariant != "" {
			name = fmt.Sprintf("%s (%s)", c.Name, c.Invariant)
		}
		fmt.Fprintf(&b, "  %s %s\n", mark, name)
		if c.Detail != "" {
			fmt.Fprintf(&b, "       %s\n", c.Detail)
		}
	}
	verdict := "PASS"
	if !r.Passed {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "\njanus-conformance: %s\n", verdict)
	return b.String()
}

// ---- the checks ------------------------------------------------------------

// checkChain is I2, run by the same verifier an auditor would run offline.
func checkChain(dir string, opts Options) Check {
	c := Check{Name: "the log verifies offline", Invariant: "I2"}
	if len(opts.Keys) == 0 {
		c.Detail = "no writer keys were supplied, so segment signatures were not checked; " +
			"a chain that verifies under no key is a chain anybody could have written"
		return c
	}
	report, err := verify.SegmentDir(dir, verify.Options{
		Keys: opts.Keys, AllowUnsealedTail: opts.AllowUnsealedTail,
	})
	if err != nil {
		c.Detail = err.Error()
		return c
	}
	var critical []string
	for _, f := range report.Findings {
		if f.Severity == verify.Critical {
			critical = append(critical, f.Code+": "+f.Message)
		}
	}
	if len(critical) > 0 {
		c.Detail = strings.Join(critical, "; ")
		return c
	}
	c.Passed = true
	c.Detail = fmt.Sprintf("%d events across %d segments", report.Events, len(report.Segments))
	return c
}

// checkReplay is I5. Folding the log twice has to produce the same projection:
// a fold that depends on anything but the events is not a fold.
func checkReplay(dir string, states map[string]saga.State, replayErr error) Check {
	c := Check{Name: "every saga replays, and replays the same way twice", Invariant: "I5"}
	if replayErr != nil {
		c.Detail = replayErr.Error()
		return c
	}
	again, err := saga.ReplayAll(dir)
	if err != nil {
		c.Detail = "the second replay failed where the first succeeded: " + err.Error()
		return c
	}
	if len(again) != len(states) {
		c.Detail = fmt.Sprintf("the log replayed to %d sagas and then to %d",
			len(states), len(again))
		return c
	}
	for id, first := range states {
		second, ok := again[id]
		if !ok {
			c.Detail = fmt.Sprintf("saga %q appeared in one replay and not the other", id)
			return c
		}
		if first.Status != second.Status || first.LastSeq != second.LastSeq ||
			len(first.Steps) != len(second.Steps) {
			c.Detail = fmt.Sprintf("saga %q replayed to %s at seq %d and then to %s at seq %d",
				id, first.Status, first.LastSeq, second.Status, second.LastSeq)
			return c
		}
	}
	c.Passed = true
	c.Detail = fmt.Sprintf("%d saga(s)", len(states))
	return c
}

// checkExpectedSagas is the check the others rest on.
func checkExpectedSagas(states map[string]saga.State, want Expectation) Check {
	c := Check{Name: "the integration produced the sagas it was asked to"}
	var problems []string
	for _, expected := range want.Sagas {
		got, ok := states[expected.SagaID]
		if !ok {
			problems = append(problems, fmt.Sprintf("saga %q is not in the log at all",
				expected.SagaID))
			continue
		}
		if expected.Status != "" && string(got.Status) != expected.Status {
			problems = append(problems, fmt.Sprintf("saga %q is %s, expected %s",
				expected.SagaID, got.Status, expected.Status))
		}
	}
	if len(problems) > 0 {
		c.Detail = strings.Join(problems, "; ")
		return c
	}
	c.Passed = true
	c.Detail = fmt.Sprintf("%d saga(s), each reaching the outcome asked for", len(want.Sagas))
	return c
}

// checkExpectedSteps compares each step against how the integration declared it.
func checkExpectedSteps(states map[string]saga.State, want Expectation) Check {
	c := Check{Name: "every step reached the log as the integration declared it"}
	var problems []string
	var checked int
	for _, expectedSaga := range want.Sagas {
		state, ok := states[expectedSaga.SagaID]
		if !ok {
			continue // already reported by the check above
		}
		for _, expected := range expectedSaga.Steps {
			step, found := state.Steps[expected.StepID]
			if !found {
				problems = append(problems, fmt.Sprintf("%s/%s is not in the plan",
					expectedSaga.SagaID, expected.StepID))
				continue
			}
			checked++
			for _, mismatch := range []struct{ what, got, want string }{
				{"participant", step.Participant, expected.Participant},
				{"action", step.Action, expected.Action},
				{"effect class", registry.ShortClass(step.EffectClass), expected.EffectClass},
				{"status", string(step.Status), expected.Status},
			} {
				if mismatch.want != "" && mismatch.got != mismatch.want {
					problems = append(problems, fmt.Sprintf("%s/%s %s is %q, expected %q",
						expectedSaga.SagaID, expected.StepID, mismatch.what,
						mismatch.got, mismatch.want))
				}
			}
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		c.Detail = strings.Join(problems, "; ")
		return c
	}
	c.Passed = true
	c.Detail = fmt.Sprintf("%d step(s)", checked)
	return c
}

// checkGates re-derives every recorded gate decision from the inputs recorded
// with it. A verdict that does not follow is a decision nothing explains.
func checkGates(dir string) Check {
	c := Check{Name: "every gate decision follows from what was recorded with it", Invariant: "I3"}
	report, err := gate.Audit(dir)
	if err != nil {
		c.Detail = err.Error()
		return c
	}
	if !report.OK() {
		c.Detail = report.String()
		return c
	}
	c.Passed = true
	c.Detail = fmt.Sprintf("%d verdict(s) across %d saga(s)", report.Verdicts, report.Sagas)
	return c
}

// checkOutbox is I1 and I4: nothing left the building that a commit did not
// authorise.
func checkOutbox(dir string, states map[string]saga.State) Check {
	c := Check{Name: "no effect was released without a commit that authorised it",
		Invariant: "I1, I4"}
	state, err := outbox.Load(dir)
	if err != nil {
		c.Detail = err.Error()
		return c
	}
	findings := outbox.Audit(state, states)
	if unauthorised := outbox.Unauthorised(findings); len(unauthorised) > 0 {
		var lines []string
		for _, f := range unauthorised {
			lines = append(lines, f.String())
		}
		c.Detail = strings.Join(lines, "; ")
		return c
	}
	c.Passed = true
	c.Detail = fmt.Sprintf("%d effect(s)", len(state.Order))
	return c
}

// checkPins is I8: every saga resolved the manifest version it recorded.
func checkPins(dir string, trust registry.TrustStore) Check {
	c := Check{Name: "every saga's manifest pins resolve", Invariant: "I8"}
	report, err := registry.Audit(dir, trust)
	if err != nil {
		c.Detail = err.Error()
		return c
	}
	if len(report.Findings) > 0 {
		var lines []string
		for _, f := range report.Findings {
			lines = append(lines, f.String())
		}
		c.Detail = strings.Join(lines, "; ")
		return c
	}
	c.Passed = true
	c.Detail = fmt.Sprintf("%d pin(s) against %d version(s); %d manifest(s) unchecked "+
		"for want of a trusted key", report.Pins, report.Versions, report.Unchecked)
	return c
}
