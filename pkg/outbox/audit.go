package outbox

import (
	"bytes"
	"fmt"
	"sort"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Auditing the outbox against the sagas that authorised it.
//
// The release path checks its authority before acting, but a check performed at
// the time is a claim about a process that has since exited. What a regulator,
// an incident review, or a nightly verifier needs is different: given only the
// log, can it be shown that no irreversible effect was released without a
// commit that authorised it?
//
// That is what this answers, and it is why the release record carries the
// commit's evidence root rather than merely a saga id. A forged release naming
// a saga that never committed, or citing a root that does not match the commit
// the log contains, is detectable afterwards by anyone — including by someone
// who does not trust the process that wrote it.
//
// Apply cannot do this on its own: it sees the outbox projection and never the
// sagas. Nothing inside a single projection can notice that an effect was
// released against a saga which was compensating at the time.

// AuditFinding is one way the outbox and the sagas disagree.
type AuditFinding struct {
	EffectID string
	SagaID   string
	// Critical marks a finding that means an effect reached the world without
	// authority, as distinct from a bookkeeping inconsistency.
	Critical bool
	Detail   string
}

func (f AuditFinding) String() string {
	severity := "inconsistent"
	if f.Critical {
		severity = "UNAUTHORISED"
	}
	return fmt.Sprintf("[%s] effect %s (saga %s): %s", severity, f.EffectID, f.SagaID, f.Detail)
}

// Audit checks every effect against the saga that was supposed to authorise it.
//
// sagas maps saga id to its projection. A saga that is absent is itself a
// finding: an effect that cites an authority nobody can produce has not been
// shown to be authorised, and for an irreversible effect that is the same as
// unauthorised.
func Audit(s State, sagas map[string]saga.State) []AuditFinding {
	var out []AuditFinding
	add := func(e *Effect, critical bool, format string, args ...any) {
		out = append(out, AuditFinding{
			EffectID: e.ID, SagaID: e.SagaID, Critical: critical,
			Detail: fmt.Sprintf(format, args...),
		})
	}

	for _, id := range s.Order {
		e := s.Effects[id]

		// Only a class that is meant to be held belongs here at all.
		switch e.Class {
		case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			janusv1.EffectClass_EFFECT_CLASS_UNSPECIFIED:
		case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE:
			add(e, true, "an IRREVERSIBLE_IMMEDIATE effect is in the outbox, but such an effect "+
				"fires when its step runs and cannot have been held")
		default:
			add(e, false, "effect class %s does not need holding; only IRREVERSIBLE_GATED effects "+
				"are withheld until commit", shortClass(e.Class))
		}

		// An effect that was never attempted needs no authority.
		if e.Attempts == 0 && e.State != StateDelivered {
			continue
		}

		st, ok := sagas[e.SagaID]
		if !ok {
			add(e, true, "was attempted %d time(s) but its saga is not in the log, so nothing "+
				"can be shown to have authorised it", e.Attempts)
			continue
		}

		// I4: released only from COMMITTED. Checked against the saga's own
		// terminal state rather than against what the releaser believed.
		if st.Status != saga.StatusCommitted {
			add(e, true, "was attempted %d time(s) while its saga is %s, so an irreversible "+
				"effect was released without a commit authorising it", e.Attempts, st.Status)
			continue
		}

		// The cited authority must be the commit that actually exists.
		if !bytes.Equal(e.CommitRoot, st.EvidenceRoot) {
			add(e, true, "cites commit root %x but its saga committed with root %x",
				truncate(e.CommitRoot), truncate(st.EvidenceRoot))
		}

		// The step that produced the effect has to be a step of that saga, and
		// one whose class called for holding.
		if e.StepID != "" {
			step, ok := st.Step(e.StepID)
			switch {
			case !ok:
				add(e, true, "names step %q, which is not in saga %q's plan", e.StepID, e.SagaID)
			case step.EffectClass != e.Class && e.Class != janusv1.EffectClass_EFFECT_CLASS_UNSPECIFIED:
				add(e, false, "is classified %s but its step %q is %s",
					shortClass(e.Class), e.StepID, shortClass(step.EffectClass))
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Critical != out[j].Critical {
			return out[i].Critical
		}
		return out[i].EffectID < out[j].EffectID
	})
	return out
}

// Unauthorised returns only the findings that mean an effect escaped without
// authority. An empty result is the claim the outbox exists to support.
func Unauthorised(findings []AuditFinding) []AuditFinding {
	var out []AuditFinding
	for _, f := range findings {
		if f.Critical {
			out = append(out, f)
		}
	}
	return out
}

func truncate(b []byte) []byte {
	if len(b) > 8 {
		return b[:8]
	}
	return b
}

func shortClass(c janusv1.EffectClass) string {
	const prefix = "EFFECT_CLASS_"
	n := c.String()
	if len(n) > len(prefix) {
		return n[len(prefix):]
	}
	return n
}
