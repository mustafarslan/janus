package console

import (
	"fmt"
	"strconv"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// Turning recorded values into the words on a screen.
//
// Everything here is presentation and nothing here decides anything. That
// division is worth keeping strict: the moment a console starts computing
// something the log does not say, it becomes a second opinion with no evidence
// behind it.

func shortVerdict(v janusv1.Verdict) string {
	if v == janusv1.Verdict_VERDICT_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(v.String(), "VERDICT_")
}

func shortGate(g janusv1.GateType) string {
	return strings.TrimPrefix(g.String(), "GATE_TYPE_")
}

func shortPhase(p janusv1.GatePhase) string {
	return strings.TrimPrefix(p.String(), "GATE_PHASE_")
}

func shortMode(m janusv1.ResourceTouch_Mode) string {
	return strings.TrimPrefix(m.String(), "MODE_")
}

func shortChildMode(m janusv1.ChildCommitMode) string {
	return strings.TrimPrefix(m.String(), "CHILD_COMMIT_MODE_")
}

// factString renders a typed fact the way the policy language reads it, so a
// value on screen matches the expression that will judge it.
func factString(v saga.FactValue) string {
	switch v.Type {
	case janusv1.FactType_FACT_TYPE_NUMBER:
		return strconv.FormatInt(v.Number, 10)
	case janusv1.FactType_FACT_TYPE_FLAG:
		return strconv.FormatBool(v.Flag)
	default:
		return v.Text
	}
}

// describeRequirement says what a gate asks for, in the terms the person
// answering it needs.
func describeRequirement(r *janusv1.GateRequirement) string {
	switch {
	case r.GetHuman() != nil:
		h := r.GetHuman()
		quorum := max(int(h.GetQuorum()), 1)
		who := "any authenticated person"
		if len(h.GetRoles()) > 0 {
			who = strings.Join(h.GetRoles(), " or ")
		}
		out := fmt.Sprintf("%s from %s", quantity(quorum, "approval"), who)
		if h.GetSeparationOfDuty() {
			out += ", and not the initiator"
		}
		return out
	case r.GetValidator() != nil:
		v := r.GetValidator()
		out := fmt.Sprintf("%s from %s", quantity(max(int(v.GetQuorum()), 1), "opinion"),
			strings.Join(v.GetValidators(), ", "))
		if v.GetEscalateOnDisagreement() {
			out += "; disagreement escalates to a person"
		}
		return out
	case r.GetSchema() != nil:
		names := make([]string, 0, len(r.GetSchema().GetFields()))
		for _, f := range r.GetSchema().GetFields() {
			names = append(names, f.GetName())
		}
		return r.GetSchema().GetSchemaId() + ": " + strings.Join(names, ", ")
	case r.GetPolicy() != nil:
		if d := r.GetPolicy().GetDescription(); d != "" {
			return d
		}
		return r.GetPolicy().GetExpr()
	case r.GetRiskLimit() != nil:
		l := r.GetRiskLimit()
		parts := make([]string, 0, len(l.GetThresholds())+2)
		for _, t := range l.GetThresholds() {
			parts = append(parts, fmt.Sprintf("%s ≤ %d", t.GetFact(), t.GetMax()))
		}
		if l.GetMaxGatedEffects() > 0 {
			parts = append(parts, fmt.Sprintf("≤ %d irreversible steps", l.GetMaxGatedEffects()))
		}
		if l.GetMaxResources() > 0 {
			parts = append(parts, fmt.Sprintf("≤ %d resources", l.GetMaxResources()))
		}
		return strings.Join(parts, ", ")
	case r.GetFrontier() != nil:
		return "no contending saga holds a resource this step touched"
	default:
		return ""
	}
}

func quantity(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// ---- what the projection does not keep -----------------------------------------

// beginRecord is what a saga's SAGA_BEGIN says that its projection does not
// keep: the manifest versions it pinned, and where in the log it began.
//
// Reading it here rather than widening saga.State is deliberate. The projection
// is what the state machine needs to decide transitions, it is what the replay
// corpus pins as recorded history, and adding a field to it for a screen would
// rewrite every fixture in that corpus to record something no transition
// depends on. The pins are in the log; the console can read the log.
type beginRecord struct {
	Seq  uint64
	Pins map[string]string
}

// loadBegins reads every SAGA_BEGIN in a directory.
func loadBegins(dir string) (map[string]beginRecord, error) {
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]beginRecord{}
	for _, id := range ids {
		path := segment.Path(dir, id)
		insp, err := segment.Inspect(path)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", path, err)
		}
		if insp.Torn {
			return nil, fmt.Errorf("segment %d ends in an incomplete record; recover the log "+
				"before reading it", id)
		}
		for i, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				return nil, fmt.Errorf("segment %d record %d: %w", id, i, err)
			}
			if h.Kind != evidence.KindSagaBegin {
				continue
			}
			// The same check every reader in this repository makes before
			// believing a record: the payload has to hash to what the envelope
			// says, and the envelope has to chain.
			if len(rec.Payload) > 0 {
				if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
					return nil, fmt.Errorf("segment %d seq %d: payload does not match its "+
						"recorded hash", id, h.Seq)
				}
			}
			if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
				return nil, fmt.Errorf("segment %d seq %d: chain hash mismatch", id, h.Seq)
			}
			var msg janusv1.SagaBegin
			if err := proto.Unmarshal(rec.Payload, &msg); err != nil {
				return nil, fmt.Errorf("segment %d seq %d: %w", id, h.Seq, err)
			}
			if _, seen := out[msg.GetSagaId()]; seen {
				// A saga begins once. A second SAGA_BEGIN is a finding for the
				// state machine and the gate audit, not something for a screen
				// to reconcile; the first one is what every pin was recorded
				// against.
				continue
			}
			out[msg.GetSagaId()] = beginRecord{Seq: h.Seq, Pins: msg.GetManifestPins()}
		}
	}
	return out, nil
}
