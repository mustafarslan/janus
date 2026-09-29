package gate

import (
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/callersig"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// signatureAudit re-checks, from the log alone, the participant signatures the
// daemon checked before recording. The keys are the ones the
// participant's manifest declared in this same log at the time of the record:
// the version its saga pinned, for a step's participant, and the active one
// otherwise -- the rule the daemon applied.
type signatureAudit struct {
	registry []registry.Event
	pins     map[string]map[string]string
}

func newSignatureAudit(dir string, bySaga map[string][]saga.Event) (*signatureAudit, error) {
	events, err := registry.LoadEvents(dir)
	if err != nil {
		return nil, fmt.Errorf("reading the registry to check signatures against: %w", err)
	}
	a := &signatureAudit{registry: events, pins: map[string]map[string]string{}}
	for id, evs := range bySaga {
		if len(evs) == 0 || evs[0].Kind != evidence.KindSagaBegin {
			continue
		}
		var begin janusv1.SagaBegin
		if err := proto.Unmarshal(evs[0].Payload, &begin); err == nil {
			a.pins[id] = begin.GetManifestPins()
		}
	}
	return a, nil
}

// keysAt is what a participant's manifest declared at a point in the log:
// its keys and its kind.
func (a *signatureAudit) keysAt(seq uint64, participant, pinned string) ([]string, error) {
	keys, _, err := a.declaredAt(seq, participant, pinned)
	return keys, err
}

func (a *signatureAudit) declaredAt(seq uint64, participant, pinned string) ([]string, string, error) {
	reg, err := registry.FoldUntil(a.registry, seq)
	if err != nil {
		return nil, "", err
	}
	var e *registry.Entry
	var ok bool
	if pinned != "" {
		e, ok = reg.Resolve(participant, pinned)
	} else {
		e, ok = reg.Active(participant)
	}
	if !ok || e.Manifest == nil {
		return nil, "", nil
	}
	return e.Manifest.Identity.PublicKeys, e.Manifest.Identity.Kind, nil
}

// check verifies one record's signature, returning how many verified (0 or 1)
// and what did not hold.
func (a *signatureAudit) check(states map[string]saga.State, t timed) (int, []Finding) {
	var who string
	var sig *janusv1.ParticipantSignature
	var canonical []byte
	var stepID string
	switch t.ev.Kind {
	case evidence.KindGateAnswer:
		var msg janusv1.GateAnswer
		if proto.Unmarshal(t.ev.Payload, &msg) != nil {
			return 0, nil
		}
		stepID, sig, canonical = msg.GetStepId(), msg.GetSignature(), callersig.Answer(&msg)
		// The fold counts an actor naming a person as that person, so the
		// signer to check is the relayer whenever a person is named.
		who = msg.GetActor().GetParticipant().GetId()
		if msg.GetActor().GetHumanSubject() != "" {
			if who != "" {
				return 0, []Finding{{Kind: FindingSignature, SagaID: t.sagaID, StepID: stepID,
					Seq: t.ev.Seq, Detail: fmt.Sprintf("this answer names both participant %q and "+
						"person %q; the fold counts it as the person's, and a participant cannot "+
						"answer as a person", who, msg.GetActor().GetHumanSubject())}}
			}
			who = sig.GetParticipantId()
			if who != "" {
				_, kind, err := a.declaredAt(t.ev.Seq, who, a.pins[t.sagaID][who])
				if err == nil && kind != "" && kind != "SYSTEM" && kind != "HUMAN" {
					return 0, []Finding{{Kind: FindingSignature, SagaID: t.sagaID, StepID: stepID,
						Seq: t.ev.Seq, Detail: fmt.Sprintf("a person's answer was relayed by %q, "+
							"a participant of kind %s; only a SYSTEM or HUMAN participant relays "+
							"what a person decided", who, kind)}}
				}
			}
		}
	case evidence.KindStepResult:
		var msg janusv1.StepResult
		if proto.Unmarshal(t.ev.Payload, &msg) != nil {
			return 0, nil
		}
		stepID, sig, canonical = msg.GetStepId(), msg.GetSignature(), callersig.Result(&msg)
		target := stepID
		if len(target) > len("~undo") && target[len(target)-len("~undo"):] == "~undo" {
			target = target[:len(target)-len("~undo")]
		}
		if st, ok := states[t.sagaID].Step(target); ok {
			who = st.Participant
		}
	default:
		return 0, nil
	}
	if who == "" {
		return 0, nil
	}
	// A participant in the registry with no version that may act now (suspended,
	// retired) is named whatever it signed: the daemon refuses its answers from
	// semantics 4 on, and a log written before that may hold them.
	if pinned := a.pins[t.sagaID][who]; pinned == "" && t.ev.Kind == evidence.KindGateAnswer {
		if reg, err := registry.FoldUntil(a.registry, t.ev.Seq); err == nil {
			if _, ok := reg.Active(who); !ok && len(reg.Versions(who)) > 0 {
				return 0, []Finding{{Kind: FindingSignature, SagaID: t.sagaID, StepID: stepID,
					Seq: t.ev.Seq, Detail: fmt.Sprintf("this answer is recorded on behalf of %q, "+
						"which had no active version in the registry at the time -- suspended, "+
						"retired or not yet activated", who)}}
			}
		}
	}
	keys, err := a.keysAt(t.ev.Seq, who, a.pins[t.sagaID][who])
	if err != nil {
		return 0, []Finding{{Kind: FindingSignature, SagaID: t.sagaID, StepID: stepID, Seq: t.ev.Seq,
			Detail: fmt.Sprintf("the registry in this log could not be read to check %q's key: %v", who, err)}}
	}
	if len(keys) == 0 && (sig == nil || len(sig.GetSignature()) == 0) {
		return 0, nil // a keyless participant: nothing to check against, as the daemon allowed
	}
	if err := callersig.Verify(sig, who, keys, canonical); err != nil {
		return 0, []Finding{{Kind: FindingSignature, SagaID: t.sagaID, StepID: stepID, Seq: t.ev.Seq,
			Detail: fmt.Sprintf("this %s is recorded on behalf of %q, whose manifest declares a key, "+
				"and its signature does not hold: %v", t.ev.Kind, who, err)}}
	}
	return 1, nil
}
