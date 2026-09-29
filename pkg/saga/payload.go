package saga

import (
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// messageFor returns an empty JTP message of the kind an event carries.
//
// It is the one place that maps an event kind to its payload type. Keeping it
// in a single function means adding a kind without giving it a payload type is
// a compile-time omission rather than a runtime surprise in whichever caller
// happens to hit it first.
func messageFor(kind evidence.Kind) (proto.Message, error) {
	switch kind {
	case evidence.KindSagaBegin:
		return &janusv1.SagaBegin{}, nil
	case evidence.KindStepPrepare:
		return &janusv1.StepPrepare{}, nil
	case evidence.KindStepResult:
		return &janusv1.StepResult{}, nil
	case evidence.KindGateVerdict:
		return &janusv1.GateVerdict{}, nil
	case evidence.KindGateAnswer:
		return &janusv1.GateAnswer{}, nil
	case evidence.KindSealRequest:
		return &janusv1.SealRequest{}, nil
	case evidence.KindCommit:
		return &janusv1.Commit{}, nil
	case evidence.KindCompensate:
		return &janusv1.Compensate{}, nil
	case evidence.KindAbort:
		return &janusv1.Abort{}, nil
	case evidence.KindQuarantine:
		return &janusv1.Quarantine{}, nil
	case evidence.KindDPR:
		return &janusv1.DecisionProvenanceRecord{}, nil
	default:
		return nil, fmt.Errorf("saga: no payload type for event kind %q", kind)
	}
}

// payloadFromJSON converts a fixture's readable payload into wire bytes.
func payloadFromJSON(kind evidence.Kind, raw []byte) ([]byte, error) {
	msg, err := messageFor(kind)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return proto.Marshal(msg)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, msg); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", kind, err)
	}
	return proto.Marshal(msg)
}

// PayloadToJSON renders a payload in the readable form fixtures store.
//
// Deterministic output matters here: a fixture whose JSON key order shifted
// between runs would produce a diff on every regeneration and train reviewers
// to ignore fixture changes, which is precisely what the corpus depends on them
// not doing.
func PayloadToJSON(kind evidence.Kind, payload []byte) ([]byte, error) {
	msg, err := messageFor(kind)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(payload, msg); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", kind, err)
	}
	return protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
}
