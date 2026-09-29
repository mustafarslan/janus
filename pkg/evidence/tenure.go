package evidence

import (
	"context"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// A tenure is a writer saying, in the log, that it has become the writer.
//
// Promotion is the moment a replica stops reading and starts writing, and it is
// the only moment in this system when the identity of the writer changes without
// the previous one handing over. Everything else about replication is arranged
// so that the two directories are the same log; this is the record
// that says which process is continuing it and from where.
//
// # Why it is written down rather than inferred
//
// After a failover an auditor is looking at one directory and asking what
// happened at the seam. Without a record the seam is a change of signing key and
// a gap in the wall-clock timestamps — both of which have innocent explanations,
// and neither of which names the operator who decided. With one, the question
// has an answer in the evidence rather than in somebody's memory.
//
// # Why it records two heads
//
// A follower legitimately holds records that are complete and correctly chained
// and that the primary never acknowledged: the writer's buffer flushes on byte
// boundaries, so a record can be whole on disk and uncovered by a barrier.
// Promotion adopts them, because that is what recovery
// does — `Appender.restore` truncates a torn tail and keeps every complete
// record, so a promoted replica behaves exactly as the primary would have on
// restart.
//
// Adopting them is right and it is not free: those records were never
// acknowledged to any caller, so no effect was released on their authority, and
// a reader who assumes "in the log" means "was acted upon" would be wrong about
// exactly this span. So both figures are recorded — the last head the primary
// stated, and the head this writer recovered to — and the difference between
// them is the adopted span, on the record rather than silent.
//
// CBOR, not protobuf: `janus-verify` has to read this, and the project keeps the
// protobuf runtime out of the verifier's import graph. The codec is already
// linked there for WriterKeyDeclaration, so what this costs is the decode path —
// measured at +5,947 bytes on linux/amd64, against the 9.3 MB the protobuf
// runtime would have added. Measured because "it should be free" is how the
// verifier went from 7.0 MB to 16.3 MB once before.

// Tenure is the payload of a WRITER_TENURE event.
type Tenure struct {
	// InheritedSeq and InheritedChain are the point this writer continues from:
	// the last record that existed before it appended anything. A verifier
	// compares them against the actual predecessor, so a tenure claiming to
	// continue from somewhere it does not is a finding rather than a footnote.
	InheritedSeq   uint64 `cbor:"1,keyasint"`
	InheritedChain string `cbor:"2,keyasint"`
	// AcknowledgedSeq is the last sequence the previous writer said it had made
	// durable, as the promoting process last heard it. Records above it and at
	// or below InheritedSeq were adopted by recovery and were never acknowledged
	// to anyone — see the type comment.
	AcknowledgedSeq uint64 `cbor:"3,keyasint"`
	// KeyID is the key this writer will sign segments with. It must already have
	// been declared in a segment the previous writer signed, or an auditor
	// following the log forward from one root cannot reach it.
	KeyID string `cbor:"4,keyasint"`
	// Node identifies the process taking over, for an operator reading the log
	// afterwards.
	Node string `cbor:"5,keyasint,omitempty"`
	// Operator is the person who decided. Promotion is never automatic, so there
	// is always one, and a tenure without one is a promotion nobody owns.
	Operator string `cbor:"6,keyasint"`
	// Reason is why the failover happened.
	Reason string `cbor:"7,keyasint,omitempty"`
}

// Encode renders a tenure for the log.
func (t Tenure) Encode() ([]byte, error) {
	if t.Operator == "" {
		return nil, fmt.Errorf("evidence: a tenure needs an operator; promotion is an act " +
			"somebody performs, and a record of one nobody performed is not evidence")
	}
	if t.KeyID == "" {
		return nil, fmt.Errorf("evidence: a tenure needs the key id it will sign with")
	}
	return cbor.Marshal(t)
}

// DecodeTenure reads a tenure payload.
func DecodeTenure(b []byte) (Tenure, error) {
	var t Tenure
	if err := cbor.Unmarshal(b, &t); err != nil {
		return t, fmt.Errorf("evidence: decoding a tenure: %w", err)
	}
	return t, nil
}

// Adopted reports how many records this writer took on that the previous one
// never acknowledged.
//
// Zero is the ordinary case: a replica that was caught up when it was promoted.
// A non-zero count is not damage — those records are complete and chained — but
// it is the span about which "in the log" does not mean "was acted upon".
func (t Tenure) Adopted() uint64 {
	if t.InheritedSeq <= t.AcknowledgedSeq {
		return 0
	}
	return t.InheritedSeq - t.AcknowledgedSeq
}

// RecordTenure appends a tenure as this writer's first act.
//
// First, and that matters: everything this writer appends afterwards is
// explained by it, and a tenure written later would leave records in front of it
// that no reader can attribute.
func (a *Appender) RecordTenure(ctx context.Context, t Tenure, by ParticipantRef) (Ref, error) {
	payload, err := t.Encode()
	if err != nil {
		return Ref{}, err
	}
	return a.Append(ctx, Request{
		Kind:        KindWriterTenure,
		Participant: by,
		Payload:     payload,
		Labels: map[string]string{
			"tenure_key":  t.KeyID,
			"tenure_node": t.Node,
		},
	})
}

// HasTenure reports whether a directory contains a tenure record — that is,
// whether **the log** has been promoted at least once.
//
// It is not "is this directory a writer's", and it used to be asked as if it
// were. A tenure is in the log and the log is replicated, so after one failover
// every replica carries one; asking this to decide whether a directory may be
// followed or promoted refused every replica of a failed-over log. That question
// has a node-local answer now — see writermark.go — and this one
// answers what it says: how many times the log has changed writer.
func HasTenure(dir string, opts ...ReadOption) (bool, error) {
	n, err := TenureCount(dir, opts...)
	return n > 0, err
}

// TenureCount counts the promotions a log has been through, which is the epoch
// its current writer serves under (the writer-lease fence compares them to decide who
// wins). The original writer has seen none and serves epoch 0; the writer a
// promotion installs serves 1.
//
// It costs a full walk, which is why `janus-orchd` takes its epoch from a flag
// and does not call this: the walk is 254 s at 100M events, and the daemon would
// pay it on every start. `janus-replicad promote` calls it because it is the
// right question for an epoch — including on a replica of a log that has already
// failed over, which correctly derives 2.
func TenureCount(dir string, opts ...ReadOption) (uint64, error) {
	var n uint64
	err := Walk(dir, func(h EventHeader, _ segment.Record) error {
		if h.Kind == KindWriterTenure {
			n++
		}
		return nil
	}, opts...)
	if err != nil {
		return 0, err
	}
	return n, nil
}
