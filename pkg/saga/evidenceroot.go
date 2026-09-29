package saga

import (
	"fmt"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/merkle"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// The evidence root of a saga: what a commit cites, and what a released effect
// points back to.
//
// A commit record carries this root, and every outbox release copies it. That gives the chain of reasoning an auditor needs, in one direction
// and without trusting any running process:
//
//	this payment happened  ->  because this release authorised it
//	this release            ->  cites this commit root
//	this commit root        ->  is the Merkle root over exactly these saga events
//	those events            ->  chain-hash into the log, which is signed
//
// A single hash would have been enough to bind the commit to the log. A Merkle
// root is used instead because it also supports the narrower question: prove
// that *this one step* was part of the committed footprint, without handing over
// the rest of the saga. That matters when the saga contains other people's data,
// which in a bank it usually does.
//
// The leaves are the events' chain hashes rather than their payloads. A chain
// hash already commits to the payload, the header, and every event before it, so
// using it as the leaf means an inclusion proof establishes position in the log
// as well as membership in the saga — a payload hash alone would prove only that
// the event existed somewhere.

// EvidenceRoot computes the Merkle root over a saga's events, in log order.
//
// It reads the segments rather than a projection because this value is cited as
// authority for releasing an irreversible effect. A root derived from anything
// other than the recorded bytes would be a claim about the log rather than a
// summary of it.
func EvidenceRoot(dir, sagaID string, opts ...evidence.ReadOption) ([]byte, error) {
	leaves, err := chainHashesFor(dir, sagaID, opts...)
	if err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("saga %q has no events, so it has no evidence root", sagaID)
	}
	root := merkle.Root(leaves)
	return root[:], nil
}

// EvidenceRootBefore computes the root over a saga's events *strictly before* a
// sequence.
//
// It exists because the root a commit carries is not the root of everything the
// saga ever produced. The coordinator computes it and then appends the COMMIT,
// so the recorded value covers the events before that commit and nothing after
// — and "after" is not hypothetical: the outbox lifecycle events carry the
// saga's id, and a delivered effect is recorded once the target answers, which
// is later by definition.
//
// So a reader checking a recorded root against the log must ask for the root as
// it stood, and this is the function that asks. The parameter is named `before`
// and is exclusive for the same reason: a caller who passes the commit's own
// sequence gets an answer that includes the commit, which is the mistake this
// signature exists to make visible.
func EvidenceRootBefore(dir, sagaID string, before uint64, opts ...evidence.ReadOption) ([]byte, error) {
	leaves, seqs, err := chainHashesAndSeqs(dir, sagaID, opts...)
	if err != nil {
		return nil, err
	}
	cut := 0
	for i, s := range seqs {
		if s >= before {
			break
		}
		cut = i + 1
	}
	if cut == 0 {
		return nil, fmt.Errorf("saga %q has no events before sequence %d, so it has no "+
			"evidence root at that point", sagaID, before)
	}
	root := merkle.Root(leaves[:cut])
	return root[:], nil
}

// EvidenceRootWithProof returns the root together with an inclusion proof for
// one event, identified by its sequence number.
//
// This is the disclosure-minimising form: it lets a holder show that a specific
// event was inside a committed footprint while revealing only that event.
func EvidenceRootWithProof(dir, sagaID string, seq uint64, opts ...evidence.ReadOption) (root []byte, proof [][]byte, size int, err error) {
	leaves, seqs, err := chainHashesAndSeqs(dir, sagaID, opts...)
	if err != nil {
		return nil, nil, 0, err
	}
	index := -1
	for i, s := range seqs {
		if s == seq {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, nil, 0, fmt.Errorf("saga %q has no event at sequence %d", sagaID, seq)
	}
	audit, err := merkle.InclusionProof(leaves, index)
	if err != nil {
		return nil, nil, 0, err
	}
	r := merkle.Root(leaves)
	out := make([][]byte, len(audit))
	for i := range audit {
		h := audit[i]
		out[i] = h[:]
	}
	return r[:], out, len(leaves), nil
}

func chainHashesFor(dir, sagaID string, opts ...evidence.ReadOption) ([][merkle.Size]byte, error) {
	leaves, _, err := chainHashesAndSeqs(dir, sagaID, opts...)
	return leaves, err
}

func chainHashesAndSeqs(dir, sagaID string, opts ...evidence.ReadOption) ([][merkle.Size]byte, []uint64, error) {
	var leaves [][merkle.Size]byte
	var seqs []uint64
	if err := evidence.WalkSaga(dir, sagaID, func(h evidence.EventHeader, rec segment.Record) error {
		// The chain hash is recomputed rather than trusted as stored. A root
		// built from bytes nobody checked would summarise whatever an
		// attacker wrote instead of what the log actually contains.
		if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
			return fmt.Errorf("seq %d: chain hash mismatch, so no evidence root "+
				"can be derived", h.Seq)
		}
		// HashLeaf rather than the raw chain hash: the 0x00 leaf prefix is
		// what keeps a leaf from being reinterpreted as an interior node,
		// which is the substitution RFC 6962 §2.1 exists to prevent.
		leaves = append(leaves, merkle.HashLeaf(rec.Chain[:]))
		seqs = append(seqs, h.Seq)
		return nil
	}, opts...); err != nil {
		return nil, nil, err
	}
	return leaves, seqs, nil
}
