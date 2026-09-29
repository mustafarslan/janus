package evidence

import (
	"fmt"

	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// Comparing two directories that claim to be the same log.
//
// Nothing prevents two writers. The writer lock is per-filesystem, so
// a promoted replica in one place and a partitioned-but-alive primary in another
// each hold a perfectly valid lock on their own directory, and each goes on
// writing a history that is internally consistent and verifiable. Neither log is
// damaged. They are two logs claiming to be one.
//
// A verifier reading either of them cannot see this, and that is not a gap it
// could close: it has nothing to compare against. The comparison needs both
// directories, which is why it lives here and why the failover drill — which
// keeps the killed primary's directory beside the promoted replica's — is where
// it gets exercised.
//
// # What this establishes and what it does not
//
// It finds the point where two logs stop agreeing and names what each did next.
// It does **not** tell you which one is right. That is not a technical question:
// both sides are valid logs, and which one a deployment should keep is a decision
// about which effects were released and which clients were answered. What this
// gives that person is the sequence number to start reading from and the tenure
// on each side, so the argument is about evidence rather than about recollection.

// Fork describes two logs that share a prefix and then diverge.
type Fork struct {
	// CommonSeq is the last sequence at which both logs agree, and the place to
	// start reading. Zero means they disagree from the very first record, which
	// is not a fork at all — it is two unrelated logs.
	CommonSeq uint64
	// CommonChain is the chain hash at that point, so a reader can confirm the
	// two really did share a history.
	CommonChain Hash
	// LeftNext and RightNext are the first sequences past the shared prefix on
	// each side. A fork needs BOTH: one side continuing alone is a log that is
	// simply longer, which is what every follower and every backup looks like.
	LeftNext, RightNext uint64
	LeftHead, RightHead uint64
	// LeftTenure and RightTenure are the promotions each side records after the
	// divergence point, if any. A fork with a tenure on one side is the ordinary
	// failover shape: somebody promoted a replica while the primary was alive.
	// A fork with tenures on both, or on neither, is a stranger story and the
	// text says so.
	LeftTenure, RightTenure *Tenure
}

// Diverged reports whether the two logs actually parted company.
//
// Both sides must have gone on past the point they last agreed. If only one did,
// the other is behind, not divergent — and the difference is the whole value of
// the tool. An earlier version of this used `||`, which called every lagging
// replica a fork; the test that should have caught it was comparing two
// identical directories and passed.
func (f Fork) Diverged() bool { return f.LeftNext != 0 && f.RightNext != 0 }

// Behind reports the name of the side that is merely lagging, and how far, when
// one log is a strict prefix of the other. It is the ordinary, healthy answer.
func (f Fork) Behind() (shorter string, by uint64) {
	switch {
	case f.Diverged():
		return "", 0
	case f.LeftNext != 0:
		return "right", f.LeftHead - f.CommonSeq
	case f.RightNext != 0:
		return "left", f.RightHead - f.CommonSeq
	}
	return "", 0
}

// Describe renders the fork for somebody who has to decide what to do about it.
func (f Fork) Describe(leftName, rightName string) string {
	if !f.Diverged() {
		side, by := f.Behind()
		switch side {
		case "right":
			return fmt.Sprintf("%s and %s agree through sequence %d; %s has %d record(s) "+
				"beyond that and %s has none. One is behind the other, which is not a fork.",
				leftName, rightName, f.CommonSeq, leftName, by, rightName)
		case "left":
			return fmt.Sprintf("%s and %s agree through sequence %d; %s has %d record(s) "+
				"beyond that and %s has none. One is behind the other, which is not a fork.",
				leftName, rightName, f.CommonSeq, rightName, by, leftName)
		}
		return fmt.Sprintf("%s and %s agree through sequence %d; neither holds a record "+
			"the other does not", leftName, rightName, f.CommonSeq)
	}
	s := fmt.Sprintf("%s and %s share a history through sequence %d and disagree after it.\n",
		leftName, rightName, f.CommonSeq)
	s += fmt.Sprintf("  %-28s diverges at %d, and goes on to %d\n", leftName, f.LeftNext, f.LeftHead)
	s += fmt.Sprintf("  %-28s diverges at %d, and goes on to %d\n", rightName, f.RightNext, f.RightHead)

	switch {
	case f.LeftTenure != nil && f.RightTenure != nil:
		s += "\n  Both sides record a promotion. Two processes each believed they were\n"
		s += "  taking over, which is the case nothing prevents and the reason fork\n"
		s += "  detection exists.\n"
	case f.LeftTenure != nil:
		s += fmt.Sprintf("\n  %s records a promotion by %q (%s); %s does not.\n",
			leftName, f.LeftTenure.Operator, f.LeftTenure.Node, rightName)
		s += "  The ordinary failover shape: a replica was promoted while the primary\n"
		s += "  was still writing.\n"
	case f.RightTenure != nil:
		s += fmt.Sprintf("\n  %s records a promotion by %q (%s); %s does not.\n",
			rightName, f.RightTenure.Operator, f.RightTenure.Node, leftName)
		s += "  The ordinary failover shape: a replica was promoted while the primary\n"
		s += "  was still writing.\n"
	default:
		s += "\n  Neither side records a promotion, so this is not a failover. Two\n"
		s += "  writers reached the same directory, or one log was edited.\n"
	}
	s += "\n  This does not say which side is right. Both are valid logs; which one a\n"
	s += "  deployment keeps depends on which effects were released and which clients\n"
	s += "  were answered, and that is a decision rather than a computation.\n"
	return s
}

// point is one record's identity, for comparison.
type point struct {
	seq   uint64
	chain Hash
	kind  Kind
}

// CompareLogs finds where two evidence directories stop agreeing.
//
// Compared by chain hash rather than by content: two records agree when they
// hash to the same chain value, which is what "the same history" means here and
// is cheaper and stricter than comparing payloads.
func CompareLogs(leftDir, rightDir string, opts ...ReadOption) (Fork, error) {
	left, leftTenure, err := readPoints(leftDir, opts...)
	if err != nil {
		return Fork{}, fmt.Errorf("reading %s: %w", leftDir, err)
	}
	right, rightTenure, err := readPoints(rightDir, opts...)
	if err != nil {
		return Fork{}, fmt.Errorf("reading %s: %w", rightDir, err)
	}

	f := Fork{LeftTenure: leftTenure, RightTenure: rightTenure}
	if len(left) > 0 {
		f.LeftHead = left[len(left)-1].seq
	}
	if len(right) > 0 {
		f.RightHead = right[len(right)-1].seq
	}

	i := 0
	for i < len(left) && i < len(right) {
		if left[i].chain != right[i].chain {
			break
		}
		f.CommonSeq, f.CommonChain = left[i].seq, left[i].chain
		i++
	}
	// A shared prefix that runs out on one side only is not a divergence: that log
	// is simply shorter, which is what a replica that stopped following looks like
	// and is the ordinary state of every backup ever taken. Both fields are still
	// recorded here; Diverged is what requires both.
	if i < len(left) {
		f.LeftNext = left[i].seq
	}
	if i < len(right) {
		f.RightNext = right[i].seq
	}
	return f, nil
}

// readPoints walks a directory for its chain and the first tenure after the
// point a fork would begin.
func readPoints(dir string, opts ...ReadOption) ([]point, *Tenure, error) {
	var pts []point
	var tenure *Tenure
	err := Walk(dir, func(h EventHeader, rec segment.Record) error {
		pts = append(pts, point{seq: h.Seq, chain: rec.Chain, kind: h.Kind})
		if h.Kind == KindWriterTenure && tenure == nil && len(rec.Payload) > 0 {
			t, terr := DecodeTenure(rec.Payload)
			if terr != nil {
				return terr
			}
			tenure = &t
		}
		return nil
	}, opts...)
	if err != nil {
		return nil, nil, err
	}
	return pts, tenure, nil
}
