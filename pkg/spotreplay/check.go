// Package spotreplay re-derives completed sagas from the evidence log and
// checks that they still come out the way the log says they did.
//
// # What this is for
//
// Determinism checking needs two things and CI only does one of them. The
// fixture corpus replays every saga history ever recorded, on every commit —
// that is the replay-determinism check, and it proves the state machine has not changed
// underneath histories somebody wrote down. What it cannot prove is anything
// about the sagas a deployment is actually running, which are the ones whose
// determinism a regulator would ask about. The other half is a "production
// spot-replay daemon [that] samples completed sagas continuously", and this is
// what it checks.
//
// # What it is not
//
// It is a detector, never an authority. It appends nothing, quarantines
// nothing, and holds no lock; it reads an evidence directory the same way
// `janus-verify` does and can run beside a live coordinator. A divergence is an
// alarm for a person, and the only correct automatic response to "the log no
// longer replays to what it said" is to stop and look, not to let a program
// decide what to do about it.
//
// It is also not the verifier. `janus-verify` and the continuous verifier check
// that the *bytes* are intact — chain hashes, segment signatures, Merkle roots.
// This checks something the bytes being intact does not imply: that feeding
// those bytes back through the state machine produces the same saga. A log can
// be perfectly intact and stop replaying the same way, and that is precisely
// what a change to the state machine does.
package spotreplay

import (
	"bytes"
	"encoding/hex"
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// Finding is what one saga's check produced.
type Finding struct {
	SagaID string
	// Status is what the saga's projection says it reached.
	Status saga.Status
	// Terminal says the saga has reached a state it will not leave on its own,
	// as `saga.State.Terminal` decides it. Only terminal sagas count towards the
	// determinism rate: the gate asks about *completed* sagas, and a saga still
	// running has not finished making the claims the other checks verify.
	Terminal bool
	// Checks are the checks that applied to this saga, and whether each passed.
	// Which ones apply depends on how the saga ended, so this is recorded rather
	// than assumed: a rate computed over a denominator nobody can see is a
	// number nobody can audit.
	Checks []Check
}

// Deterministic reports whether every check that applied to this saga passed.
func (f Finding) Deterministic() bool {
	for _, c := range f.Checks {
		if !c.Passed {
			return false
		}
	}
	return len(f.Checks) > 0
}

// Divergences lists the checks that failed, with what they found.
func (f Finding) Divergences() []Check {
	var out []Check
	for _, c := range f.Checks {
		if !c.Passed {
			out = append(out, c)
		}
	}
	return out
}

// Check is one applied check.
type Check struct {
	Name   string
	Passed bool
	// Detail says what was found when it did not pass. It is empty on a pass:
	// an explanation of something that did not happen is noise in a log that a
	// person is meant to be able to scan for the things that did.
	Detail string
}

// Names of the checks, so a report and an alert can agree on what failed.
const (
	// CheckReplayIsStable is invariant I5 stated directly: the state machine is a
	// pure function of the event sequence, so replaying the same events twice
	// must land on the same projection. It applies to every saga.
	//
	// This is the check that catches the nondeterminism that actually happens —
	// a map iterated without sorting, a decision that reads the clock, a slice
	// shared between two states — none of which the fixture corpus sees, because
	// the corpus compares against a value recorded by the same code.
	CheckReplayIsStable = "replay-is-stable"

	// CheckRootAgrees compares the evidence root recorded in the saga's COMMIT
	// against the root recomputed from the log. It applies only to committed
	// sagas: an aborted or compensated saga never recorded one.
	//
	// It is the strongest of the three because it is a comparison against
	// something *written down at the time*, by a different process, and cited
	// afterwards as the authority for releasing an irreversible effect.
	// The other two compare the system against itself.
	CheckRootAgrees = "root-agrees"

	// CheckCommitSeqAgrees compares the LastSeq the COMMIT recorded against the
	// sequence the replay reaches at that point.
	//
	// It is worth being precise about what kind of check this is, because it
	// looks like a third independent anchor and is not one. The coordinator
	// takes that value from its own in-memory state, so on a log a single
	// coordinator wrote alone the two numbers are equal by construction and this
	// can never fire.
	//
	// What it catches is a saga id being written by two things at once — which
	// is possible, because the outbox lifecycle events carry one. So it is a
	// tripwire for a second writer, kept because it costs nothing, and it is not
	// evidence of determinism on its own.
	CheckCommitSeqAgrees = "commit-seq-agrees"

	// CheckReadable is not a determinism check: it is what is recorded when a
	// saga could not be re-derived at all, because its events would not decode
	// or the log could not be read.
	//
	// It exists so that "could not check" is a finding rather than a gap. A
	// sampler that skipped an unreadable saga would produce a report saying
	// everything checked out, over a denominator quietly missing the one saga
	// that could not be read — and a saga whose events will not decode is the
	// most alarming thing this daemon can encounter, not the least.
	CheckReadable = "readable"
)

// CheckSaga re-derives one saga and reports what it found.
//
// The events are read once and replayed twice from the same slice. Reading them
// twice would test the reader as well, which is a different question and one
// `janus-verify` already answers; what is under test here is the state machine.
func CheckSaga(dir, sagaID string) (Finding, error) {
	events, err := saga.LoadEvents(dir, sagaID)
	if err != nil {
		return Finding{}, fmt.Errorf("spotreplay: read saga %q: %w", sagaID, err)
	}
	if len(events) == 0 {
		return Finding{}, fmt.Errorf("spotreplay: saga %q has no events", sagaID)
	}

	first, err := saga.Replay(events)
	if err != nil {
		return Finding{}, fmt.Errorf("spotreplay: replay saga %q: %w", sagaID, err)
	}
	second, err := saga.Replay(events)
	if err != nil {
		return Finding{}, fmt.Errorf("spotreplay: replay saga %q a second time: %w", sagaID, err)
	}

	f := Finding{SagaID: sagaID, Status: first.Status, Terminal: first.Terminal()}

	stable := Check{Name: CheckReplayIsStable, Passed: true}
	if diffs := saga.Diff(first, second); len(diffs) > 0 {
		stable.Passed = false
		stable.Detail = fmt.Sprintf("replaying the same %d events twice produced different "+
			"projections: %v", len(events), diffs)
	}
	f.Checks = append(f.Checks, stable)

	commitSeq, recorded, ok := commitRecord(events)
	if !ok {
		// No commit, so no recorded root and no recorded LastSeq. This is not a
		// gap in coverage to apologise for: an aborted or compensated saga never
		// made the claim these two checks verify.
		return f, nil
	}

	// Strictly before the commit. The coordinator computes the root and *then*
	// appends the COMMIT, and events keep arriving afterwards — a delivered
	// effect carries the saga's id and is recorded when the target answers. A
	// recomputation over everything would disagree with a healthy log.
	root, err := saga.EvidenceRootBefore(dir, sagaID, commitSeq)
	agrees := Check{Name: CheckRootAgrees, Passed: true}
	switch {
	case err != nil:
		agrees.Passed = false
		agrees.Detail = fmt.Sprintf("could not recompute the evidence root: %v", err)
	case len(recorded.GetEvidenceRoot()) == 0:
		agrees.Passed = false
		agrees.Detail = "the commit records no evidence root, so it authorised an effect " +
			"while citing nothing"
	case !bytes.Equal(root, recorded.GetEvidenceRoot()):
		agrees.Passed = false
		agrees.Detail = fmt.Sprintf("the commit at sequence %d recorded root %s; the log now "+
			"produces %s", commitSeq,
			hex.EncodeToString(recorded.GetEvidenceRoot()), hex.EncodeToString(root))
	}
	f.Checks = append(f.Checks, agrees)

	seqAgrees := Check{Name: CheckCommitSeqAgrees, Passed: true}
	if got := lastSeqBefore(events, commitSeq); got != recorded.GetLastSeq() {
		seqAgrees.Passed = false
		seqAgrees.Detail = fmt.Sprintf("the commit recorded last_seq %d; the log's last event "+
			"before it is at %d", recorded.GetLastSeq(), got)
	}
	f.Checks = append(f.Checks, seqAgrees)
	return f, nil
}

// lastSeqBefore is the highest sequence among the saga's events before one.
func lastSeqBefore(events []saga.Event, before uint64) uint64 {
	var out uint64
	for _, ev := range events {
		if ev.Seq >= before {
			break
		}
		out = ev.Seq
	}
	return out
}

// commitRecord finds the saga's COMMIT, if it has one.
func commitRecord(events []saga.Event) (seq uint64, commit commitLike, ok bool) {
	for _, ev := range events {
		if ev.Kind != evidence.KindCommit {
			continue
		}
		c, err := decodeCommit(ev.Payload)
		if err != nil {
			// A commit whose payload will not decode is a finding in its own
			// right, but it is one `janus-verify` and the replay above will both
			// have raised already. Treating it as "no commit" here would hide
			// it, so it is reported as a commit with nothing in it and the
			// checks below fail on that.
			return ev.Seq, commitLike{}, true
		}
		return ev.Seq, c, true
	}
	return 0, commitLike{}, false
}

// commitLike is the part of a Commit this package reads.
//
// The protobuf message is decoded into a small local shape rather than passed
// around, so that adding a field to Commit cannot silently change what a
// determinism check compares.
type commitLike struct {
	evidenceRoot []byte
	lastSeq      uint64
}

func (c commitLike) GetEvidenceRoot() []byte { return c.evidenceRoot }
func (c commitLike) GetLastSeq() uint64      { return c.lastSeq }

func decodeCommit(payload []byte) (commitLike, error) {
	var msg janusv1.Commit
	if err := proto.Unmarshal(payload, &msg); err != nil {
		return commitLike{}, err
	}
	return commitLike{evidenceRoot: msg.GetEvidenceRoot(), lastSeq: msg.GetLastSeq()}, nil
}
