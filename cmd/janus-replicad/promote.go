package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/fence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// Promotion: a replica stops reading and starts writing.
//
// # It is an operator act, and that is a decision rather than an omission
//
// Automatic failover needs a failure detector, and a wrong one produces two
// writers that each believe they are the primary — which is the situation
// nothing here can prevent, because the writer lock is per-filesystem
// (`syscall.Flock`) and cannot see across regions. A human names the moment. The
// cost is that the human's decision time is inside the RTO, and any drill
// measuring RTO has to say whether it included it.
//
// # What it inherits
//
// Promotion is an `evidence.Open` on the replica's directory, so it inherits
// exactly what a restarted primary inherits: recovery truncates a torn tail and
// keeps every complete record, including records the previous writer never
// acknowledged. That is the right behaviour — it is what the primary itself
// would have done — and it is not free, because no effect was ever released on
// the authority of those records. Both figures go into the tenure so the adopted
// span is on the record.
//
// # The fence, and where the epoch comes from
//
// `-fence-bucket` makes the promotion itself conditional on taking the writer
// lease, which is what stops two operators promoting two replicas of
// one log at the same moment. It is taken *before* the tenure is written, so a
// promotion that cannot fence records nothing.
//
// The epoch is derived here rather than accepted from a flag. It decides who
// wins — a higher one displaces a live writer — and a number that decides that
// should not be one an operator can typo. It is the count of tenures already in
// the log plus one, which is a walk this process was doing anyway.
//
// The lease is released on the way out, because the process that goes on writing
// is `janus-orchd` and not this one. That leaves a window between the two in
// which a stale writer could take the free lease; the epoch is what bounds it.
// The promoted daemon starts at the epoch printed here, takes the lease back
// from anything lower, and waits out whatever it displaced.
//
// # The follower must be stopped first
//
// A follower holds no writer lock. Two processes writing one evidence directory
// is the situation the writer lock exists to refuse, and here the lock will refuse the
// *promotion* rather than the follower — so stop `janus-replicad` before
// promoting, and the runbook says so.

func promote(args []string) error {
	fs := flag.NewFlagSet("promote", flag.ContinueOnError)
	dir := fs.String("dir", "", "the replica directory to promote")
	keyPath := fs.String("key", "", "the signing key this writer will use. It must already\n"+
		"have been declared in the log by the previous writer (janus-keys rotate),\n"+
		"or an auditor following from one root cannot reach it")
	operator := fs.String("operator", "", "who is promoting this replica; required")
	reason := fs.String("reason", "", "why the failover is happening")
	node := fs.String("node", "", "name of this node, for whoever reads the log later")
	acked := fs.Uint64("acknowledged", 0, "the last sequence the previous writer stated it had\n"+
		"made durable, if known. Records above it that this directory holds were\n"+
		"adopted by recovery and were never acknowledged to anyone")
	fenceFlags := fence.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The same flag names as janus-orchd, so an operator has one set to
	// remember -- except this one, which is read from the log instead.
	var epochSupplied bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "fence-epoch" {
			epochSupplied = true
		}
	})
	if epochSupplied {
		return errors.New("-fence-epoch is not accepted here: promotion derives it from the " +
			"log, because it decides which writer wins and a number that decides that " +
			"should not be one an operator can mistype. This command prints the value to " +
			"start janus-orchd with")
	}
	if *dir == "" || *keyPath == "" {
		return promoteUsage("-dir and -key are required")
	}
	if *operator == "" {
		return promoteUsage("-operator is required: promotion is an act somebody performs, " +
			"and a record of one nobody performed is not evidence")
	}

	// Has *this directory* already been promoted? Asked of the writer marker,
	// which is node-local, rather than of the log, which is replicated.
	//
	// The tenure count used to answer this and answered a different question. A
	// tenure is in the log, so after one promotion every replica of that log
	// carries one — and a replica that has never been promoted was refused,
	// which meant a deployment could fail over exactly once.
	owned, err := evidence.HasWriterMark(*dir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *dir, err)
	}
	if owned {
		return fmt.Errorf("%s is already a writer's directory: an appender has opened it, so "+
			"promoting it would record a handover that did not happen.\n\n"+
			"If this is the replica you meant, it is the one no daemon has written — a "+
			"follower's mirror. A directory that has itself been promoted stays promoted", *dir)
	}

	// The epoch, and this *is* the log's question: an epoch counts the
	// promotions the log has been through, so a replica of a once-promoted log
	// correctly derives 2. Same call, different question, and the two were
	// conflated until they disagreed.
	tenures, err := evidence.TenureCount(*dir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *dir, err)
	}
	epoch := tenures + 1

	// Take the lease before writing anything. A promotion that cannot fence
	// records no tenure, so a refused second promotion leaves a directory that
	// is still a replica rather than one that is half a writer.
	//
	// Establishing, not serving: an expired lease at this epoch is not an
	// opening. It is what the *other* operator's promotion left behind on its
	// way out, and the writer it belongs to may simply not have been started
	// yet -- which is the five-second window a second promotion would otherwise
	// walk straight through.
	fenceFlags.Establishing(epoch)
	fenceFlags.WarnIfUnfenced("janus-replicad promote")
	host, _ := os.Hostname()
	lease, err := fenceFlags.Open(context.Background(),
		fmt.Sprintf("promote:%s@%s", *operator, host))
	if err != nil {
		return fmt.Errorf("%w\n\nThe lease is the arbitration between two operators "+
			"promoting two replicas of one log at the same moment. Nothing has been "+
			"written to %s", err, *dir)
	}
	if lease != nil {
		// Released on every path out: the process that goes on holding it is
		// janus-orchd, started separately, and a lease left behind by a process
		// that has exited would make the promoted daemon wait out the TTL for
		// no reason.
		defer func() { _ = lease.Release(context.Background()) }()
	}

	signer, err := keys.Load(*keyPath)
	if err != nil {
		return fmt.Errorf("loading the signing key: %w", err)
	}

	// Opening takes the writer lock — which is the check that the follower has
	// been stopped, and it is a better check than asking, because it cannot be
	// answered wrongly.
	//
	// No clock attestation here, deliberately, and it is the one writer left out
	// of the clock wiring. This process appends exactly one record — the tenure — and the
	// tenure has to be the first thing the promoted writer writes: an
	// attestation taken before it would make the new writer's first act
	// something other than declaring what it inherited, and would put this
	// process's own record inside the InheritedSeq it is claiming to continue
	// from. Taken after it, the attestation is pointed at by nothing, because
	// the next thing to run here is `janus-orchd`, which takes its own on
	// startup. So the TENURE record carries no clock reference, the same way the
	// first attestation in any log does, and the daemon that follows attests
	// from its first append onward.
	app, err := evidence.Open(evidence.Options{
		Dir: *dir, Signer: signer, SyncMode: segment.SyncModeFull,
	})
	if err != nil {
		if errors.Is(err, evidence.ErrLocked) {
			return fmt.Errorf("%w: something else owns %s — stop janus-replicad before "+
				"promoting, because two processes writing one evidence directory is "+
				"the situation the lock exists to refuse", err, *dir)
		}
		return fmt.Errorf("opening %s as a writer: %w", *dir, err)
	}
	defer func() { _ = app.Close() }()

	// Read *after* Open, so it is the head recovery established rather than the
	// head that was on disk before recovery ran.
	st := app.Stats()
	chain := st.LastChain
	t := evidence.Tenure{
		InheritedSeq:    st.LastSeq,
		InheritedChain:  "blake3:" + hex.EncodeToString(chain[:]),
		AcknowledgedSeq: *acked,
		KeyID:           signer.KeyID(),
		Node:            *node,
		Operator:        *operator,
		Reason:          *reason,
	}
	ref, err := app.RecordTenure(context.Background(), t, evidence.ParticipantRef{
		ID: "sys_replicad", Kind: "SYSTEM", Principal: "pr_operator",
	})
	if err != nil {
		return fmt.Errorf("recording the tenure: %w", err)
	}

	// The epoch, written into this node's marker now that the tenure it counts
	// is durable, so the daemon that takes over here does not need to be told.
	// After the record and not before: until the log says the
	// promotion happened, the epoch is a plan rather than a fact.
	//
	// A failure here is worth stopping for. The promotion has succeeded — the
	// tenure is in the log — but a writer started against this directory would
	// resolve epoch 0 and be refused by the lease, which is an outage arriving
	// later and looking like something else.
	if err := evidence.SetWriterEpoch(*dir, epoch); err != nil {
		return fmt.Errorf("the tenure is recorded at sequence %d, but the epoch could not be "+
			"written to this directory's writer marker: %w\n\n"+
			"janus-orchd reads the epoch from there, so it would start at 0 and be refused "+
			"by the lease. Fix the directory's permissions and re-run, or start the daemon "+
			"with -fence-epoch %d", ref.Seq, err, epoch)
	}

	fmt.Printf("promoted %s\n", *dir)
	fmt.Printf("  continuing from sequence %d (%s)\n", t.InheritedSeq, t.InheritedChain)
	fmt.Printf("  signing with %s\n", t.KeyID)
	fmt.Printf("  tenure recorded at sequence %d\n", ref.Seq)
	if n := t.Adopted(); n > 0 {
		fmt.Printf("\n  %d record(s) were adopted that the previous writer never\n", n)
		fmt.Printf("  acknowledged (it stated %d, this directory holds %d). They are\n",
			t.AcknowledgedSeq, t.InheritedSeq)
		fmt.Printf("  complete and correctly chained, and no effect was released on\n")
		fmt.Printf("  their authority. The tenure records both figures.\n")
	} else if *acked == 0 {
		fmt.Printf("\n  The previous writer's acknowledged head was not supplied, so the\n")
		fmt.Printf("  adopted span is unknown rather than zero. Pass -acknowledged with\n")
		fmt.Printf("  the follower's last reported sequence to record it.\n")
	}
	if lease != nil {
		fmt.Printf("\n  The writer lease was taken at epoch %d and is being released: the\n", epoch)
		fmt.Printf("  process that holds it from here is janus-orchd. Start it with the\n")
		fmt.Printf("  same -fence-bucket and no -fence-epoch: the epoch is recorded in\n")
		fmt.Printf("  this directory's writer marker and the daemon reads it from there.\n")
		fmt.Printf("  A daemon at a lower epoch is refused, which is how the old primary\n")
		fmt.Printf("  is kept out; one at a higher one would take this log from a writer\n")
		fmt.Printf("  that legitimately holds it -- which is why the number is not one\n")
		fmt.Printf("  anybody has to retype.\n")
	}
	fmt.Printf("\n  This directory is now a writer and janus-replicad will refuse to\n")
	fmt.Printf("  follow it. Point clients at it and start janus-orchd.\n")
	// Said every time rather than only when it looks doubtful, because this
	// process cannot tell whether the follower was checking signatures — that
	// state lived in a process that has been stopped. Promotion establishes no
	// integrity of its own; it records a handover on top of whatever was there.
	fmt.Printf("\n  Promotion did NOT verify this log. It records a handover on top of\n")
	fmt.Printf("  whatever was already here, and a replica that was following without\n")
	fmt.Printf("  a trust root was never checking signatures at all. Run:\n")
	fmt.Printf("      janus-tier sweep -evidence %s -keys <roots>\n", *dir)
	return nil
}

// promoteUsage prints how to promote, and why the two constraints that are easy
// to get wrong are constraints.
func promoteUsage(why string) error {
	fmt.Fprint(os.Stderr, `usage:
  janus-replicad promote -dir <replica dir> -key <signing key> -operator <who> [-reason ...] [-acknowledged N]
                         [-fence-bucket <bucket> -fence-endpoint <url>]

Pass -fence-bucket if the primary was started with one. Promotion then takes the
writer lease before it records anything, so a second operator promoting a second
replica of the same log is refused and their directory is left untouched -- and
it records the epoch in the directory's writer marker, where janus-orchd
reads it, so nothing has to be retyped. -fence-epoch is not
accepted here: it decides which writer wins, and it is derived from the log.

Stop the follower first: promotion takes the writer lock, and two processes
writing one evidence directory is what the lock exists to refuse.

The signing key must already have been declared in the log by the previous
writer, while it was healthy (janus-keys rotate -new). A key first introduced by
the promoted writer dangles from no in-chain declaration, and an auditor
following the log from one root cannot reach it.
`)
	return errors.New(why)
}
