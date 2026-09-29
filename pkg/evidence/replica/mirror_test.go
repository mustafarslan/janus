package replica_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/continuous"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/replica"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// damagedMirror runs a follower to completion, then flips a byte in a sealed
// segment it has already verified — a bad disk on the replica host, or a
// careless operator, and specifically not the primary.
func damagedMirror(t *testing.T) (*replica.Follower, string, keys.PublicKeySet, uint64) {
	t.Helper()
	app, pdir, src, signer := primary(t, func(o *evidence.Options) {
		o.SegmentTargetBytes = 4 << 10
	})
	appendN(t, app, 80)
	settle(t, pdir)

	roots := keys.PublicKeySet{signer.KeyID(): signer.Public()}
	dir := t.TempDir() + "/replica"
	f, err := replica.New(replica.Options{Dir: dir, Source: src, Keys: roots})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}
	checked := f.Status().SignaturesCheckedThrough
	if checked < 2 {
		t.Fatalf("the follower verified through segment %d; this needs a sealed segment "+
			"strictly below its cursor to damage", checked)
	}

	victim := segment.Path(dir, 1)
	blob, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)/2] ^= 0xff
	if err := os.WriteFile(victim, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	return f, dir, roots, checked
}

// A follower does not notice damage to its own history, and says so.
//
// `SignaturesCheckedThrough` is a statement about what this follower *copied*,
// not about what is on disk now: a poll asks only about segments at or above its
// cursor, so a sealed segment corrupted underneath it afterwards never
// lowers the number. That was true before polls were narrowed too — nothing about a
// follower ever re-read its own history.
//
// Pinned as a fact rather than left in a doc comment. The number is what an
// operator watching `janus-replicad` reads, and "signatures checked through
// segment 4" is exactly the sentence that invites the wrong conclusion. If this
// test ever fails because a follower *did* notice, that is not a regression —
// it is a change that makes `replica.Status`'s doc comment and the advice
// `janus-replicad` prints both stale, and they have to change with it.
func TestAFollowerDoesNotNoticeDamageToItsOwnHistory(t *testing.T) {
	f, _, _, checked := damagedMirror(t)

	for pass := range 3 {
		if err := f.Follow(context.Background()); err != nil {
			t.Fatalf("pass %d failed: %v — a follower that refuses here is a follower that "+
				"re-reads its history, which is the cost narrowing the poll removed", pass, err)
		}
		st := f.Status()
		if st.SignaturesCheckedThrough != checked {
			t.Fatalf("pass %d reports signatures checked through segment %d, was %d: if a "+
				"follower now notices damage below its cursor, replica.Status's comment and "+
				"janus-replicad's advice to run janus-tier watch are both stale",
				pass, st.SignaturesCheckedThrough, checked)
		}
	}
}

// And the advice a follower gives instead is real: the watcher catches it.
//
// `janus-replicad` tells an operator to run `janus-tier watch` over the mirror.
// That is advice a person acts on, so it is worth knowing it works rather than
// assuming it: the same damage the follower passes over is a Critical finding in
// the sweep, which is the pass that re-reads history (`SweepStep` is what the
// watcher's hourly sweep is made of).
func TestTheWatcherCatchesWhatTheFollowerPassesOver(t *testing.T) {
	_, dir, roots, _ := damagedMirror(t)

	v, err := continuous.New(continuous.Config{
		Dir: dir, Keys: roots, CheckpointPath: t.TempDir() + "/ckpt.json",
	})
	if err != nil {
		t.Fatal(err)
	}

	var found []verify.Finding
	ctx := context.Background()
	for range 20 {
		rep, done, err := v.SweepStep(ctx, 2)
		if err != nil {
			t.Fatal(err)
		}
		if rep != nil {
			for _, fi := range rep.Findings {
				if fi.Severity == verify.Critical {
					found = append(found, fi)
				}
			}
		}
		if done {
			break
		}
	}
	if len(found) == 0 {
		t.Fatal("the sweep found nothing critical in a mirror with a flipped byte in a " +
			"sealed segment: janus-replicad's advice to run janus-tier watch would be a " +
			"gesture, and the follower's own silence is then the only word on the subject")
	}
	var codes []string
	for _, fi := range found {
		codes = append(codes, fi.Code)
	}
	t.Logf("the sweep reported %d critical finding(s): %s", len(found), strings.Join(codes, ", "))
}
