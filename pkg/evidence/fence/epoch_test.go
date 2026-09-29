package fence_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/fence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// writerDir is a directory an appender has owned, which is the only kind that
// can carry an epoch.
func writerDir(t *testing.T) string {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindStepResult, SagaID: "sg_fence", StepID: "st",
		Participant: evidence.ParticipantRef{ID: "ag_fence"}, Payload: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// reopen is what janus-orchd's own evidence.Open does to the directory, which
// is what puts a marker back.
func reopen(t *testing.T, dir string) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

// resolve runs the flags a daemon would be started with against dir.
func resolve(t *testing.T, dir string, args ...string) (*fence.Flags, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := fence.RegisterFlags(fs)
	if err := fs.Parse(append([]string{"-fence-bucket", "b"}, args...)); err != nil {
		t.Fatal(err)
	}
	return f, f.ResolveEpoch(dir, fs)
}

// The normal path after a promotion: nothing is passed and the epoch comes from
// the marker the promotion left. This is the whole point — the flag exists to
// be forgotten, and forgetting it used to refuse a legitimate start.
func TestTheEpochComesFromTheMarkerWhenNobodyPassesOne(t *testing.T) {
	dir := writerDir(t)
	if err := evidence.SetWriterEpoch(dir, 2); err != nil {
		t.Fatal(err)
	}
	f, err := resolve(t, dir)
	if err != nil {
		t.Fatalf("ResolveEpoch: %v", err)
	}
	if f.Epoch() != 2 {
		t.Fatalf("resolved epoch %d, want the marker's 2", f.Epoch())
	}
}

// A directory nobody promoted serves the original writer's epoch.
func TestAnUnpromotedDirectoryServesEpochZero(t *testing.T) {
	f, err := resolve(t, writerDir(t))
	if err != nil {
		t.Fatalf("ResolveEpoch: %v", err)
	}
	if f.Epoch() != 0 {
		t.Fatalf("resolved epoch %d, want 0", f.Epoch())
	}
}

// The migration path: a directory promoted before the marker carried an epoch
// has a marker with no epoch in it, is told once, and the telling sticks — so
// the next start needs no flag.
func TestAFlagOnADirectoryWithNoRecordedEpochIsKept(t *testing.T) {
	dir := writerDir(t)
	// The premise. This directory has a marker — an appender owned it — and no
	// epoch, which is what every directory written by an older build looks like.
	if _, ok, err := evidence.ReadWriterMark(dir); err != nil || !ok {
		t.Fatalf("the directory has no writer marker (err %v); the test is not set up", err)
	}

	f, err := resolve(t, dir, "-fence-epoch", "1")
	if err != nil {
		t.Fatalf("ResolveEpoch: %v", err)
	}
	if f.Epoch() != 1 {
		t.Fatalf("resolved epoch %d, want the flag's 1", f.Epoch())
	}
	if err := f.RecordEpoch(dir); err != nil {
		t.Fatalf("RecordEpoch: %v", err)
	}
	again, err := resolve(t, dir)
	if err != nil {
		t.Fatalf("ResolveEpoch on the second start: %v", err)
	}
	if again.Epoch() != 1 {
		t.Fatalf("the second start resolved %d; the flag was not recorded", again.Epoch())
	}
}

// A flag that agrees with the marker is not an argument.
func TestAFlagThatAgreesWithTheMarkerIsAccepted(t *testing.T) {
	dir := writerDir(t)
	if err := evidence.SetWriterEpoch(dir, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(t, dir, "-fence-epoch", "3"); err != nil {
		t.Fatalf("ResolveEpoch refused a flag matching the marker: %v", err)
	}
}

// And one that disagrees is refused rather than guessed.
//
// The direction that decides it: a marker at 1 with a stray -fence-epoch 2 is a
// writer claiming a promotion that never happened, and the lease would grant it
// — a higher epoch takes the log from whoever legitimately holds it. The lease
// cannot arbitrate what it is being told.
func TestAFlagContradictingTheMarkerIsRefused(t *testing.T) {
	dir := writerDir(t)
	if err := evidence.SetWriterEpoch(dir, 1); err != nil {
		t.Fatal(err)
	}
	_, err := resolve(t, dir, "-fence-epoch", "2")
	if err == nil {
		t.Fatal("a -fence-epoch contradicting the marker was accepted")
	}
	// Both numbers, because an operator who cannot see which two values are in
	// conflict cannot tell which one to change.
	for _, want := range []string{"2", "1", "writer marker"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// With no fence there is no epoch to resolve, and reading the marker to decide
// nothing would make an unfenced deployment fail on an unreadable guard rail.
func TestAnUnfencedWriterResolvesNothing(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := fence.RegisterFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := f.ResolveEpoch("/nonexistent/directory", fs); err != nil {
		t.Fatalf("an unfenced writer tried to resolve an epoch: %v", err)
	}
}

// The recovery path the marker's own documentation promises: a marker that has
// been deleted takes the epoch with it, the writer would resolve 0, and the
// lease would refuse it as a superseded writer. -fence-epoch is the way back,
// and it has to actually work.
//
// The order is what makes this a real case rather than a hypothetical.
// janus-orchd resolves the epoch *before* it opens the directory, because the
// lease is taken at start-up and before anything touches the log. So
// at the moment the flag is read there may be no marker at all, and a
// resolution that insisted on writing one would refuse the start it exists to
// permit — leaving an operator with a daemon the lease refuses and a flag that
// refuses too.
func TestAFlagIsAcceptedWhenTheMarkerIsGone(t *testing.T) {
	dir := writerDir(t)
	if err := os.Remove(filepath.Join(dir, ".janus-writer.json")); err != nil {
		t.Fatal(err)
	}
	f, err := resolve(t, dir, "-fence-epoch", "1")
	if err != nil {
		t.Fatalf("a -fence-epoch against a directory with no marker was refused: %v", err)
	}
	if f.Epoch() != 1 {
		t.Fatalf("resolved epoch %d, want the flag's 1", f.Epoch())
	}
}

// And once the directory is open — which is when a marker exists again — the
// epoch is recorded, so the operator needs the flag once rather than forever.
func TestARecoveredEpochIsRecordedOnceTheDirectoryIsOpen(t *testing.T) {
	dir := writerDir(t)
	if err := os.Remove(filepath.Join(dir, ".janus-writer.json")); err != nil {
		t.Fatal(err)
	}
	f, err := resolve(t, dir, "-fence-epoch", "1")
	if err != nil {
		t.Fatal(err)
	}
	// What janus-orchd does after orchd.New has opened the log.
	reopen(t, dir)
	if err := f.RecordEpoch(dir); err != nil {
		t.Fatalf("RecordEpoch: %v", err)
	}

	again, err := resolve(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Epoch() != 1 {
		t.Fatalf("the next start resolved %d; the recovered epoch was not recorded", again.Epoch())
	}
}
