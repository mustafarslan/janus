package evidence_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// openAt opens a directory as a writer and closes it again, which is what a
// daemon restart does to the marker.
func openAt(t *testing.T, dir string) {
	t.Helper()
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: mustSigner(t), SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindStepResult, SagaID: "sg_epoch", StepID: "st",
		Participant: evidence.ParticipantRef{ID: "ag_epoch"},
		Payload:     []byte(`{}`),
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// The epoch survives the next open, and this is the whole reason the field is
// not simply rewritten like the rest of the marker.
//
// evidence.Open stamps the marker on every start. A promoted directory's epoch
// written by `janus-replicad promote` and then dropped by the first
// janus-orchd start would be gone at exactly the moment it is needed: the
// daemon would resolve 0, the lease would say the log has moved to 1, and a
// legitimate start would be refused as if it were the old primary coming back.
func TestAPromotedDirectoryRemembersItsEpochAcrossRestarts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	openAt(t, dir)

	if err := evidence.SetWriterEpoch(dir, 1); err != nil {
		t.Fatalf("SetWriterEpoch: %v", err)
	}

	for i := range 3 {
		openAt(t, dir)
		epoch, marked, err := evidence.WriterEpoch(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !marked || epoch != 1 {
			t.Fatalf("after restart %d the marker says epoch %d (recorded %v), want 1 recorded",
				i+1, epoch, marked)
		}
	}
}

// A directory nobody promoted serves the original writer's epoch, and says so
// as "not recorded" rather than as a zero somebody might read as an answer.
func TestADirectoryNobodyPromotedHasNoEpoch(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	openAt(t, dir)

	epoch, marked, err := evidence.WriterEpoch(dir)
	if err != nil {
		t.Fatal(err)
	}
	if marked || epoch != 0 {
		t.Fatalf("an unpromoted directory reports epoch %d (recorded %v), want 0 not recorded",
			epoch, marked)
	}
}

// There is nothing to record an epoch against until an appender has owned the
// directory, and saying so beats writing a marker that claims one has.
func TestAnEpochNeedsADirectoryAWriterOwns(t *testing.T) {
	dir := t.TempDir()
	if err := evidence.SetWriterEpoch(dir, 1); err == nil {
		t.Fatal("SetWriterEpoch accepted a directory with no writer marker")
	}
}
