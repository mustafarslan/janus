package replica_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/replica"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// A follower's idle poll: nothing new to copy, so the whole cost is asking.
//
// This is the tightest of the idle-polling loops — three
// times a second by default, forever — and it lists the directory twice per
// poll, once in verifySeals and once inside the verify.Range it calls.
func BenchmarkIdleFollowerPoll(b *testing.B) {
	for _, events := range []int{4000, 40000} {
		signer, err := keys.Generate()
		if err != nil {
			b.Fatal(err)
		}
		dir := filepath.Join(b.TempDir(), fmt.Sprintf("evidence%d", events))
		a, err := evidence.Open(evidence.Options{
			Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 4096,
		})
		if err != nil {
			b.Fatal(err)
		}
		for i := range events {
			if _, err := a.Append(context.Background(), evidence.Request{
				Kind: evidence.KindStepResult, SagaID: "sg", StepID: fmt.Sprint(i),
				Participant: evidence.ParticipantRef{ID: "ag"},
				Payload:     fmt.Appendf(nil, `{"i":%d,"p":"%0100d"}`, i, i),
			}); err != nil {
				b.Fatal(err)
			}
		}
		mirror := filepath.Join(b.TempDir(), fmt.Sprintf("mirror%d", events))
		f, err := replica.New(replica.Options{
			Dir: mirror, Source: replica.FromAppender(dir, a),
			Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()},
		})
		if err != nil {
			b.Fatal(err)
		}
		if err := f.Follow(context.Background()); err != nil {
			b.Fatal(err)
		}
		ids, _ := segment.ScanComplete(mirror)
		b.Run(fmt.Sprintf("segments=%d", len(ids)), func(b *testing.B) {
			for b.Loop() {
				if err := f.Follow(context.Background()); err != nil {
					b.Fatal(err)
				}
			}
		})
		if err := a.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
