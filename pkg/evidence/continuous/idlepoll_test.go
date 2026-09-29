package continuous_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/continuous"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// The cost of one idle round: nothing new to verify, so the whole cost is
// asking. This is the soak's round.
func BenchmarkIdleIncremental(b *testing.B) {
	const segBytes = int64(4096)
	{
		for _, events := range []int{4000, 40000} {
			dir, signer := benchLog(b, events, segBytes)
			ids, _ := segment.ScanComplete(dir)
			v, err := continuous.New(continuous.Config{
				Dir: dir, Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()},
			})
			if err != nil {
				b.Fatal(err)
			}
			if _, err := v.Incremental(context.Background()); err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("segments=%d", len(ids)), func(b *testing.B) {
				for b.Loop() {
					if _, err := v.Incremental(context.Background()); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func benchLog(b *testing.B, events int, segBytes int64) (string, *keys.Signer) {
	b.Helper()
	signer, err := keys.Generate()
	if err != nil {
		b.Fatal(err)
	}
	dir := b.TempDir() + "/evidence"
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: segBytes,
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
	if err := a.Close(); err != nil {
		b.Fatal(err)
	}
	return dir, signer
}
