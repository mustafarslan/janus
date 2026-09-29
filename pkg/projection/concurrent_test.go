package projection_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/registry"
)

// TestAFoldDoesNotDisturbAReaderHoldingASnapshot.
//
// `registry.Registry` hands out pointers into its own state and has no deep
// copy, so a projector that applied an event to a registry a reader already
// held would change what that reader was in the middle of reading. The
// projector refolds into a fresh Registry and swaps the pointer instead — which
// is an argument until something runs it under the race detector with a reader
// actually holding one.
//
// The CI job runs this package with -race, which is what makes this test worth
// having; without that flag it asserts very little.
func TestAFoldDoesNotDisturbAReaderHoldingASnapshot(t *testing.T) {
	store, ctx := newStore(t)

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "ag_operator", Principal: "pr_bank", Kind: "AGENT", ManifestVersion: "1.0.0",
	}, registry.New(), trust)

	proj := projection.NewProjector(store, dir)

	// One registration up front, so the reader has something to read from its
	// very first pass rather than racing an empty registry.
	m := testManifest("tool_0", "1.0.0", "COMPENSABLE")
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Register(ctx, m, sig); err != nil {
		t.Fatal(err)
	}
	if _, err := proj.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Zero required sequence: this reader is deliberately not asserting
			// freshness. What it is testing is that walking a snapshot while a
			// fold replaces it is safe, and requiring the head would just make
			// it wait for the writer.
			reg, err := proj.Registry(context.Background(), 0)
			if err != nil {
				continue
			}
			for _, pid := range reg.Participants() {
				for _, e := range reg.Versions(pid) {
					_ = e.State
					if e.Manifest != nil {
						_ = len(e.Manifest.Actions)
					}
				}
			}
		}
	}()

	for i := 1; i <= 12; i++ {
		mi := testManifest("tool_"+string(rune('a'+i)), "1.0.0", "COMPENSABLE")
		si, err := registry.Sign(mi, signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rec.Register(ctx, mi, si); err != nil {
			t.Fatal(err)
		}
		if err := rec.Evaluate(ctx, mi.Identity.ParticipantID, mi.Version,
			&janusv1.EvaluationReport{
				Passed: true, HarnessVersion: "test", Sandbox: "double",
				TriggersCovered: mi.Risk.RevalidationTriggers,
			}); err != nil {
			t.Fatal(err)
		}
		if err := rec.Activate(ctx, mi.Identity.ParticipantID, mi.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := proj.CatchUp(ctx); err != nil {
			t.Fatalf("fold %d: %v", i, err)
		}
	}

	close(stop)
	wg.Wait()

	// And the end state is still right, so this was not safe by virtue of doing
	// nothing.
	fromLog, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	head, err := proj.CatchUp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fromProjection, err := proj.Registry(ctx, head)
	if err != nil {
		t.Fatal(err)
	}
	if want, got := describeRegistry(t, fromLog), describeRegistry(t, fromProjection); want != got {
		t.Errorf("after concurrent reads the projected registry differs from the log's.\n"+
			"--- log ---\n%s\n--- projection ---\n%s", want, got)
	}
	if len(fromLog.Participants()) < 13 {
		t.Fatalf("only %d participants were registered; the reader had little to race with",
			len(fromLog.Participants()))
	}
}
