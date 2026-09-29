package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
)

// TestAGatedSagaPaysSevenBarriersNotNine is the barrier-count fix, end to end.
//
// A gated saga writes nine records — SAGA_BEGIN, DPR, GATE_VERDICT,
// STEP_PREPARE, STEP_RESULT, DPR, GATE_VERDICT, SEAL_REQUEST, COMMIT — and used
// to pay a durability barrier for each. Two of the eight boundaries between
// them have no decision across them: each DPR and the verdict that cites it.
// Those two pairs now share a barrier, so the same nine records cost seven.
//
// The record count is asserted alongside the batch count on purpose. Seven
// barriers would also be what you got by dropping two records, and that would
// be a different and much worse change.
func TestAGatedSagaPaysSevenBarriersNotNine(t *testing.T) {
	policy, err := gate.LoadPolicyFile(filepath.Join("..", "..", "docs", "policy", "reference.json"))
	if err != nil {
		t.Fatalf("load the reference policy: %v", err)
	}
	engine = gate.NewEngine(policy)

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer app.Close()

	w := wire{sagaID: "sg_pair_end_to_end", resource: "acct:0000"}
	if err := engine.Admit(w.Begin()); err != nil {
		t.Fatalf("admit: %v", err)
	}

	index := gate.IndexFromLiveLog(dir, func() uint64 { return app.Stats().LastSeq })
	before := app.Stats()
	if err := drive(context.Background(), app, dir, gate.NewKeeper(index), w); err != nil {
		t.Fatalf("drive: %v", err)
	}
	got := app.Stats()

	if events := got.Events - before.Events; events != 9 {
		t.Fatalf("a gated saga wrote %d records, want the same 9 it always wrote", events)
	}
	if batches := got.Batches - before.Batches; batches != 7 {
		t.Fatalf("a gated saga took %d durability barriers, want 7 "+
			"(9 records, less one for each of the two DPR/verdict pairs)", batches)
	}
}
