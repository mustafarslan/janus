package projection_test

import (
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/saga"
)

// TestFrontierAgreesAtEveryInterruptionPoint is the safety property stated the
// way it will actually be met in production: a coordinator asks a frontier
// question at an arbitrary moment, against a projection that was last folded at
// whatever point the previous interruption left it, and must get the answer the
// log supports.
//
// Each step of the loop appends a random slice of a contending history, folds it
// with a *brand new* projector -- a restart, with the in-memory working set gone
// and only `last_event_seq` to resume from -- and then compares the frontier
// answer for every saga against `IndexFromLog` on the same directory. Both sides
// are asked at the same point in the log, so any disagreement is the projection
// being wrong rather than the two being asked different questions.
//
// This is the shape of `make sagachaos-hosted` applied to one component: not
// "does the fold work" but "is every intermediate state a coordinator could
// observe a state in which the gate still decides correctly". The seed is fixed
// so a failure is reproducible; change it and rerun to widen the search.
func TestFrontierAgreesAtEveryInterruptionPoint(t *testing.T) {
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

	// A history in which sagas genuinely compete, laid out as one flat list of
	// events so an interruption can fall anywhere -- including between a saga's
	// touch and its commit, which is the window in which a contender is
	// unsettled and must block.
	type pending struct {
		id     string
		events []saga.FixtureEvent
	}
	var flat []pending
	for _, c := range []contender{
		{id: "cx-a1", resource: "acct:A", write: true, end: "commit"},
		{id: "cx-b1", resource: "acct:B", write: true},
		{id: "cx-a2", resource: "acct:A", write: true},
		{id: "cx-b2", resource: "acct:B", write: true, end: "quarantine"},
		{id: "cx-c1", resource: "acct:C", write: true},
		{id: "cx-a3", resource: "acct:A", write: true, end: "compensate"},
		{id: "cx-c2", resource: "acct:C", write: false},
		{id: "cx-b3", resource: "acct:B", write: true},
	} {
		for _, e := range contenderEvents(t, c) {
			flat = append(flat, pending{id: c.id, events: []saga.FixtureEvent{e}})
		}
	}

	rng := rand.New(rand.NewSource(20260829))
	fromLog := gate.IndexFromLog(dir)

	checks, disagreements := 0, 0
	for i := 0; i < len(flat); {
		// An interruption falls after a random number of events, so the fold
		// boundary lands mid-saga as often as not.
		n := 1 + rng.Intn(4)
		if i+n > len(flat) {
			n = len(flat) - i
		}
		for _, pe := range flat[i : i+n] {
			appendEvents(t, app, pe.id, pe.events)
		}
		i += n

		head, err := projection.NewProjector(store, dir).CatchUp(ctx)
		if err != nil {
			t.Fatalf("fold after %d events: %v", i, err)
		}

		states, err := saga.ReplayAll(dir)
		if err != nil {
			t.Fatal(err)
		}
		for id, subject := range states {
			whole, err := fromLog(subject)
			if err != nil {
				t.Fatal(err)
			}
			scoped, err := store.FrontierIndex(ctx, subject, head)
			if err != nil {
				t.Fatalf("after %d events, saga %s: %v", i, id, err)
			}
			want, got := describeBlockers(whole.Blockers(id)), describeBlockers(scoped.Blockers(id))
			if want != got {
				disagreements++
				t.Errorf("after %d events, saga %s:\n  whole log:  %s\n  projection: %s",
					i, id, want, got)
			}
			if len(whole.Blockers(id)) > 0 {
				checks++
			}
		}
	}

	if checks == 0 {
		t.Fatal("no interruption point produced a blocked saga, so this compared empty answers")
	}
	t.Logf("agreed at every interruption point; %d of the comparisons had blockers, %d disagreed",
		checks, disagreements)
}
