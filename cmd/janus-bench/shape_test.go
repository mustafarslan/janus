package main

import (
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// TestTheSagaShapeWritesSagasSomethingCanFold.
//
// The default shape writes a STEP_RESULT whose SAGA_BEGIN is nowhere in the
// log. That is fine for measuring appends and it is not a saga: `janus-projection
// rebuild` on such a log fails with *saga "sg_bench_0007" has no events at or
// before sequence 0*, which is how timing a rebuild
// found out that the restore drill's log could not be folded at all.
//
// So the claim to hold is not "the shape flag produces different bytes" — it is
// that what it produces replays. `saga.Replay` is the same state machine the
// projector folds with, which is what makes this the right check and not a
// restatement of the generator.
func TestTheSagaShapeWritesSagasSomethingCanFold(t *testing.T) {
	// Two whole sagas and one event of a third: a log being written always ends
	// mid-saga, and a generator that only ever emits whole ones would hide the
	// case a projector has to handle.
	const eventsPerSaga = 3
	const want = 2*eventsPerSaga + 1

	part := evidence.ParticipantRef{ID: "ag_bench", ManifestVersion: "1.0.0", Principal: "pr_bench"}
	reqs, err := sagaRequests(3, want, part)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != want {
		t.Fatalf("asked for %d events and got %d", want, len(reqs))
	}

	// Grouped the way a projector groups them: by saga id, in log order.
	bySaga := map[string][]saga.Event{}
	var order []string
	for i, r := range reqs {
		if _, seen := bySaga[r.SagaID]; !seen {
			order = append(order, r.SagaID)
		}
		bySaga[r.SagaID] = append(bySaga[r.SagaID], saga.Event{
			Seq: uint64(i + 1), Kind: r.Kind, Payload: r.Payload,
		})
	}
	if len(order) != 3 {
		t.Fatalf("%d events at %d per saga should be 3 sagas, got %d: %v",
			want, eventsPerSaga, len(order), order)
	}

	for i, id := range order {
		st, err := saga.Replay(bySaga[id])
		if err != nil {
			t.Fatalf("saga %s does not replay: %v", id, err)
		}
		if st.SagaID != id {
			t.Errorf("saga %s replayed to id %q", id, st.SagaID)
		}
		if i < 2 && len(st.Steps) == 0 {
			t.Errorf("whole saga %s replayed with no steps, so a projection would keep no step rows", id)
		}
	}
}
