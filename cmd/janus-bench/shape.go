package main

import (
	"fmt"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Event shapes.
//
// `steps` is what this tool has always written: one STEP_RESULT, repeated. It
// measures the append path, which is what a throughput benchmark is for, and it
// is deliberately the default — every number in docs/bench was taken at this
// shape and changing it silently would invalidate all of them.
//
// `sagas` exists because that log cannot be read by anything downstream. A
// STEP_RESULT carrying a saga id whose SAGA_BEGIN is nowhere in the log is not a
// saga; `janus-projection rebuild` on such a log fails outright with *saga
// "sg_bench_0007" has no events at or before sequence 0*, and `janus-verify`
// passes it because chain integrity is not saga validity. Anything that needs a
// log a projector can fold — the restore drill's projection phase is the first —
// needs this shape.
const (
	shapeSteps = "steps"
	shapeSagas = "sagas"
)

// sagaRequests builds n events' worth of whole sagas for one producer.
//
// A saga is three events — begin, prepare, result — which is the shortest
// sequence that reaches a sealed one, and therefore the shortest that leaves a
// projection holding a finished row rather than one it is still waiting on.
//
// It runs before the timed loop on purpose. Turning JSON into the protobuf
// payload the log stores costs far more than an append does, and doing it
// inside the loop would make this tool a benchmark of protojson.
//
// A count that is not a multiple of three ends on a partial saga, which is
// correct rather than tolerated: a log being written always has one.
func sagaRequests(producer, n int, part evidence.ParticipantRef) ([]evidence.Request, error) {
	out := make([]evidence.Request, 0, n)
	for s := 0; len(out) < n; s++ {
		id := fmt.Sprintf("sg_bench_%04d_%08d", producer, s)
		events := []saga.FixtureEvent{
			{Kind: "SAGA_BEGIN", Payload: []byte(`{"saga_id":"` + id + `","mode":"supervised",` +
				`"intent":{"intent_id":"in_` + id + `","principal":"pr_bench"},` +
				`"plan":[{"step_id":"st","participant":"ag_bench","action":"a",` +
				`"effect_class":"EFFECT_CLASS_PURE"}]}`)},
			{Kind: "STEP_PREPARE", Payload: []byte(`{"saga_id":"` + id + `","step_id":"st"}`)},
			{Kind: "STEP_RESULT", Payload: []byte(`{"saga_id":"` + id + `","step_id":"st",` +
				`"outcome":{"status":"STATUS_OK"}}`)},
		}
		replayable, err := saga.Fixture{Name: id, Events: events}.Replayable()
		if err != nil {
			return nil, fmt.Errorf("building saga %s: %w", id, err)
		}
		for _, e := range replayable {
			if len(out) == n {
				break
			}
			out = append(out, evidence.Request{
				Kind: e.Kind, SagaID: id, Participant: part, Payload: e.Payload,
			})
		}
	}
	return out, nil
}
