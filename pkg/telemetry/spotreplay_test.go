package telemetry_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mustafarslan/janus/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// reader installs a manual metric reader and returns a function that collects.
//
// The global meter provider is swapped, which is what `Recorder` reads through.
// Restored on cleanup, because a test that leaves a reader installed makes the
// next one measure this one's gauges.
func reader(t *testing.T) func() (map[string]int64, error) {
	t.Helper()
	rd := metric.NewManualReader()
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(metric.NewMeterProvider(metric.WithReader(rd)))
	t.Cleanup(func() { otel.SetMeterProvider(prev) })

	return func() (map[string]int64, error) {
		t.Helper()
		var rm metricdata.ResourceMetrics
		if err := rd.Collect(context.Background(), &rm); err != nil {
			return nil, err
		}
		out := map[string]int64{}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				g, ok := m.Data.(metricdata.Gauge[int64])
				if !ok {
					continue
				}
				for _, dp := range g.DataPoints {
					out[m.Name] = dp.Value
				}
			}
		}
		return out, nil
	}
}

// collected is reader's result for the cases where an error would be a failure.
func collected(t *testing.T, collect func() (map[string]int64, error)) map[string]int64 {
	t.Helper()
	got, err := collect()
	if err != nil {
		t.Fatalf("collecting: %v", err)
	}
	return got
}

// The sampler's three gauges are read back, and `checked` is the one that says
// it is still looking.
//
// Item 35 registered these and recorded the proof as **UNPROVED**: `pkg/telemetry`
// had no test files at all, so neither these nor the `ProjectionLag` they are
// modelled on was ever observed. A registered gauge nothing reads is the shape
// this project keeps finding — a control that looks present and has never run.
//
// The case that matters is the one the entry names: a sampler that has stopped
// looking reports a perfect rate forever. `diverged` at zero and `agreed` equal
// to `checked` is the same picture whether the sampler checked ten thousand
// sagas or none, so `checked` has to move on its own.
func TestTheSpotReplayGaugesAreObservable(t *testing.T) {
	collect := reader(t)

	var checked, agreed, diverged uint64
	reg, err := telemetry.New("janus-test").SpotReplay("janus-test",
		func(context.Context) (uint64, uint64, uint64, error) {
			return checked, agreed, diverged, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reg.Unregister() }()

	// Nothing checked yet: every gauge present and zero, which is the state an
	// alert on `diverged` alone cannot tell from a healthy one.
	got := collected(t, collect)
	for _, name := range []string{
		"janus.spotreplay.checked", "janus.spotreplay.agreed", "janus.spotreplay.diverged",
	} {
		if v, ok := got[name]; !ok || v != 0 {
			t.Fatalf("%s reads %d (present=%v) before anything ran, want 0 and present: a "+
				"gauge that is registered and never observed is the control this exists "+
				"to avoid being", name, v, ok)
		}
	}

	// One check that agreed. `diverged` has not moved and `checked` has, which
	// is the distinction the entry says a rate alone cannot make.
	checked, agreed = 1, 1
	got = collected(t, collect)
	if got["janus.spotreplay.checked"] != 1 || got["janus.spotreplay.agreed"] != 1 {
		t.Fatalf("after one agreeing check the gauges read checked=%d agreed=%d, want 1 and 1",
			got["janus.spotreplay.checked"], got["janus.spotreplay.agreed"])
	}
	if got["janus.spotreplay.diverged"] != 0 {
		t.Fatalf("diverged reads %d after a check that agreed", got["janus.spotreplay.diverged"])
	}

	// And a divergence reaches the gauge an alarm fires on.
	checked, agreed, diverged = 2, 1, 1
	got = collected(t, collect)
	if got["janus.spotreplay.diverged"] != 1 {
		t.Fatalf("a divergence reads %d at the gauge an integrity alarm fires on",
			got["janus.spotreplay.diverged"])
	}
}

// An observer that fails does not publish a stale number.
//
// The sampler reads a directory, so its observer can fail — and a gauge that
// kept its last value through an error would say "checked 10,000, diverged 0"
// about a sampler that cannot read the log at all. That is the same failure the
// three gauges exist to prevent, one level down.
func TestAFailingObserverPublishesNothingRatherThanAStaleNumber(t *testing.T) {
	collect := reader(t)

	fail := false
	reg, err := telemetry.New("janus-test").SpotReplay("janus-test",
		func(context.Context) (uint64, uint64, uint64, error) {
			if fail {
				return 0, 0, 0, errors.New("the evidence directory is unreadable")
			}
			return 10_000, 10_000, 0, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reg.Unregister() }()

	if got := collected(t, collect); got["janus.spotreplay.checked"] != 10_000 {
		t.Fatalf("checked reads %d, want 10000", got["janus.spotreplay.checked"])
	}

	fail = true
	got, err := collect()
	if err == nil {
		t.Fatalf("a collection whose observer could not read the log succeeded, reporting "+
			"checked=%d diverged=%d: a sampler that has stopped looking reporting a "+
			"perfect rate is exactly what these three exist to make visible",
			got["janus.spotreplay.checked"], got["janus.spotreplay.diverged"])
	}
	if got["janus.spotreplay.checked"] == 10_000 {
		t.Fatalf("the failed collection still published 10,000 checked: %v", err)
	}
}
