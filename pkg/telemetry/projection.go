package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// ProjectionLag reports how far a projection is behind the log it is folded
// from.
//
// Three instruments rather than two. A dashboard could subtract the sequences
// itself, and the number an operator actually needs is the difference — so it is
// emitted directly. The reason: an alert that makes somebody
// subtract two numbers to find out whether the projection has stopped is an
// alert that will be misread at three in the morning.
//
// The sequences are emitted as well because the difference alone cannot
// distinguish "folding steadily, one event behind" from "stopped at sequence
// 40,000 while the log ran on" — the first is healthy and the second is the
// failure this exists to catch, and they look identical on a lag graph if the
// log has also stopped.
//
// Like every other measurement in this package: **this is not evidence.** It is
// sampled, it is dropped when nothing is collecting, and when it disagrees with
// the log the log is right. Nothing may decide anything from it — the frontier
// gate and admission read the projection's own `last_event_seq` and refuse for
// themselves.
//
// Observe is called by the metric SDK when something scrapes, so it must be
// cheap and must not block on a fold. Returning an error from it leaves the
// instruments unreported for that collection rather than failing the process: a
// database that cannot be read is exactly when the operator most needs the rest
// of the daemon to carry on.
// The returned Registration must be unregistered when the reporter goes away.
// The instruments are registered on the global meter under fixed names, so a
// process that started two daemons — a test, most often — would otherwise have
// two callbacks answering for one gauge, and the readings would alternate
// between them.
func (r *Recorder) ProjectionLag(name string,
	observe func(context.Context) (projected, head uint64, err error)) (metric.Registration, error) {

	meter := otel.Meter(name)
	projected, err := meter.Int64ObservableGauge("janus.projection.last_event_seq",
		metric.WithDescription("the evidence sequence the projection has folded to"))
	if err != nil {
		return nil, fmt.Errorf("telemetry: projection sequence gauge: %w", err)
	}
	head, err := meter.Int64ObservableGauge("janus.log.last_event_seq",
		metric.WithDescription("the evidence sequence the log stands at"))
	if err != nil {
		return nil, fmt.Errorf("telemetry: log sequence gauge: %w", err)
	}
	lag, err := meter.Int64ObservableGauge("janus.projection.lag_events",
		metric.WithDescription("how many events the projection is behind the log"))
	if err != nil {
		return nil, fmt.Errorf("telemetry: projection lag gauge: %w", err)
	}

	reg, err := meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		p, h, err := observe(ctx)
		if err != nil {
			// Reported as a failed collection, not as a zero. A gauge that read
			// zero because the database was unreachable would look exactly like
			// a projection that had caught up.
			return err
		}
		o.ObserveInt64(projected, int64(p))
		o.ObserveInt64(head, int64(h))
		var behind int64
		if h > p {
			behind = int64(h - p)
		}
		o.ObserveInt64(lag, behind)
		return nil
	}, projected, head, lag)
	if err != nil {
		return nil, fmt.Errorf("telemetry: register the projection lag callback: %w", err)
	}
	return reg, nil
}

// SpotReplay reports what the determinism sampler has found.
//
// Three counts, and the third is the one an alert fires on. Checked and agreed
// are emitted as well because a rate alone cannot distinguish "nothing has
// diverged" from "nothing has been checked" — and a sampler that has stopped
// looking reports a perfect rate forever, which is the failure mode this exists
// to make visible.
//
// The same rule as everything else here: **this is not evidence.** A divergence
// is an integrity alarm and the daemon that found it printed the saga id and the
// check that failed; this is the number that makes somebody go and read that.
func (r *Recorder) SpotReplay(name string,
	observe func(context.Context) (checked, agreed, diverged uint64, err error)) (metric.Registration, error) {

	meter := otel.Meter(name)
	checked, err := meter.Int64ObservableGauge("janus.spotreplay.checked",
		metric.WithDescription("completed sagas re-derived and compared with the log"))
	if err != nil {
		return nil, fmt.Errorf("telemetry: spot-replay checked gauge: %w", err)
	}
	agreed, err := meter.Int64ObservableGauge("janus.spotreplay.agreed",
		metric.WithDescription("those that replayed to what the log says they did"))
	if err != nil {
		return nil, fmt.Errorf("telemetry: spot-replay agreed gauge: %w", err)
	}
	diverged, err := meter.Int64ObservableGauge("janus.spotreplay.diverged",
		metric.WithDescription("those that did not; any value above zero is an integrity alarm"))
	if err != nil {
		return nil, fmt.Errorf("telemetry: spot-replay diverged gauge: %w", err)
	}

	reg, err := meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		c, a, d, err := observe(ctx)
		if err != nil {
			return err
		}
		o.ObserveInt64(checked, int64(c))
		o.ObserveInt64(agreed, int64(a))
		o.ObserveInt64(diverged, int64(d))
		return nil
	}, checked, agreed, diverged)
	if err != nil {
		return nil, fmt.Errorf("telemetry: register the spot-replay callback: %w", err)
	}
	return reg, nil
}
