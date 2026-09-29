// Package clockwire connects a clock monitor to an evidence log, for any
// process that writes one.
//
// `pkg/evidence/clockatt` was first wired into `janus-orchd` and stopped there,
// so for as long as the daemon was the only writer anyone thought about, that
// was the whole deployment. It is not. `janus-mcpd` and `janus-a2ad` are the
// interception edges — the records a regulator actually asks about, every tool
// call and every agent-to-agent message — and they own their own evidence
// directories. `janus-tier`, `janus-registry`, `janus-keys` and
// `janus-replicad promote` open a log directly to record an operator act. Every
// one of those events carried no clock attestation reference in a deployment
// whose sagas carried one, and `business_clocks_are_traceable_to_utc` reported
// it as "a clock source is configured, but these events were appended by
// something that does not record the reference".
//
// # Why each writer takes its own attestation
//
// The tempting cheap fix is for a writer to read the log's most recent
// attestation and point at that. It is wrong, and not by a little: an
// attestation measures *the clock of the process that took it*. `janus-tier`
// may run on a different host from `janus-orchd`, so borrowing the daemon's
// attestation would vouch for one machine's timestamp with a measurement of
// another machine's clock. That reads as attested and is not, which is the
// failure mode this project exists to prevent. A staleness bound does not help;
// the problem is *which* clock, not *when*.
//
// # The two shapes
//
// A daemon runs the monitor on a ticker, exactly as `janus-orchd` does: `Start`
// blocks until the first attestation has been taken, so the process never
// serves events with no clock statement at all. A one-shot command calls
// `Attest` once — a CLI that appends a handful of events and exits needs one
// attestation, not a schedule.
//
// Both go through `clockatt.Monitor`, never `Source.Attest` directly, because
// the monitor is what stamps the declared tolerance onto the record. A writer
// that called a source itself would produce attestations declaring nothing and
// would quietly undo half of what the compliance check grades.
package clockwire

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/clockatt"
)

// Config describes how one process attests its clock.
type Config struct {
	// Sources are the time sources, tried in order. Empty means this process
	// takes no attestation and says so by omitting the reference: an
	// opt-in, kept because the design asks for an air-gapped install with no
	// mandatory external dependency, and a default pointing at a public NTP
	// server would put one in the write path of every deployment that never
	// thought about it.
	Sources []clockatt.Source
	// Interval between attestations, for a process that runs the loop. Ignored
	// by Attest. Zero means the monitor's five minutes.
	Interval time.Duration
	// Tolerance is the synchronisation bound this deployment claims to hold. It
	// is recorded in every attestation, so a reader can check the figure that
	// was claimed rather than only the article's ceiling. Zero means one second.
	Tolerance time.Duration
	// Participant is who the attestation records as having appended it. Every
	// record says who wrote it, and an attestation is an ordinary record.
	Participant evidence.ParticipantRef
	// OnBreach is called when the clock leaves the declared tolerance. Nil logs
	// a line, which is what a breach deserves and no more: refusing to append on
	// a clock breach would turn a time-source outage into an evidence-write
	// outage.
	OnBreach func(clockatt.Attestation)
}

// Clock is one process's clock attestation, wired to its evidence log.
//
// The zero value is not usable; New builds one. A Clock with no sources is
// usable and does nothing, so a caller never branches on whether attestation is
// configured — the branch is where the reference is omitted, which is the same
// place it has always been.
type Clock struct {
	monitor *clockatt.Monitor

	mu  sync.Mutex
	app *evidence.Appender

	// sources and tolerance are kept for the declaration left in the writer
	// marker: the monitor holds them too, but as its own configuration rather
	// than as something to report.
	sources   []clockatt.Source
	tolerance time.Duration

	ready     sync.Once
	readyCh   chan struct{}
	stop      context.CancelFunc
	done      chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
}

// New builds a Clock. No sources is not an error: it is a deployment that chose
// not to attest, and the resulting Clock records nothing and refers to nothing.
func New(cfg Config) (*Clock, error) {
	c := &Clock{readyCh: make(chan struct{}), sources: cfg.Sources, tolerance: cfg.Tolerance}
	if len(cfg.Sources) == 0 {
		return c, nil
	}

	onBreach := cfg.OnBreach
	if onBreach == nil {
		onBreach = func(a clockatt.Attestation) {
			log.Printf("clock outside the declared tolerance: %s", a.Summary())
		}
	}

	m, err := clockatt.New(clockatt.Config{
		Sources:   cfg.Sources,
		Interval:  cfg.Interval,
		Tolerance: cfg.Tolerance,
		OnAttestation: func(a clockatt.Attestation) {
			// Signalled whatever happens below: the clock has been checked,
			// which is what a starting process is waiting to know. Signalling
			// only on success would hang a daemon whose time source is down.
			defer c.ready.Do(func() { close(c.readyCh) })

			ref, err := c.record(cfg.Participant, a)
			if err != nil {
				// Logged, not fatal, and the reference deliberately not
				// advanced: the next append then points at the last attestation
				// that is actually in the log rather than at one that is not.
				log.Printf("clockwire: recording a clock attestation: %v", err)
				return
			}
			c.monitor.SetRef(ref)
		},
		OnBreach: onBreach,
	})
	if err != nil {
		return nil, fmt.Errorf("clockwire: %w", err)
	}
	c.monitor = m
	return c, nil
}

// Enabled reports whether this process attests its clock at all, so a caller can
// say out loud that it does not.
//
// Said out loud rather than left to be inferred from an absent field in the log:
// a deployment that meant to attest and mistyped the flag would otherwise look
// identical to one that chose not to.
func (c *Clock) Enabled() bool { return c != nil && c.monitor != nil }

// Ref is what an appender is given as Options.ClockAttestationRef. It answers
// the empty string until the first attestation has been recorded, and forever if
// this process takes none.
//
// It is a method value rather than a closure at the call site because the
// appender has to be handed something before the first attestation exists: the
// cycle — the appender needs the reference, the attestation needs the appender —
// is broken by both sides being lazy.
func (c *Clock) Ref() string {
	if !c.Enabled() {
		return ""
	}
	return c.monitor.Ref()
}

// Bind names the appender the attestations are written to. It is called after
// the appender is open, which is after Ref has already been handed to it.
func (c *Clock) Bind(app *evidence.Appender) {
	c.mu.Lock()
	c.app = app
	c.mu.Unlock()

	// And leave the hint behind. A writer that attests states what it attests
	// against in the directory's node-local marker, so a later process given no
	// `-clock-sources` can tell an operator which kind of deployment this is
	// rather than repeating the same sentence at both of them.
	// Nothing reads it to configure itself — see the field's own comment.
	if !c.Enabled() {
		return
	}
	names := make([]string, 0, len(c.sources))
	for _, s := range c.sources {
		names = append(names, s.Name())
	}
	if err := evidence.SetWriterClockDeclaration(app.Dir(), names, c.tolerance); err != nil {
		log.Printf("clockwire: recording the clock declaration in the writer marker: %v", err)
	}
}

// Attest takes and records one attestation now, and is what a one-shot command
// uses: a process that appends a handful of events and exits needs a statement
// about its clock, not a schedule.
//
// It returns the attestation so a caller can report it. An unreachable source is
// not an error here — it produces an attestation saying so, which is the record
// an auditor can act on.
func (c *Clock) Attest(ctx context.Context) (clockatt.Attestation, bool) {
	if !c.Enabled() {
		return clockatt.Attestation{}, false
	}
	return c.monitor.Attest(ctx), true
}

// Start runs the attestation loop and does not return until the first
// attestation has been taken.
//
// Starting it and returning would race every append made in the process's first
// few hundred milliseconds, and those appends would silently carry no
// reference — the exact failure this wiring exists to remove, reintroduced at a
// smaller scale.
//
// It waits for the attestation to have been *taken*, not to have been recorded
// successfully. An unreachable time source still produces an attestation saying
// so, and a daemon that refused to start because NTP was down would have turned
// a clock problem into an outage.
func (c *Clock) Start(ctx context.Context) {
	if !c.Enabled() {
		return
	}
	c.startOnce.Do(func() {
		runCtx, cancel := context.WithCancel(ctx)
		c.stop = cancel
		c.done = make(chan struct{})
		go func() {
			defer close(c.done)
			c.monitor.Run(runCtx)
		}()
	})
	<-c.readyCh
}

// Stop ends the loop and waits for it. It is safe to call without Start, and
// safe to call twice, because a daemon's shutdown path is where a second close
// is most likely to be written by accident.
//
// **Call it before closing the appender.** A tick that fires after the appender
// is closed is refused with ErrClosed rather than lost, so nothing is corrupted
// — but the process then logs a failure it caused itself, which is a shutdown
// somebody has to investigate. With defers that means registering this one
// *after* the appender's close, because defers run last-registered-first.
func (c *Clock) Stop() {
	if !c.Enabled() || c.stop == nil {
		return
	}
	c.stopOnce.Do(func() {
		c.stop()
		<-c.done
	})
}

// record appends one attestation and returns its evidence reference.
//
// The attestation is an ordinary event — chained, signed with the segment, and
// verifiable by the same reader — because a claim about the clock that was not
// itself evidence would be a footnote rather than a record.
//
// Like every other event it is stamped with whatever reference is current when
// its batch is chained, so the first attestation carries none and later ones
// point at their predecessor. That is the appender's uniform behaviour and it is
// left alone: exempting a kind would be machinery bought to preserve a tidier
// sentence.
func (c *Clock) record(by evidence.ParticipantRef, a clockatt.Attestation) (string, error) {
	c.mu.Lock()
	app := c.app
	c.mu.Unlock()
	if app == nil {
		return "", fmt.Errorf("no appender: an attestation with nowhere to go is not a record")
	}
	payload, err := a.Payload()
	if err != nil {
		return "", fmt.Errorf("render the attestation: %w", err)
	}
	ref, err := app.Append(context.Background(), evidence.Request{
		Kind:        evidence.KindClockAttestation,
		Participant: by,
		Payload:     payload,
	})
	if err != nil {
		return "", err
	}
	return ref.EventID, nil
}

// Open is the one-shot form: it wires a clock to an appender, opens the log,
// takes one attestation and records it, so the events the caller goes on to
// append point at a statement about *this* process's clock.
//
// It exists because the ordering is the subtle part and there are five commands
// that need it. The reference has to be handed to the appender before the
// appender exists, the appender has to be bound before the first attestation is
// recorded, and the attestation has to land before the first real event — get
// any of the three wrong and the events carry no reference while an attestation
// sits in the log beside them, which is precisely the state this is fixing.
//
// `opts.ClockAttestationRef` is set here and anything the caller put there is
// replaced; there is only one right answer and it is this clock's.
func Open(ctx context.Context, cfg Config, opts evidence.Options) (*evidence.Appender, *Clock, error) {
	c, err := New(cfg)
	if err != nil {
		return nil, nil, err
	}
	opts.ClockAttestationRef = c.Ref
	app, err := evidence.Open(opts)
	if err != nil {
		return nil, nil, err
	}
	c.Bind(app)
	// Recorded before the caller appends anything. A failure to record is
	// already handled inside the callback — logged, with the reference not
	// advanced — so a command whose time source is down still runs and its
	// events still say honestly that they point at nothing.
	c.Attest(ctx)
	return app, c, nil
}
