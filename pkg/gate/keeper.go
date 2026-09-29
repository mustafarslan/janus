package gate

import (
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Keeper is what the coordinator consults, adapting the engine to
// saga.Gatekeeper.
//
// It is deliberately thin. Everything that decides anything is in Decide, which
// is a pure function; this adds the two things a decision needs from the world
// and cannot compute — the cross-saga index a frontier check reads, and an
// identifier for the provenance record.
type Keeper struct {
	// index supplies the cross-saga view a frontier gate needs. When it is nil
	// a frontier check refuses rather than assuming the resource is clear, so
	// leaving it out is a decision to have no frontier gates rather than a
	// decision to skip them.
	index IndexFunc
}

// IndexFunc supplies the cross-saga index for one subject saga, rebuilt each
// time it is asked for.
//
// It is a function rather than a value because the answer changes: between one
// gate decision and the next, a contending saga may have committed and released
// the resource. Caching would make a step wait on a conflict that had already
// cleared, which is the failure mode that turns a correct safety property into
// something operators route around.
//
// A projection is not that cache, and the difference is worth being precise
// about because the shapes look alike. A cache answers from what it remembers
// and cannot say how old the memory is. A projection carries the sequence it was
// built to, so an implementation can be made to catch up to the head of the log
// before answering and refuse when it cannot — which is a fresh answer obtained
// cheaply, not a stale one served quickly. `projection.Store.FrontierIndex` is
// the implementation that does this.
//
// The subject is passed in because it decides which resources the question is
// even about. An implementation that reads only part of the log needs to know
// what to read, and the subject's own touch list is that scope.
type IndexFunc func(subject saga.State) (*saga.Index, error)

// NewKeeper returns a gatekeeper. Pass nil for index when no policy in use
// carries a frontier gate.
func NewKeeper(index IndexFunc) *Keeper { return &Keeper{index: index} }

// IndexFromLog builds an index by replaying every saga in an evidence
// directory.
//
// This is the slow, unconditionally correct implementation, and it stays. It is
// what a deployment with no projection database uses, and it is the thing a
// projection is checked against — including by the equivalence test that keeps
// `projection.Store.FrontierIndex` honest. "Rebuild it, don't trust it" needs
// something to rebuild from, and this is it.
func IndexFromLog(dir string) IndexFunc { return IndexFromLiveLog(dir, nil) }

// IndexFromLiveLog is IndexFromLog for a reader that shares the directory with
// an appender, which in a running daemon is every reader.
//
// head reports the appender's acknowledged sequence. It is what lets the replay
// read past a record that is half-written rather than refusing the whole
// directory as damaged — and, just as importantly,
// what stops that tolerance from becoming a fail-open answer: a frontier gate
// that silently read a short prefix would report no conflict, which is
// indistinguishable from having found none. The contract is the same one
// the projection keeps, and `projection.FrontierIndex` reads its
// head in the same place for the same reason.
//
// A nil head means there is no appender to ask — an offline tool, a test on a
// closed directory — and the replay keeps the strict behaviour, because a
// reader that cannot name the head has no basis for deciding a tear is benign.
func IndexFromLiveLog(dir string, head func() uint64) IndexFunc {
	return func(saga.State) (*saga.Index, error) {
		var opts []evidence.ReadOption
		if head != nil {
			// Read before the replay, never after: a concurrent append that
			// moved the bar mid-read would make the answer depend on a race.
			opts = append(opts, evidence.AsOf(head()))
		}
		states, err := saga.ReplayAll(dir, opts...)
		if err != nil {
			return nil, err
		}
		ix := saga.NewIndex()
		for _, s := range states {
			ix.Add(s)
		}
		return ix, nil
	}
}

// Decide judges a step at one phase.
func (k *Keeper) Decide(phase janusv1.GatePhase, s saga.State, st *saga.Step,
	declared map[string]saga.FactValue) (*janusv1.GateVerdict, *janusv1.DecisionProvenanceRecord, error) {

	in := Input{Saga: s, Step: st, Declared: declared}

	// The index is built only when a frontier gate is actually due. Replaying
	// every saga in the log is not something to do on the way past.
	if k.index != nil && needsIndex(st, phase) {
		ix, err := k.index(s)
		if err != nil {
			// Refusing here rather than deciding without the index is the
			// fail-closed choice: a frontier check with no index would report
			// no conflicts, which is indistinguishable from having found none.
			return nil, nil, fmt.Errorf("build the cross-saga index a frontier gate needs: %w", err)
		}
		in.Index = ix
	}

	d := Decide(phase, in)
	return d.GateVerdict(""), d.DPR(dprID(s.SagaID, st, phase)), nil
}

func needsIndex(st *saga.Step, phase janusv1.GatePhase) bool {
	for _, r := range saga.GatesFor(st, phase) {
		if r.GetGate() == janusv1.GateType_GATE_TYPE_FRONTIER {
			return true
		}
	}
	return false
}

// dprID names a provenance record descriptively.
//
// The identifier that matters is the event id the appender assigns, which is
// what the verdict's dpr_ref cites and what an auditor follows. This is the
// human-facing label, so it says what was being decided rather than being a
// random string nobody can place.
func dprID(sagaID string, st *saga.Step, phase janusv1.GatePhase) string {
	return fmt.Sprintf("dpr:%s/%s/%s#%d", sagaID, st.ID, shortPhase(phase), st.Attempt+1)
}

func shortPhase(p janusv1.GatePhase) string {
	switch p {
	case janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION:
		return "pre-execution"
	case janusv1.GatePhase_GATE_PHASE_PRE_RELEASE:
		return "pre-release"
	default:
		return "unspecified"
	}
}
