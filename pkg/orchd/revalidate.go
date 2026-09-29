package orchd

import (
	"context"
	"log"
	"time"

	"github.com/mustafarslan/janus/pkg/registry"
)

// Scheduling the periodic revalidations a manifest asks for.
//
// A manifest may declare `periodic` as a revalidation trigger, and the registry
// already refuses to activate a version that owes one. What was missing was the
// process that notices a review has come due — and it is the same gap gate
// timeouts had: nothing loops, so nothing sees a calendar pass. The daemon's ticker is
// the only thing that wakes up on its own and owns the log.
//
// # This is a daemon capability, like the gate expiry
//
// A deployment with no `janus-orchd` gets no scheduled revalidation. Its
// versions stay in whatever standing they were last put in, which is the
// behaviour before this existed and is fail-open in a way worth naming: an
// evaluation that is quietly two years old reads exactly like a fresh one. That
// asymmetry is stated here rather than left for somebody to discover.
//
// # The clock is read once, and the decision is written down
//
// Same rule as gate expiry. `Cadence.Due` compares two recorded times and reads no
// clock of its own, so a scheduler and an auditor reading the same log reach the
// same answer about whether a version was in good standing.

// requireDueRevalidations appends a REVALIDATION_REQUIRED for every active
// version whose periodic review has come due.
func (s *Server) requireDueRevalidations(ctx context.Context) {
	if s.cadence == nil {
		return
	}
	reg, err := s.registryNow(ctx)
	if err != nil {
		log.Printf("orchd: could not read the registry to schedule revalidations: %v", err)
		return
	}

	// A recorder over the registry as it was just folded, rather than one held
	// across ticks. The fold is the state this decision is made against, and a
	// recorder carrying an older one would validate the transition against a
	// registry that has since moved.
	//
	// No trust store: this path records a debt against a version already in the
	// log and registers nothing, so there is no signature for one to check.
	rec := registry.NewRecorder(s.app, s.participant, reg, nil)

	now := time.Now().UTC()
	for _, e := range reg.Due(s.cadence, now) {
		// One reason string, built from the recorded anchor rather than from
		// the clock, so the record says what made it due rather than when
		// somebody happened to look.
		reason := "periodic review came due: the last evaluation was recorded " +
			e.ValidatedAt.Format(time.RFC3339)
		if err := rec.RequireRevalidation(ctx,
			e.Manifest.Identity.ParticipantID, e.Manifest.Version,
			[]string{registry.TriggerPeriodic}, reason); err != nil {
			// Logged and carried on, the same trade expireDueGates makes: one
			// version whose debt could not be recorded must not stop the rest
			// being looked at.
			log.Printf("orchd: requiring revalidation of %s@%s: %v",
				e.Manifest.Identity.ParticipantID, e.Manifest.Version, err)
		}
		// The registry moved; the signing checks must not read the old one.
		s.forgetRegistry()
	}
}
