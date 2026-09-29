package main

import (
	"fmt"

	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/saga"
)

// auditFindsForgedRelease asks pkg/outbox's audit the question an auditor would:
// given only this directory, was any irreversible effect released without a
// commit that authorised it?
//
// Folded from the log rather than from a running process's memory, which is the
// whole point of the audit existing separately from the release path — a check
// performed at the time is a claim about a process that has since exited.
func auditFindsForgedRelease(dir string) (bool, string) {
	state, err := outbox.Load(dir)
	if err != nil {
		return false, "could not load the outbox: " + err.Error()
	}
	sagas, err := saga.ReplayAll(dir)
	if err != nil {
		// A forged record that makes the log unreplayable is itself a detection:
		// the adversary wanted a plausible history and produced one nothing can
		// read.
		return true, "the log no longer replays: " + err.Error()
	}
	findings := outbox.Audit(state, sagas)
	for _, f := range findings {
		if f.Critical {
			return true, fmt.Sprintf("effect %s (saga %s): %s", f.EffectID, f.SagaID, f.Detail)
		}
	}
	if len(findings) > 0 {
		return true, fmt.Sprintf("effect %s (saga %s): %s",
			findings[0].EffectID, findings[0].SagaID, findings[0].Detail)
	}
	return false, fmt.Sprintf("the audit returned no findings over %d effect(s)", len(state.Order))
}
