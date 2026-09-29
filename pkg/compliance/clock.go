package compliance

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/clockatt"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// RTS25NonHFTTolerance is the one-second bound RTS 25 sets for activity that is
// not high-frequency trading, and it is what the clock check grades against.
//
// It is read text rather than a chosen number: Commission Delegated Regulation
// (EU) 2017/574 Art. 2(2) requires that business clocks "do not diverge by more
// than one second from UTC" for a voice trading system, a request-for-quote
// system where the response requires human intervention, or one that does not
// allow algorithmic trading.
//
// It is a ceiling, not a default. An attestation now carries the bound its
// deployment declared (`clockatt.Attestation.ToleranceNanos`), and a deployment
// that declared 100 ms is graded against both: the article's second, which it
// cannot relax, and its own figure, which is the claim RTS 25 Art. 4 asks it to
// demonstrate. A declaration looser than a second is itself a finding — Art. 2(2)
// does not permit it, whatever the operator typed.
//
// Attestations written before the tolerance was recorded carry none, and are
// graded against this constant alone. The finding says so rather than leaving a
// reader to assume the stricter figure was the one checked.
const RTS25NonHFTTolerance = time.Second

// ClockTraceability is what a log says about the clock its events were stamped
// by. It is a summary, not the log: the same shape as the tenant binding, which
// is also a fact about the deployment read out of its own evidence.
type ClockTraceability struct {
	// Events counts the events that could carry an attestation reference,
	// which is every event except the attestations themselves — an attestation
	// cannot point at itself, and counting them would make a log of nothing but
	// attestations read as entirely unattested.
	Events int
	// Attested counts those that do carry one.
	Attested int
	// Attestations, Unsynchronised and OutOfTolerance describe the attestation
	// records themselves.
	Attestations   int
	Unsynchronised int
	OutOfTolerance int
	// OutOfDeclared counts synchronised attestations that fell outside the
	// tolerance their own record declares. Graded per attestation rather than
	// per log: an operator who changed -clock-tolerance across restarts writes a
	// log with mixed declarations, and each attestation is answerable for the
	// bound that was in force when it was taken.
	OutOfDeclared int
	// Undeclared counts attestations carrying no declared tolerance at all —
	// every attestation written before the field existed, and any writer that
	// does not record one.
	Undeclared int
	// LooserThanArticle counts attestations declaring a bound wider than
	// RTS25NonHFTTolerance. The declaration itself is the finding: Art. 2(2)
	// sets one second as a maximum, so declaring five is not a laxer compliance
	// posture, it is a non-compliant one.
	LooserThanArticle int
	// WorstOffset is the largest |offset| + uncertainty seen on a synchronised
	// attestation: what the log can actually demonstrate about divergence, as
	// opposed to what was configured.
	WorstOffset time.Duration
	// Declared lists the distinct tolerances the log's attestations declare,
	// ascending, so a finding can name the bound rather than only its verdict.
	Declared []time.Duration
	// Sources names what the clock was checked against, for a finding that can
	// be acted on rather than only disagreed with.
	Sources []string
}

// ClockTraceabilityOf reads an evidence directory and summarises what it can
// demonstrate about the clock.
//
// One pass. The linter already reads this directory for the registry and the
// tenant binding, and this is the same kind of read: a fact about the deployment
// taken from its own evidence rather than from a flag somebody typed.
func ClockTraceabilityOf(dir string) (*ClockTraceability, error) {
	out := &ClockTraceability{}
	seen := map[string]bool{}
	declaredSeen := map[time.Duration]bool{}
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.Kind == evidence.KindClockAttestation {
			out.Attestations++
			var a clockatt.Attestation
			if err := json.Unmarshal(rec.Payload, &a); err != nil {
				return fmt.Errorf("seq %d: decode the clock attestation: %w", h.Seq, err)
			}
			if a.Source != "" && !seen[a.Source] {
				seen[a.Source] = true
				out.Sources = append(out.Sources, a.Source)
			}
			tol, declared := a.DeclaredTolerance()
			switch {
			case !declared:
				out.Undeclared++
			case !declaredSeen[tol]:
				declaredSeen[tol] = true
				out.Declared = append(out.Declared, tol)
			}
			if declared && tol > RTS25NonHFTTolerance {
				out.LooserThanArticle++
			}
			switch {
			case !a.Synchronised:
				// An unreachable source still records an attestation saying so,
				// which is the honest behaviour and is also a demonstrable gap
				// in traceability for the window it covers. It is counted once,
				// here: grading it against a tolerance as well would report the
				// same missing measurement twice under two names.
				out.Unsynchronised++
			default:
				if !a.WithinTolerance(RTS25NonHFTTolerance) {
					out.OutOfTolerance++
				}
				if declared && !a.WithinTolerance(tol) {
					out.OutOfDeclared++
				}
				off := a.Offset()
				if off < 0 {
					off = -off
				}
				if w := off + a.Uncertainty(); w > out.WorstOffset {
					out.WorstOffset = w
				}
			}
			return nil
		}
		out.Events++
		if h.TS.ClockAttestationRef != "" {
			out.Attested++
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(out.Sources)
	sort.Slice(out.Declared, func(i, j int) bool { return out.Declared[i] < out.Declared[j] })
	return out, nil
}
