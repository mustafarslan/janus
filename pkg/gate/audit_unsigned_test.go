package gate_test

import (
	"testing"

	"github.com/mustafarslan/janus/pkg/gate"
)

// TestTheAuditCountsWhatNobodySigned: an audit that reports only the
// signatures that held reads the same for a log where every answer was signed
// and one where none was. Two committed runs of the same protocol over the same
// recorded intakes -- one before caller signatures, one with every participant
// signing -- must say which is which.
func TestTheAuditCountsWhatNobodySigned(t *testing.T) {
	for _, tc := range []struct {
		dir              string
		signed, unsigned int
	}{
		{"../../docs/bench/agentic/2026-09-29T055849Z/evidence", 0, 186},
		{"../../docs/bench/agentic/2026-09-29T075041Z/evidence", 186, 0},
	} {
		rep, err := gate.Audit(tc.dir)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Signed != tc.signed || rep.Unsigned != tc.unsigned {
			t.Fatalf("%s: signed %d, unsigned %d; want %d and %d\n%s",
				tc.dir, rep.Signed, rep.Unsigned, tc.signed, tc.unsigned, rep)
		}
	}
}

// TestAPersonsAnswerWithNoRelayerIsCountedUnsigned: an answer naming only a
// person, which no participant signed as relayer, is vouched for by nobody but
// the daemon -- the other way a record can go unsigned.
func TestAPersonsAnswerWithNoRelayerIsCountedUnsigned(t *testing.T) {
	dir, err := writeApprovedNothing(t, 2)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unsigned != 1 || rep.Signed != 0 {
		t.Fatalf("one unsigned answer from a person with no relayer: signed %d, unsigned %d\n%s",
			rep.Signed, rep.Unsigned, rep)
	}
}
