package main

import (
	"strings"
	"testing"
)

// TestAConcurrencyColumnDescribesWhatWasMeasured pins the refusal that a real
// sweep needed and did not have.
//
// The case that motivated it: -samples 300 -concurrency 1024 ran 300 drivers in
// one burst, reported them under a column saying 1024, and produced a plausible
// "16x the concurrency costs 2.4x the latency". Nothing in the output said
// otherwise; the only tell was the fold count collapsing from 10 to 2.
func TestAConcurrencyColumnDescribesWhatWasMeasured(t *testing.T) {
	for _, tc := range []struct {
		name          string
		conc, samples int
		refused       bool
		says          string
	}{
		{"the sweep that produced the artifact", 1024, 300, true, "724 of the 1024 slots"},
		{"more samples than slots, but too few rounds", 256, 300, true, "1.17 times each"},
		{"exactly the floor", 64, 192, false, ""},
		{"one under the floor", 64, 191, true, "2.98 times each"},
		{"the phase 6 gate's own configuration", 64, 300, false, ""},
		{"the Makefile default's widest point", 8, 300, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sustained(tc.conc, tc.samples)
			if tc.refused && err == nil {
				t.Fatalf("sustained(%d, %d) allowed a run measuring %d drivers "+
					"under a column saying %d", tc.conc, tc.samples,
					min(tc.samples, tc.conc), tc.conc)
			}
			if !tc.refused {
				if err != nil {
					t.Fatalf("sustained(%d, %d) refused a configuration that is "+
						"already in use: %v", tc.conc, tc.samples, err)
				}
				return
			}
			// The refusal has to name the shape, not just say no: an operator
			// who cannot tell which of the two failures they hit cannot tell
			// whether raising -samples or lowering -concurrency is the fix.
			if tc.says != "" && !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("refusal did not name the shape.\n got: %v\nwant substring: %q",
					err, tc.says)
			}
			if !strings.Contains(err.Error(), "-samples") {
				t.Fatalf("refusal does not say what to pass instead: %v", err)
			}
		})
	}
}
