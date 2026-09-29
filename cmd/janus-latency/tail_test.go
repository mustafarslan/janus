package main

import "testing"

// The tail summary's percentiles are reported as computed, and p99 is the
// one the argument turns on: a design for not waiting on a fold has to
// survive the decision that arrives just before a fold completes, not the one
// that arrives just after. A percentile that is off by one position reports a
// different number into a document that reads as measured.
func TestTheTailSummaryReportsThePercentileItNames(t *testing.T) {
	for _, tc := range []struct {
		name                string
		in                  []uint64
		count               int
		mean, p50, p99, max float64
	}{
		{"nothing observed", nil, 0, 0, 0, 0, 0},
		{"one observation is every percentile of itself", []uint64{7}, 1, 7, 7, 7, 7},
		{
			// 1..100: p50 is the 50th value and p99 the 99th, counting from
			// one. An index computed against len rather than len-1 reads 100
			// for p99, or runs off the end.
			name: "a hundred observations", in: seq(100), count: 100,
			mean: 50.5, p50: 50, p99: 99, max: 100,
		},
		{
			// Order of arrival must not matter: these are sorted before they
			// are read, and a summary that reported them in arrival order
			// would call the last decision the worst one.
			//
			// p50 is sorted[1] and p99 is sorted[2] under this harness's
			// definition — the k-th of n by position, indexed against n-1, so
			// every number printed is an observation that happened. At four
			// observations that reads low; at the 769 a real run produces it is
			// the 9th worst. What matters is that it is the *same* definition
			// the latency rows use, which is why both go through
			// percentileIndex.
			name: "arrival order does not decide the answer",
			in:   []uint64{100, 1, 50, 2}, count: 4,
			mean: 38.25, p50: 2, p99: 50, max: 100,
		},
		{
			// And the two agree, which is the property that would otherwise
			// drift: a percentile printed on the tail line and one printed on
			// the rows above have to mean the same thing.
			name: "the tail summary and the latency rows agree",
			in:   seq(769), count: 769,
			mean: 385, p50: 385, p99: 761, max: 769,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tl := &tailLengths{}
			for _, v := range tc.in {
				tl.add(v)
			}
			count, mean, p50, p99, max := tl.summary()
			if count != tc.count || mean != tc.mean || p50 != tc.p50 || p99 != tc.p99 || max != tc.max {
				t.Fatalf("summary = (%d, %.2f, %.0f, %.0f, %.0f), want (%d, %.2f, %.0f, %.0f, %.0f)",
					count, mean, p50, p99, max, tc.count, tc.mean, tc.p50, tc.p99, tc.max)
			}
		})
	}
}

func seq(n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = uint64(i + 1)
	}
	return out
}
