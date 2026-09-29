package replica

import (
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// onlyUnknownKey is what decides whether a refused range is reported as an
// unreachable signing key or as divergence, and "every critical" rather than
// "any critical" is the load-bearing word.
//
// A range that is both signed by a key this copy cannot reach *and* broken
// somewhere else is not a range to soften the language about. The second
// finding is the one that decides, and the combination is not hypothetical: a
// follower that copied a partial set of segments around a key rotation reports
// an unreachable key beside a torn or unsealed one.
func TestOnlyAnUnreachableKeyCountsAsAnUnreachableKey(t *testing.T) {
	unknown := verify.Finding{
		Severity: verify.Critical, Code: "UNKNOWN_SIGNING_KEY",
		Message: "footer is signed by key ed25519-abc, which was neither supplied as a root",
	}
	torn := verify.Finding{
		Severity: verify.Critical, Code: "SEGMENT_TORN",
		Message: "segment ends in an incomplete record",
	}
	note := verify.Finding{Severity: verify.Warning, Code: "SEGMENT_ID_GAP", Message: "segment id jumps from 4 to 6"}

	for _, tc := range []struct {
		name     string
		findings []verify.Finding
		want     bool
		wantKey  string
	}{
		{"the key alone", []verify.Finding{unknown}, true, "ed25519-abc"},
		{"the key, twice", []verify.Finding{unknown, unknown}, true, "ed25519-abc"},
		{"the key, alongside something that is not critical", []verify.Finding{note, unknown}, true, "ed25519-abc"},
		{"the key and a tear", []verify.Finding{unknown, torn}, false, ""},
		{"a tear and then the key", []verify.Finding{torn, unknown}, false, ""},
		{"a tear alone", []verify.Finding{torn}, false, ""},
		{"nothing critical at all", []verify.Finding{note}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, key := onlyUnknownKey(&verify.Report{Findings: tc.findings})
			if got != tc.want {
				t.Fatalf("onlyUnknownKey = %v, want %v", got, tc.want)
			}
			if key != tc.wantKey {
				t.Fatalf("named key %q, want %q", key, tc.wantKey)
			}
		})
	}
}

// The key id is what an operator has to go and look up, so pulling it out of
// the verifier's sentence is worth being exact about — and a sentence in a
// shape this does not recognise degrades to the whole message rather than to
// nothing, because "which key?" with no answer is worse than a long line.
func TestTheUnreachableKeyIsNamed(t *testing.T) {
	for _, tc := range []struct{ msg, want string }{
		{"footer is signed by key ed25519-dead, which was neither supplied as a root", "ed25519-dead"},
		{"footer is signed by key ed25519-dead", "ed25519-dead"},
		{"something the verifier does not say today", "something the verifier does not say today"},
	} {
		if got := unknownKeyID(tc.msg); got != tc.want {
			t.Fatalf("unknownKeyID(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}
