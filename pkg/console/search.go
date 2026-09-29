package console

import (
	"fmt"
	"strings"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// Evidence search, run through the verifier rather than beside it.
//
// The console could walk the segments itself and be faster. It does not,
// because a screen that shows an event is making a claim about the log, and the
// only honest way to make that claim is to check it. So search calls the same
// verifier an auditor runs, takes its event list, and filters that.
//
// What "checked" means depends on what the operator gave it. With writer keys,
// every segment's signature is checked and the answer is as strong as
// janus-verify's. Without them, the chain and the Merkle roots are checked and
// the signatures are not — which catches corruption and does not catch an
// insider who re-signed what they edited. The result says which of the two it
// was, in those words, rather than printing a bare list either way.

// Filter narrows a search. Empty fields match everything.
type Filter struct {
	SagaID      string
	StepID      string
	Kind        string
	Participant string
	Subject     string
	// Text matches anywhere in the event id, saga, step, participant, or any
	// label value. It is the box somebody types an account number into.
	Text  string
	From  time.Time
	Until time.Time
	// Limit caps the rows returned. Zero means the default.
	Limit int
}

// EventRow is one event as the console shows it.
type EventRow struct {
	Seq         uint64            `json:"seq"`
	SegmentID   uint64            `json:"segment_id"`
	EventID     string            `json:"event_id"`
	Kind        string            `json:"kind"`
	SagaID      string            `json:"saga_id,omitempty"`
	StepID      string            `json:"step_id,omitempty"`
	Participant string            `json:"participant,omitempty"`
	Manifest    string            `json:"manifest_version,omitempty"`
	Subject     string            `json:"subject,omitempty"`
	Wall        time.Time         `json:"wall"`
	PayloadSize int               `json:"payload_size"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// SearchResult is what a search found, and what was checked to find it.
type SearchResult struct {
	Rows []EventRow `json:"rows"`
	// Matched is how many events matched before the limit was applied.
	Matched int `json:"matched"`
	// Scanned is how many events were in the log.
	Scanned int `json:"scanned"`
	// Truncated says the limit cut the answer short, so nobody reads a partial
	// result as a complete one.
	Truncated bool `json:"truncated"`
	// Integrity is what the verifier concluded about the log these rows came
	// from — the sentence that decides whether the rows mean anything.
	Integrity string `json:"integrity"`
	// SignaturesChecked is false when no writer keys were supplied.
	SignaturesChecked bool `json:"signatures_checked"`
	// Findings are the verifier's complaints, if any.
	Findings []string `json:"findings,omitempty"`
}

// DefaultSearchLimit caps a search that does not ask for a size.
const DefaultSearchLimit = 200

// WithKeys returns a console that checks segment signatures when it reads.
func (c *Console) WithKeys(set keys.PublicKeySet) *Console {
	out := *c
	out.keys = set
	return &out
}

// Search runs the verifier over the directory and filters its event list.
func (c *Console) Search(f Filter) (SearchResult, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultSearchLimit
	}

	// Filtered during the walk rather than after it. Asking the verifier for
	// its whole event list allocated about 2.6 KB per event in the log — 261 MiB
	// on a 100,000-event log, to return 200 rows — and a console is refreshed by
	// people, so several of those overlap. The walk is unchanged: every record is
	// still read and verified, because that is what makes this page a statement
	// about the log rather than about a cache.
	var out SearchResult
	rep, err := verify.SegmentDir(c.dir, verify.Options{
		Keys: c.keys,
		// The tail segment of a live log has no footer yet. Refusing to read it
		// would mean the console could not show what just happened, which is
		// most of what a console is for.
		AllowUnsealedTail: true,
		OnEvent: func(e verify.EventSummary) {
			out.Scanned++
			if !matches(f, e) {
				return
			}
			out.Matched++
			if len(out.Rows) >= limit {
				out.Truncated = true
				return
			}
			out.Rows = append(out.Rows, EventRow{
				Seq: e.Seq, SegmentID: e.SegmentID, EventID: e.EventID, Kind: e.Kind,
				SagaID: e.SagaID, StepID: e.StepID, Participant: e.Participant,
				Manifest: e.ManifestVersion, Subject: e.Subject, Wall: e.Wall,
				PayloadSize: e.PayloadSize, Labels: e.Labels,
			})
		},
	})
	if err != nil {
		return SearchResult{}, fmt.Errorf("console: verify the log before showing it: %w", err)
	}
	out.SignaturesChecked = len(c.keys) > 0

	// With no trusted keys, the verifier reports every segment as signed by an
	// unknown key — which is true, and is a statement about the empty key set
	// rather than about the log. Reporting that as "the log does not verify"
	// would be a false alarm that teaches an operator to ignore the banner, and
	// the banner is the only thing standing between a screen and a claim.
	// Everything else it found is reported unchanged.
	var real []string
	for _, fnd := range rep.Findings {
		if len(c.keys) == 0 && fnd.Code == "UNKNOWN_SIGNING_KEY" {
			continue
		}
		real = append(real, fmt.Sprintf("%s: %s", fnd.Code, fnd.Message))
	}
	out.Findings = real

	switch {
	case len(real) > 0:
		out.Integrity = "the log does not verify; what follows is what it contains, not what it proves"
	case len(c.keys) == 0:
		out.Integrity = "chain and Merkle roots check out; no writer keys were supplied, so the " +
			"segment signatures were not checked"
	default:
		out.Integrity = "chain, Merkle roots and segment signatures all check out"
	}

	return out, nil
}

func matches(f Filter, e verify.EventSummary) bool {
	switch {
	case f.SagaID != "" && e.SagaID != f.SagaID:
		return false
	case f.StepID != "" && e.StepID != f.StepID:
		return false
	case f.Kind != "" && !strings.EqualFold(e.Kind, f.Kind):
		return false
	case f.Participant != "" && e.Participant != f.Participant:
		return false
	case f.Subject != "" && e.Subject != f.Subject:
		return false
	case !f.From.IsZero() && e.Wall.Before(f.From):
		return false
	case !f.Until.IsZero() && e.Wall.After(f.Until):
		return false
	}
	if f.Text == "" {
		return true
	}
	needle := strings.ToLower(f.Text)
	for _, hay := range []string{e.EventID, e.SagaID, e.StepID, e.Participant, e.Kind, e.Subject} {
		if strings.Contains(strings.ToLower(hay), needle) {
			return true
		}
	}
	for k, v := range e.Labels {
		if strings.Contains(strings.ToLower(k), needle) ||
			strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}
