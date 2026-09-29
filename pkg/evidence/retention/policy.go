// Package retention decides how long evidence must be kept and when it may be
// disposed of.
//
// The rules are data rather than code: a policy set is
// a document a compliance function can read, review, and change without a
// release. That is deliberate — retention periods move when regulation moves,
// and a system that needs an engineer for every such change will drift out of
// compliance between releases.
//
// Two ideas do most of the work here.
//
// A minimum retention is a floor that nothing can lower. A legal hold overrides
// even an expired maximum, because a matter under litigation freezes disposal
// regardless of what the schedule says. So the answer to "may this be deleted?"
// is never a single comparison; it is a floor, a ceiling, and a set of holds.
//
// Disposal is itself an event. Deleting evidence without recording that it was
// deleted turns a gap in the record into an unanswerable question at audit
// time: was there nothing, or was something removed? A DISPOSAL record makes
// the difference visible, names the policy that authorised it, and is chained
// like everything else.
package retention

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

// Class names a kind of record for retention purposes. It is deliberately
// coarser than an event kind: a schedule talks about "transaction records" and
// "decision provenance", not about STEP_RESULT.
type Class string

// Classes recognised by this version.
const (
	// ClassTransaction covers the saga lifecycle: what was done.
	ClassTransaction Class = "transaction"
	// ClassDecision covers decision provenance: why it was done.
	ClassDecision Class = "decision"
	// ClassCommunication covers messages exchanged with tools and other agents.
	ClassCommunication Class = "communication"
	// ClassControl covers Janus's own administration.
	ClassControl Class = "control"
	// ClassPersonal covers records containing personal data, which are subject
	// to erasure rights as well as retention duties.
	ClassPersonal Class = "personal"
)

// AllClasses lists every class this build understands.
func AllClasses() []Class {
	return []Class{ClassTransaction, ClassDecision, ClassCommunication, ClassControl, ClassPersonal}
}

// DisposalMode says what disposal actually does to a record.
type DisposalMode string

const (
	// DisposeDelete removes the record outright. Only legitimate for classes
	// held outside the hash chain, such as content-addressed payloads.
	DisposeDelete DisposalMode = "delete"
	// DisposeCryptoShred destroys the key a record was encrypted under, leaving
	// the ciphertext in place so the chain stays intact. This is how erasure
	// and immutability are reconciled; the mechanism arrives in Phase 1c
	// and this version only records the intent.
	DisposeCryptoShred DisposalMode = "crypto-shred"
	// DisposeNone means records of this class are never disposed of.
	DisposeNone DisposalMode = "none"
)

// Policy is one rule in a schedule.
type Policy struct {
	// Class and Jurisdiction together select the policy. An empty Jurisdiction
	// matches anything, so a schedule can state a global floor and then raise
	// it where a particular regime demands more.
	Class        Class  `json:"class"`
	Jurisdiction string `json:"jurisdiction,omitempty"`

	// MinRetention is the floor. Nothing may be disposed of before it.
	MinRetention Duration `json:"min_retention"`
	// MaxRetention is the ceiling, after which a record *should* be disposed
	// of. Zero means keep indefinitely; a data-protection regime that requires
	// data not be kept longer than necessary is expressed by setting it.
	MaxRetention Duration `json:"max_retention,omitempty"`

	// Mode says what disposal does.
	Mode DisposalMode `json:"mode"`
	// Authority names the rule this implements, so a report can cite it.
	Authority string `json:"authority,omitempty"`
}

// Schedule is a set of policies, usually loaded from a file.
type Schedule struct {
	Version  int      `json:"version"`
	Policies []Policy `json:"policies"`
}

// Errors returned by this package.
var (
	// ErrNoPolicy means nothing in the schedule covers a record. It is an error
	// rather than a permissive default: disposing of something no rule mentions
	// is exactly the mistake a schedule exists to prevent.
	ErrNoPolicy = errors.New("retention: no policy covers this record")
	// ErrInvalidSchedule means the schedule is self-contradictory.
	ErrInvalidSchedule = errors.New("retention: invalid schedule")
)

// Validate checks a schedule for contradictions.
func (s Schedule) Validate() error {
	if len(s.Policies) == 0 {
		return fmt.Errorf("%w: no policies", ErrInvalidSchedule)
	}
	seen := map[string]bool{}
	for i, p := range s.Policies {
		key := string(p.Class) + "/" + p.Jurisdiction
		if seen[key] {
			return fmt.Errorf("%w: two policies for class %q in jurisdiction %q",
				ErrInvalidSchedule, p.Class, p.Jurisdiction)
		}
		seen[key] = true

		if p.Class == "" {
			return fmt.Errorf("%w: policy %d has no class", ErrInvalidSchedule, i)
		}
		if !slices.Contains(AllClasses(), p.Class) {
			return fmt.Errorf("%w: policy %d has unknown class %q", ErrInvalidSchedule, i, p.Class)
		}
		if p.MinRetention < 0 || p.MaxRetention < 0 {
			return fmt.Errorf("%w: policy %d has a negative retention", ErrInvalidSchedule, i)
		}
		if p.MaxRetention > 0 && p.MaxRetention < p.MinRetention {
			return fmt.Errorf("%w: policy for %s/%s keeps records for at most %s but at least %s",
				ErrInvalidSchedule, p.Class, p.Jurisdiction, p.MaxRetention, p.MinRetention)
		}
		if p.Mode == "" {
			return fmt.Errorf("%w: policy %d has no disposal mode", ErrInvalidSchedule, i)
		}
		switch p.Mode {
		case DisposeDelete, DisposeCryptoShred, DisposeNone:
		default:
			return fmt.Errorf("%w: policy %d has unknown disposal mode %q", ErrInvalidSchedule, i, p.Mode)
		}
	}
	return nil
}

// Lookup returns the policy governing a record.
//
// A jurisdiction-specific policy wins over a global one, so a schedule can set
// a baseline and then override it where a regime is stricter.
func (s Schedule) Lookup(class Class, jurisdiction string) (Policy, error) {
	var global *Policy
	for i := range s.Policies {
		p := &s.Policies[i]
		if p.Class != class {
			continue
		}
		switch p.Jurisdiction {
		case jurisdiction:
			return *p, nil
		case "":
			global = p
		}
	}
	if global != nil {
		return *global, nil
	}
	return Policy{}, fmt.Errorf("%w: class %q in jurisdiction %q", ErrNoPolicy, class, jurisdiction)
}

// LoadSchedule reads and validates a schedule from a JSON file.
func LoadSchedule(path string) (Schedule, error) {
	var s Schedule
	blob, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(blob, &s); err != nil {
		return s, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return s, err
	}
	return s, nil
}

// Duration is a time.Duration that reads and writes as a string in JSON, so a
// schedule says "2160h" rather than a count of nanoseconds nobody can check.
type Duration time.Duration

// MarshalJSON renders the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON accepts a duration string, and also the common shorthand of
// days and years, which is how retention schedules are actually written.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// String renders a retention period the way a schedule is written rather than
// the way Go prints durations. "6y" is checkable against a regulation at a
// glance; "52560h0m0s" is how transcription errors survive review.
func (d Duration) String() string {
	td := time.Duration(d)
	if td == 0 {
		return "0"
	}
	const day = 24 * time.Hour
	const year = 365 * day
	switch {
	case td%year == 0:
		return fmt.Sprintf("%dy", td/year)
	case td%day == 0:
		return fmt.Sprintf("%dd", td/day)
	default:
		return td.String()
	}
}

// ParseDuration extends time.ParseDuration with "d" for days and "y" for years.
//
// Retention rules are written as "6 months", "5 years", "10 years"; expressing
// those as hours is where transcription errors come from. A year here is 365
// days, which is the convention retention schedules use and is deliberately not
// calendar-aware — a record kept one day too long is not a compliance failure,
// one deleted a day early is.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("retention: empty duration")
	}
	switch {
	case strings.HasSuffix(s, "y"):
		var years float64
		if _, err := fmt.Sscanf(strings.TrimSuffix(s, "y"), "%g", &years); err != nil {
			return 0, fmt.Errorf("retention: bad duration %q: %w", s, err)
		}
		return time.Duration(years * 365 * 24 * float64(time.Hour)), nil
	case strings.HasSuffix(s, "d"):
		var days float64
		if _, err := fmt.Sscanf(strings.TrimSuffix(s, "d"), "%g", &days); err != nil {
			return 0, fmt.Errorf("retention: bad duration %q: %w", s, err)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	default:
		return time.ParseDuration(s)
	}
}

// DefaultSchedule is a starting point covering the regimes Janus
// targets (EU AI Act, GDPR, MiFID II, FINRA). It is an engineering default, not legal advice: a
// deployment replaces it with a schedule its own compliance function owns, and
// the durations here are the conservative reading of each rule.
func DefaultSchedule() Schedule {
	years := func(n float64) Duration {
		d, _ := ParseDuration(fmt.Sprintf("%gy", n))
		return Duration(d)
	}
	return Schedule{
		Version: 1,
		Policies: []Policy{
			{
				Class: ClassTransaction, MinRetention: years(6), Mode: DisposeNone,
				Authority: "EU AI Act Art. 12/19 (at least six months, longer where sectoral law applies); " +
					"MiFID II RTS 6 five years; SEC 17a-4 six years",
			},
			{
				Class: ClassDecision, MinRetention: years(6), Mode: DisposeNone,
				Authority: "EU AI Act Art. 12(2) reconstructability; GDPR Art. 15 meaningful information about the logic",
			},
			{
				Class: ClassCommunication, MinRetention: years(5), Mode: DisposeNone,
				Authority: "MiFID II RTS 6 Art. 16; FINRA 4511",
			},
			{
				Class: ClassControl, MinRetention: years(6), Mode: DisposeNone,
				Authority: "Janus's own administration is evidence too",
			},
			{
				// Personal data is the one class where a maximum matters: the
				// duty to keep and the duty not to keep longer than necessary
				// both apply, and crypto-shredding is what resolves them.
				Class: ClassPersonal, MinRetention: years(6), MaxRetention: years(10),
				Mode:      DisposeCryptoShred,
				Authority: "GDPR Arts. 5(1)(e) and 17 against sectoral retention; KVKK equivalents",
			},
		},
	}
}

// LongestMinimum is the longest floor any policy in this schedule states.
//
// It exists because `worm.Config.Retention` says what it needs and had no way to
// get it: "Retention must therefore be the longest any record in the log could
// require". An archived segment holds records of every class mixed together, so
// one lock duration has to cover all of them, and the only safe choice is the
// largest minimum in force. Until this, `janus-tier archive` took the number
// from a flag defaulting to six years — which matched the built-in schedule by
// coincidence and would silently under-lock any schedule stating more.
//
// Zero when the schedule states no floors at all, which Validate does not
// forbid; the caller decides what to do with that rather than being handed a
// made-up duration.
func (s Schedule) LongestMinimum() time.Duration {
	var longest time.Duration
	for _, p := range s.Policies {
		if d := time.Duration(p.MinRetention); d > longest {
			longest = d
		}
	}
	return longest
}

// Marshal renders a schedule as indented JSON.
func (s Schedule) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Jurisdictions lists the jurisdictions a schedule mentions, sorted.
func (s Schedule) Jurisdictions() []string {
	set := map[string]struct{}{}
	for _, p := range s.Policies {
		if p.Jurisdiction != "" {
			set[p.Jurisdiction] = struct{}{}
		}
	}
	out := slices.Collect(maps.Keys(set))
	sort.Strings(out)
	return out
}
