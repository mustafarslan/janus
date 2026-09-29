package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// When a periodic revalidation comes due.
//
// A manifest may declare `periodic` as a revalidation trigger, and nothing
// decided *when* it came due — so a supervisor's quarterly review was something
// an operator remembered to run a command for.
//
// # Where the cadence lives, and why it is not the manifest's
//
// In deployment configuration, keyed by risk tier. A quarterly model review is
// an expectation a regulator places on an *institution*, not on a piece of
// software, which is what the compliance packs are shaped around. It also
// survives the thing that happens to real inventories: a bank re-tiers a model
// after an incident, and every schedule that depended on the tier moves with it
// without a single manifest being reissued.
//
// A manifest may still name a shorter period, because a vendor can know
// something the tier does not — a model that drifts in weeks should not sit on
// a yearly schedule because its tier permits one. The shorter of the two wins,
// and that is computed here rather than checked at registration, so a
// re-tiering corrects itself.

// Cadence is how long an evaluation stays good for, by risk tier.
type Cadence struct {
	// ByTier maps a risk tier (1 highest, 4 lowest) to a number of days. A tier
	// with no entry has no periodic schedule, which is a deliberate default:
	// scheduling nothing is visible as "nothing was scheduled", where a
	// guessed default is a control that looks configured and is not.
	ByTier map[uint32]uint32 `json:"by_tier"`
}

// LoadCadenceFile reads a cadence from JSON.
func LoadCadenceFile(path string) (*Cadence, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Cadence
	dec := json.NewDecoder(bytes.NewReader(blob))
	// Unknown fields are refused rather than ignored: a cadence file with a
	// misspelled key would otherwise configure nothing and look configured.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("registry: read the revalidation cadence from %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("registry: %s: %w", path, err)
	}
	return &c, nil
}

// Validate refuses a cadence that would schedule nothing or schedule nonsense.
func (c *Cadence) Validate() error {
	if c == nil || len(c.ByTier) == 0 {
		return fmt.Errorf("a revalidation cadence with no tiers in it schedules nothing; " +
			"leave the configuration out entirely rather than configuring an empty one")
	}
	for tier, days := range c.ByTier {
		if tier < 1 || tier > 4 {
			return fmt.Errorf("risk tier %d is outside 1..4", tier)
		}
		if days == 0 {
			return fmt.Errorf("tier %d has a cadence of zero days, which would require a "+
				"revalidation every time the scheduler looked", tier)
		}
	}
	return nil
}

// Period returns how long this version's evaluation stays good for, and whether
// it is on a schedule at all.
//
// The shorter of the deployment's tier cadence and anything the manifest
// declares. A manifest with a longer period than its tier is ignored rather
// than refused: the tier is the institution's floor and a vendor does not get
// to raise it.
func (c *Cadence) Period(e *Entry) (time.Duration, bool) {
	if c == nil || e == nil || e.Manifest == nil {
		return 0, false
	}
	// A version that does not ask for periodic revalidation is not on a
	// schedule, however the deployment is configured. The trigger is the
	// manifest's statement that this participant needs one.
	if !hasTrigger(e.Manifest.Risk.RevalidationTriggers, TriggerPeriodic) {
		return 0, false
	}
	tierDays, ok := c.ByTier[e.Manifest.Risk.Tier]
	if !ok {
		return 0, false
	}
	days := tierDays
	if d := e.Manifest.Risk.RevalidateAfterDays; d > 0 && d < days {
		days = d
	}
	return time.Duration(days) * 24 * time.Hour, true
}

// Due reports whether a version's periodic revalidation has come due at now.
//
// It compares two times and reads no clock of its own, which is the property
// gate expiry established and is here for the same reason: a
// scheduler and an auditor looking at the same log must reach the same answer,
// and one that computed "now" for itself would not.
//
// A version that already owes a periodic revalidation is not due for another.
// Appending a second would be log noise, and an inventory listing the same debt
// twice reads as two overdue reviews.
func (c *Cadence) Due(e *Entry, now time.Time) bool {
	period, scheduled := c.Period(e)
	if !scheduled {
		return false
	}
	// Only an active version is on a schedule. A suspended or retired one is
	// not in service, and a draft one cannot be activated until its evidence is
	// in order anyway.
	if e.State != StateActive {
		return false
	}
	if hasTrigger(e.PendingTriggers, TriggerPeriodic) {
		return false
	}
	if e.ValidatedAt.IsZero() {
		// Nothing in the log says when this version's standing was
		// established, so there is no anchor to count from. Scheduling from
		// "now" would start the clock at whenever the daemon happened to
		// restart, which is a schedule nobody chose.
		return false
	}
	return !now.Before(e.ValidatedAt.Add(period))
}

// Due lists the active versions whose periodic revalidation has come due, in a
// stable order so two runs of a scheduler produce the same log.
//
// It is on the registry rather than on the cadence because the registry is what
// knows which versions are active, and it returns entries rather than appending
// anything: recording the debt is the daemon's job, and a folded projection
// that could append would be a projection deciding something.
func (r *Registry) Due(c *Cadence, now time.Time) []*Entry {
	var out []*Entry
	for _, id := range r.Participants() {
		e, ok := r.Active(id)
		if !ok {
			continue
		}
		if c.Due(e, now) {
			out = append(out, e)
		}
	}
	return out
}

func hasTrigger(triggers []string, want string) bool {
	for _, t := range triggers {
		if t == want {
			return true
		}
	}
	return false
}
