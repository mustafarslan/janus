package registry_test

import (
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/registry"
)

func entry(tier uint32, manifestDays uint32, triggers []string,
	state registry.State, validatedAt time.Time, pending []string) *registry.Entry {

	return &registry.Entry{
		Manifest: &registry.Manifest{
			Version: "1.0.0",
			Risk: registry.Risk{
				Tier:                 tier,
				RevalidateAfterDays:  manifestDays,
				RevalidationTriggers: triggers,
			},
		},
		State:           state,
		ValidatedAt:     validatedAt,
		PendingTriggers: pending,
	}
}

var periodic = []string{registry.TriggerPeriodic}

func tiers() *registry.Cadence {
	return &registry.Cadence{ByTier: map[uint32]uint32{1: 90, 2: 180, 3: 365}}
}

// The cadence comes from the deployment's tier, which is the whole decision
// this entry was waiting on.
func TestTheTiersCadenceIsWhatSchedules(t *testing.T) {
	c := tiers()
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := entry(1, 0, periodic, registry.StateActive, anchor, nil)

	if c.Due(e, anchor.AddDate(0, 0, 89)) {
		t.Fatal("a tier-1 version came due on day 89 of a 90-day cadence")
	}
	if !c.Due(e, anchor.AddDate(0, 0, 90)) {
		t.Fatal("a tier-1 version did not come due on day 90 of a 90-day cadence")
	}
}

// A manifest may tighten the deployment's cadence.
func TestAManifestMayTightenTheCadence(t *testing.T) {
	c := tiers()
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Tier 3 is a year; this manifest says thirty days.
	e := entry(3, 30, periodic, registry.StateActive, anchor, nil)

	if !c.Due(e, anchor.AddDate(0, 0, 30)) {
		t.Fatal("a manifest asking for a 30-day cadence was left on its tier's 365")
	}
}

// A manifest may not loosen it, and this is the half that matters: the tier is
// the institution's floor and a vendor does not get to raise it.
func TestAManifestMayNotLoosenTheCadence(t *testing.T) {
	c := tiers()
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Tier 1 is 90 days; this manifest would like a decade.
	e := entry(1, 3650, periodic, registry.StateActive, anchor, nil)

	if !c.Due(e, anchor.AddDate(0, 0, 90)) {
		t.Fatal("a manifest declaring a longer period than its tier excused itself " +
			"from the deployment's schedule")
	}
}

// Re-tiering moves the schedule with no manifest reissued, which is the reason
// the shorter of the two is taken when the schedule is computed rather than
// checked at registration.
func TestReTieringMovesTheScheduleWithNoManifestChange(t *testing.T) {
	c := tiers()
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day100 := anchor.AddDate(0, 0, 100)

	lowRisk := entry(3, 0, periodic, registry.StateActive, anchor, nil)
	if c.Due(lowRisk, day100) {
		t.Fatal("a tier-3 version came due after 100 days of a 365-day cadence")
	}

	// The same manifest, re-tiered. Nothing else changed.
	lowRisk.Manifest.Risk.Tier = 1
	if !c.Due(lowRisk, day100) {
		t.Fatal("re-tiering to 1 did not bring the version onto the 90-day schedule")
	}
}

// A version already owing a periodic revalidation is not due for another.
func TestADebtAlreadyRecordedIsNotRecordedAgain(t *testing.T) {
	c := tiers()
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := entry(1, 0, periodic, registry.StateActive, anchor, periodic)

	if c.Due(e, anchor.AddDate(0, 0, 400)) {
		t.Fatal("a version already owing a periodic revalidation was scheduled for " +
			"a second one, which would list the same debt twice")
	}
}

// Nothing is scheduled without the trigger, without a tier entry, or for a
// version that is not in service.
func TestWhatIsNotScheduled(t *testing.T) {
	c := tiers()
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := anchor.AddDate(0, 0, 400)

	for _, tc := range []struct {
		name string
		e    *registry.Entry
	}{
		{"no periodic trigger", entry(1, 0, nil, registry.StateActive, anchor, nil)},
		{"tier absent from the cadence", entry(4, 0, periodic, registry.StateActive, anchor, nil)},
		{"suspended", entry(1, 0, periodic, registry.StateSuspended, anchor, nil)},
		{"draft", entry(1, 0, periodic, registry.StateDraft, anchor, nil)},
		{"no anchor in the log", entry(1, 0, periodic, registry.StateActive, time.Time{}, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if c.Due(tc.e, late) {
				t.Fatalf("%s was scheduled for a periodic revalidation", tc.name)
			}
		})
	}
}

// A cadence that schedules nothing is refused rather than accepted quietly. A
// file somebody wrote and got wrong should say so, not configure silence.
func TestAnEmptyCadenceIsRefused(t *testing.T) {
	if err := (&registry.Cadence{}).Validate(); err == nil {
		t.Fatal("a cadence with no tiers in it was accepted")
	}
	if err := (&registry.Cadence{ByTier: map[uint32]uint32{1: 0}}).Validate(); err == nil {
		t.Fatal("a cadence of zero days was accepted, which would require a " +
			"revalidation every time the scheduler looked")
	}
	if err := (&registry.Cadence{ByTier: map[uint32]uint32{9: 30}}).Validate(); err == nil {
		t.Fatal("a cadence naming a tier outside 1..4 was accepted")
	}
}

// A period with no `periodic` trigger is refused rather than silently inert.
//
// The manifest field only takes effect when the version has asked to be on a
// calendar at all. A vendor who writes a period and omits the trigger has
// configured nothing, believes otherwise, and nothing tells them — which is the
// shape of failure this project exists to prevent.
func TestAPeriodWithNoPeriodicTriggerIsRefused(t *testing.T) {
	m := wireManifest()
	m.Risk.RevalidateAfterDays = 30
	m.Risk.RevalidationTriggers = []string{registry.TriggerModelChange}

	if err := m.Validate(); err == nil {
		t.Fatal("a manifest declaring revalidate_after_days without the periodic " +
			"trigger was accepted, so it asks for a review nothing will ever schedule")
	}

	// With the trigger it is fine.
	m.Risk.RevalidationTriggers = append(m.Risk.RevalidationTriggers, registry.TriggerPeriodic)
	if err := m.Validate(); err != nil {
		t.Fatalf("a manifest with both the period and the trigger was refused: %v", err)
	}
}
