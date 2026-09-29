package tenancy_test

import (
	"errors"
	"testing"

	"github.com/mustafarslan/janus/pkg/tenancy"
)

func TestValidateAcceptsTheUnboundTenant(t *testing.T) {
	// Every deployment before Phase 5c is this one. It has to stay legal, and
	// it has to stamp nothing.
	var zero tenancy.Tenant
	if err := zero.Validate(); err != nil {
		t.Fatalf("the unbound tenant was refused: %v", err)
	}
	if zero.Bound() {
		t.Fatal("the zero value reports itself as a bound tenant")
	}
	if got := zero.Labels(); len(got) != 0 {
		t.Fatalf("the unbound tenant stamped %v", got)
	}
}

func TestValidateRefusesAJurisdictionWithNoTenant(t *testing.T) {
	// This is the configuration that reads as a deployment-wide default and is
	// not one: the next tenant added inherits a jurisdiction nobody chose.
	tn := tenancy.Tenant{Jurisdiction: "DE"}
	if err := tn.Validate(); !errors.Is(err, tenancy.ErrInvalidTenant) {
		t.Fatalf("a jurisdiction with no tenant was accepted: %v", err)
	}
}

func TestValidateRefusesIdsThatWouldEscapeTheirContext(t *testing.T) {
	for _, id := range []string{
		"../other", // a path
		"bank a",   // a space
		"Bank_A",   // uppercase, so two spellings of one tenant
		"bank\na",  // a newline, in something that gets logged
		"",         // handled by Bound, but not by the pattern
		"-leading", // must start alphanumeric
	} {
		tn := tenancy.Tenant{ID: id}
		if !tn.Bound() {
			continue
		}
		if err := tn.Validate(); !errors.Is(err, tenancy.ErrInvalidTenant) {
			t.Fatalf("id %q was accepted: %v", id, err)
		}
	}
	for _, id := range []string{"bank_a", "a", "tenant-1.eu", "0"} {
		tn := tenancy.Tenant{ID: id}
		if err := tn.Validate(); err != nil {
			t.Fatalf("id %q was refused: %v", id, err)
		}
	}
}

func TestValidateRefusesALowercaseJurisdiction(t *testing.T) {
	// A retention schedule looking up "de" against a policy written for "DE"
	// finds nothing and falls through to the global policy. That is a silent
	// downgrade of a retention period, which is the kind of mistake that is
	// only discovered when the data an inspector asks for is gone.
	tn := tenancy.Tenant{ID: "bank_a", Jurisdiction: "de"}
	if err := tn.Validate(); !errors.Is(err, tenancy.ErrInvalidTenant) {
		t.Fatalf("jurisdiction %q was accepted: %v", tn.Jurisdiction, err)
	}
}

func TestCheckLabelsRefusesEveryReservedKey(t *testing.T) {
	for _, key := range []string{tenancy.LabelTenant, tenancy.LabelJurisdiction} {
		err := tenancy.CheckLabels(map[string]string{key: "anything"})
		if !errors.Is(err, tenancy.ErrReservedLabel) {
			t.Fatalf("label %q was accepted: %v", key, err)
		}
	}
	if err := tenancy.CheckLabels(map[string]string{"mcp.method": "tools/call"}); err != nil {
		t.Fatalf("an ordinary label was refused: %v", err)
	}
}

func TestALabelMatchingTheBindingIsStillRefused(t *testing.T) {
	// Harmless this time. It is a client that has learned to send a field it
	// does not own, and the value it sends next is the interesting one.
	err := tenancy.CheckLabels(map[string]string{tenancy.LabelTenant: "bank_a"})
	if !errors.Is(err, tenancy.ErrReservedLabel) {
		t.Fatalf("a label agreeing with the binding was accepted: %v", err)
	}
}

func TestLabelsAndOfRoundTrip(t *testing.T) {
	tn := tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"}
	if got := tenancy.Of(tn.Labels()); got != tn {
		t.Fatalf("read back %+v, wrote %+v", got, tn)
	}
	// A tenant with no jurisdiction stamps one label, not two with an empty
	// value: an empty jurisdiction label would look like a declared answer.
	partial := tenancy.Tenant{ID: "bank_a"}
	if got := partial.Labels(); len(got) != 1 {
		t.Fatalf("a tenant with no jurisdiction stamped %v", got)
	}
}

func TestAnUnpinnedTenantPermitsEverything(t *testing.T) {
	var zero tenancy.Tenant
	if zero.Pinned() {
		t.Fatal("the unbound tenant reports itself as pinned")
	}
	for _, declared := range [][]string{nil, {}, {"US"}, {"EU", "DE"}} {
		if !zero.Permits(declared) {
			t.Fatalf("an unpinned tenant refused %v", declared)
		}
	}
}

// TestDeclaringNothingIsNotPermissionEverywhere is the rule the pin rests on.
//
// Reading "says nothing" as "no restriction" is the tempting choice, and it
// would make the pin useless on exactly the population it exists for: every
// participant registered before anybody thought about jurisdiction. A
// participant that has not said where it may run has not been assessed for
// anywhere.
func TestDeclaringNothingIsNotPermissionEverywhere(t *testing.T) {
	tn := tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"}
	if tn.Permits(nil) {
		t.Fatal("a participant declaring no jurisdiction was permitted in a pinned tenant")
	}
	if tn.Permits([]string{}) {
		t.Fatal("a participant declaring an empty jurisdiction list was permitted")
	}
}

// TestPermitsDoesNotInventAHierarchy: EU does not cover DE here, and that is a
// decision rather than an omission.
//
// Whether a member state is inside a supranational declaration depends on which
// body's rules the containment is claimed under — true for GDPR, not for a
// national prudential regulator. Encoding one answer in a string comparison
// would be inventing law. A participant that may run in Germany and elsewhere
// in the union declares both.
func TestPermitsDoesNotInventAHierarchy(t *testing.T) {
	de := tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"}
	if de.Permits([]string{"EU"}) {
		t.Fatal("a DE pin was satisfied by a participant declaring only EU")
	}
	if !de.Permits([]string{"EU", "DE", "FR"}) {
		t.Fatal("a DE pin was not satisfied by a participant that declares DE explicitly")
	}
	eu := tenancy.Tenant{ID: "bank_a", Jurisdiction: "EU"}
	if eu.Permits([]string{"DE"}) {
		t.Fatal("an EU pin was satisfied by a participant declaring only DE")
	}
}
