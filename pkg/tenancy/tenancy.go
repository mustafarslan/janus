// Package tenancy makes a tenant a boundary instead of a label.
//
// Before this package a tenant was a string in an event's labels, put there by
// whichever call site remembered to pass one. That arrangement has two
// properties a bank cannot accept, and both are invisible until somebody looks:
//
//   - **It is forgeable.** The Appender merged its configured labels first and
//     let a request's own labels overwrite them, so any caller that could reach
//     the write path could stamp its events with another tenant's name. Nothing
//     in the log would say it had happened, because a label is exactly as true
//     as whoever wrote it.
//
//   - **It is optional.** A call site that forgot the label produced evidence
//     belonging to nobody. The A2A proxy did precisely that: every intercepted
//     message it recorded carried no tenant at all.
//
// So the tenant is not a label a caller supplies. It is a property of the
// writer, held by the process that owns the evidence directory, and
// stamped by that writer onto everything it appends — the same rule the
// participant identity already follows, for the same reason: the log says who
// wrote, and who asked is inside the record.
//
// The isolation that follows is structural rather than filtered. One tenant,
// one evidence directory, one process holding its writer lock, and — because
// the key path is derived from the directory (pkg/evidence.Options) — one
// signing key. A verifier holding tenant A's keys does not merely decline to
// show tenant B's events; it cannot establish them at all, because they are
// signed by a key it does not have. A filter that leaks yields somebody else's
// data. A key that is absent yields a failed verification, which is the failure
// somebody notices.
//
// This package holds no policy about *which* tenants exist. That is a
// deployment's business, and a registry of tenants inside the process that
// serves one of them would be a list of names it has no use for.
package tenancy

import (
	"errors"
	"fmt"
	"regexp"
)

// Reserved label keys. These are stamped by the binding and may not be
// supplied by a caller — see Tenant.CheckLabels.
const (
	LabelTenant       = "tenant"
	LabelJurisdiction = "jurisdiction"
)

// ErrReservedLabel is returned when a request tries to set a label that
// belongs to the writer's binding.
var ErrReservedLabel = errors.New("tenancy: reserved label")

// ErrInvalidTenant is returned by Validate.
var ErrInvalidTenant = errors.New("tenancy: invalid tenant")

// A tenant id ends up in file paths, bundle manifests, metric labels and query
// strings. Constraining it here means none of those places has to decide what
// to do with a name containing a slash or a newline.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Jurisdictions are the codes compliance packs and retention schedules already
// use: ISO 3166-1 alpha-2 country codes and supranational codes like EU.
// Uppercase, because a schedule looking up "de" when the log says "DE" finds
// no policy and falls through to the global one, which is a silent downgrade.
var jurisdictionPattern = regexp.MustCompile(`^[A-Z][A-Z0-9-]{1,7}$`)

// Tenant is the boundary an evidence directory is written under.
//
// The zero value is the unbound tenant: a single-tenant deployment, which is
// every deployment that existed before this package. Unbound is not a weaker
// tenant, it is the absence of the question, and it stamps nothing.
type Tenant struct {
	// ID names the tenant. Empty means unbound.
	ID string `json:"id,omitempty"`
	// Jurisdiction is where this tenant's evidence lives and what law it
	// answers to. Phase 5c uses it for retention lookup and, once pinned, for
	// refusing work that would leave it.
	Jurisdiction string `json:"jurisdiction,omitempty"`
}

// Bound reports whether this is a real tenant rather than the zero value.
func (t Tenant) Bound() bool { return t.ID != "" }

// Validate checks the syntax of a binding.
//
// A jurisdiction without a tenant is refused rather than accepted as a
// deployment-wide default. It would read as one — and then the first tenant
// added to that deployment would inherit a jurisdiction nobody chose for it.
func (t Tenant) Validate() error {
	if !t.Bound() {
		if t.Jurisdiction != "" {
			return fmt.Errorf("%w: a jurisdiction (%q) without a tenant names nobody",
				ErrInvalidTenant, t.Jurisdiction)
		}
		return nil
	}
	if !idPattern.MatchString(t.ID) {
		return fmt.Errorf("%w: id %q is not [a-z0-9][a-z0-9._-]{0,63}", ErrInvalidTenant, t.ID)
	}
	if t.Jurisdiction != "" && !jurisdictionPattern.MatchString(t.Jurisdiction) {
		return fmt.Errorf("%w: jurisdiction %q is not an uppercase region code",
			ErrInvalidTenant, t.Jurisdiction)
	}
	return nil
}

// Labels are the reserved labels this binding stamps onto every event.
// The unbound tenant stamps none, so a single-tenant log looks exactly as it
// did before.
func (t Tenant) Labels() map[string]string {
	if !t.Bound() {
		return nil
	}
	out := map[string]string{LabelTenant: t.ID}
	if t.Jurisdiction != "" {
		out[LabelJurisdiction] = t.Jurisdiction
	}
	return out
}

// Pinned reports whether this tenant has declared a jurisdiction that work
// must stay inside.
//
// A tenant with no jurisdiction is not pinned, and nothing is refused on
// jurisdictional grounds. That is what every deployment before Phase 5c is, and
// making the absence of a declaration mean "anywhere" for tenants — while
// making it mean "nowhere" for participants, below — is deliberate. The two
// absences are not the same absence: a deployment that has not said which
// jurisdiction it operates in has not asked the question, and a participant
// that has not said where it may run has not been assessed for anywhere.
func (t Tenant) Pinned() bool { return t.Jurisdiction != "" }

// Permits reports whether a set of declared jurisdictions covers this tenant.
//
// Three rules, and the middle one is the whole point:
//
//   - An unpinned tenant permits everything. Nothing changes for a deployment
//     that has not made the declaration.
//
//   - A pinned tenant is not covered by an empty declaration. "Declares
//     nothing" must not read as "permitted everywhere", because it is the
//     state of every participant registered before anybody thought about
//     jurisdiction — which is exactly the population a pin exists to stop
//     silently including.
//
//   - Matching is exact. Janus does not know that DE is inside the EU, and
//     encoding that would mean encoding which body's rules the containment
//     holds for: it is true for GDPR and not for a national prudential
//     regulator. A participant that may run in Germany and elsewhere in the
//     union declares both; guessing on its behalf would be inventing law in a
//     string comparison.
func (t Tenant) Permits(declared []string) bool {
	if !t.Pinned() {
		return true
	}
	for _, j := range declared {
		if j == t.Jurisdiction {
			return true
		}
	}
	return false
}

// Reserved reports whether a label key belongs to the binding.
func Reserved(key string) bool {
	return key == LabelTenant || key == LabelJurisdiction
}

// CheckLabels refuses a label set that carries a reserved key.
//
// Refusing is deliberate, and the alternative — quietly overwriting the
// caller's value with the binding's — was the first design. It is worse. A
// client stamping another tenant's name is either misconfigured or hostile, and
// both want to find out at the call rather than in an audit six months later.
// Silent correction produces a log that is correct and a client that is wrong,
// and the second one keeps running.
//
// A label matching what the binding would stamp anyway is refused too. It is
// harmless this time; it is a client that has learned to send a field it does
// not own, and the next value it sends is the interesting one.
//
// It takes no binding, because the answer does not depend on one. An unbound
// deployment that accepted a caller-supplied tenant would be exactly the
// forgeable arrangement this package exists to end — and it is the deployment
// most likely to become multi-tenant later.
func CheckLabels(l map[string]string) error {
	for k := range l {
		if Reserved(k) {
			return fmt.Errorf("%w: %q is set by the writer's binding, not by a caller",
				ErrReservedLabel, k)
		}
	}
	return nil
}

// Of reads the tenant a set of event labels was written under.
func Of(labels map[string]string) Tenant {
	return Tenant{
		ID:           labels[LabelTenant],
		Jurisdiction: labels[LabelJurisdiction],
	}
}

// String renders a binding for logs and error messages.
func (t Tenant) String() string {
	switch {
	case !t.Bound():
		return "unbound"
	case t.Jurisdiction == "":
		return t.ID
	default:
		return t.ID + "/" + t.Jurisdiction
	}
}
