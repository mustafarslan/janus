package outbox

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/registry"
)

// Where an effect is allowed to land.
//
// Phase 5c pinned a jurisdiction in three places: the participant a step runs
// on, where that participant stores its data, and where Janus keeps its own
// blobs and archive. Then the step committed and the outbox delivered the
// effect to a target — and nothing anywhere said where the target was.
//
// So a saga could be pinned to DE, admitted against a DE participant, write its
// payloads to a DE bucket, and hand the payment instruction to an endpoint in
// Ohio. The pin held everywhere except at the moment the data left, which is
// the moment a residency rule is actually about.
//
// # Why this is not covered by admission
//
// `registry.AdmitFor` refuses a plan whose *participant* may not run in the
// tenant's jurisdiction, and in the common case the delivery target is that
// same participant (pkg/mcp sets `Target` to the participant id). Where the two
// coincide, admission has already decided.
//
// They do not have to coincide. A target is a string chosen by whoever composed
// the effect, resolved to a transport by whoever runs the daemon, and
// nothing requires it to name a participant at all. The looseness is
// deliberate — it is what lets a deliverer connect and be trusted only for
// transport — and it is exactly the gap a pin has to cover.
//
// # What is refused, and what is not
//
// The same asymmetry as the rest of the pin. An unpinned tenant is unaffected:
// every deployment before Phase 5c, and every deployment that has not made the
// declaration. A pinned tenant refuses a target it cannot resolve to a
// participant declaring that jurisdiction — including a target nothing in the
// log declares at all, because "nobody registered this endpoint" is not a
// statement that it is local.

// ErrResidency means the effect's target is outside the tenant's jurisdiction,
// or is somewhere nothing says.
var ErrResidency = errors.New("outbox: the target is outside this tenant's jurisdiction")

// Residency answers where a delivery target's effects are allowed to land.
//
// It is an interface for the same reason CommitAuthority is: the question is
// consequential, and a test has to be able to lie to the outbox about the
// answer in order to prove the outbox does not simply take its word for it.
type Residency interface {
	// Placement returns what the log declares about a target. ok is false when
	// nothing declares anything about it, which is a different answer from "it
	// declared none" and is treated the same way: a pinned tenant refuses both.
	Placement(ctx context.Context, target string) (p Placement, ok bool, err error)
}

// Placement is what a target declared about itself, in the same vocabulary a
// participant manifest uses.
type Placement struct {
	// DeployableIn is where the target may be used.
	DeployableIn []string
	// DataResidency is where it keeps what it receives, when it says. Empty
	// means it has not said, which is not the same as saying "here" — but is
	// not refused on its own, because DeployableIn is the declaration a
	// deployment is asked for first.
	DataResidency string
}

// LogResidency resolves a target against the registry folded out of an evidence
// directory.
//
// Folded per call rather than cached, for this reason: the
// registry is a projection of the log, a manifest can be suspended between one
// effect and the next, and a cached answer is a claim about the past being used
// to decide the present.
type LogResidency struct {
	dir  string
	live func() []evidence.ReadOption
}

// NewLogResidency reads target jurisdictions from an evidence directory.
func NewLogResidency(dir string) *LogResidency { return &LogResidency{dir: dir} }

// NewLiveLogResidency is NewLogResidency for a releaser sharing the directory
// with an appender.
//
// Without the head, a release could be refused because the writer was mid-flush
// rather than because the target was out of jurisdiction — a refusal on the
// release path naming the wrong reason.
func NewLiveLogResidency(dir string, live func() []evidence.ReadOption) *LogResidency {
	return &LogResidency{dir: dir, live: live}
}

// Placement implements Residency.
func (l *LogResidency) Placement(_ context.Context, target string) (Placement, bool, error) {
	var opts []evidence.ReadOption
	if l.live != nil {
		opts = l.live()
	}
	events, err := registry.LoadEvents(l.dir, opts...)
	if err != nil {
		return Placement{}, false, err
	}
	reg, err := registry.Fold(events)
	if err != nil {
		return Placement{}, false, err
	}
	entry, ok := reg.Active(target)
	if !ok {
		return Placement{}, false, nil
	}
	j := entry.Manifest.Jurisdiction
	return Placement{DeployableIn: j.DeployableIn, DataResidency: j.DataResidency}, true, nil
}

// residencyAllows refuses a target this tenant's work may not reach.
//
// The tenant comes from the appender's binding — the log's own — rather than
// from anything on the effect. An effect that could name its own jurisdiction
// would be an effect that could authorise its own destination.
func (r *Releaser) residencyAllows(ctx context.Context, target string) error {
	tenant := r.app.Tenant()
	if !tenant.Pinned() {
		return nil
	}
	if r.residency == nil {
		// A pinned deployment with no way to resolve a target cannot say where
		// its effects are going. Refusing is the fail-closed answer and the
		// only honest one: the alternative is a deployment that believes it is
		// pinned and is not.
		return fmt.Errorf("%w: this log is pinned to %s and the releaser has no way to resolve "+
			"where %q is", ErrResidency, tenant.Jurisdiction, target)
	}
	place, known, err := r.residency.Placement(ctx, target)
	if err != nil {
		return fmt.Errorf("outbox: cannot establish where target %q is, so the effect stays "+
			"held: %w", target, err)
	}
	if !known {
		return fmt.Errorf("%w: this log is pinned to %s and nothing in it declares where %q is; "+
			"an endpoint nobody registered is not thereby local", ErrResidency,
			tenant.Jurisdiction, target)
	}
	// Deployability is where the target may be used. Data residency, when it
	// declares one, has to agree as well: a target that runs in Frankfurt and
	// keeps what it receives in Ohio has answered one of the two questions a
	// residency rule asks.
	if place.DataResidency != "" && place.DataResidency != tenant.Jurisdiction {
		return fmt.Errorf("%w: this log is pinned to %s and %q keeps what it receives in %s",
			ErrResidency, tenant.Jurisdiction, target, place.DataResidency)
	}
	if !tenant.Permits(place.DeployableIn) {
		return fmt.Errorf("%w: this log is pinned to %s and %q may be used in %s",
			ErrResidency, tenant.Jurisdiction, target, orNowhere(place.DeployableIn))
	}
	return nil
}

func orNowhere(codes []string) string {
	if len(codes) == 0 {
		return "nowhere it has declared"
	}
	return strings.Join(codes, ", ")
}
