package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Doubles: a sandbox small enough to be obviously honest.
//
// Each action is described by what it does to a set of named counters — a
// ledger balance, a count of emails sent — plus whether the participant
// deduplicates repeated deliveries and whether it enforces its own limits. That
// is enough for every check the harness runs: a compensation restores when its
// deltas cancel the action's, a PURE action has no deltas, a duplicate is
// absorbed or it is not.
//
// Two things about this are worth saying out loud rather than discovering.
//
// The doubles belong to whoever is evaluating, not to the participant being
// evaluated. A conformance test written by the thing under test proves nothing;
// the report records which sandbox it ran against so a reader can ask whose it
// was.
//
// And a double is a model. It proves a manifest's claims are coherent against
// somebody's understanding of the participant. It does not prove the production
// participant behaves that way — for that the harness has to drive the
// participant's own sandbox deployment, which is not built yet.

// Doubles is a declarative sandbox: action name -> what it does.
type Doubles struct {
	// Label identifies the doubles in the evaluation report. It is the JSON
	// "name" field; the Go field is spelled differently because Name() is the
	// method Sandbox requires.
	Label string `json:"name"`
	// Actions describes each action the participant declares. An action with no
	// entry does nothing and refuses nothing, which the harness reports as an
	// unobservable check rather than as a pass.
	Actions map[string]Double `json:"actions"`

	world map[string]int64
	seen  map[string]bool
}

// Double is what one action does to the sandbox world.
type Double struct {
	// Deltas are the changes the action applies to named counters.
	Deltas map[string]int64 `json:"deltas,omitempty"`
	// IgnoresIdempotency makes the double apply its deltas again on a repeated
	// key. It is spelled as the deviation rather than as the good behaviour so
	// that a doubles file written in a hurry defaults to the participant
	// behaving correctly, and a participant modelled as broken is a deliberate
	// statement.
	IgnoresIdempotency bool `json:"ignores_idempotency,omitempty"`
	// AcceptsOverLimit makes the double accept an argument above the manifest's
	// declared cap.
	AcceptsOverLimit bool `json:"accepts_over_limit,omitempty"`
	// Refuses makes the double decline every call, whatever the arguments.
	Refuses bool `json:"refuses,omitempty"`
}

// LoadDoubles reads a doubles description from disk.
func LoadDoubles(path string) (*Doubles, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read sandbox: %w", err)
	}
	var d Doubles
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("registry: parse sandbox %s: %w", path, err)
	}
	if d.Label == "" {
		// The report says which doubles produced a verdict, and "unnamed" is
		// not an answer somebody reviewing an evaluation can act on.
		return nil, fmt.Errorf("registry: sandbox %s has no name; an evaluation report has to "+
			"say what it ran against", path)
	}
	d.Reset()
	return &d, nil
}

// NewDoubles returns an empty, named sandbox.
func NewDoubles(name string) *Doubles {
	d := &Doubles{Label: name, Actions: map[string]Double{}}
	d.Reset()
	return d
}

// With adds or replaces an action's double, and returns the sandbox for
// chaining.
func (d *Doubles) With(action string, double Double) *Doubles {
	if d.Actions == nil {
		d.Actions = map[string]Double{}
	}
	d.Actions[action] = double
	return d
}

// Reset clears the world and the record of keys already delivered.
func (d *Doubles) Reset() {
	d.world = map[string]int64{}
	d.seen = map[string]bool{}
}

// Name implements Sandbox.
func (d *Doubles) Name() string { return d.Label }

// World implements Sandbox.
func (d *Doubles) World() map[string]int64 {
	out := make(map[string]int64, len(d.world))
	for k, v := range d.world {
		if v != 0 {
			out[k] = v
		}
	}
	return out
}

// Invoke implements Sandbox.
func (d *Doubles) Invoke(_ context.Context, call Call) (Result, error) {
	if d.world == nil {
		d.Reset()
	}
	double, known := d.Actions[call.Action]
	if !known {
		// An action the doubles do not describe is not an error: a manifest may
		// declare more than the operator has modelled. It applies nothing, and
		// the harness reports the checks over it as unobservable.
		return Result{Detail: "not modelled by this sandbox"}, nil
	}
	if double.Refuses {
		return Result{Refused: true, Detail: "the double refuses every call"}, nil
	}

	// A limit check passes an argument above the declared cap. The double
	// refuses it unless it has been described as a participant that does not
	// enforce its own limits.
	if over, field := d.overLimit(call); over && !double.AcceptsOverLimit {
		return Result{Refused: true, Detail: fmt.Sprintf("%s is above the participant's limit", field)}, nil
	}

	if call.IdemKey != "" && d.seen[call.Action+"\x00"+call.IdemKey] {
		if !double.IgnoresIdempotency {
			return Result{Duplicate: true, Detail: "already applied under this key"}, nil
		}
	}
	if call.IdemKey != "" {
		d.seen[call.Action+"\x00"+call.IdemKey] = true
	}

	for k, v := range double.Deltas {
		d.world[k] += v
	}
	return Result{}, nil
}

// overLimit reports whether the call carries an argument the harness marked as
// exceeding a cap.
//
// The harness only ever sets the amount field a manifest names, and only when
// testing a limit, so any argument present here is the over-limit probe.
func (d *Doubles) overLimit(call Call) (bool, string) {
	names := make([]string, 0, len(call.Args))
	for k := range call.Args {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return false, ""
	}
	return true, names[0]
}
