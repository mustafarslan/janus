package saga

import "fmt"

// Mode is how much rope a saga gets.
//
// # What a mode is, and what it was
//
// There are three:
// exploratory runs with sandbox effects only, supervised runs with human gates
// dense, and crystallized runs a validated template with the model confined to
// declared slots. The proto has carried `// exploratory | supervised |
// crystallized` next to the field since Phase 2.
//
// Until Phase 6e nothing checked it. The mode arrived on `SagaBegin`, from the
// caller, and its only use was as a match key in the gate policy — so a policy
// rule scoped to `modes: ["supervised"]` applied to a saga that said
// "supervised" and did not apply to one that said "supervized". **Scoping a gate
// to a mode made that gate optional**, at the discretion of whoever composed the
// plan, and the failure was silent in the direction that removes protection.
//
// That is the same shape as a jurisdiction that was declared and never read
// and a tenant that was a field on a request, and it gets
// the same answer: the vocabulary is closed, and a mode that is not in it is
// refused rather than treated as a mode nobody wrote a rule for.
type Mode string

const (
	// ModeUnscoped is the empty mode. It is *valid*, and it matches only policy
	// rules that do not scope themselves to a mode.
	//
	// It is kept rather than defaulted to something, because defaulting would
	// change which rules match for every saga already recorded without one —
	// including the whole fixture corpus. A saga that says nothing about its
	// mode is asking for the rules that apply to everything, and that is a
	// coherent thing to ask for.
	ModeUnscoped Mode = ""
	// ModeExploratory is sandbox effects only. Its effects never reach a target
	// that has not been declared a sandbox, enforced in the outbox at release
	// rather than only at admission.
	ModeExploratory Mode = "exploratory"
	// ModeSupervised is the ordinary mode: whatever gates the policy says.
	ModeSupervised Mode = "supervised"
	// ModeCrystallized runs a validated template with the model confined to
	// declared slots. There is no template registry yet, so a saga declaring it
	// is refused at admission rather than admitted under a promise nothing can
	// keep.
	ModeCrystallized Mode = "crystallized"
)

// KnownModes is the closed vocabulary, in order of increasing confinement.
func KnownModes() []Mode {
	return []Mode{ModeExploratory, ModeSupervised, ModeCrystallized}
}

// ValidateMode refuses a mode outside the vocabulary.
//
// The error names the vocabulary, because the realistic way to reach it is a
// typo and the realistic consequence of a typo is fewer gates.
func ValidateMode(m string) error {
	switch Mode(m) {
	case ModeUnscoped, ModeExploratory, ModeSupervised, ModeCrystallized:
		return nil
	}
	return fmt.Errorf("%w: mode %q is not one of exploratory, supervised or crystallized; "+
		"a mode outside the vocabulary is refused rather than treated as one nobody wrote a "+
		"rule for, because a policy rule scoped to a mode would silently not apply",
		ErrTransition, m)
}

// IsExploratory reports whether a saga runs with sandbox effects only.
func IsExploratory(m string) bool { return Mode(m) == ModeExploratory }
