// Command janus-evilauditor is the standing adversarial suite, and Phase 5's
// internal gate.
//
// # What it is
//
// A persona, not a test file. Somebody who wants the evidence to say something
// it should not, and who has whatever access the attack requires: the disk, the
// writer's API, a participant's manifest. Each attack is performed for real
// against a real log, and then the question is asked that an auditor would ask:
//
//	**does the system NAME this, from the log alone?**
//
// Not "did the write fail". A refusal at the door is prevention and counts; but
// an attack that succeeds at the door and is caught afterwards by the verifier
// also counts, and an attack that succeeds and is never named does not — however
// unlikely somebody thinks it is. The plan's criterion is 100% detection or
// prevention, and this reports the fraction.
//
// # Why it is a separate command
//
// The individual mechanisms are tested where they live: tamper detection in
// `pkg/evidence`, release authority in `pkg/outbox`, manifest claims in
// `pkg/registry`. What none of those can do is answer "is there an attack in
// the attack list that nothing catches", because each of them only looks where it
// already knows to look. This looks from the outside, at the whole system, with
// a list written by somebody imagining harm rather than by somebody implementing
// a feature.
//
// # Phase 5's gate, and what it is not
//
// Phase 5's external gate is split into an internal gate that blocks and an
// external criterion that is tracked. This is Phase 5's internal gate. It is not
// the mock supervisory inspection: it simulates the *adversary*, which can be
// simulated, and not the *inspector*, who decides whether the evidence suffices
// and cannot be simulated without grading our own homework.
package main

import (
	"fmt"
	"os"
	"strings"
)

var version = "dev"

// attack is one thing an adversary tries.
type attack struct {
	// name is how the attack is reported.
	name string
	// goal states what the adversary is trying to achieve, in their words. It
	// is printed on failure, because "attack 3 failed" tells an operator
	// nothing about what is now possible.
	goal string
	// run performs the attack and reports how the system responded.
	run func(t *harness) outcome
}

// outcome is what happened when an attack was attempted.
type outcome struct {
	// caught is the whole verdict: was this named, one way or another.
	caught bool
	// how says which mechanism named it, so a reader can tell prevention from
	// detection — and can tell a lucky catch from the intended one.
	how string
	// detail carries the finding or refusal verbatim.
	detail string
}

func prevented(how, detail string) outcome { return outcome{true, "prevented at " + how, detail} }
func detected(how, detail string) outcome  { return outcome{true, "detected by " + how, detail} }
func undetected(detail string) outcome     { return outcome{false, "NOT CAUGHT", detail} }

func main() {
	only := ""
	if len(os.Args) > 1 {
		only = os.Args[1]
	}

	fmt.Printf("janus-evilauditor %s — the adversarial suite, Phase 5's internal gate\n\n", version)
	fmt.Printf("Each attack is performed against a real log. The question is not whether\n")
	fmt.Printf("the write failed; it is whether the system NAMES what happened, from the\n")
	fmt.Printf("log alone. The gate is 100%%.\n\n")

	var caught, total int
	var failures []string
	for _, a := range attacks() {
		if only != "" && !strings.Contains(a.name, only) {
			continue
		}
		total++
		h, err := newHarness(a.name)
		if err != nil {
			fmt.Printf("  %-28s SETUP FAILED  %v\n", a.name, err)
			failures = append(failures, a.name+": setup: "+err.Error())
			continue
		}
		out := a.run(h)
		h.cleanup()

		mark := "CAUGHT"
		if !out.caught {
			mark = "NOT CAUGHT"
		} else {
			caught++
		}
		fmt.Printf("  %-28s %-11s %s\n", a.name, mark, out.how)
		if out.detail != "" {
			fmt.Printf("  %-28s              %s\n", "", trim(out.detail))
		}
		if !out.caught {
			failures = append(failures, fmt.Sprintf("%s — the adversary's goal: %s", a.name, a.goal))
		}
	}

	fmt.Printf("\n%d of %d attacks caught\n", caught, total)
	if len(failures) > 0 {
		fmt.Printf("\nWhat an adversary can currently do without being named:\n")
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		fmt.Printf("\njanus-evilauditor: FAIL — release is blocked on 100%% detection or\n")
		fmt.Printf("prevention, and this is not 100%%. An attack nobody catches is not made\n")
		fmt.Printf("safe by being thought unlikely.\n")
		os.Exit(1)
	}
	fmt.Printf("\njanus-evilauditor: PASS — every attack in the list is named.\n\n")
	// Printed on the way past, so that "seven attacks" is never mistaken for
	// "seven is the whole list". Two listed attacks are the subject of a standing
	// gate elsewhere, and a reader comparing this output against the list should
	// be able to see they were considered rather than dropped.
	fmt.Printf("Two of the listed attacks are gated elsewhere and are not repeated here:\n")
	for _, c := range coveredElsewhere {
		fmt.Printf("  - %s\n", c)
	}
	fmt.Printf("Named here only in the case the artifact can answer for:\n")
	for _, c := range notCoveredAndWhy {
		fmt.Printf("  - %s\n", c)
	}
	fmt.Printf("\n")
	fmt.Printf("This is the adversarial half of Phase 5's gate and not the whole of it.\n")
	fmt.Printf("A mock supervisory inspection also asks whether the evidence SUFFICES,\n")
	fmt.Printf("which is a judgement a person makes and this cannot simulate.\n")
}

func trim(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) > 110 {
		return s[:107] + "..."
	}
	return s
}
