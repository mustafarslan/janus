// Command janus-gate works with gate policies and the decisions made under
// them.
//
// It has three jobs, and the third is the one that matters.
//
//	check    validate a policy document and print its content address
//	explain  show what a plan would owe under a policy, before running it
//	audit    re-derive every gate decision in an evidence log and compare
//
// "check" and "explain" are for the person writing the policy. A typo in an
// expression should be caught when somebody deploys the file, not when a
// payment reaches the gate it guards at three in the morning; and "which gates
// will this workflow have to pass" is a question asked constantly and usually
// answered by reading code.
//
// "audit" is for the person who does not trust the answer. A gate verdict in
// the log proves a decision was made. It does not prove the decision was
// correct, and a coordinator with a bug — or one doing what an injected
// instruction told it — writes a passing verdict that looks exactly like an
// honest one. Everything a verdict rested on is recorded beside it, so the
// decision can be recomputed by somebody else, later, holding nothing but the
// log. That is the difference between evidence and paperwork.
package main

import (
	"flag"
	"fmt"
	"os"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/gate"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}

	var err error
	switch cmd := flag.Arg(0); cmd {
	case "check":
		err = check(flag.Arg(1))
	case "explain":
		err = explain(flag.Arg(1), flag.Arg(2))
	case "audit":
		err = audit(flag.Arg(1))
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "janus-gate: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `janus-gate — gate policies and the decisions made under them

  janus-gate check   <policy.json>
      Validate a policy and print its content address. Every expression is
      compiled, so a typo fails here rather than at a gate.

  janus-gate explain <policy.json> <plan.json>
      Print what each step in a saga plan would owe under the policy.
      The plan is a SagaBegin message in protojson form.

  janus-gate audit   <evidence-dir>
      Re-derive every gate decision in the log from the inputs recorded with
      it, and report any verdict the inputs do not support. Needs nothing but
      the log — not the policy document, and not the system that wrote it.
      Exits non-zero if anything does not hold.
`)
}

func check(path string) error {
	if path == "" {
		return fmt.Errorf("check needs a policy file")
	}
	p, err := gate.LoadPolicyFile(path)
	if err != nil {
		return err
	}
	rules := 0
	for range p.Rules {
		rules++
	}
	fmt.Printf("policy %s\n", p.ID)
	fmt.Printf("  version %s\n", p.Version())
	fmt.Printf("  %d rule(s), every expression compiles\n", rules)
	return nil
}

func explain(policyPath, planPath string) error {
	if policyPath == "" || planPath == "" {
		return fmt.Errorf("explain needs a policy file and a plan file")
	}
	p, err := gate.LoadPolicyFile(policyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(planPath)
	if err != nil {
		return fmt.Errorf("read plan: %w", err)
	}
	var begin janusv1.SagaBegin
	if err := protojson.Unmarshal(raw, &begin); err != nil {
		return fmt.Errorf("decode plan: %w", err)
	}

	e := gate.NewEngine(p)
	fmt.Print(e.Explain(&begin))

	// Explaining says what the gates would be; admitting says whether the plan
	// is allowed to run at all. Reporting both means an inadmissible plan is
	// visible here rather than at submission.
	if err := e.Admit(&begin); err != nil {
		return err
	}
	fmt.Printf("\nadmissible under %s\n", e.Version())
	return nil
}

func audit(dir string) error {
	if dir == "" {
		return fmt.Errorf("audit needs an evidence directory")
	}
	rep, err := gate.Audit(dir)
	if err != nil {
		return err
	}
	fmt.Print(rep)
	if !rep.OK() {
		return fmt.Errorf("%d gate decision(s) are not supported by the log", len(rep.Findings))
	}
	return nil
}
