// janus-compliance says which regulatory articles a deployment can satisfy,
// before an inspector says which it cannot.
//
//	janus-compliance lint -evidence ./janus-evidence -policy docs/policy/reference.json
//
// It reads the registry and the gate policy — what participants declared and
// what the policy requires of them — and evaluates them against compliance
// packs. Packs are data: a legal review that changes a mapping produces a new
// pack version, not a new build.
//
// It deliberately does not read a log. An article about controls asks what is
// allowed to happen; a log answers what did. The second question is what
// janus-verify and janus-conformance are for, and conflating them would let a
// quiet month read as a control.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mustafarslan/janus/pkg/compliance"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/registry"
)

var version = "dev"

const usage = `janus-compliance %s — which articles a deployment can satisfy

usage:
  janus-compliance lint    [-evidence dir] [-policy file] [-packs dir] [-json]
  janus-compliance packs   [-packs dir]      list the packs and what they check
  janus-compliance checks                    list the check vocabulary

flags:
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "janus-compliance: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		evidenceDir = flag.String("evidence", "./janus-evidence",
			"evidence directory the registry is read from")
		policyPath = flag.String("policy", "", "gate policy document")
		packDir    = flag.String("packs", "docs/compliance/packs", "directory of compliance packs")
		asJSON     = flag.Bool("json", false, "print the report as JSON")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), usage, version)
		flag.PrintDefaults()
	}
	command := ""
	if len(os.Args) > 1 && os.Args[1][0] != '-' {
		command = os.Args[1]
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	flag.Parse()
	if *showVer {
		fmt.Println("janus-compliance", version)
		return nil
	}

	switch command {
	case "checks":
		for _, name := range compliance.CheckNames() {
			fmt.Println(name)
		}
		return nil
	case "packs":
		packs, err := compliance.LoadPacks(*packDir)
		if err != nil {
			return err
		}
		for _, pack := range packs {
			fmt.Printf("%s  %s (%s, pack version %s)\n",
				pack.ID, pack.Framework, pack.Jurisdiction, pack.Version)
			for _, article := range pack.Articles {
				fmt.Printf("    %-14s %s\n", article.ID, article.Title)
			}
		}
		return nil
	case "lint":
		return lint(*evidenceDir, *policyPath, *packDir, *asJSON)
	default:
		flag.Usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func lint(evidenceDir, policyPath, packDir string, asJSON bool) error {
	packs, err := compliance.LoadPacks(packDir)
	if err != nil {
		return err
	}

	subject := compliance.Subject{}
	events, err := registry.LoadEvents(evidenceDir)
	if err != nil {
		return fmt.Errorf("reading the registry: %w", err)
	}
	reg, err := registry.Fold(events)
	if err != nil {
		return fmt.Errorf("folding the registry: %w", err)
	}
	subject.Registry = reg

	// The pin comes from the log, not from a flag. A jurisdiction typed on this
	// command line would be a claim about the deployment; one read out of its
	// own evidence is a fact about it, and a report built on the first would
	// lint against a pin the deployment does not have.
	tenant, err := evidence.TenantOfDir(evidenceDir)
	if err != nil {
		return fmt.Errorf("reading the tenant binding from the log: %w", err)
	}
	subject.Tenant = tenant

	// The same read, for the same reason. RTS 25 Art. 4 asks a firm to
	// *demonstrate* traceability to UTC, and a demonstration is not something a
	// deployment can declare — it is either in the evidence or it is not. A flag
	// saying "our clocks are synchronised" would be the claim rather than the
	// demonstration.
	clock, err := compliance.ClockTraceabilityOf(evidenceDir)
	if err != nil {
		return fmt.Errorf("reading the clock attestations from the log: %w", err)
	}
	subject.Clock = clock

	if policyPath != "" {
		policy, perr := gate.LoadPolicyFile(policyPath)
		if perr != nil {
			return fmt.Errorf("loading the policy: %w", perr)
		}
		subject.Policy = policy
	}

	report := compliance.Lint(subject, packs)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Print(report)
	if !report.Clean() {
		// Exposed articles are the point of running this, so the exit status
		// says so — a lint nobody can put in a pipeline is a lint nobody runs.
		os.Exit(1)
	}
	return nil
}
