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
//
// Re-deriving a decision says nothing about who wrote the record it rests on.
// A log re-sealed under a stranger's key re-derives exactly as well as the
// real one, and the signature check on answers trusts the registry the log
// itself carries. So "audit -keys" authenticates the log against the writer's
// public key first, the way janus-verify does, and audits only a log that
// passes; without it, the report says the log was not authenticated.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
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
		err = audit(flag.Args()[1:], os.Stdout)
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

  janus-gate audit   [-keys pub.json [-expect-head H] [-require-signed-manifest]] <evidence-dir|bundle>
      Re-derive every gate decision in the log from the inputs recorded with
      it, and report any verdict the inputs do not support. Needs nothing but
      the log and, with -keys, the writer's public key — not the policy
      document, and not the system that wrote it. With -keys the log is
      verified against that key first and not audited if it fails; without
      it, nothing says who wrote the log. Exits non-zero if anything does not
      hold.
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

// errNotAuthenticated is the refusal to audit a log that does not verify
// against the key the auditor trusts.
var errNotAuthenticated = errors.New("the log does not verify against the trusted key; not audited")

func audit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	keyFile := fs.String("keys", "", "the writer's public key set (as janus-keys pub writes it); "+
		"the log is verified against it before anything is re-derived")
	expectHead := fs.String("expect-head", "", "with -keys: the head chain hash obtained out of band, "+
		"as janus-verify takes it; without one, a log cut off at its end verifies as a shorter log")
	reqSigned := fs.Bool("require-signed-manifest", false, "with -keys, for a bundle: fail unless "+
		"its manifest is signed, as janus-verify does")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := fs.Arg(0)
	if dir == "" || fs.NArg() > 1 {
		return fmt.Errorf("audit needs one evidence directory or bundle")
	}
	// A bundle keeps its segments under segments/; audited as it stands, it
	// would hold no sagas and pass vacuously.
	segments := dir
	_, statErr := os.Stat(filepath.Join(dir, bundle.ManifestName))
	isBundle := statErr == nil
	if isBundle {
		segments = filepath.Join(dir, "segments")
	}
	if *keyFile == "" && (*expectHead != "" || *reqSigned) {
		return fmt.Errorf("-expect-head and -require-signed-manifest need -keys")
	}
	if *keyFile == "" {
		_, _ = fmt.Fprintln(out, "log not authenticated: no -keys given, so nothing here says who wrote it, "+
			"and answer signatures are checked against the registry the log carries; "+
			"pass -keys or run janus-verify first")
	} else {
		set, err := loadKeys(*keyFile)
		if err != nil {
			return err
		}
		opts := verify.Options{Keys: set, ExpectHeadChain: *expectHead, RequireSignedManifest: *reqSigned}
		var vrep *verify.Report
		switch {
		case isBundle:
			vrep, err = verify.Bundle(dir, opts)
		case *reqSigned:
			return fmt.Errorf("%s is a segment directory, not a bundle, so it has no manifest to "+
				"require a signature on; use -expect-head for a raw log", dir)
		default:
			vrep, err = verify.SegmentDir(dir, opts)
		}
		if err != nil {
			return err
		}
		if !vrep.OK {
			_, _ = fmt.Fprint(out, vrep.Text())
			return errNotAuthenticated
		}
		_, _ = fmt.Fprintf(out, "log authenticated: %d events verify against %s\n", vrep.Events, *keyFile)
	}
	rep, err := gate.Audit(segments)
	if err != nil {
		return err
	}
	if rep.Sagas == 0 {
		return fmt.Errorf("%s holds no sagas; an audit of nothing is not a pass", dir)
	}
	_, _ = fmt.Fprint(out, rep)
	if !rep.OK() {
		return fmt.Errorf("%d gate decision(s) are not supported by the log", len(rep.Findings))
	}
	return nil
}

// loadKeys reads a public key set the way janus-verify does.
func loadKeys(path string) (keys.PublicKeySet, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set keys.PublicKeySet
	if err := json.Unmarshal(blob, &set); err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", path, err)
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("key file %s contains no keys", path)
	}
	return set, nil
}
