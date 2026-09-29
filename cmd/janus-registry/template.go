package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/clockwire"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/template"
)

// Saga templates on the command line.
//
// `template.Extract` and `registry.RegisterTemplate` were library calls, so
// crystallized mode was built, enforced, and unusable by anyone who was not
// compiling this repository. A control nobody can switch on is a control the
// deployment does not have.
//
// # Why extract does not register
//
// It prints the document and stops. The tempting shape is one command that
// extracts, registers and activates, and it would make it trivial to crystallise
// whatever a handful of recent runs happened to do — which is the failure
// `template.MinimumRuns` only half prevents, because a count is a floor and not
// a judgement.
//
// The judgement is a person reading the shape and the provenance and deciding
// whether those runs are representative. That step should be inconvenient to
// skip, so the two verbs are separate and the second one takes a file somebody
// has looked at.

func templateCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("template needs a subcommand: extract, register, evaluate")
	}
	switch args[0] {
	case "extract":
		return templateExtract(args[1:])
	case "register":
		return templateRegister(args[1:])
	case "evaluate":
		return templateEvaluate(args[1:])
	default:
		return fmt.Errorf("unknown template subcommand %q; try extract, register or evaluate",
			args[0])
	}
}

func templateExtract(args []string) error {
	fs := flag.NewFlagSet("template extract", flag.ExitOnError)
	dir := fs.String("evidence", defaultDir, "evidence segment directory")
	id := fs.String("id", "", "template id, e.g. tpl_loan_intake")
	version := fs.String("version", "", "version this shape is registered as")
	principal := fs.String("principal", "", "legal entity answerable for the template")
	risk := fs.Uint("risk", 0, "risk tier, 1 (highest) to 4")
	sagas := fs.String("sagas", "", "comma-separated saga ids to extract the shape from")
	out := fs.String("out", "", "write the document here instead of stdout")
	child := fs.String("child", "", "step=templateID pairs, comma separated: the template a "+
		"sub-saga spawned by that step must pin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *id == "" || *version == "" || *principal == "":
		return fmt.Errorf("template extract needs -id, -version and -principal")
	case *risk == 0 || *risk > 4:
		return fmt.Errorf("template extract needs -risk between 1 and 4; the tier is what a " +
			"deployment decides how much evidence to demand from, and there is no default " +
			"that is right for a shape nobody has looked at")
	case *sagas == "":
		return fmt.Errorf("template extract needs -sagas: the shape comes from runs that " +
			"already happened")
	}

	var ids []string
	for _, p := range strings.Split(*sagas, ",") {
		if p = strings.TrimSpace(p); p != "" {
			ids = append(ids, p)
		}
	}
	states, err := saga.ReplaySome(*dir, ids)
	if err != nil {
		return err
	}

	children, err := childTemplates(*dir, *child)
	if err != nil {
		return err
	}

	runs := make([]template.Run, 0, len(ids))
	for _, sagaID := range ids {
		st := states[sagaID]
		begin, err := saga.BeginOf(*dir, sagaID)
		if err != nil {
			return err
		}
		spawned, err := childBegins(*dir, st)
		if err != nil {
			return err
		}
		runs = append(runs, template.Run{State: st, Begin: begin, Children: spawned})
	}

	tpl, err := template.Extract(*id, *version, *principal, uint32(*risk), runs, children)
	if err != nil {
		return err
	}
	blob, err := json.MarshalIndent(tpl, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')

	if *out == "" {
		fmt.Print(string(blob))
	} else if err := os.WriteFile(*out, blob, 0o640); err != nil {
		return err
	}

	// To stderr, so it is visible when the document is being piped to a file and
	// is not part of the document.
	fmt.Fprintf(os.Stderr, "\nextracted %s@%s from %d run(s) in %s mode\n",
		tpl.TemplateID, tpl.Version, tpl.Provenance.Runs, tpl.Provenance.ExtractedFrom)
	fmt.Fprintf(os.Stderr, "  %d step(s), %d slot(s)\n", len(tpl.Steps), len(tpl.Slots))
	for _, sl := range tpl.Slots {
		if len(sl.Observed) == 1 {
			fmt.Fprintf(os.Stderr, "  slot %s.%s never varied across these runs (always %q) "+
				"— it may be a constant rather than a choice\n", sl.StepID, sl.Name, sl.Observed[0])
		}
	}
	fmt.Fprintln(os.Stderr, "\nread it before registering it. A template confines every saga "+
		"that pins it, and these runs are a sample somebody chose.")
	return nil
}

func templateRegister(args []string) error {
	fs := flag.NewFlagSet("template register", flag.ExitOnError)
	dir := fs.String("evidence", defaultDir, "evidence segment directory")
	keyPath := fs.String("key", "", "Ed25519 key that signs the template for its principal")
	trustPath := fs.String("trust", "", "JSON file of principals to trusted key ids")
	clockFlags := clockwire.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("template register needs a template document")
	}
	if *keyPath == "" {
		return fmt.Errorf("template register needs -key: an unsigned template confines sagas " +
			"on nobody's authority")
	}

	blob, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var tpl template.Template
	if err := json.Unmarshal(blob, &tpl); err != nil {
		return fmt.Errorf("reading %s: %w", fs.Arg(0), err)
	}
	if err := tpl.Validate(); err != nil {
		return err
	}
	signer, err := keys.Load(*keyPath)
	if err != nil {
		return err
	}
	sig, err := registry.SignTemplate(&tpl, signer)
	if err != nil {
		return err
	}

	var trust registry.TrustStore
	if *trustPath != "" {
		if trust, err = loadTrust(*trustPath); err != nil {
			return err
		}
	}
	return withRecorder(*dir, clockFlags, trust, func(rec *registry.Recorder) error {
		e, err := rec.RegisterTemplate(context.Background(), &tpl, sig)
		if err != nil {
			return err
		}
		fmt.Printf("registered template %s@%s as %s\n", e.ParticipantID, e.Version, e.State)
		fmt.Printf("  content %s\n", e.ContentAddress)
		fmt.Printf("  signed  %s by %s\n", sig.GetKeyId(), tpl.Principal)
		fmt.Printf("  from    %d run(s) in %s mode\n",
			tpl.Provenance.Runs, tpl.Provenance.ExtractedFrom)
		fmt.Printf("\nit confines nothing until it is evaluated and activated:\n")
		fmt.Printf("  janus-registry evaluate %s %s ...\n", e.ParticipantID, e.Version)
		fmt.Printf("  janus-registry activate %s %s\n", e.ParticipantID, e.Version)
		return nil
	})
}

// childTemplates resolves the -child declarations against the registry.
//
// The templates are read from the log rather than taken on the operator's word
// for the same reason `Extract` then matches them against the runs: this flag is
// a claim about what a sub-saga is confined to, and a claim about a template
// that is not registered confines nothing. Registration order follows —
// leaves first, then the parent that names them.
func childTemplates(dir, spec string) (map[string]*template.Template, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	reg, err := registry.Replay(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		stepID, templateID, ok := strings.Cut(pair, "=")
		stepID, templateID = strings.TrimSpace(stepID), strings.TrimSpace(templateID)
		if !ok || stepID == "" || templateID == "" {
			return nil, fmt.Errorf("-child takes step=templateID pairs; %q is not one", pair)
		}
		e, active := reg.ActiveTemplate(templateID)
		if !active {
			return nil, fmt.Errorf("-child names template %q for step %q, and no version of "+
				"it is active; a step cannot be confined to a shape nobody has validated",
				templateID, stepID)
		}
		out[stepID] = e.Template
	}
	return out, nil
}

// childBegins reads the SAGA_BEGIN of every sub-saga this run spawned.
//
// `State.Steps[id].Child` says which saga a step delegated to; the plan that
// saga ran is on its own beginning, which is the second read `template.Extract`
// cannot do for itself.
func childBegins(dir string, st saga.State) (map[string]*janusv1.SagaBegin, error) {
	var out map[string]*janusv1.SagaBegin
	for stepID, step := range st.Steps {
		if step == nil || step.Child == nil {
			continue
		}
		begin, err := saga.BeginOf(dir, step.Child.SagaID)
		if err != nil {
			return nil, fmt.Errorf("reading sub-saga %q, spawned by step %q of %q: %w",
				step.Child.SagaID, stepID, st.SagaID, err)
		}
		if out == nil {
			out = map[string]*janusv1.SagaBegin{}
		}
		out[stepID] = begin
	}
	return out, nil
}

// templateEvaluate re-reads the runs a template names and records the verdict.
//
// A separate verb from `janus-registry evaluate` because the two harnesses ask
// different questions of different documents: a manifest's claims are
// about behaviour and need a sandbox, a template's are about runs already in the
// log and need the log. Sharing one verb would mean a `-sandbox` flag that is
// required for one kind and meaningless for the other.
//
// The log walk is the same one `extract` does, deliberately: whatever the
// extractor compared the document against is what the evaluation re-compares it
// against, and two different walks would be two different questions.
func templateEvaluate(args []string) error {
	fs := flag.NewFlagSet("template evaluate", flag.ExitOnError)
	dir := fs.String("evidence", defaultDir, "evidence segment directory")
	clockFlags := clockwire.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("template evaluate needs a template id and a version")
	}
	templateID, version := fs.Arg(0), fs.Arg(1)

	return withRecorder(*dir, clockFlags, nil, func(rec *registry.Recorder) error {
		ctx := context.Background()
		e, ok := rec.Registry().ResolveTemplate(templateID, version)
		if !ok {
			return fmt.Errorf("%s@%s is not a registered template", templateID, version)
		}
		tpl := e.Template

		runs, children, err := sourceRuns(*dir, rec.Registry(), tpl)
		if err != nil {
			return err
		}
		report, err := template.Evaluate(tpl, runs, children)
		if err != nil {
			return err
		}
		if err := rec.Evaluate(ctx, templateID, version, report); err != nil {
			return err
		}
		fmt.Print(registry.ReportText(report))
		if !report.GetPassed() {
			return fmt.Errorf("template conformance failed; the result is on the record and " +
				"the version cannot be activated")
		}
		return nil
	})
}

// sourceRuns reads the runs a template's provenance names, and the templates its
// steps confine their children to.
//
// The child templates are resolved by whichever version is *active*, the same as
// `-child` at extract time: the check is that those runs' sub-sagas have the
// shape the operator can still point at, and matching against a draft would be
// checking a claim with a document nobody has reviewed.
func sourceRuns(dir string, reg *registry.Registry, tpl *template.Template) ([]template.Run,
	map[string]*template.Template, error) {

	ids := append([]string(nil), tpl.Provenance.SagaIDs...)
	states, err := saga.ReplaySome(dir, ids)
	if err != nil {
		return nil, nil, err
	}
	runs := make([]template.Run, 0, len(ids))
	for _, sagaID := range ids {
		st, ok := states[sagaID]
		if !ok {
			return nil, nil, fmt.Errorf("template %s@%s names saga %q in its provenance and "+
				"the log at %s has no such saga; the provenance is what makes a template's "+
				"claim checkable, so an unreadable one is not a verdict",
				tpl.TemplateID, tpl.Version, sagaID, dir)
		}
		begin, err := saga.BeginOf(dir, sagaID)
		if err != nil {
			return nil, nil, err
		}
		spawned, err := childBegins(dir, st)
		if err != nil {
			return nil, nil, err
		}
		runs = append(runs, template.Run{State: st, Begin: begin, Children: spawned})
	}

	var children map[string]*template.Template
	for _, step := range tpl.Steps {
		if step.ChildTemplate == "" {
			continue
		}
		child, active := reg.ActiveTemplate(step.ChildTemplate)
		if !active {
			return nil, nil, fmt.Errorf("template %s@%s confines step %q's children to %q, and "+
				"no version of it is active; the claim cannot be checked against a shape "+
				"nobody has validated", tpl.TemplateID, tpl.Version, step.StepID,
				step.ChildTemplate)
		}
		if children == nil {
			children = map[string]*template.Template{}
		}
		children[step.ChildTemplate] = child.Template
	}
	return runs, children, nil
}
