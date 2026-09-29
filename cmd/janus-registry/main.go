// Command janus-registry works with participant manifests and the lifecycle
// they move through.
//
// The registry answers one question for every step Janus ever runs: what is
// this participant declared to do, and who said so. Everything else here
// follows from taking that question seriously.
//
//	check      validate a manifest and print its content address
//	register   enter a signed manifest as DRAFT
//	evaluate   run the conformance harness and attach the evidence
//	activate   make a version the one new sagas pin
//	suspend    stop a version, for a reason that goes on the record
//	retire     end a version permanently
//	resolve    print a manifest version as the log records it
//	inventory  the model inventory: every participant, version and standing
//	audit      re-derive the whole registry from the log and report what does
//	           not hold
//
// "audit" is the one that matters, for the same reason janus-gate audit does. A
// registry service can record an activation nothing evaluated, or a change
// record that understates what changed to dodge a revalidation. From inside,
// those look exactly like honest records. Everything they rested on is in the
// log — the manifest bytes, the signature, the evaluation, the pins every saga
// recorded — so the whole thing can be recomputed by somebody who does not
// trust the service that wrote it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mustafarslan/janus/pkg/clockwire"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/registry"
)

var version = "dev"

const usage = `janus-registry %s — participant manifests and their lifecycle

usage:
  janus-registry check     <manifest.json>
  janus-registry register  <manifest.json>        [-evidence dir] [-key path]
  janus-registry evaluate  <participant> <ver>    [-evidence dir] -sandbox doubles.json
  janus-registry activate  <participant> <ver>    [-evidence dir]
  janus-registry suspend   <participant> <ver>    [-evidence dir] -reason why
  janus-registry retire    <participant> <ver>    [-evidence dir] -reason why
  janus-registry resolve   <participant> [<ver>]  [-evidence dir]
  janus-registry inventory                        [-evidence dir]
  janus-registry audit                            [-evidence dir] [-trust keys.json]
  janus-registry trust     <principal> <keys.json>

  janus-registry template extract  -id <id> -version <v> -principal <p> -risk <1-4> \
                                   -sagas <a,b,c> [-evidence dir] [-out file]
  janus-registry template register <template.json>   [-evidence dir] -key path

  A template is a saga shape later sagas can be confined to. extract
  prints it and stops: a template confines every saga that pins it, and the runs
  it came from are a sample somebody chose, so a person reads it before it is
  registered. Once registered it is DRAFT and confines nothing until the ordinary
  evaluate and activate verbs are used on it -- a template is a registry entry.

flags:
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "check":
		err = check(args)
	case "register":
		err = register(args)
	case "evaluate":
		err = evaluate(args)
	case "activate":
		err = transition(args, "activate")
	case "suspend":
		err = transition(args, "suspend")
	case "retire":
		err = transition(args, "retire")
	case "resolve":
		err = resolve(args)
	case "inventory":
		err = inventory(args)
	case "audit":
		err = audit(args)
	case "template":
		err = templateCmd(args)
	case "trust":
		err = buildTrust(args)
	case "-h", "--help", "help":
		fmt.Fprintf(os.Stderr, usage, version)
		return
	case "-version", "--version":
		fmt.Printf("janus-registry %s\n", version)
		return
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		err = fmt.Errorf("unknown command %q", cmd)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "janus-registry: %v\n", err)
		os.Exit(1)
	}
}

// ---- reading -------------------------------------------------------------------

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("check needs a manifest file")
	}
	m, err := registry.LoadManifestFile(fs.Arg(0))
	if err != nil {
		return err
	}

	fmt.Printf("manifest %s@%s\n", m.Identity.ParticipantID, m.Version)
	fmt.Printf("  content   %s\n", m.ContentAddress())
	fmt.Printf("  principal %s (%s)\n", m.Identity.Principal, m.Identity.Kind)
	fmt.Printf("  risk      tier %d", m.Risk.Tier)
	if len(m.Risk.RevalidationTriggers) > 0 {
		fmt.Printf(", revalidates on %s", strings.Join(m.Risk.RevalidationTriggers, ", "))
	}
	fmt.Println()
	for _, a := range m.Actions {
		line := fmt.Sprintf("  %-24s %s", a.Name, a.EffectClass)
		if a.Compensation != nil {
			line += fmt.Sprintf("  undo %s", a.Compensation.Action)
		}
		if a.Limits != nil && a.Limits.MaxAmount > 0 {
			line += fmt.Sprintf("  %s ≤ %d %s", a.Limits.AmountField, a.Limits.MaxAmount, a.Limits.Currency)
		}
		fmt.Println(line)
	}
	return nil
}

func resolve(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	dir := fs.String("evidence", defaultDir, "evidence segment directory")
	asJSON := fs.Bool("json", false, "print the manifest as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("resolve needs a participant id")
	}

	reg, err := registry.Replay(*dir)
	if err != nil {
		return err
	}
	participant := fs.Arg(0)

	var e *registry.Entry
	if fs.NArg() >= 2 {
		found, ok := reg.ResolveEither(participant, fs.Arg(1))
		if !ok {
			return fmt.Errorf("%s@%s is not in the log at %s", participant, fs.Arg(1), *dir)
		}
		e = found
	} else {
		found, ok := activeEither(reg, participant)
		if !ok {
			return fmt.Errorf("%s has no active version; give a version to see one that is not",
				participant)
		}
		e = found
	}

	if *asJSON {
		blob, err := json.MarshalIndent(e.Manifest, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(blob))
		return nil
	}

	fmt.Printf("%s@%s  %s\n", e.ParticipantID, e.Version, e.State)
	fmt.Printf("  content     %s\n", e.ContentAddress)
	fmt.Printf("  registered  seq %d\n", e.RegisteredSeq)
	if e.ActivatedSeq > 0 {
		fmt.Printf("  activated   seq %d\n", e.ActivatedSeq)
	}
	if e.Reason != "" {
		fmt.Printf("  reason      %s\n", e.Reason)
	}
	if e.Change != nil {
		fmt.Printf("  changed     from %s: %s\n", e.Change.GetFromVersion(),
			strings.Join(e.Change.GetChanged(), ", "))
	}
	if len(e.PendingTriggers) > 0 {
		fmt.Printf("  owes        revalidation for %s\n", strings.Join(e.PendingTriggers, ", "))
	}
	if e.Evaluation != nil {
		fmt.Print(indent(registry.ReportText(e.Evaluation), "  "))
	}
	return nil
}

// inventory prints the model inventory a supervisor asks for: what is deployed,
// at which version, in what standing, and what it owes.
func inventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	dir := fs.String("evidence", defaultDir, "evidence segment directory")
	all := fs.Bool("all", false, "include versions that are not active")
	if err := fs.Parse(args); err != nil {
		return err
	}

	reg, err := registry.Replay(*dir)
	if err != nil {
		return err
	}
	participants := reg.Participants()
	if len(participants) == 0 {
		fmt.Printf("no participants registered in %s\n", *dir)
		return nil
	}

	fmt.Printf("%-22s %-9s %-11s %-5s %-18s %s\n",
		"PARTICIPANT", "VERSION", "STATE", "TIER", "MODEL", "NOTE")
	for _, id := range participants {
		for _, e := range reg.Versions(id) {
			if !*all && e.State != registry.StateActive {
				continue
			}
			note := ""
			switch {
			case len(e.PendingTriggers) > 0:
				note = "revalidation due: " + strings.Join(e.PendingTriggers, ", ")
			case e.Evaluation.GetInheritedFrom() != "":
				note = "evidence inherited from " + e.Evaluation.GetInheritedFrom()
			case e.Reason != "":
				note = e.Reason
			}
			model := e.Manifest.Runtime.ModelID
			if model == "" {
				model = "—"
			}
			fmt.Printf("%-22s %-9s %-11s %-5d %-18s %s\n",
				e.ParticipantID, e.Version, e.State, e.Manifest.Risk.Tier, model, note)
		}
	}
	return nil
}

func audit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	dir := fs.String("evidence", defaultDir, "evidence segment directory")
	trustPath := fs.String("trust", "", "JSON file mapping principals to the key ids trusted to sign for them")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var trust registry.TrustStore
	if *trustPath != "" {
		loaded, err := loadTrust(*trustPath)
		if err != nil {
			return err
		}
		trust = loaded
	}

	rep, err := registry.Audit(*dir, trust)
	if err != nil {
		return err
	}
	fmt.Print(rep)
	if !rep.OK() {
		return fmt.Errorf("%d thing(s) in the registry are not supported by the log", len(rep.Findings))
	}
	return nil
}

// ---- writing -------------------------------------------------------------------

func register(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	dir := fs.String("evidence", defaultDir, "evidence segment directory")
	keyPath := fs.String("key", "", "Ed25519 key that signs the manifest for its principal")
	trustPath := fs.String("trust", "", "JSON file of principals to trusted key ids; without it the signature is recorded but not checked")
	clockFlags := clockwire.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("register needs a manifest file")
	}

	m, err := registry.LoadManifestFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if *keyPath == "" {
		return fmt.Errorf("register needs -key: an unsigned manifest records a declaration " +
			"nobody is answerable for")
	}
	signer, err := keys.Load(*keyPath)
	if err != nil {
		return err
	}
	sig, err := registry.Sign(m, signer)
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
		e, err := rec.Register(context.Background(), m, sig)
		if err != nil {
			return err
		}
		fmt.Printf("registered %s@%s as %s\n", e.ParticipantID, e.Version, e.State)
		fmt.Printf("  content %s\n", e.ContentAddress)
		fmt.Printf("  signed  %s by %s\n", sig.GetKeyId(), m.Identity.Principal)
		if e.Change != nil {
			fmt.Printf("  changed from %s: %s\n", e.Change.GetFromVersion(),
				strings.Join(e.Change.GetChanged(), ", "))
			if len(e.PendingTriggers) > 0 {
				fmt.Printf("  revalidation required: %s\n", strings.Join(e.PendingTriggers, ", "))
				fmt.Printf("  the evidence that cleared %s does not carry over\n",
					e.Change.GetFromVersion())
			} else {
				fmt.Printf("  no revalidation trigger fired; `evaluate -inherit` carries the " +
					"predecessor's evidence forward, on the record\n")
			}
		}
		return nil
	})
}

func evaluate(args []string) error {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	dir := fs.String("evidence", defaultDir, "evidence segment directory")
	sandbox := fs.String("sandbox", "", "JSON description of the doubles the claims are exercised against")
	inherit := fs.Bool("inherit", false, "carry the predecessor's evidence forward, when the change fired no revalidation trigger")
	clockFlags := clockwire.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("evaluate needs a participant id and a version")
	}
	participant, ver := fs.Arg(0), fs.Arg(1)

	return withRecorder(*dir, clockFlags, nil, func(rec *registry.Recorder) error {
		ctx := context.Background()
		if *inherit {
			if err := rec.InheritEvaluation(ctx, participant, ver); err != nil {
				return err
			}
			fmt.Printf("%s@%s carries forward the evidence that cleared its predecessor\n",
				participant, ver)
			return nil
		}
		if *sandbox == "" {
			return fmt.Errorf("evaluate needs -sandbox: the declared compensations, idempotency " +
				"recipes and limits are checked by running them, not by reading them")
		}
		e, ok := rec.Registry().ResolveEither(participant, ver)
		if !ok {
			return fmt.Errorf("%s@%s is not registered", participant, ver)
		}
		if e.Template != nil {
			return fmt.Errorf("%s@%s is a template; its claims are about runs already in the "+
				"log rather than about behaviour, so it is evaluated by re-reading them: "+
				"janus-registry template evaluate %s %s", participant, ver, participant, ver)
		}
		doubles, err := registry.LoadDoubles(*sandbox)
		if err != nil {
			return err
		}
		report, err := registry.Evaluate(ctx, e.Manifest, doubles)
		if err != nil {
			return err
		}
		if err := rec.Evaluate(ctx, participant, ver, report); err != nil {
			return err
		}
		fmt.Print(registry.ReportText(report))
		if !report.GetPassed() {
			return fmt.Errorf("conformance failed; the result is on the record and the version " +
				"cannot be activated")
		}
		return nil
	})
}

func transition(args []string, what string) error {
	fs := flag.NewFlagSet(what, flag.ExitOnError)
	dir := fs.String("evidence", defaultDir, "evidence segment directory")
	reason := fs.String("reason", "", "why")
	clockFlags := clockwire.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("%s needs a participant id and a version", what)
	}
	participant, ver := fs.Arg(0), fs.Arg(1)

	return withRecorder(*dir, clockFlags, nil, func(rec *registry.Recorder) error {
		ctx := context.Background()
		var err error
		switch what {
		case "activate":
			err = rec.Activate(ctx, participant, ver)
		case "suspend":
			if *reason == "" {
				return fmt.Errorf("suspend needs -reason: without it the log records that " +
					"somebody stopped a participant and nothing about what would have to be " +
					"true to start it again")
			}
			err = rec.Suspend(ctx, participant, ver, *reason)
		case "retire":
			err = rec.Retire(ctx, participant, ver, *reason)
		}
		if err != nil {
			return err
		}
		e, ok := rec.Registry().ResolveEither(participant, ver)
		if !ok {
			// Unreachable: the transition above resolved it. Said rather than
			// dereferenced, because the version that *was* reachable here
			// segfaulted on every template -- after the event was already in
			// the log, so an operator saw a crash and could not tell whether
			// the activation had happened.
			return fmt.Errorf("%s@%s transitioned and could not be read back", participant, ver)
		}
		fmt.Printf("%s@%s is now %s\n", participant, ver, e.State)
		if what == "activate" {
			for _, other := range rec.Registry().VersionsEither(participant) {
				if other.Version != ver && other.State == registry.StateSuperseded {
					fmt.Printf("  %s@%s is superseded; sagas that pinned it still resolve to it\n",
						participant, other.Version)
				}
			}
		}
		return nil
	})
}

// ---- plumbing ------------------------------------------------------------------

const defaultDir = "./janus-evidence"

// withRecorder opens the log, folds the registry out of it, and runs one
// mutation.
//
// The projection is rebuilt from the segments every time rather than cached
// anywhere. That is slow and it is the only version that cannot be wrong: the
// log is the system of record, and a CLI holding a stale idea of which version
// is active would refuse or permit transitions on the strength of it.
func withRecorder(dir string, clockFlags *clockwire.Flags, trust registry.TrustStore,
	fn func(*registry.Recorder) error) error {
	who := evidence.ParticipantRef{
		ID:              "sys_registry",
		ManifestVersion: version,
		Kind:            "SYSTEM",
	}
	// One-shot: this command records one lifecycle transition and exits, so it
	// takes a single attestation rather than running a monitor. It attests its
	// own clock rather than pointing at the daemon's, because an attestation
	// measures the clock of the process that took it.
	clockCfg := clockFlags.Config(who)
	clockCfg.WarnIfUnattested("janus-registry", dir)

	// The log is opened before it is read, because opening it is what creates
	// the directory on a first registration. Nothing is appended by opening —
	// except the attestation, which is appended deliberately and is the reason
	// the registry's own records can now say anything about when they happened.
	app, _, err := clockwire.Open(context.Background(), clockCfg,
		evidence.Options{Dir: dir, SyncMode: segment.SyncModeFull})
	if err != nil {
		return err
	}
	reg, err := registry.Replay(dir)
	if err != nil {
		_ = app.Close()
		return err
	}
	rec := registry.NewRecorder(app, who, reg, trust)

	runErr := fn(rec)
	closeErr := app.Close()
	if runErr != nil {
		return runErr
	}
	return closeErr
}

// trustFile is the on-disk trust store: principal -> key id -> hex public key.
//
// It is a separate artifact from the evidence and from the manifests on purpose.
// A signature checked against keys that travelled with the thing they sign
// proves nothing, which is the same reason janus-verify takes writer keys
// separately.
type trustFile map[string]keys.PublicKeySet

// buildTrust prints a trust store binding a principal to the keys in a public
// key set, so an operator can assemble one with the tools already in the box.
//
// Deciding that a key may speak for a legal entity is the whole substance of
// the trust store, so it is a deliberate command somebody runs rather than
// something a registration infers from the manifest in front of it.
func buildTrust(args []string) error {
	fs := flag.NewFlagSet("trust", flag.ExitOnError)
	into := fs.String("into", "", "an existing trust store to merge into, rather than starting a new one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("trust needs a principal and a public key set (janus-keys pub ...)")
	}
	principal, keySetPath := fs.Arg(0), fs.Arg(1)

	out := trustFile{}
	if *into != "" {
		raw, err := os.ReadFile(*into)
		if err != nil {
			return fmt.Errorf("read trust store: %w", err)
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return fmt.Errorf("parse trust store %s: %w", *into, err)
		}
	}

	raw, err := os.ReadFile(keySetPath)
	if err != nil {
		return fmt.Errorf("read key set: %w", err)
	}
	var set keys.PublicKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return fmt.Errorf("parse key set %s: %w", keySetPath, err)
	}
	if len(set) == 0 {
		return fmt.Errorf("%s holds no keys", keySetPath)
	}
	if out[principal] == nil {
		out[principal] = keys.PublicKeySet{}
	}
	for id, pub := range set {
		out[principal][id] = pub
	}

	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(blob))
	return nil
}

func loadTrust(path string) (registry.TrustStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust store: %w", err)
	}
	var tf trustFile
	if err := json.Unmarshal(raw, &tf); err != nil {
		return nil, fmt.Errorf("parse trust store %s: %w", path, err)
	}
	out := registry.TrustStore{}
	principals := make([]string, 0, len(tf))
	for p := range tf {
		principals = append(principals, p)
	}
	sort.Strings(principals)
	for _, p := range principals {
		for _, pub := range tf[p] {
			out.Trust(p, pub)
		}
	}
	return out, nil
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n") + "\n"
}

// activeEither is `Active` for whichever map holds the id.
func activeEither(reg *registry.Registry, id string) (*registry.Entry, bool) {
	if e, ok := reg.Active(id); ok {
		return e, true
	}
	return reg.ActiveTemplate(id)
}
