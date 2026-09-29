package clockwire

import (
	"flag"
	"log"
	"strings"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/clockatt"
)

// Flags are the three flags every process that writes an evidence log takes.
//
// They are registered from here rather than copied into each binary because six
// copies of a flag's help text drift, and the text is where the reasoning lives:
// that the empty default is deliberate, and that the tolerance is a
// maximum rather than a dial.
type Flags struct {
	sources   *string
	interval  *time.Duration
	tolerance *time.Duration
}

// RegisterFlags adds the clock flags to a flag set. Pass flag.CommandLine for a
// binary with no subcommands.
func RegisterFlags(fs *flag.FlagSet) *Flags {
	return &Flags{
		sources: fs.String("clock-sources", "",
			"comma-separated NTP servers (host:port) to attest this process's clock against,\n"+
				"tried in order. Every event this process appends then points at a recorded\n"+
				"attestation of what the clock was disciplined against and how far off it was\n"+
				"(MiFID II RTS 25). Empty takes no attestation and says so by omitting\n"+
				"the reference: an air-gapped install should not acquire a network dependency\n"+
				"by default"),
		interval: fs.Duration("clock-interval", 0,
			"how often to attest the clock in a long-running process; zero means every five\n"+
				"minutes. A one-shot command attests once and ignores this"),
		tolerance: fs.Duration("clock-tolerance", 0,
			"the synchronisation bound this deployment claims to hold; crossing it is logged,\n"+
				"and the bound itself is recorded in every attestation so an auditor reading\n"+
				"the log can check the figure that was claimed rather than only RTS 25's\n"+
				"ceiling. Zero means one second, RTS 25's figure for activity other than\n"+
				"high-frequency trading -- and it is a maximum, so declaring more is a\n"+
				"finding, not a looser posture"),
	}
}

// Config turns the parsed flags into a Config for the given participant.
func (f *Flags) Config(by evidence.ParticipantRef) Config {
	cfg := Config{Interval: *f.interval, Tolerance: *f.tolerance, Participant: by}
	for _, server := range strings.Split(*f.sources, ",") {
		if server = strings.TrimSpace(server); server != "" {
			cfg.Sources = append(cfg.Sources, clockatt.NTPSource{Server: server})
		}
	}
	return cfg
}

// WarnIfUnattested says out loud that this process will record nothing about
// its clock, so a deployment that meant to attest and mistyped the flag does not
// look identical to one that chose not to.
//
// It is on the Config rather than on the Clock because a caller has the config
// before it has anything else, and the thing worth saying at startup is what was
// asked for.
//
// `dir` is the evidence directory about to be written, and it is what makes the
// two cases distinguishable. `-clock-sources` is per process, so an operator who
// set it on the daemon can still forget it on a one-shot, and at one time both
// deployments got the same sentence: the one that chose not to attest, and the
// one that attests everywhere except this invocation. The directory's writer
// marker says which — it records what the writer that attested here was
// configured with. An empty `dir` skips the lookup and keeps the old sentence,
// which is the right answer for a caller with no directory in hand.
func (cfg Config) WarnIfUnattested(prog, dir string) {
	if len(cfg.Sources) > 0 {
		return
	}
	if dir != "" {
		if sources, tolerance, ok, err := evidence.WriterClockDeclaration(dir); err == nil && ok {
			log.Printf("%s: no clock source configured, so the events this process appends "+
				"will carry no clock attestation — and a writer in %s attests against %s "+
				"(tolerance %s), so this log will hold attested events beside these "+
				"unattested ones. Pass -clock-sources %s unless that is what you meant",
				prog, dir, strings.Join(sources, ","), tolerance,
				strings.Join(stripScheme(sources), ","))
			return
		}
	}
	log.Printf("%s: no clock source configured, so the events this process appends will "+
		"carry no clock attestation; pass -clock-sources to record one", prog)
}

// stripScheme turns the source names back into the form the flag takes.
//
// A source records itself as `ntp:host:port` and `-clock-sources` wants
// `host:port`. Printing the recorded form in an instruction to retype would be
// telling an operator to pass something the flag does not accept, which is a
// worse kind of wrong than saying nothing.
func stripScheme(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, strings.TrimPrefix(n, "ntp:"))
	}
	return out
}
