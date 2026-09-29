// Command janus-tier moves sealed evidence into the write-once archive and
// reports on retention.
//
// It is the operator-facing half of the archive tier and retention. The
// three things it does are deliberately separate commands, because they carry
// very different consequences: archiving is additive, the immutability drill is
// a read-only proof, and retention reporting only ever answers questions —
// nothing here deletes anything.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mustafarslan/janus/pkg/clockwire"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/continuous"
	"github.com/mustafarslan/janus/pkg/evidence/crypto"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/objstore"
	"github.com/mustafarslan/janus/pkg/evidence/retention"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
	"github.com/mustafarslan/janus/pkg/evidence/worm"
)

var version = "dev"

const usage = `janus-tier %s — evidence archive and retention

usage:
  janus-tier archive   [flags]   copy sealed segments into write-once storage
  janus-tier prove     [flags]   attempt to destroy an archived record and require refusal
  janus-tier retention [flags]   print the retention schedule, and what enforces it
  janus-tier retention hold      place or release a legal hold ('retention holds' lists them)
  janus-tier erase     [flags]   erase a data subject by destroying their key
  janus-tier export    [flags]   write an audit bundle: sealed segments, with proofs
  janus-tier backup    [flags]   write a signed backup, open tail included
  janus-tier restore   [flags]   restore one into an empty directory, verifying as it goes
  janus-tier sweep     [flags]   run one full re-verification now and time it
  janus-tier watch     [flags]   continuously re-verify the log

export and backup both write bundles, and the difference is the point of having
two commands. An audit bundle is sealed segments only, so every byte in it is
covered by a signed footer, and it can carry Merkle inclusion proofs for one
saga. A backup adds the two things an auditor does not want: the unsealed tail,
because leaving it out costs a whole segment of RPO, and a signature over the
manifest, because an unsealed segment carries no footer of its own and because a
manifest an attacker can rewrite is a segment list they can shorten. A restore
refuses an unsigned one for that reason.

Neither artifact can prove that records were not dropped from its end — a valid
prefix of a hash chain is a valid hash chain. The manifest's head closes that,
and only if it reaches the auditor by a route the bundle did not. export prints
it in the form janus-verify -expect-head takes.

A restore checks the signature, the digests and the chain before it finishes, and
does NOT run the signature and Merkle sweep — at 100M events that alone took
254.5 s against a 300 s RTO budget. Run janus-tier sweep against the
restored directory afterwards; until it completes, the bytes are trusted on their
digests and their chain alone, and how long that lasts is what sweep measures.

flags:
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "archive":
		err = archive(args)
	case "prove":
		err = prove(args)
	case "retention":
		// `retention` prints the schedule; `retention hold(s)` is about the
		// holds recorded in a particular log, which is a different question and
		// takes different flags.
		switch {
		case len(args) > 0 && args[0] == "hold":
			err = holdCmd(args[1:])
		case len(args) > 0 && args[0] == "holds":
			err = showHolds(args[1:])
		default:
			err = showRetention(args)
		}
	case "erase":
		err = erase(args)
	case "export":
		err = export(args)
	case "backup":
		err = backup(args)
	case "restore":
		err = restore(args)
	case "sweep":
		err = sweep(args)
	case "watch":
		err = watch(args)
	case "-h", "--help", "help":
		fmt.Fprintf(os.Stderr, usage, version)
		return
	case "-version", "--version":
		fmt.Printf("janus-tier %s\n", version)
		return
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "janus-tier: %v\n", err)
		os.Exit(1)
	}
}

// storageFlags are shared by the commands that talk to object storage.
type storageFlags struct {
	endpoint     string
	bucket       string
	accessKey    string
	secretKey    string
	pathStyle    bool
	prefix       string
	jurisdiction string
	retention    time.Duration
	schedule     string
}

func (s *storageFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.endpoint, "endpoint", os.Getenv("JANUS_S3_ENDPOINT"), "S3 endpoint (empty for AWS)")
	fs.StringVar(&s.bucket, "bucket", "janus-evidence", "bucket, which must have been created with Object Lock enabled")
	fs.StringVar(&s.accessKey, "access-key", os.Getenv("JANUS_S3_ACCESS_KEY"), "access key (empty uses the ambient credential chain)")
	fs.StringVar(&s.secretKey, "secret-key", os.Getenv("JANUS_S3_SECRET_KEY"), "secret key")
	fs.BoolVar(&s.pathStyle, "path-style", true, "address buckets as /bucket/key, which MinIO and most appliances need")
	fs.StringVar(&s.prefix, "prefix", "", "key prefix, for keeping several kinds of artefact apart in one bucket. Not for separating tenants: a prefix separates key names and nothing else — one bucket policy, one credential, one Object Lock configuration.")
	fs.StringVar(&s.jurisdiction, "jurisdiction", "", "region code the operator declares this bucket's bytes rest in (EU, DE, UK). Declared, not measured; it is what a jurisdictionally pinned tenant is checked against.")
	fs.DurationVar(&s.retention, "retention", 0, "how long archived segments cannot be deleted.\n"+
		"Zero derives it from the retention schedule's longest minimum, which is what\n"+
		"an archived segment needs: it holds records of every class mixed together, so\n"+
		"one lock has to cover all of them. Setting this SHORTER than the schedule\n"+
		"requires is refused")
	fs.StringVar(&s.schedule, "schedule", "", "retention schedule JSON file the lock duration is\n"+
		"derived from and checked against (default: the built-in schedule)")
}

// lockDuration is how long the archive must hold a segment.
//
// `worm.Config.Retention` states what it needs — "the longest any record in the
// log could require" — and until now had no way to get it: the flag defaulted to
// six years, which matched the built-in schedule by coincidence. An operator
// running a schedule with a longer floor would have archived under a shorter
// lock and been told nothing.
//
// So the schedule is the source, and an explicit flag may only ever *raise* it.
// Refusing a shorter one is the fail-closed direction: Object Lock in COMPLIANCE
// mode cannot be shortened after the fact, so a segment locked for too little is
// a segment that becomes deletable before the schedule permits, and no later
// correction reaches it.
func (s *storageFlags) lockDuration() (time.Duration, string, error) {
	schedule := retention.DefaultSchedule()
	source := "the built-in schedule"
	if s.schedule != "" {
		loaded, err := retention.LoadSchedule(s.schedule)
		if err != nil {
			return 0, "", err
		}
		schedule, source = loaded, s.schedule
	}
	required := schedule.LongestMinimum()
	if s.retention == 0 {
		if required == 0 {
			return 0, "", fmt.Errorf("%s states no retention minimum, so there is nothing to "+
				"derive a lock duration from; pass -retention explicitly", source)
		}
		return required, fmt.Sprintf("%s (longest minimum)", source), nil
	}
	if s.retention < required {
		return 0, "", fmt.Errorf("-retention %s is shorter than %s requires (%s). Object Lock "+
			"in COMPLIANCE mode cannot be shortened later, so a segment locked for too "+
			"little becomes deletable before the schedule permits and nothing can reach "+
			"back to fix it. Raise -retention, or state a schedule that asks for less",
			retention.Duration(s.retention), source, retention.Duration(required))
	}
	return s.retention, "-retention", nil
}

func (s *storageFlags) uploader(ctx context.Context) (*worm.Uploader, error) {
	client, err := objstore.New(ctx, objstore.Config{
		Endpoint:     s.endpoint,
		Bucket:       s.bucket,
		AccessKey:    s.accessKey,
		SecretKey:    s.secretKey,
		UsePathStyle: s.pathStyle,
		Jurisdiction: s.jurisdiction,
		Prefix:       s.prefix,
	})
	if err != nil {
		return nil, err
	}
	// Fail here rather than on the first upload: a bucket without Object Lock
	// will happily accept objects and simply not hold them, which is the
	// failure mode this tier exists to rule out.
	if err := client.EnsureBucket(ctx, true); err != nil {
		return nil, err
	}
	lock, source, err := s.lockDuration()
	if err != nil {
		return nil, err
	}
	log.Printf("janus-tier: locking archived segments for %s, from %s", retention.Duration(lock), source)
	return worm.New(worm.Config{Client: client, Retention: lock})
}

func archive(args []string) error {
	fs := flag.NewFlagSet("archive", flag.ExitOnError)
	dir := fs.String("evidence", "./janus-evidence", "evidence segment directory")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	var sf storageFlags
	sf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	u, err := sf.uploader(ctx)
	if err != nil {
		return err
	}

	results, err := u.UploadAll(ctx, *dir)
	if err != nil {
		return err
	}

	if *asJSON {
		blob, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(blob))
		return nil
	}

	if len(results) == 0 {
		fmt.Printf("no sealed segments to archive in %s\n", *dir)
		fmt.Printf("(an open segment is still being written and is not archived until it is sealed)\n")
		return nil
	}
	fmt.Printf("%-10s %12s %10s %-12s %s\n", "SEGMENT", "BYTES", "STATE", "MODE", "RETAIN UNTIL")
	var uploaded, present int
	for _, r := range results {
		state := "uploaded"
		if r.AlreadyPresent {
			state = "present"
			present++
		} else {
			uploaded++
		}
		fmt.Printf("%-10d %12d %10s %-12s %s\n",
			r.SegmentID, r.Bytes, state, r.Mode, r.RetainUntil.Format(time.RFC3339))
	}
	fmt.Printf("\n%d newly archived, %d already present\n", uploaded, present)
	return nil
}

func prove(args []string) error {
	fs := flag.NewFlagSet("prove", flag.ExitOnError)
	segmentID := fs.Uint64("segment", 1, "segment id to run the drill against")
	var sf storageFlags
	sf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	u, err := sf.uploader(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("attempting to destroy segment %d in %s...\n", *segmentID, sf.bucket)
	if err := u.ProveImmutable(ctx, *segmentID); err != nil {
		return err
	}
	fmt.Printf("PASS — the store refused to destroy the record, and it reads back unchanged.\n")
	fmt.Printf("Object Lock is enabled, the retention is in the future, and the mode is COMPLIANCE.\n")
	return nil
}

func showRetention(args []string) error {
	fs := flag.NewFlagSet("retention", flag.ExitOnError)
	path := fs.String("schedule", "", "retention schedule JSON file (default: the built-in schedule)")
	asJSON := fs.Bool("json", false, "emit the schedule as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	schedule := retention.DefaultSchedule()
	source := "built-in default"
	if *path != "" {
		loaded, err := retention.LoadSchedule(*path)
		if err != nil {
			return err
		}
		schedule, source = loaded, *path
	}

	if *asJSON {
		blob, err := schedule.Marshal()
		if err != nil {
			return err
		}
		fmt.Print(string(blob))
		return nil
	}

	fmt.Printf("retention schedule v%d (%s)\n\n", schedule.Version, source)
	fmt.Printf("%-15s %-14s %10s %10s %-14s\n", "CLASS", "JURISDICTION", "MINIMUM", "MAXIMUM", "DISPOSAL")
	for _, p := range schedule.Policies {
		jurisdiction := p.Jurisdiction
		if jurisdiction == "" {
			jurisdiction = "(all)"
		}
		maximum := "none"
		if p.MaxRetention > 0 {
			maximum = p.MaxRetention.String()
		}
		fmt.Printf("%-15s %-14s %10s %10s %-14s\n",
			p.Class, jurisdiction, p.MinRetention, maximum, p.Mode)
		if p.Authority != "" {
			fmt.Printf("%-15s   %s\n", "", p.Authority)
		}
	}
	fmt.Printf("\nThis schedule is engineering configuration, not legal advice. A deployment\n")
	fmt.Printf("replaces it with one its own compliance function owns and reviews.\n")
	fmt.Printf("\nWhat enforces this schedule, and what does not.\n\n")
	fmt.Printf("  MINIMUMS are enforced for archived segments, and only for those.\n")
	fmt.Printf("  janus-tier archive locks each uploaded segment in Object Lock\n")
	fmt.Printf("  COMPLIANCE mode for %s -- the longest minimum above -- and\n",
		retention.Duration(schedule.LongestMinimum()))
	fmt.Printf("  janus-tier prove demonstrates the store refusing to destroy one.\n")
	fmt.Printf("  A segment still only in the live directory is protected by nothing\n")
	fmt.Printf("  but the filesystem.\n\n")
	fmt.Printf("  MAXIMUMS are enforced by NOTHING. Nothing in Janus disposes of a\n")
	fmt.Printf("  record when its ceiling passes: no daemon evaluates this schedule,\n")
	fmt.Printf("  and the DISPOSAL column says what an operator's own\n")
	fmt.Printf("  janus-tier erase would do, not what will happen on its own. For the\n")
	fmt.Printf("  personal class that is a GDPR Art. 5(1)(e) obligation this software\n")
	fmt.Printf("  does not discharge for you.\n\n")
	fmt.Printf("  LEGAL HOLDS are records in the log and survive a restart\n")
	fmt.Printf("  (janus-tier retention hold place / release / list). What a hold\n")
	fmt.Printf("  stops today is janus-tier erase, which refuses a held subject.\n")
	fmt.Printf("  It stops nothing else, because nothing else disposes of anything.\n")
	return nil
}

// showHolds lists the legal holds folded from the log.
func showHolds(args []string) error {
	fs := flag.NewFlagSet("retention holds", flag.ExitOnError)
	dir := fs.String("evidence", "./janus-evidence", "evidence segment directory")
	all := fs.Bool("all", false, "include released holds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	held, err := retention.FoldHolds(*dir)
	if err != nil {
		return err
	}
	rows := held.All()
	now := time.Now().UTC()
	if !*all {
		rows = held.Active(now)
	}
	if len(rows) == 0 {
		if *all {
			fmt.Println("no legal holds have ever been placed on this log")
		} else {
			fmt.Println("no legal holds are in force (use -all to include released ones)")
		}
		return nil
	}
	fmt.Printf("%-20s %-12s %-26s %s\n", "HOLD", "STATE", "PLACED", "MATTER")
	for _, h := range rows {
		state := "in force"
		if !h.Active(now) {
			state = "released"
		}
		fmt.Printf("%-20s %-12s %-26s %s\n",
			h.ID, state, h.PlacedAt.Format(time.RFC3339), h.Matter)
		fmt.Printf("%-20s   placed by %s\n", "", h.PlacedBy)
		if h.ReleasedAt != nil {
			fmt.Printf("%-20s   released by %s on %s\n", "",
				h.ReleasedBy, h.ReleasedAt.Format(time.RFC3339))
		}
		if h.Scope.Empty() {
			fmt.Printf("%-20s   scope: everything\n", "")
			continue
		}
		fmt.Printf("%-20s   scope:%s\n", "", describeScope(h.Scope))
	}
	return nil
}

func describeScope(s retention.Scope) string {
	var b strings.Builder
	for label, vs := range map[string][]string{
		" sagas=": s.SagaIDs, " subjects=": s.Subjects, " tenants=": s.Tenants,
	} {
		if len(vs) > 0 {
			b.WriteString(label)
			b.WriteString(strings.Join(vs, ","))
		}
	}
	if len(s.Classes) > 0 {
		b.WriteString(" classes=")
		for i, c := range s.Classes {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(string(c))
		}
	}
	return b.String()
}

// holdCmd places and releases legal holds.
//
// Both go through the same path -- open the directory with the writer key,
// append -- because there is no daemon in retention and inventing one for this
// would be a second way to write a log that one process owns. The
// asymmetry drawn between granting and revoking authority does not apply
// here: placing a hold is fail-closed, and releasing one is the dangerous
// direction, so both demand a named accountable person and neither is a
// startup flag.
func holdCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: janus-tier retention hold <place|release> [flags]")
	}
	action, rest := args[0], args[1:]

	fs := flag.NewFlagSet("retention hold "+action, flag.ExitOnError)
	dir := fs.String("evidence", "./janus-evidence", "evidence segment directory")
	writerKey := fs.String("writer-key", "", "writer key that signs the LEGAL_HOLD event (default: <evidence>/../keys/writer.key)")
	id := fs.String("id", "", "hold identifier (required)")
	by := fs.String("by", "", "accountable person placing or releasing the hold (required)")
	matter := fs.String("matter", "", "the litigation, investigation or supervisory request (required to place)")
	reason := fs.String("reason", "", "why disposal was allowed to resume (release only)")
	sagas := fs.String("saga", "", "comma-separated saga ids to freeze")
	subjects := fs.String("subject", "", "comma-separated data subjects to freeze")
	tenants := fs.String("tenant", "", "comma-separated tenants to freeze")
	classes := fs.String("class", "", "comma-separated retention classes to freeze")
	clockFlags := clockwire.RegisterFlags(fs)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *id == "" || *by == "" {
		fs.Usage()
		return errors.New("both -id and -by are required: a hold nobody is accountable for is not a hold")
	}

	// Same trap as erase: opening without naming the writer key would mint a
	// fresh one, the hold would look placed, and the log would stop verifying
	// against the key set the auditor holds.
	if *writerKey == "" {
		*writerKey = filepath.Join(filepath.Dir(filepath.Clean(*dir)), "keys", "writer.key")
	}
	if _, err := os.Stat(*writerKey); err != nil {
		return fmt.Errorf("writer key %s is not readable, so the LEGAL_HOLD event would be "+
			"signed by a newly generated key and the log would stop verifying: %w", *writerKey, err)
	}
	// One-shot: this command appends a record or two and exits, so it takes one
	// attestation rather than running a monitor. It attests its own clock and
	// does not borrow the daemon's — janus-tier may run on a different host, and
	// an attestation measures the clock of the process that took it.
	who := evidence.ParticipantRef{ID: "janus-tier"}
	clockCfg := clockFlags.Config(who)
	clockCfg.WarnIfUnattested("janus-tier", *dir)
	ctx := context.Background()
	app, _, err := clockwire.Open(ctx, clockCfg,
		evidence.Options{Dir: *dir, KeyPath: *writerKey})
	if err != nil {
		return err
	}
	defer func() { _ = app.Close() }()
	rec := retention.NewRecorder(app, who)
	now := time.Now().UTC()

	switch action {
	case "place":
		if *matter == "" {
			return errors.New("-matter is required: a hold with no matter is one nobody can later justify or lift")
		}
		scope := retention.Scope{
			SagaIDs: splitList(*sagas), Subjects: splitList(*subjects), Tenants: splitList(*tenants),
		}
		for _, c := range splitList(*classes) {
			scope.Classes = append(scope.Classes, retention.Class(c))
		}
		if err := rec.Place(ctx, *dir, retention.LegalHold{
			ID: *id, Matter: *matter, PlacedBy: *by, PlacedAt: now, Scope: scope,
		}); err != nil {
			return err
		}
		fmt.Printf("placed legal hold %s\n", *id)
		fmt.Printf("  matter     %s\n", *matter)
		fmt.Printf("  placed by  %s at %s\n", *by, now.Format(time.RFC3339))
		if scope.Empty() {
			fmt.Printf("  scope      everything\n")
		} else {
			fmt.Printf("  scope     %s\n", describeScope(scope))
		}
		fmt.Printf("\nDisposal is frozen for what this covers. Today that means janus-tier erase\n")
		fmt.Printf("refuses a held subject; nothing else in Janus disposes of anything yet.\n")
		return nil

	case "release":
		if err := rec.Release(ctx, *dir, *id, *by, *reason, now); err != nil {
			return err
		}
		fmt.Printf("released legal hold %s\n", *id)
		fmt.Printf("  released by %s at %s\n", *by, now.Format(time.RFC3339))
		if *reason != "" {
			fmt.Printf("  reason      %s\n", *reason)
		}
		fmt.Printf("\nDisposal may resume for what this covered. The hold stays in the log:\n")
		fmt.Printf("a hold that was in force until now is what explains records\n")
		fmt.Printf("outliving their ceiling.\n")
		return nil

	default:
		return fmt.Errorf("unknown hold action %q: place or release", action)
	}
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// erase honours a data subject's erasure request.
//
// It is a separate command from everything else here because it is the only
// irreversible one. Nothing about the invocation is convenient: the subject, the
// reason, and the accountable approver are all required, because an erasure
// with no reason and nobody's name on it is not something a controller can
// defend later.
func erase(args []string) error {
	fs := flag.NewFlagSet("erase", flag.ExitOnError)
	dir := fs.String("evidence", "./janus-evidence", "evidence segment directory")
	writerKey := fs.String("writer-key", "", "writer key that signs the SHRED event (default: <evidence>/../keys/writer.key)")
	keyring := fs.String("keyring", "./janus-keyring", "key ring directory")
	masterPath := fs.String("master-key", "./janus-keyring/master.key", "master key file")
	subject := fs.String("subject", "", "data subject to erase (required)")
	reason := fs.String("reason", "", "legal basis for the erasure, e.g. \"GDPR Art. 17 request 2026-114\" (required)")
	approver := fs.String("approved-by", "", "accountable person authorising the erasure (required)")
	confirm := fs.Bool("confirm", false, "required: erasure destroys the key permanently and cannot be undone")
	clockFlags := clockwire.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *subject == "" || *reason == "" || *approver == "" {
		fs.Usage()
		return errors.New("subject, reason, and approved-by are all required")
	}
	if !*confirm {
		return fmt.Errorf("refusing to erase %s without -confirm: destroying the key is permanent "+
			"and no privilege recovers the content afterwards", *subject)
	}

	// A legal hold outranks an erasure request, and this is the only place today
	// where that has teeth. Erasure destroys the subject's data encryption key
	// permanently -- the command says so itself -- so a hold that did not stop it
	// would be a hold in name only: a court tells the deployment to preserve
	// records, and the next GDPR Art. 17 request destroys them anyway, with
	// nothing in the log saying the hold was ever considered.
	//
	// First, before the keyring is even opened, and the order is deliberate. A
	// held subject whose key happens to be missing should be refused for the
	// hold, not for the keyring: "subject unknown" sends an operator to fix
	// their setup and try again, when the true answer is that a court told this
	// deployment not to destroy those records. The overriding constraint
	// reports first.
	//
	// Nothing is written on a refusal -- the appender has not opened. Folded
	// from the log rather than read from a process's memory, which is the point
	// of the change that made holds records.
	held, err := retention.FoldHolds(*dir)
	if err != nil {
		return fmt.Errorf("reading the legal holds on %s: %w", *dir, err)
	}
	if blocking := held.CoveringSubject(*subject, time.Now().UTC()); len(blocking) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "refusing to erase %s: %d legal hold(s) freeze disposal\n", *subject, len(blocking))
		for _, h := range blocking {
			scope := "everything"
			if !h.Scope.Empty() {
				scope = "scoped"
			}
			fmt.Fprintf(&b, "  %s  %s\n    placed by %s on %s (%s)\n",
				h.ID, h.Matter, h.PlacedBy, h.PlacedAt.Format(time.RFC3339), scope)
		}
		b.WriteString("\nRelease the hold first, with the person accountable for resuming\n")
		b.WriteString("disposal named:  janus-tier retention hold release <id> -by <person>")
		return errors.New(b.String())
	}

	master, err := crypto.LoadOrCreateMasterKey(*masterPath)
	if err != nil {
		return err
	}
	ring, err := crypto.NewFileKeyRing(*keyring, master)
	if err != nil {
		return err
	}
	if state := ring.State(*subject); state != crypto.KeyLive {
		return fmt.Errorf("subject %s is %s, not live", *subject, state)
	}

	// Recording the erasure appends an event, which means signing a segment. If
	// the log's writer key lives somewhere other than the default, opening
	// without saying so would mint a fresh one: the erasure would look like it
	// succeeded, and the log would then fail to verify against the key set the
	// auditor holds.
	if *writerKey == "" {
		*writerKey = filepath.Join(filepath.Dir(filepath.Clean(*dir)), "keys", "writer.key")
	}
	if _, err := os.Stat(*writerKey); err != nil {
		return fmt.Errorf("writer key %s is not readable, so the SHRED event would be signed by a "+
			"newly generated key and the log would stop verifying: %w", *writerKey, err)
	}
	// Same one-shot shape as the hold command: the SHRED record points at a
	// statement about the clock of the process that wrote it.
	clockCfg := clockFlags.Config(evidence.ParticipantRef{ID: "janus-tier"})
	clockCfg.WarnIfUnattested("janus-tier", *dir)
	ctx := context.Background()
	app, _, err := clockwire.Open(ctx, clockCfg,
		evidence.Options{Dir: *dir, KeyPath: *writerKey})
	if err != nil {
		return err
	}
	defer func() { _ = app.Close() }()

	ref, receipt, err := evidence.Erase(ctx, app, ring, *subject, *reason, *approver)
	if err != nil {
		return err
	}

	fmt.Printf("erased %s\n", receipt.Subject)
	fmt.Printf("  key            %s (created %s)\n", receipt.KeyFingerprint, receipt.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  reason         %s\n", receipt.Reason)
	fmt.Printf("  approved by    %s\n", receipt.ApprovedBy)
	fmt.Printf("  recorded at    seq %d\n", ref.Seq)
	fmt.Printf("\nThe records remain in the log and the chain still verifies; their content is\n")
	fmt.Printf("no longer recoverable by anyone. See docs/compliance/DPIA-crypto-shredding.md.\n")
	return nil
}

// watch runs the continuous verifier in the foreground.
func watch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	dir := fs.String("evidence", "./janus-evidence", "evidence segment directory")
	keyFile := fs.String("keys", "", "JSON file of trusted writer public keys (required)")
	checkpoint := fs.String("checkpoint", "", "file to persist incremental progress in")
	incremental := fs.Duration("incremental", 10*time.Second, "how often to check for new segments")
	sweep := fs.Duration("sweep", time.Hour, "period within which a full pass over the log completes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("-keys is required: without a trusted key set the verifier would only be " +
			"checking the log against itself")
	}
	blob, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	var set keys.PublicKeySet
	if err := json.Unmarshal(blob, &set); err != nil {
		return fmt.Errorf("parse %s: %w", *keyFile, err)
	}

	v, err := continuous.New(continuous.Config{
		Dir:                 *dir,
		Keys:                set,
		CheckpointPath:      *checkpoint,
		IncrementalInterval: *incremental,
		SweepInterval:       *sweep,
		OnFinding: func(f verify.Finding) {
			fmt.Printf("[%s] %s %s\n", f.Severity, f.Code, f.Message)
		},
	})
	if err != nil {
		return err
	}

	fmt.Printf("watching %s\n", *dir)
	fmt.Printf("  new segments checked every %s\n", *incremental)
	fmt.Printf("  history re-read in full every %s — that, not the interval above, is how long\n", *sweep)
	fmt.Printf("  tampering with an old record can go unnoticed\n\n")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				st := v.Status()
				state := "healthy"
				if !st.Healthy {
					state = "UNHEALTHY"
				}
				fmt.Printf("%s · %d incremental passes · %d full sweeps · %d events verified\n",
					state, st.IncrementalRuns, st.SweepsCompleted, st.EventsVerified)
			}
		}
	}()

	if err := v.Run(ctx); err != nil {
		return err
	}
	if !v.Status().Healthy {
		return errors.New("the log did not verify; see the findings above")
	}
	return nil
}
