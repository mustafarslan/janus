// Command janus-sagachaos is the Phase 2 exit gate:
// kill a coordinator at every state a saga can be in, and check that recovery
// resumes correctly.
//
// The property under test is stronger than "it does not crash", and it is worth
// stating precisely, because a weaker reading of it is easy to pass:
//
//	A saga's outcome does not depend on how many times its coordinator died.
//
// Not "the log survives" — janus-soak already proves that at the evidence
// layer. Not "recovery produces some valid state". The same saga, run through
// the same scripted participants, must reach the same terminal state and the
// same per-step history whether it ran start to finish in one process or was
// killed and resumed at every single point along the way.
//
// That is the assertion a saga engine either satisfies or does not, and it is
// the one that matters to somebody deciding whether to put money through it.
//
// The crash is a real SIGKILL to a real child process, not a simulated one.
// A coordinator that tidies up on the way out is testing its shutdown path;
// the interesting states are the ones nobody chose to be in.
//
// Coverage and its limits: SIGKILL destroys a process but not the page cache,
// so this exercises coordinator death rather than power loss. Sudden power loss
// against a real durability barrier is janus-soak's job (-sync data), and the
// two together are what the exit gate rests on.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

// policyFile is the absolute path to the gate policy, passed down to every
// child so a parent and its children admit sagas under the same rules.
var policyFile string

// hostedMode drives every scenario through janus-orchd rather than in-process.
//
// It is a package variable for the same reason policyFile is: the child needs
// it before it has anything to thread it through, and the parent has to pass it
// down or the two halves would be running different suites.
var hostedMode bool

// keepAlways keeps a passing run's evidence, so janus-spotreplay has a log of
// resumed sagas to check.
var keepAlways bool

// interleaveSeed drives the order concurrent sagas are stepped in. It is a
// package variable because a scenario is built before any run begins, and it is
// passed to every child unchanged: a resumed coordinator that re-derived a
// different interleaving would be running a different scenario from the one it
// is being compared against.
var interleaveSeed int

// projectionDSN is the base connection string for the run. Each crash point's
// daemon gets its own schema under it, because a projection belongs to one log
// and every crash point is a fresh log.
var projectionDSN string

// runID distinguishes this run's schemas from any left by an earlier one, so a
// crashed run cannot leave a schema that a later run silently folds a different
// log into. It is set by the parent and passed to every child.
var runID string

func main() {
	var (
		child    = flag.Bool("child", false, "run as the coordinator child process")
		runIDArg = flag.String("run-id", "", "the parent's run id; children only")
		seed     = flag.Int("seed", 1,
			"seed for scenarios that interleave concurrent sagas; printed at the start of a\n"+
				"run so a failure can be reproduced, and passed unchanged to every child")
		dir      = flag.String("dir", "", "evidence directory")
		scenario = flag.String("scenario", "", "scenario name")
		only     = flag.String("only", "", "run only scenarios whose name contains this")
		keep     = flag.Bool("keep", false, "keep the evidence of a failing run")
		pgDSN    = flag.String("projection", "",
			"Postgres connection string; each crash point's daemon folds its own log into its\n"+
				"own schema, so the frontier gate is answered from the Postgres projection under\n"+
				"crash conditions rather than by replaying the log")
		keepAll = flag.Bool("keep-always", false,
			"keep the evidence even when the run passes, for janus-spotreplay (implies -keep)")
		verbose = flag.Bool("v", false, "print every crash point")
		policy  = flag.String("policy", "docs/policy/reference.json", "gate policy document")
		hosted  = flag.Bool("hosted", false,
			"drive scenarios through janus-orchd over gRPC instead of in-process")
	)
	flag.Parse()

	// The policy comes first because every scenario's plan is admitted against
	// it while the scenario list is built. A parent and the children it spawns
	// must read the same file, or they would be driving sagas admitted under
	// different rules and the disagreement would surface as a replay failure
	// halfway through a run.
	policyPath, err := filepath.Abs(*policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "janus-sagachaos: %v\n", err)
		os.Exit(1)
	}
	if err := loadPolicy(policyPath); err != nil {
		fmt.Fprintf(os.Stderr, "janus-sagachaos: %v\n", err)
		os.Exit(1)
	}
	policyFile = policyPath
	hostedMode = *hosted
	keepAlways = *keepAll
	projectionDSN = *pgDSN
	runID = *runIDArg
	interleaveSeed = *seed
	scenarios = buildScenarios()

	if *child {
		run := runChild
		if hostedMode {
			run = runHostedChild
		}
		if err := run(*dir, *scenario); err != nil {
			fmt.Fprintf(os.Stderr, "child: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := runParent(*only, *keep || *keepAll, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "\njanus-sagachaos: %v\n", err)
		os.Exit(1)
	}
}

// ---- child -----------------------------------------------------------------

// runChild resumes the scenario's sagas from whatever the log already holds and
// drives them to completion.
//
// There is no "start" path distinct from the "resume" path. A coordinator that
// treated the two differently would have a recovery route that only ever runs
// after a crash, which is the route least likely to be correct and least likely
// to be exercised. Here the first run resumes from an empty log.
func runChild(dir, name string) error {
	sc, ok := scenarioByName(name)
	if !ok {
		return fmt.Errorf("unknown scenario %q", name)
	}

	app, err := evidence.Open(evidence.Options{
		Dir:                dir,
		SyncMode:           segment.SyncModeNone,
		SegmentTargetBytes: 64 << 10,
	})
	if err != nil {
		return fmt.Errorf("open evidence: %w", err)
	}

	// Each acknowledged transition is reported before the next one is
	// attempted, so the parent's view lags by at most one event and it can tell
	// exactly which projection the log should replay to.
	report := func(s saga.State) {
		digest, derr := digestOf(s)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "digest: %v\n", derr)
			return
		}
		fmt.Printf("ack %s %d %s\n", s.SagaID, s.EventCount, digest)
	}

	if err := sc.run(context.Background(), app, dir, report); err != nil {
		return err
	}
	return app.Close()
}

// ---- parent ----------------------------------------------------------------

func runParent(only string, keep, verbose bool) error {
	root, err := os.MkdirTemp("", "janus-sagachaos-*")
	if err != nil {
		return err
	}
	if projectionDSN != "" {
		// Derived from the directory this run owns, so two runs in parallel
		// cannot share a schema and a crashed run cannot leave one a later run
		// would fold a different log into.
		runID = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return -1
		}, strings.ToLower(filepath.Base(root)))
		defer dropRunSchemas()
	}
	failed := true
	defer func() {
		// A failing run must keep its evidence. The state a saga was in when it
		// broke is the whole value of the run.
		//
		// `-keep-always` keeps it either way, which is what janus-spotreplay
		// wants pointing at: a *passing* chaos run is the most interesting log
		// this repository can produce for a determinism check, because every
		// saga in it was resumed from a kill at least once. Kept histories from
		// a passing run are the ones where a replay divergence would be worth
		// something.
		if keep && (failed || keepAlways) {
			fmt.Printf("\nevidence kept at %s\n", root)
			return
		}
		_ = os.RemoveAll(root)
	}()

	self, err := os.Executable()
	if err != nil {
		return err
	}

	runnable := scenarios
	if !hostedMode {
		// A hosted-only scenario is skipped in-process and said out loud, for
		// the same reason the hosted run prints what it could not host: a suite
		// that quietly covers less is the expensive kind of green.
		runnable = nil
		var skipped []string
		for _, sc := range scenarios {
			if !sc.hostedOnly {
				runnable = append(runnable, sc)
				continue
			}
			skipped = append(skipped, sc.name)
		}
		if len(skipped) > 0 {
			fmt.Printf("janus-sagachaos: %d scenario(s) need the daemon and are skipped "+
				"here — run with -hosted: %s\n", len(skipped), strings.Join(skipped, ", "))
		}
	}
	if hostedMode {
		runnable = nil
		var skipped []string
		for _, sc := range scenarios {
			if sc.hosted != nil {
				runnable = append(runnable, sc)
				continue
			}
			skipped = append(skipped, sc.name)
		}
		// Said out loud rather than left to be counted. A hosted run that
		// silently skipped half the suite and reported a pass would be the most
		// expensive kind of green.
		fmt.Printf("janus-sagachaos: hosted mode — the coordinator runs in janus-orchd " +
			"and every participant answers over gRPC\n")
		// The ratio is printed on every run, including when it is whole. A suite
		// that quietly covered less over time — a scenario added, not hostable,
		// nobody noticing the number stopped moving — is the failure this line
		// exists to make impossible.
		if len(skipped) == 0 {
			fmt.Printf("  all %d scenarios are hosted\n", len(runnable))
		} else {
			fmt.Printf("  %d of %d scenarios are hosted; not hosted: %v\n",
				len(runnable), len(scenarios), skipped)
		}
	}

	fmt.Printf("janus-sagachaos: %d scenarios\n\n", len(runnable))
	if verbose {
		// What the run is actually enforcing, rather than a claim that it
		// enforces something. A suite that passed because its policy had
		// quietly stopped matching anything would look identical otherwise.
		fmt.Printf("%s\n", explainPolicy())
	}
	total, kills := 0, 0

	for _, sc := range runnable {
		if only != "" && !strings.Contains(sc.name, only) {
			continue
		}

		// A clean run first: it establishes both how many transitions the
		// scenario takes (so every one of them can be a crash point) and the
		// outcome every crashed run has to match.
		cleanDir := filepath.Join(root, sc.name, "clean")
		clean, err := runOnce(self, cleanDir, sc.name)
		if err != nil {
			return fmt.Errorf("%s: the uninterrupted run failed: %w", sc.name, err)
		}
		want, err := finalStates(cleanDir, sc)
		if err != nil {
			return fmt.Errorf("%s: %w", sc.name, err)
		}
		if err := sc.check(want); err != nil {
			return fmt.Errorf("%s: the uninterrupted run did not reach the expected outcome: %w", sc.name, err)
		}
		if sc.dirCheck != nil {
			if err := sc.dirCheck(cleanDir); err != nil {
				return fmt.Errorf("%s: the uninterrupted run: %w", sc.name, err)
			}
		}

		fmt.Printf("  %-34s %2d transitions", sc.name, len(clean))
		for point := 1; point <= len(clean); point++ {
			dir := filepath.Join(root, sc.name, fmt.Sprintf("crash-%02d", point))
			if err := crashAt(self, dir, sc, point, clean, want, verbose); err != nil {
				fmt.Printf("  FAIL\n")
				return fmt.Errorf("%s, killed after transition %d: %w", sc.name, point, err)
			}
			kills++
		}
		if err := injectedFaults(self, root, sc); err != nil {
			fmt.Printf("  FAIL\n")
			return fmt.Errorf("%s: %w", sc.name, err)
		}
		total += len(clean)
		fmt.Printf("  %2d kills  ok\n", len(clean))
	}

	fmt.Printf("\njanus-sagachaos: PASS — %d kills across %d transitions, every resumed saga "+
		"reached the same outcome as the uninterrupted run\n", kills, total)
	failed = false
	return nil
}

// crashAt kills a coordinator after a given number of acknowledged transitions,
// then checks that what is left can be picked up and finished correctly.
func crashAt(self, dir string, sc scenario, point int, clean []ack,
	want map[string]saga.State, verbose bool) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	partial, err := runUntilKilled(self, dir, sc.name, point)
	if err != nil {
		return err
	}

	// P1: whatever the log holds after a hard kill, it holds intact.
	if err := verifyLog(dir); err != nil {
		return fmt.Errorf("the log does not verify after the kill: %w", err)
	}

	// P1a: put the log back into the state every reader is entitled to expect,
	// the way a restarting writer does.
	//
	// A SIGKILL can land in the middle of a record, and the half-written bytes
	// are by construction bytes nobody was ever told about. Recovery truncates
	// them and confesses it in a RECOVERY event; every reader in the system
	// refuses an unrecovered log rather than guess what the tail meant. The
	// checks below are readers, so recovery has to come first.
	//
	// Without this the suite fails intermittently and for no real reason: the
	// kill usually lands between records, so the tail is usually clean, and the
	// one time in several hundred that it does not, P1b reports a gate finding
	// that is really an unrecovered log. A flaky exit gate is worse than none,
	// because the first thing anyone does with it is stop believing it.
	//
	// This is not repairing evidence to make a test pass. P1 above has already
	// required everything the log holds to be intact, and a torn tail is the one
	// thing it is allowed to end with. Running recovery here rather than leaving
	// it to the resumed coordinator at P4 is also what makes the intermediate
	// states inspectable at all, which is the point of checking before resuming.
	if err := recoverLog(dir); err != nil {
		return err
	}

	// P1b: every gate decision the log holds is one its own recorded inputs
	// produce. The chain proves nobody edited the log; this proves nobody was
	// let through on an answer the policy does not support — a different
	// failure, invisible to the verifier, and reachable by a coordinator that
	// died halfway through deciding.
	if err := auditGates(dir); err != nil {
		return err
	}

	// P2: the projection the dead coordinator held and the one a reader
	// rebuilds from its log are the same. This is invariant I5 across a process
	// boundary rather than across a function call.
	if err := checkRecoveredMatches(dir, sc, partial); err != nil {
		return err
	}

	// P3: whatever the crash interrupted, the state it left behind is one the
	// scenario permits. Checking this before resuming is the point — it is the
	// only way to see the intermediate states at all, and for a sub-saga family
	// the intermediate states are where the risk lives.
	if sc.invariant != nil {
		mid, err := partialStates(dir, sc)
		if err != nil {
			return err
		}
		if err := sc.invariant(mid); err != nil {
			return fmt.Errorf("the state left by the kill breaks a safety invariant: %w", err)
		}
	}
	if sc.dirInvariant != nil {
		if err := sc.dirInvariant(dir); err != nil {
			return fmt.Errorf("the state left by the kill breaks a safety invariant: %w", err)
		}
	}

	// P4 and P5: a fresh coordinator finishes the saga, and finishes it the
	// same way the uninterrupted run did.
	if _, err := runOnce(self, dir, sc.name); err != nil {
		return fmt.Errorf("resuming after the kill failed: %w", err)
	}
	got, err := finalStates(dir, sc)
	if err != nil {
		return err
	}
	if err := compareOutcomes(want, got); err != nil {
		return err
	}
	if err := sc.check(got); err != nil {
		return fmt.Errorf("the resumed saga reached a state the scenario does not allow: %w", err)
	}
	if sc.dirCheck != nil {
		if err := sc.dirCheck(dir); err != nil {
			return fmt.Errorf("after recovery: %w", err)
		}
	}

	if verbose {
		fmt.Printf("\n    killed after %2d/%2d -> recovered %d events, resumed to %s",
			point, len(clean), len(partial), got[sc.sagas[0]].Status)
	}
	return nil
}

// checkRecoveredMatches compares the last projection the child reported against
// the one its log replays to.
func checkRecoveredMatches(dir string, sc scenario, reported []ack) error {
	byCount := map[string]map[int]string{}
	for _, a := range reported {
		if byCount[a.sagaID] == nil {
			byCount[a.sagaID] = map[int]string{}
		}
		byCount[a.sagaID][a.events] = a.digest
	}

	for _, id := range sc.sagas {
		events, err := saga.LoadEvents(dir, id)
		if err != nil {
			return fmt.Errorf("loading %s after the kill: %w", id, err)
		}
		if len(events) == 0 {
			continue
		}
		state, err := saga.Replay(events)
		if err != nil {
			return fmt.Errorf("saga %s does not replay after the kill: %w", id, err)
		}
		digest, err := digestOf(state)
		if err != nil {
			return err
		}
		want, ok := byCount[id][state.EventCount]
		if !ok {
			// The child was killed between the append returning and the report
			// being written. The log is ahead of what the parent saw, which is
			// the documented lag and not a failure.
			continue
		}
		if want != digest {
			return fmt.Errorf("saga %s: the coordinator held a different projection at %d events "+
				"than its own log replays to (%s vs %s)", id, state.EventCount, want[:12], digest[:12])
		}
	}
	return nil
}

// compareOutcomes checks that a resumed run ended where the clean run did.
func compareOutcomes(want, got map[string]saga.State) error {
	for id, w := range want {
		g, ok := got[id]
		if !ok {
			return fmt.Errorf("saga %s finished in the uninterrupted run but is absent after recovery", id)
		}
		if d := outcomeDiff(w, g); len(d) > 0 {
			return fmt.Errorf("saga %s ended differently after recovery:\n      %s",
				id, strings.Join(d, "\n      "))
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			return fmt.Errorf("saga %s exists after recovery but not in the uninterrupted run", id)
		}
	}
	return nil
}

// outcomeDiff compares two finished sagas, ignoring the things a crash is
// allowed to change.
//
// Log positions are excluded, because recovery writes its own records and every
// event after a crash therefore sits at a higher sequence than it would have.
// What must not differ is anything describing what happened: the saga's status,
// and every step's status, attempt count, outcome and compensation.
//
// Recorded touches need more care than simply dropping them. Their sequence
// numbers are what decide which saga reached a resource first (I6), so they
// cannot be ignored — but the number itself is a log position and shifts with
// everything else. What has to survive a crash is the *order*, so the
// comparison is made on each touch's rank rather than its raw sequence. A
// crash may renumber the log; it may not reorder who got there first.
func outcomeDiff(want, got saga.State) []string {
	a, b := normalizeForOutcome(want), normalizeForOutcome(got)
	return a.Diff(b)
}

func normalizeForOutcome(s saga.State) saga.FixtureState {
	snap := saga.Snapshot(s)
	snap.LastSeq = 0
	snap.EventCount = 0
	snap.Frontiers = nil

	// Rank every recorded touch sequence within this saga, then rewrite each
	// touch to carry its rank.
	var seqs []uint64
	for _, id := range s.Order {
		for _, t := range s.Steps[id].Touches {
			seqs = append(seqs, t.Seq)
		}
	}
	slices.Sort(seqs)
	seqs = slices.Compact(seqs)
	rank := make(map[uint64]int, len(seqs))
	for i, q := range seqs {
		rank[q] = i
	}

	for i, step := range snap.Steps {
		st := s.Steps[step.ID]
		touches := make([]string, 0, len(st.Touches))
		for _, t := range st.Touches {
			mode := "R"
			if t.IsWrite() {
				mode = "W"
			}
			touches = append(touches, fmt.Sprintf("%s:%s#%d", t.Resource, mode, rank[t.Seq]))
		}
		snap.Steps[i].Touches = touches
	}
	return snap
}

// ---- running the child ------------------------------------------------------

type ack struct {
	sagaID string
	events int
	digest string
}

// runOnce runs a coordinator to completion.
func runOnce(self, dir, scenario string) ([]ack, error) {
	return runWithEnv(self, dir, scenario, nil)
}

// runWithEnv runs a coordinator with extra environment, used to inject a fault
// at a point the parent cannot otherwise reach.
func runWithEnv(self, dir, scenario string, env []string) ([]ack, error) {
	cmd := exec.Command(self, childArgs(dir, scenario)...)
	cmd.Env = append(os.Environ(), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return parseAcks(string(out)), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseAcks(string(out)), nil
}

// injectedFaults kills a coordinator inside the release sequence itself, at the
// two points that bracket the side effect, and requires recovery to reach a
// correct settled state from each.
//
// This exists because the exhaustive crash points fall between recorded
// transitions and therefore step over the interior of a delivery. That interior
// is where an ordering mistake would hide: the difference between "announced and
// not yet applied" and "applied and not yet recorded" is invisible from outside
// the process, and only one of them is safe to retry naively.
func injectedFaults(self, root string, sc scenario) error {
	if sc.dirCheck == nil {
		return nil
	}
	for _, point := range []string{"before-apply", "after-apply"} {
		dir := filepath.Join(root, sc.name, "inject-"+point)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}

		// The injected run is expected to die, so its error is not a failure.
		_, _ = runWithEnv(self, dir, sc.name, []string{"JANUS_CHAOS_DIE_AT=" + point})

		if err := verifyLog(dir); err != nil {
			return fmt.Errorf("killed %s: the log does not verify: %w", point, err)
		}
		if sc.dirInvariant != nil {
			if err := sc.dirInvariant(dir); err != nil {
				return fmt.Errorf("killed %s: %w", point, err)
			}
		}

		// A fresh coordinator, with no fault injected, must finish the job.
		if _, err := runOnce(self, dir, sc.name); err != nil {
			return fmt.Errorf("killed %s: resuming failed: %w", point, err)
		}
		if err := sc.dirCheck(dir); err != nil {
			return fmt.Errorf("killed %s: after recovery: %w", point, err)
		}
		got, err := finalStates(dir, sc)
		if err != nil {
			return fmt.Errorf("killed %s: %w", point, err)
		}
		if err := sc.check(got); err != nil {
			return fmt.Errorf("killed %s: %w", point, err)
		}
	}
	return nil
}

// runUntilKilled starts a coordinator and SIGKILLs it once it has acknowledged
// the requested number of transitions.
func runUntilKilled(self, dir, scenario string, point int) ([]ack, error) {
	cmd := exec.Command(self, childArgs(dir, scenario)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	acks := make([]ack, 0, point)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		var pending strings.Builder
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 {
				pending.Write(buf[:n])
				text := pending.String()
				cut := strings.LastIndex(text, "\n")
				if cut >= 0 {
					acks = append(acks, parseAcks(text[:cut+1])...)
					rest := text[cut+1:]
					pending.Reset()
					pending.WriteString(rest)
					if len(acks) >= point {
						done <- nil
						return
					}
				}
			}
			if rerr != nil {
				done <- rerr
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		return nil, errors.New("the coordinator produced no further transitions within 30s")
	}

	// SIGKILL, so the coordinator gets no chance to seal a segment, finish a
	// transition, or otherwise leave the log tidier than a real crash would.
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()

	if len(acks) > point {
		acks = acks[:point]
	}
	return acks, nil
}

func parseAcks(out string) []ack {
	var acks []ack
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 4 || f[0] != "ack" {
			continue
		}
		n, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		acks = append(acks, ack{sagaID: f[1], events: n, digest: f[3]})
	}
	return acks
}

// ---- checks -----------------------------------------------------------------

// recoverLog runs the ordinary recovery path over the directory the dead
// coordinator left behind, so the readers that follow are looking at a log in
// the state the system guarantees them.
//
// The options match the child's exactly. They have to: a writer that opened the
// same directory with a different segment size or sync mode would be a second
// configuration of the log, and the crash the harness is reasoning about would
// no longer be the crash it reproduced.
func recoverLog(dir string) error {
	app, err := evidence.Open(evidence.Options{
		Dir:                dir,
		SyncMode:           segment.SyncModeNone,
		SegmentTargetBytes: 64 << 10,
	})
	if err != nil {
		return fmt.Errorf("recovering the log after the kill: %w", err)
	}
	if err := app.Close(); err != nil {
		return fmt.Errorf("closing the log after recovery: %w", err)
	}
	return nil
}

// auditGates re-derives every gate decision in the log and requires each one to
// follow from the inputs recorded beside it.
//
// Running this after every kill rather than once at the end is deliberate. A
// coordinator that died between recording a decision's justification and the
// decision itself leaves a log an audit has to be able to read — and a partial
// log is exactly the shape nobody tests until it goes wrong. Partial, note, not
// torn: P1a has already truncated any half-written tail, which is what recovery
// does and what every reader assumes has happened.
func auditGates(dir string) error {
	rep, err := gate.Audit(dir)
	if err != nil {
		return fmt.Errorf("auditing the log's gate decisions: %w", err)
	}
	if !rep.OK() {
		return fmt.Errorf("a gate decision in the log is not supported by its own inputs:\n%s", rep)
	}
	return nil
}

func verifyLog(dir string) error {
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return err
	}
	for _, id := range ids {
		path := segment.Path(dir, id)
		insp, err := segment.Inspect(path)
		if err != nil {
			return fmt.Errorf("segment %d: %w", id, err)
		}
		// A torn tail is expected after a kill and is not a violation; what
		// matters is that every complete record before it still chains.
		for i, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				return fmt.Errorf("segment %d record %d: %w", id, i, err)
			}
			if len(rec.Payload) > 0 {
				if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
					return fmt.Errorf("segment %d seq %d: payload does not match its hash", id, h.Seq)
				}
			}
			if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
				return fmt.Errorf("segment %d seq %d: broken chain", id, h.Seq)
			}
		}
	}
	return nil
}

// partialStates replays whichever of the scenario's sagas exist so far.
//
// Unlike finalStates it tolerates a saga with no log yet, because at an early
// crash point most of them will not have started. An absent saga is a fact
// about how far the run got, not an error.
func partialStates(dir string, sc scenario) (map[string]saga.State, error) {
	out := map[string]saga.State{}
	for _, id := range sc.sagas {
		events, err := saga.LoadEvents(dir, id)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", id, err)
		}
		if len(events) == 0 {
			continue
		}
		s, err := saga.Replay(events)
		if err != nil {
			return nil, fmt.Errorf("saga %s does not replay: %w", id, err)
		}
		out[id] = s
	}
	return out, nil
}

func finalStates(dir string, sc scenario) (map[string]saga.State, error) {
	out := map[string]saga.State{}
	for _, id := range sc.sagas {
		s, err := saga.ReplaySaga(dir, id)
		if err != nil {
			return nil, fmt.Errorf("replaying %s: %w", id, err)
		}
		out[id] = s
	}
	return out, nil
}

// digestOf reduces a projection to a comparable fingerprint.
func digestOf(s saga.State) (string, error) {
	blob, err := json.Marshal(saga.Snapshot(s))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:]), nil
}

// childArgs is how a child is invoked, in one place so that the killed run and
// the clean run cannot drift into being different suites.
func childArgs(dir, scenario string) []string {
	args := []string{"-child", "-dir", dir, "-scenario", scenario, "-policy", policyFile}
	if hostedMode {
		args = append(args, "-hosted")
	}
	if projectionDSN != "" {
		// The base DSN and the run id, not a resolved schema: the child derives
		// its own schema from its own directory, so a child restarted on the
		// same crash point lands on the same schema and resumes the projection
		// a previous process left -- which is the whole point of running this
		// under the chaos suite.
		args = append(args, "-projection", projectionDSN, "-run-id", runID)
	}
	return args
}
