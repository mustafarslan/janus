// Command janus-soak is the chaos harness for the evidence write path.
//
// It runs the Phase 1 exit criterion: kill the writer
// repeatedly, at arbitrary moments, and require that the chain never silently
// corrupts. Where the in-process fault injector can make storage misbehave, only
// a real SIGKILL can cut a process off mid-syscall with no chance to clean up —
// which is the case crash recovery exists for.
//
// The harness is a parent and a child of the same binary. The child appends
// events forever and prints the sequence number of every event the appender
// acknowledged. The parent kills it at random intervals, reopens the log,
// recovers, verifies, and checks the properties below. Then it does it again.
//
//	P1  the log verifies completely after every kill
//	P2  every acknowledged sequence number is still present
//	P3  sequence numbers are contiguous from 1, with no duplicates
//	P4  a repaired log records a RECOVERY event
//
// P2 is the one that matters most. The child prints an acknowledgement only
// after Append returns success, which happens only after the durability barrier
// — so anything the parent has seen was, by the system's own claim, safe to act
// on. Losing one would mean an agent could have released a side effect backed by
// evidence that no longer exists.
//
// The parent's view of acknowledgements can only lag reality (a kill may destroy
// buffered stdout), never lead it, so the check errs towards passing rather than
// towards false alarms.
//
// # Why the round cost is flat, and what that costs in return
//
// The gate is a 72-hour run. Every check above was originally a pass over the
// whole log, so round k cost proportional to k and the run was quadratic: about
// 2,100 kills over 72 hours instead of 157,000, with the final rounds spending
// four minutes verifying per 1.65 seconds of chaos. A harness that spends its
// last hours re-reading old data reports a pass while testing almost nothing,
// which is worse than reporting nothing at all.
//
// Three changes make the round cost independent of how long the run has been
// going, and each gives something up:
//
// Verification is incremental, through the same [continuous.Verifier] the
// service uses — the soak should not grow a second implementation of the thing
// it is meant to be testing. The incremental pass reads only segments written
// since its checkpoint. What it gives up is history: it would never re-read a
// segment from an hour ago, so an insider editing old evidence would go
// unnoticed. That is the attack the hash chain exists for, so it cannot simply
// be dropped.
//
// So a rolling full sweep re-reads the log a slice at a time, sized so a
// complete pass finishes within -sweep-period. That period, not the round rate,
// is the detection latency for tampering with history, and the summary prints
// the period actually achieved rather than the one that was asked for.
//
// Epoch rotation bounds disk. With flat round times a 72-hour run reaches
// billions of events and terabytes, so when an evidence directory passes
// -epoch-bytes it gets one final full verification and a fresh directory starts.
// What this gives up is the scope of P2: "nothing acknowledged was lost" is
// proven within each epoch rather than across the whole run. That is still the
// property that matters — an acknowledgement is a claim about a durable write,
// and a write in a directory that was fully verified and then retired was not
// lost.
//
// The sequence checks are incremental for the same reason and by the same
// argument: contiguity is transitive. If every previous round proved that
// sequences 1..h are present exactly once, this round need only prove the new
// records are exactly h+1..h'. See [epoch.scanNew].
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/continuous"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

var version = "dev"

func main() {
	var (
		child     = flag.Bool("child", false, "run as the writer child process (used by the parent)")
		dir       = flag.String("dir", "", "evidence directory (default: a temp dir, removed afterwards)")
		duration  = flag.Duration("duration", time.Minute, "how long to soak")
		minLife   = flag.Duration("min-life", 300*time.Millisecond, "shortest time a child is allowed to live")
		maxLife   = flag.Duration("max-life", 3*time.Second, "longest time a child is allowed to live")
		payload   = flag.Int("payload", 256, "payload bytes per event")
		producers = flag.Int("producers", 4, "concurrent producers inside the child")
		segBytes  = flag.Int64("segment-bytes", 64<<10, "segment rotation threshold; small values exercise rotation hard")
		syncMode  = flag.String("sync", "data", "durability barrier: full|data|none")
		keyPath   = flag.String("key", "", "writer key file (child only; defaults beside the evidence directory)")
		seed      = flag.Uint64("seed", 0, "random seed for kill timing (0 picks one and prints it)")
		keep      = flag.Bool("keep", false, "keep the evidence directory afterwards")

		// The detection latency for tampering with history, which is a different
		// and much longer figure than the incremental check's. Naming it as a
		// period rather than a segment count keeps the slice size a consequence
		// of the guarantee rather than the other way round.
		sweepPeriod = flag.Duration("sweep-period", 15*time.Minute,
			"period within which a full re-verification of the current epoch completes (0 disables the sweep)")
		// 5 GiB is roughly two hours of a hard soak at the default settings:
		// long enough that rotation is rare, small enough that a laptop running
		// this overnight does not fill its disk.
		epochBytes = flag.Int64("epoch-bytes", 5<<30,
			"start a fresh evidence directory once the current one passes this size")
	)
	flag.Parse()

	if *child {
		if err := runChild(*dir, *keyPath, *payload, *producers, *segBytes, *syncMode); err != nil {
			fmt.Fprintf(os.Stderr, "child: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := runParent(parentConfig{
		dir: *dir, duration: *duration, minLife: *minLife, maxLife: *maxLife,
		payload: *payload, producers: *producers, segBytes: *segBytes,
		syncMode: *syncMode, seed: *seed, keep: *keep,
		sweepPeriod: *sweepPeriod, epochBytes: *epochBytes,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "\njanus-soak: %v\n", err)
		os.Exit(1)
	}
}

// ---- child -----------------------------------------------------------------

// runChild appends until it is killed, printing each acknowledged sequence.
func runChild(dir, keyPath string, payload, producers int, segBytes int64, syncName string) error {
	mode, err := segment.ParseSyncMode(syncName)
	if err != nil {
		return err
	}
	a, err := evidence.Open(evidence.Options{
		Dir:                dir,
		KeyPath:            keyPath,
		SyncMode:           mode,
		SegmentTargetBytes: segBytes,
	})
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	body := make([]byte, payload)
	for i := range body {
		body[i] = byte('a' + i%26)
	}

	// Unbuffered writes, one line per acknowledgement. Buffering would widen
	// the window in which the parent's view lags the truth.
	var mu sync.Mutex

	for p := range producers {
		go func(p int) {
			ctx := context.Background()
			for i := 0; ; i++ {
				ref, err := a.Append(ctx, evidence.Request{
					Kind:        evidence.KindStepResult,
					SagaID:      fmt.Sprintf("sg_soak_%02d", p),
					StepID:      fmt.Sprintf("st_%d", i),
					Participant: evidence.ParticipantRef{ID: "ag_soak", ManifestVersion: "1.0.0"},
					Payload:     body,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "child append: %v\n", err)
					return
				}
				mu.Lock()
				_, _ = fmt.Fprintf(os.Stdout, "acked %d\n", ref.Seq)
				mu.Unlock()
			}
		}(p)
	}

	// Wait to be killed. A clean exit would defeat the purpose.
	select {}
}

// ---- parent ----------------------------------------------------------------

type parentConfig struct {
	dir         string
	duration    time.Duration
	minLife     time.Duration
	maxLife     time.Duration
	payload     int
	producers   int
	segBytes    int64
	syncMode    string
	seed        uint64
	keep        bool
	sweepPeriod time.Duration
	epochBytes  int64
}

type roundResult struct {
	Round         int    `json:"round"`
	Epoch         int    `json:"epoch"`
	Lifetime      string `json:"lifetime"`
	AckedHigh     uint64 `json:"acked_high_water"`
	EventsInLog   uint64 `json:"events_in_log"`
	Segments      int    `json:"segments"`
	Recovered     bool   `json:"recovered"`
	VerifyOK      bool   `json:"verify_ok"`
	VerifyMS      int64  `json:"verify_ms"`
	SealedOnRecov int    `json:"sealed_on_recovery"`
	SweptSegments int    `json:"swept_segments"`
	// SweepsDone is the current epoch's own count of completed passes, so it
	// restarts at zero on every rotation. Read across the whole report it looks
	// like passes were lost; they were not, they belong to the epoch before.
	// Sum the epochs, or read the total the summary prints.
	SweepsDone uint64 `json:"sweeps_completed"`
}

// epochResult is one retired evidence directory, and the full verification that
// let it be retired.
type epochResult struct {
	Epoch        int    `json:"epoch"`
	Rounds       int    `json:"rounds"`
	Events       uint64 `json:"events"`
	Segments     int    `json:"segments"`
	Bytes        int64  `json:"bytes"`
	AckedHigh    uint64 `json:"acked_high_water"`
	FullVerifyMS int64  `json:"full_verify_ms"`
	Sweeps       uint64 `json:"sweeps_completed"`
	// LivedMS is how long the epoch was written to before its full
	// verification. It is the other half of the history guarantee: an epoch is
	// read end to end exactly once, when it retires, so its lifetime is how
	// stale that reading can be.
	LivedMS int64 `json:"lived_ms"`
}

// epoch is one evidence directory, and the cursors that let a round check it
// without re-reading what earlier rounds already proved.
type epoch struct {
	n        int
	dir      string
	verifier *continuous.Verifier
	// scan lists this epoch's complete segments without re-stat-ing every file.
	// Both of the soak's per-round listings go through it -- `check` and
	// `scanNew` -- two of the three listings that needed a cache. An epoch is
	// exactly the caller-with-a-lifetime the cache needed: one directory, one cursor, thousands of rounds.
	scan *segment.Scanner

	// scanFrom is the first segment whose records have not been folded into the
	// counters below. It can move to the end of the log after every round
	// because the recovery that opens each check seals everything: there is no
	// open tail left to re-read, which is the property that makes a cursor here
	// safe at all.
	scanFrom  uint64
	segments  int
	events    uint64
	bytes     int64
	highSeq   uint64
	ackedHigh uint64
	rounds    int
	started   time.Time
}

// scanNew folds every segment at or after e.scanFrom into the epoch's counters,
// and checks P3 over exactly those records.
//
// The old harness rebuilt a set of every sequence number in the log on every
// round and then walked 1..max looking for a hole. That is a whole pass over the
// log per round, and by hour twenty of a 72-hour run it is most of what the
// harness does — with a set of tens of millions of entries to hold while doing
// it.
//
// It is also more work than the property needs, because contiguity is
// transitive. If every previous round established that 1..h is present exactly
// once, this round only has to establish that the new records are exactly
// h+1..h', and 1..h' follows. Three facts about the new records are together
// equivalent to that: none repeats, the lowest is h+1, and there are h'-h of
// them. A missing sequence makes the count short; an extra or out-of-range one
// makes the lowest wrong or trips the duplicate check.
func (e *epoch) scanNew() error {
	ids, err := e.scan.Complete()
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	seen := map[uint64]bool{}
	var minSeq, maxSeq, lastID uint64
	for _, id := range ids {
		if id < e.scanFrom {
			continue
		}
		lastID = id
		e.segments++
		path := segment.Path(e.dir, id)
		if info, serr := os.Stat(path); serr == nil {
			e.bytes += info.Size()
		}
		insp, ierr := segment.Inspect(path)
		if ierr != nil {
			return fmt.Errorf("inspect segment %d: %w", id, ierr)
		}
		for _, rec := range insp.Records {
			h, derr := evidence.DecodeHeader(rec.Header)
			if derr != nil {
				return derr
			}
			if seen[h.Seq] {
				return fmt.Errorf("INTEGRITY VIOLATION: sequence %d appears twice", h.Seq)
			}
			seen[h.Seq] = true
			if h.Seq > maxSeq {
				maxSeq = h.Seq
			}
			if minSeq == 0 || h.Seq < minSeq {
				minSeq = h.Seq
			}
		}
	}

	if len(seen) == 0 {
		// The child was killed before anything of its own reached disk. Nothing
		// to check, and the cursor stays where it is.
		return nil
	}
	if minSeq != e.highSeq+1 {
		return fmt.Errorf("INTEGRITY VIOLATION: the log resumes at sequence %d, "+
			"but the previous round left it at %d — %d record(s) between them are unaccounted for",
			minSeq, e.highSeq, int64(minSeq)-int64(e.highSeq)-1)
	}
	// After the check above, maxSeq >= minSeq > e.highSeq, so this subtraction
	// cannot go negative. The order matters: reversed, a log that resumed behind
	// the head would refuse on unsigned underflow with a nonsense count in the
	// message rather than on the thing that was actually wrong.
	if want := maxSeq - e.highSeq; uint64(len(seen)) != want {
		return fmt.Errorf("INTEGRITY VIOLATION: sequences %d..%d should be %d records "+
			"but the log holds %d, so at least one is missing from the middle",
			e.highSeq+1, maxSeq, want, len(seen))
	}

	e.highSeq = maxSeq
	e.events += uint64(len(seen))
	e.scanFrom = lastID + 1
	return nil
}

func runParent(cfg parentConfig) error {
	if cfg.seed == 0 {
		cfg.seed = uint64(time.Now().UnixNano())
	}
	rng := rand.New(rand.NewPCG(cfg.seed, 0x2545F4914F6CDD1D))

	dir := cfg.dir
	// A failing soak must never delete its own evidence. The whole value of a
	// long run is the state it was in when it broke, and that state is
	// unreproducible — the failure took hours of random kills to reach.
	failed := true
	if dir == "" {
		tmp, err := os.MkdirTemp("", "janus-soak-")
		if err != nil {
			return err
		}
		dir = tmp
		defer func() {
			switch {
			case failed:
				fmt.Fprintf(os.Stderr, "\nevidence preserved for investigation: %s\n", tmp)
			case cfg.keep:
				fmt.Printf("evidence kept at %s\n", tmp)
			default:
				_ = os.RemoveAll(tmp)
			}
		}()
	}
	defer func() {
		if failed && cfg.dir != "" {
			fmt.Fprintf(os.Stderr, "\nevidence preserved for investigation: %s\n", cfg.dir)
		}
	}()
	keyPath := dir + "/keys/writer.key"

	// One key for the whole soak, so every child signs into the same chain of
	// custody and the parent can verify with a fixed trusted key. Epoch
	// directories are siblings under dir for the same reason: the appender's
	// default key path is beside its evidence directory, so every epoch resolves
	// to this one key without being told about it.
	signer, err := keys.LoadOrCreate(keyPath)
	if err != nil {
		return fmt.Errorf("writer key: %w", err)
	}
	keySet := keys.PublicKeySet{signer.KeyID(): signer.Public()}

	self, err := os.Executable()
	if err != nil {
		return err
	}

	fmt.Printf("janus-soak %s\n", version)
	fmt.Printf("duration %s · child life %s..%s · sync %s · segments %d B · seed %d\n",
		cfg.duration, cfg.minLife, cfg.maxLife, cfg.syncMode, cfg.segBytes, cfg.seed)
	fmt.Printf("sweep period %s · epoch cap %s\n", sweepDesc(cfg.sweepPeriod), bytesDesc(cfg.epochBytes))
	fmt.Printf("evidence %s\n\n", dir)
	fmt.Printf("%-6s %5s %10s %12s %12s %9s %6s %7s %7s\n",
		"ROUND", "EPOCH", "LIFETIME", "ACKED", "IN EPOCH", "SEGMENTS", "RECOV", "VERIFY", "SWEPT")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started := time.Now()
	deadline := started.Add(cfg.duration)
	var (
		rounds      int
		totalAcked  uint64
		totalEvents uint64
		results     []roundResult
		epochs      []epochResult
	)
	sweeps := &sweepLedger{last: started}

	e, err := newEpoch(1, dir, keySet, cfg.sweepPeriod)
	if err != nil {
		return err
	}

	for time.Now().Before(deadline) && ctx.Err() == nil {
		rounds++
		e.rounds++
		life := cfg.minLife + time.Duration(rng.Int64N(int64(cfg.maxLife-cfg.minLife)+1))

		high, err := runOneRound(ctx, self, e.dir, keyPath, cfg, life)
		if err != nil {
			return fmt.Errorf("round %d: %w", rounds, err)
		}
		if high > e.ackedHigh {
			e.ackedHigh = high
		}
		if high > totalAcked {
			totalAcked = high
		}

		// Size the slice from the pace the run is actually keeping, so a full
		// pass lands inside the requested period rather than inside a period
		// guessed before the first round.
		res, err := e.check(ctx, sweepSlice(e.segments, cfg.sweepPeriod, time.Since(started), rounds))
		if err != nil {
			return fmt.Errorf("round %d (epoch %d): %w", rounds, e.n, err)
		}
		res.Round = rounds
		res.Lifetime = life.Round(time.Millisecond).String()
		results = append(results, res)

		sweeps.observe(res.SweepsDone, time.Now())

		fmt.Printf("%-6d %5d %10s %12d %12d %9d %6s %7s %7d\n",
			res.Round, res.Epoch, res.Lifetime, res.AckedHigh, res.EventsInLog, res.Segments,
			yesNo(res.Recovered), okFail(res.VerifyOK), res.SweptSegments)

		if cfg.epochBytes > 0 && e.bytes >= cfg.epochBytes {
			ms, verr := e.fullVerify(keySet)
			if verr != nil {
				return fmt.Errorf("round %d: %w", rounds, verr)
			}
			epochs = append(epochs, epochResult{
				Epoch: e.n, Rounds: e.rounds, Events: e.events, Segments: e.segments,
				Bytes: e.bytes, AckedHigh: e.ackedHigh, FullVerifyMS: ms,
				Sweeps:  e.verifier.Status().SweepsCompleted,
				LivedMS: time.Since(e.started).Milliseconds(),
			})
			totalEvents += e.events
			fmt.Printf("  epoch %d retired: %d events in %s, fully verified in %d ms\n",
				e.n, e.events, bytesDesc(e.bytes), ms)

			// Only now is the directory safe to remove: it has been read end to
			// end and found whole. Keeping it would defeat the point of rotating.
			if !cfg.keep {
				if rerr := os.RemoveAll(e.dir); rerr != nil {
					return fmt.Errorf("retiring epoch %d: %w", e.n, rerr)
				}
			}
			// The next epoch's verifier starts its pass counter again at zero.
			// The ledger has to be told, or every pass the new epoch completes
			// before it overtakes the retired epoch's total is counted as no
			// pass at all — and the wait for it is then billed to a single pass.
			sweeps.rotate()
			if e, err = newEpoch(e.n+1, dir, keySet, cfg.sweepPeriod); err != nil {
				return err
			}
		}
	}

	totalEvents += e.events
	if rounds == 0 {
		return errors.New("no rounds ran; the soak proved nothing")
	}

	// The last epoch never retired, so it has never had a full read. Give it one
	// before claiming the run passed: otherwise the tail of every soak — which on
	// a short run is the whole soak — rests on partial views alone.
	tailMS, err := e.fullVerify(keySet)
	if err != nil {
		return err
	}
	epochs = append(epochs, epochResult{
		Epoch: e.n, Rounds: e.rounds, Events: e.events, Segments: e.segments,
		Bytes: e.bytes, AckedHigh: e.ackedHigh, FullVerifyMS: tailMS,
		Sweeps:  e.verifier.Status().SweepsCompleted,
		LivedMS: time.Since(e.started).Milliseconds(),
	})

	elapsed := time.Since(started)
	fmt.Printf("\n%d kill/recover rounds over %s in %d epoch(s), %d events, all present\n",
		rounds, elapsed.Round(time.Second), len(epochs), totalEvents)
	fmt.Printf("round cost stayed flat: %s per round on average\n",
		(elapsed / time.Duration(rounds)).Round(time.Millisecond))

	// State the detection latency for tampering with *history*. It is not the
	// round rate — a round only looks at what is new — and it is not the sweep
	// period alone either.
	//
	// Two mechanisms re-read old segments and they are not alternatives. The
	// rolling sweep covers an epoch that is still being written; retirement reads
	// an epoch end to end once, before deleting it. A run with a small
	// -epoch-bytes rotates faster than it can sweep and completes no sweep at
	// all, and reporting only the sweep there would say history went unchecked
	// when in fact every epoch was read whole. The binding figure is whichever of
	// the two is shorter, and both are printed so the reader can see which.
	epochLife := slowest(epochLives(epochs))
	sweepLatency := sweeps.slowest()

	fmt.Printf("history — what re-read an old segment, and how stale that reading can be:\n")
	switch {
	case cfg.sweepPeriod <= 0:
		fmt.Printf("  rolling sweep    disabled (-sweep-period 0)\n")
	case sweeps.total() > 0:
		fmt.Printf("  rolling sweep    %d pass(es) completed, slowest %s (asked for %s)\n",
			sweeps.total(), sweepLatency.Round(time.Second), cfg.sweepPeriod)
	default:
		fmt.Printf("  rolling sweep    no pass completed in %s\n", elapsed.Round(time.Second))
	}
	fmt.Printf("  epoch retirement %d epoch(s) read end to end, longest lived %s\n",
		len(epochs), epochLife.Round(time.Second))

	binding := sweepLatency
	if binding == 0 || (epochLife > 0 && epochLife < binding) {
		binding = epochLife
	}
	fmt.Printf("  => tampering with an old segment would be found within %s\n",
		binding.Round(time.Second))
	if sweeps.total() == 0 && len(epochs) == 1 {
		// The only full read was the one at the end, so the latency is the run
		// itself. Fine for a two-minute check, and not what the gate asks for.
		fmt.Printf("     which is the whole run: nothing re-read history until the end.\n" +
			"     For the 72-hour gate, shorten -sweep-period or lower -epoch-bytes.\n")
	}
	fmt.Printf("janus-soak: PASS — zero integrity violations across %d kills\n", rounds)
	failed = false

	if cfg.keep {
		blob, _ := json.MarshalIndent(struct {
			Rounds []roundResult `json:"rounds"`
			Epochs []epochResult `json:"epochs"`
		}{results, epochs}, "", "  ")
		path := dir + "/soak-report.json"
		if err := os.WriteFile(path, append(blob, '\n'), 0o644); err == nil {
			fmt.Printf("report written to %s\n", path)
		}
	}
	return nil
}

// newEpoch creates the next evidence directory and the verifier that watches it.
//
// The first epoch keeps the name "evidence" so that a short run — which is every
// run except the gate itself — leaves the directory where it has always been.
func newEpoch(n int, root string, keySet keys.PublicKeySet, sweepPeriod time.Duration) (*epoch, error) {
	name := root + "/evidence"
	if n > 1 {
		name = fmt.Sprintf("%s/evidence-%03d", root, n)
	}
	v, err := continuous.New(continuous.Config{
		Dir:  name,
		Keys: keySet,
		// The soak drives Incremental and SweepStep itself, once per round, so
		// these only affect what Status reports. SweepInterval is the honest one:
		// it is what HistoryCheckedWithin will claim.
		SweepInterval: sweepPeriod,
	})
	if err != nil {
		return nil, fmt.Errorf("epoch %d: %w", n, err)
	}
	return &epoch{n: n, dir: name, verifier: v, scan: segment.NewScanner(name), started: time.Now()}, nil
}

// sweepLedger counts completed rolling-sweep passes, and how long each one took,
// across epoch rotations.
//
// It exists because the obvious version of this is wrong in a way that only
// shows up on a run long enough to rotate. The pass counter belongs to the
// verifier, and a verifier belongs to an epoch, so at every rotation it starts
// again at zero. Code that keeps a single running maximum across the whole run
// therefore stops counting at each rotation, waits until the new epoch has
// completed more passes than the retired one ever did, and then bills that
// entire wait — hours, on the gate settings — to one pass.
//
// The damage is not a cosmetic count. The slowest recorded interval is printed
// as the detection latency for tampering with history, so the bug reports a
// number tens of times worse than the run achieved. It did exactly that on the
// 72-hour gate run: one rotation, and a 13h30m8s "pass" against a 15m0s ask.
// A control that misreports itself in the safe direction is still misreporting.
type sweepLedger struct {
	prior   uint64          // passes completed in epochs that have been retired
	current uint64          // passes completed in the epoch being written now
	last    time.Time       // when the most recent pass was seen to complete
	periods []time.Duration // how long each completed pass took, end to end
}

// observe records the pass counter reported by the current epoch's verifier.
// Comparison is against this epoch's own previous value, never a cross-epoch
// maximum, which is the whole point.
func (l *sweepLedger) observe(epochSweeps uint64, now time.Time) {
	if epochSweeps <= l.current {
		return
	}
	l.current = epochSweeps
	l.periods = append(l.periods, now.Sub(l.last))
	l.last = now
}

// rotate is called when the epoch is retired and its verifier goes away, taking
// its counter with it.
func (l *sweepLedger) rotate() {
	l.prior += l.current
	l.current = 0
}

// total is every pass the run completed, in every epoch.
func (l *sweepLedger) total() uint64 { return l.prior + l.current }

// slowest is the longest a single pass took, which is the detection latency the
// rolling sweep can honestly claim.
func (l *sweepLedger) slowest() time.Duration { return slowest(l.periods) }

// sweepSlice picks how many segments the rolling sweep should re-read this
// round so that a full pass over the epoch finishes within the requested period.
//
// It divides by the pace measured so far rather than an assumed one. A soak's
// round time depends on the child's lifetime distribution and on the disk, so a
// slice size chosen up front would be wrong on every machine but the one it was
// tuned on — and wrong in the direction that quietly lengthens the detection
// latency without saying so.
//
// The growth term is the part that is easy to leave out and expensive to leave
// out. The sweep is chasing a target that is still moving: the log gains
// segments every round, so a slice of exactly segments/rounds-per-sweep advances
// the cursor by about as much as the log grows, and the sweep crawls. The first
// version of this function did that.
func sweepSlice(segments int, period, elapsed time.Duration, rounds int) int {
	if period <= 0 || segments <= 0 || rounds <= 0 {
		return 0
	}
	perRound := elapsed / time.Duration(rounds)
	if perRound <= 0 {
		return segments
	}
	roundsPerSweep := int(period / perRound)
	if roundsPerSweep < 1 {
		// The period is shorter than a single round, so the only way to honour
		// it is to sweep the whole epoch every round.
		return segments
	}

	// How many segments a round adds, on average, rounded up: the cursor has to
	// outpace this before any of it counts as progress.
	growth := (segments + rounds - 1) / rounds

	size := segments/roundsPerSweep + growth
	if size < 1 {
		size = 1
	}
	return size
}

func epochLives(es []epochResult) []time.Duration {
	out := make([]time.Duration, 0, len(es))
	for _, e := range es {
		out = append(out, time.Duration(e.LivedMS)*time.Millisecond)
	}
	return out
}

func slowest(ds []time.Duration) time.Duration {
	var longest time.Duration
	for _, d := range ds {
		if d > longest {
			longest = d
		}
	}
	return longest
}

func sweepDesc(d time.Duration) string {
	if d <= 0 {
		return "disabled"
	}
	return d.String()
}

func bytesDesc(n int64) string {
	switch {
	case n <= 0:
		return "unbounded"
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// runOneRound starts a child, lets it write, then SIGKILLs it. It returns the
// highest sequence number the child reported as acknowledged.
func runOneRound(ctx context.Context, self, evidenceDir, keyPath string, cfg parentConfig, life time.Duration) (uint64, error) {
	cmd := exec.Command(self,
		"-child",
		"-dir", evidenceDir,
		"-payload", strconv.Itoa(cfg.payload),
		"-producers", strconv.Itoa(cfg.producers),
		"-segment-bytes", strconv.FormatInt(cfg.segBytes, 10),
		"-sync", cfg.syncMode,
		"-key", keyPath,
	)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start child: %w", err)
	}

	acked := make(chan uint64, 1)
	go func() {
		var high uint64
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "acked ") {
				continue
			}
			n, err := strconv.ParseUint(strings.TrimPrefix(line, "acked "), 10, 64)
			if err == nil && n > high {
				high = n
			}
		}
		acked <- high
	}()

	select {
	case <-time.After(life):
	case <-ctx.Done():
	}

	// SIGKILL, not SIGTERM: the child must get no chance to seal, flush, or
	// tidy up. Anything it managed to make durable before this instant is what
	// recovery has to work with.
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		return 0, fmt.Errorf("kill child: %w", err)
	}
	_ = cmd.Wait()

	select {
	case high := <-acked:
		return high, nil
	case <-time.After(10 * time.Second):
		return 0, errors.New("timed out collecting the child's acknowledgements")
	}
}

// check recovers the log and asserts the soak's properties over what the round
// just added. Its cost is proportional to the round, not to the run.
func (e *epoch) check(ctx context.Context, sweepSegments int) (roundResult, error) {
	res := roundResult{Epoch: e.n}

	// Only segments the previous round did not already see can be unsealed:
	// recovery seals everything it opens, so the whole log below the cursor is
	// sealed by construction. Counting from the cursor is what stops this from
	// being another full pass.
	ids, err := e.scan.Complete()
	if err != nil {
		return res, fmt.Errorf("scan: %w", err)
	}
	unsealedBefore := 0
	for _, id := range ids {
		if id < e.scanFrom {
			continue
		}
		sealed, serr := segment.IsSealed(segment.Path(e.dir, id))
		if serr != nil {
			return res, serr
		}
		if !sealed {
			unsealedBefore++
		}
	}

	// Recovery happens on open. Closing immediately leaves a fully sealed log.
	a, err := evidence.Open(evidence.Options{Dir: e.dir, SyncMode: segment.SyncModeData})
	if err != nil {
		return res, fmt.Errorf("recovery refused to open the log after a kill: %w", err)
	}
	if err := a.Close(); err != nil {
		return res, fmt.Errorf("close after recovery: %w", err)
	}
	res.Recovered = unsealedBefore > 0
	res.SealedOnRecov = unsealedBefore

	// P1, for what is new: the segments written since the last checkpoint verify,
	// and their chain continues from the one the checkpoint ended on. The join is
	// the part that matters — without it each round would be checking an island.
	rep, err := e.verifier.Incremental(ctx)
	if err != nil {
		return res, fmt.Errorf("incremental verify: %w", err)
	}
	res.VerifyOK = rep.OK
	res.VerifyMS = rep.DurationMS
	if !rep.OK {
		return res, fmt.Errorf("INTEGRITY VIOLATION after a kill:\n%s", rep.Text())
	}

	// P3: the new records continue the sequence exactly.
	if err := e.scanNew(); err != nil {
		return res, err
	}
	res.EventsInLog = e.events
	res.Segments = e.segments

	// P2: nothing acknowledged is missing. P3 has established that every sequence
	// from 1 to e.highSeq is present exactly once, so an acknowledged sequence is
	// present if and only if it is not past the head — which makes the whole
	// check this one comparison rather than a walk over every sequence ever
	// acknowledged.
	if e.ackedHigh > e.highSeq {
		return res, fmt.Errorf("DURABILITY VIOLATION: sequence %d was acknowledged to a caller "+
			"but the log's head is %d — an append returned success for an event that did not survive",
			e.ackedHigh, e.highSeq)
	}
	res.AckedHigh = e.ackedHigh

	// The rolling sweep. This is what covers history: the incremental pass above
	// would never look at an old segment again, so without this an insider could
	// edit an hour-old segment and no round would ever read it.
	if sweepSegments > 0 {
		srep, _, serr := e.verifier.SweepStep(ctx, sweepSegments)
		if serr != nil {
			return res, fmt.Errorf("rolling sweep: %w", serr)
		}
		if srep != nil {
			res.SweptSegments = len(srep.Segments)
			if !srep.OK {
				return res, fmt.Errorf("INTEGRITY VIOLATION found by the rolling sweep — "+
					"this is tampering with history, not a crash artefact:\n%s", srep.Text())
			}
		}
		res.SweepsDone = e.verifier.Status().SweepsCompleted
	}
	return res, nil
}

// fullVerify re-reads the entire epoch. It runs once, when the epoch is retired,
// and it is what licenses retiring it: the incremental checks and the rolling
// sweep are both partial views, and a directory about to be deleted deserves one
// look at the whole thing.
func (e *epoch) fullVerify(keySet keys.PublicKeySet) (int64, error) {
	rep, err := verify.SegmentDir(e.dir, verify.Options{Keys: keySet, Version: version})
	if err != nil {
		return 0, fmt.Errorf("final verification of epoch %d: %w", e.n, err)
	}
	if !rep.OK {
		return rep.DurationMS, fmt.Errorf("INTEGRITY VIOLATION in epoch %d's final verification:\n%s",
			e.n, rep.Text())
	}
	return rep.DurationMS, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func okFail(b bool) string {
	if b {
		return "PASS"
	}
	return "FAIL"
}
