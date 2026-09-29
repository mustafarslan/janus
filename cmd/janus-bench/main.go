// Command janus-bench measures the evidence append path.
//
// This is the Phase 0 go/no-go gate: if chained, signed,
// group-committed, fsynced appends cannot sustain the throughput and latency the
// product assumes, the architecture has to change before anything is built on
// top of it. The benchmark therefore measures the real path — canonical
// encoding, BLAKE3 chaining, segment writes, durability barrier, Merkle root and
// Ed25519 seal — and then re-verifies the log it just wrote, because a fast
// write path that produces unverifiable evidence is worth nothing.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// version is stamped at build time; the default keeps local runs honest.
var version = "dev"

// Targets: the design's throughput and append-latency budgets.
const (
	targetEventsPerSec = 50_000
	targetP99Append    = 10 * time.Millisecond
)

type result struct {
	SyncMode string `json:"sync_mode"`
	// Shape is beside the numbers rather than in the run's header because it
	// changes what they mean: a throughput figure at `sagas` is a figure for
	// three different event kinds and a payload this tool did not choose.
	Shape           string  `json:"shape"`
	Producers       int     `json:"producers"`
	Events          int     `json:"events"`
	PayloadBytes    int     `json:"payload_bytes"`
	Linger          string  `json:"linger"`
	DurationSec     float64 `json:"duration_sec"`
	EventsPerSec    float64 `json:"events_per_sec"`
	MiBPerSec       float64 `json:"mib_per_sec"`
	Batches         uint64  `json:"batches"`
	EventsPerBatch  float64 `json:"events_per_batch"`
	P50MS           float64 `json:"p50_ms"`
	P99MS           float64 `json:"p99_ms"`
	P999MS          float64 `json:"p999_ms"`
	MaxMS           float64 `json:"max_ms"`
	SegmentsSealed  uint64  `json:"segments_sealed"`
	MeetsThroughput bool    `json:"meets_throughput_target"`
	MeetsLatency    bool    `json:"meets_latency_target"`
}

type report struct {
	Version      string    `json:"version"`
	Host         string    `json:"host"`
	GOARCH       string    `json:"goarch"`
	GOOS         string    `json:"goos"`
	CPUs         int       `json:"cpus"`
	RanAt        time.Time `json:"ran_at"`
	Results      []result  `json:"results"`
	VerifyOK     bool      `json:"verify_ok"`
	VerifyEvents int       `json:"verify_events"`
	VerifyMS     int64     `json:"verify_ms"`
}

// benchSigner returns the signer for one run: a file-backed one when the caller
// named a path, and otherwise a fresh in-memory key.
func benchSigner(path string) (*keys.Signer, error) {
	if path == "" {
		return keys.Generate()
	}
	return keys.LoadOrCreate(path)
}

func main() {
	var (
		dir        = flag.String("dir", "", "working directory (default: a temp dir, removed afterwards)")
		events     = flag.Int("events", 200_000, "events to append per run")
		producers  = flag.Int("producers", runtime.NumCPU(), "concurrent producer goroutines")
		payload    = flag.Int("payload", 256, "payload bytes per event")
		modes      = flag.String("sync", "full,data,none", "comma-separated durability barriers to measure")
		sweep      = flag.String("sweep", "", "comma-separated producer counts to sweep (overrides -producers)")
		linger     = flag.Duration("linger", 0, "group-commit linger window (0 = sync as soon as the writer is free)")
		segBytes   = flag.Int64("segment-bytes", 16<<20, "segment rotation threshold")
		jsonOut    = flag.String("json", "", "also write the report as JSON to this path")
		skipVerify = flag.Bool("skip-verify", false, "skip re-verifying the log that was written")
		shape      = flag.String("shape", shapeSteps, "event shape: `steps` repeats one STEP_RESULT per\n"+
			"producer and is the append-throughput shape every docs/bench number\n"+
			"was taken at; `sagas` writes whole three-event sagas, which is the\n"+
			"only shape anything that folds the log can read. -payload applies to\n"+
			"steps only: a saga's payload is decided by the saga, not by a flag")
		keyFile = flag.String("key", "", "writer key file, created if absent. Without one each run\n"+
			"signs with a fresh in-memory key that is never written down — fine for a\n"+
			"throughput number, and useless for a log anybody wants to keep, back up or\n"+
			"hand to an auditor")
	)
	flag.Parse()

	// Throughput on a group-commit path is bounded by how many appends are in
	// flight at once: with N producers and a sync costing T, no configuration
	// can exceed N/T. A single producer count therefore measures the load
	// generator as much as the write path, which is why the gate is a sweep.
	counts := []int{*producers}
	if *sweep != "" {
		counts = nil
		for _, s := range splitCSV(*sweep) {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "janus-bench: bad -sweep value %q\n", s)
				os.Exit(1)
			}
			counts = append(counts, n)
		}
	}

	switch *shape {
	case shapeSteps, shapeSagas:
	default:
		fmt.Fprintf(os.Stderr, "janus-bench: unknown -shape %q; want %s or %s\n",
			*shape, shapeSteps, shapeSagas)
		os.Exit(1)
	}

	if err := run(*dir, *events, counts, *payload, *modes, *linger, *segBytes, *jsonOut, *skipVerify, *keyFile, *shape); err != nil {
		fmt.Fprintf(os.Stderr, "janus-bench: %v\n", err)
		os.Exit(1)
	}
}

func run(dir string, events int, producerCounts []int, payload int, modes string, linger time.Duration, segBytes int64, jsonOut string, skipVerify bool, keyPath, shape string) error {
	if events <= 0 || len(producerCounts) == 0 {
		return fmt.Errorf("events must be positive and at least one producer count is required")
	}
	base := dir
	if base == "" {
		tmp, err := os.MkdirTemp("", "janus-bench-")
		if err != nil {
			return err
		}
		base = tmp
		defer func() { _ = os.RemoveAll(tmp) }()
	} else if err := os.MkdirAll(base, 0o750); err != nil {
		return err
	}

	host, _ := os.Hostname()
	rep := report{
		Version: version,
		Host:    host,
		GOARCH:  runtime.GOARCH,
		GOOS:    runtime.GOOS,
		CPUs:    runtime.NumCPU(),
		RanAt:   time.Now().UTC(),
	}

	printHeader(rep, events, producerCounts, payload, linger, shape)

	var lastDir string
	var lastSigner *keys.Signer
	for _, name := range splitCSV(modes) {
		mode, err := segment.ParseSyncMode(name)
		if err != nil {
			return err
		}
		for _, producers := range producerCounts {
			runDir := filepath.Join(base, fmt.Sprintf("run-%s-%d", name, producers))
			// A fresh key per run unless the caller named a file. Fresh is right
			// for a throughput measurement, which nobody verifies afterwards
			// against a root they hold — and wrong for anything that wants to
			// *keep* the log: the private half is never written down, so a log
			// this wrote can never be signed for, backed up, or handed to an
			// auditor. `-key` is for callers that need the log rather than the
			// number (scripts/restore-drill.sh).
			signer, err := benchSigner(keyPath)
			if err != nil {
				return err
			}
			res, err := measure(runDir, signer, mode, events, producers, payload, linger, segBytes, shape)
			if err != nil {
				return fmt.Errorf("sync=%s producers=%d: %w", name, producers, err)
			}
			rep.Results = append(rep.Results, res)
			printResult(res)
			lastDir, lastSigner = runDir, signer
		}
	}

	if !skipVerify && lastDir != "" {
		fmt.Printf("\nre-verifying the log written by the last run...\n")
		vr, err := verify.SegmentDir(lastDir, verify.Options{
			Keys:              keys.PublicKeySet{lastSigner.KeyID(): lastSigner.Public()},
			AllowUnsealedTail: false,
			Version:           version,
		})
		if err != nil {
			return fmt.Errorf("verify: %w", err)
		}
		rep.VerifyOK, rep.VerifyEvents, rep.VerifyMS = vr.OK, vr.Events, vr.DurationMS
		status := "PASS"
		if !vr.OK {
			status = "FAIL"
		}
		fmt.Printf("  %s — %d events, %d segments, %d ms\n", status, vr.Events, len(vr.Segments), vr.DurationMS)
		if !vr.OK {
			fmt.Print(vr.Text())
		}
	}

	printVerdict(rep)

	if jsonOut != "" {
		blob, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(jsonOut, append(blob, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("\nreport written to %s\n", jsonOut)
	}
	return nil
}

// measure runs one configuration and returns its numbers.
func measure(dir string, signer segment.Signer, mode segment.SyncMode, events, producers, payload int, linger time.Duration, segBytes int64, shape string) (result, error) {
	a, err := evidence.Open(evidence.Options{
		Dir:                dir,
		Signer:             signer,
		SyncMode:           mode,
		SegmentTargetBytes: segBytes,
		Linger:             linger,
		QueueDepth:         1 << 16,
	})
	if err != nil {
		return result{}, err
	}

	body := make([]byte, payload)
	for i := range body {
		body[i] = byte('a' + i%26)
	}

	// Each producer records its own latencies to keep the hot path lock-free.
	perProducer := make([][]time.Duration, producers)
	share := events / producers
	remainder := events % producers

	// Whole sagas are built here, before anything is timed: the JSON-to-protobuf
	// conversion each one costs is an order more than the append it feeds, and
	// inside the loop it would be most of what this tool measured.
	var shaped [][]evidence.Request
	if shape == shapeSagas {
		shaped = make([][]evidence.Request, producers)
		for p := range producers {
			n := share
			if p < remainder {
				n++
			}
			rs, err := sagaRequests(p, n, evidence.ParticipantRef{
				ID: "ag_bench", ManifestVersion: "1.0.0", Principal: "pr_bench",
			})
			if err != nil {
				_ = a.Close()
				return result{}, err
			}
			shaped[p] = rs
		}
	}

	// Warm the path so that first-touch page faults and lazy initialisation do
	// not land inside the measured window.
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindControl, Participant: evidence.ParticipantRef{ID: "janus-bench"}, Payload: body,
	}); err != nil {
		_ = a.Close()
		return result{}, err
	}

	var wg sync.WaitGroup
	start := time.Now()
	for p := range producers {
		n := share
		if p < remainder {
			n++
		}
		perProducer[p] = make([]time.Duration, 0, n)
		wg.Add(1)
		go func(p, n int) {
			defer wg.Done()
			ctx := context.Background()
			req := evidence.Request{
				Kind:        evidence.KindStepResult,
				SagaID:      fmt.Sprintf("sg_bench_%04d", p),
				Participant: evidence.ParticipantRef{ID: "ag_bench", ManifestVersion: "1.0.0", Principal: "pr_bench"},
				Payload:     body,
			}
			// Two loops rather than one indexing a slice, so that the default
			// shape's hot path is exactly the code every number in docs/bench
			// was taken with.
			if shaped != nil {
				for i := range n {
					t0 := time.Now()
					if _, err := a.Append(ctx, shaped[p][i]); err != nil {
						fmt.Fprintf(os.Stderr, "append failed: %v\n", err)
						return
					}
					perProducer[p] = append(perProducer[p], time.Since(t0))
				}
				return
			}
			for range n {
				t0 := time.Now()
				if _, err := a.Append(ctx, req); err != nil {
					fmt.Fprintf(os.Stderr, "append failed: %v\n", err)
					return
				}
				perProducer[p] = append(perProducer[p], time.Since(t0))
			}
		}(p, n)
	}
	wg.Wait()
	elapsed := time.Since(start)

	stats := a.Stats()
	if err := a.Close(); err != nil {
		return result{}, err
	}

	lat := make([]time.Duration, 0, events)
	for _, l := range perProducer {
		lat = append(lat, l...)
	}
	slices.Sort(lat)

	eps := float64(len(lat)) / elapsed.Seconds()
	res := result{
		SyncMode:       mode.String(),
		Shape:          shape,
		Producers:      producers,
		Events:         len(lat),
		PayloadBytes:   payload,
		Linger:         linger.String(),
		DurationSec:    elapsed.Seconds(),
		EventsPerSec:   eps,
		MiBPerSec:      float64(stats.Bytes) / (1 << 20) / elapsed.Seconds(),
		Batches:        stats.Batches,
		P50MS:          ms(percentile(lat, 0.50)),
		P99MS:          ms(percentile(lat, 0.99)),
		P999MS:         ms(percentile(lat, 0.999)),
		MaxMS:          ms(percentile(lat, 1.0)),
		SegmentsSealed: stats.SegmentsSealed,
	}
	if stats.Batches > 0 {
		res.EventsPerBatch = float64(stats.Events) / float64(stats.Batches)
	}
	res.MeetsThroughput = res.EventsPerSec >= targetEventsPerSec
	res.MeetsLatency = percentile(lat, 0.99) <= targetP99Append
	return res, nil
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(q * float64(len(sorted)-1))
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func ms(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func printHeader(r report, events int, producerCounts []int, payload int, linger time.Duration, shape string) {
	fmt.Printf("janus-bench %s — evidence append path\n", r.Version)
	fmt.Printf("host %s · %s/%s · %d CPUs\n", r.Host, r.GOOS, r.GOARCH, r.CPUs)
	if shape == shapeSagas {
		fmt.Printf("%d events per run · producers %v · shape %s (payload set by the saga) · linger %s\n",
			events, producerCounts, shape, linger)
	} else {
		fmt.Printf("%d events per run · producers %v · %d B payload · linger %s\n", events, producerCounts, payload, linger)
	}
	fmt.Printf("targets: >= %d events/s, p99 append <= %s\n\n", targetEventsPerSec, targetP99Append)
	fmt.Printf("%-6s %6s %12s %10s %9s %8s %8s %9s %9s %6s\n",
		"SYNC", "PROD", "EVENTS/S", "MiB/S", "EV/BATCH", "P50 ms", "P99 ms", "P99.9 ms", "MAX ms", "SEGS")
}

func printResult(r result) {
	fmt.Printf("%-6s %6d %12.0f %10.1f %9.1f %8.3f %8.3f %9.3f %9.3f %6d\n",
		r.SyncMode, r.Producers, r.EventsPerSec, r.MiBPerSec, r.EventsPerBatch,
		r.P50MS, r.P99MS, r.P999MS, r.MaxMS, r.SegmentsSealed)
}

func printVerdict(r report) {
	fmt.Printf("\nverdict\n")
	best := map[string]result{}
	for _, res := range r.Results {
		fmt.Printf("  sync=%-5s producers=%-5d throughput %s (%9.0f/s)   latency %s (p99 %7.3f ms)\n",
			res.SyncMode, res.Producers,
			passFail(res.MeetsThroughput), res.EventsPerSec,
			passFail(res.MeetsLatency), res.P99MS)
		// Track the best configuration that satisfies both targets at once,
		// since trading latency away for throughput is not a pass.
		if res.MeetsThroughput && res.MeetsLatency {
			if cur, ok := best[res.SyncMode]; !ok || res.EventsPerSec > cur.EventsPerSec {
				best[res.SyncMode] = res
			}
		}
	}
	fmt.Printf("\ngate (both targets met simultaneously)\n")
	for _, mode := range []string{"full", "data", "none"} {
		res, ok := best[mode]
		if !ok {
			continue
		}
		fmt.Printf("  sync=%-5s PASS at %d producers: %.0f events/s, p99 %.3f ms\n",
			mode, res.Producers, res.EventsPerSec, res.P99MS)
	}
	if len(best) == 0 {
		fmt.Printf("  no configuration met both targets\n")
	}

	fmt.Printf("\nReading these numbers:\n")
	fmt.Printf("  'full' is the strongest barrier the platform offers and the one the\n")
	fmt.Printf("  evidence-before-effect guarantee assumes. On linux that is fsync; on darwin\n")
	fmt.Printf("  it is F_FULLFSYNC, which also flushes the drive's write cache and costs an\n")
	fmt.Printf("  order of magnitude more. A darwin 'full' result is therefore not comparable\n")
	fmt.Printf("  to a deployment number — judge the gate on a linux 'full' run against the\n")
	fmt.Printf("  storage you intend to deploy on, since the disk is what decides the outcome.\n")
	fmt.Printf("  'data' (fsync/fdatasync without the device flush) and 'none' are shown for\n")
	fmt.Printf("  comparison, not as deployment options.\n")
	fmt.Printf("  Throughput is bounded by concurrency: with P appends in flight and a sync\n")
	fmt.Printf("  costing T, no configuration can exceed P/T. Low producer counts measure the\n")
	fmt.Printf("  load generator, not the write path.\n")
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
