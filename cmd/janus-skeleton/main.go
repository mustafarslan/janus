// Command janus-skeleton runs the Phase 0 walking skeleton end to end.
//
// It is the exit gate of Phase 0 made executable: begin a
// saga, run one PURE step, seal, commit — recording every transition in the
// evidence log — then replay the saga from the log and assert the projection is
// identical, export a verifiable bundle, and verify that bundle offline the way
// an auditor would.
//
// Everything it prints is derived from the artifact it produced. If any stage
// disagrees with another, it exits non-zero.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

var version = "dev"

func main() {
	var (
		workDir = flag.String("dir", "", "working directory (default: a temp dir, removed afterwards)")
		keep    = flag.Bool("keep", false, "keep the working directory instead of removing it")
		sagaID  = flag.String("saga", "sg_skeleton_0001", "saga id to run")
	)
	flag.Parse()

	if err := run(*workDir, *sagaID, *keep); err != nil {
		fmt.Fprintf(os.Stderr, "\njanus-skeleton: %v\n", err)
		os.Exit(1)
	}
}

func run(workDir, sagaID string, keep bool) error {
	if workDir == "" {
		tmp, err := os.MkdirTemp("", "janus-skeleton-")
		if err != nil {
			return err
		}
		workDir = tmp
		if !keep {
			defer func() { _ = os.RemoveAll(tmp) }()
		}
	}
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		return err
	}
	evidenceDir := filepath.Join(workDir, "evidence")
	bundleDir := filepath.Join(workDir, "bundle")

	fmt.Printf("janus-skeleton %s\n", version)
	fmt.Printf("working directory: %s\n\n", workDir)

	signer, err := keys.Generate()
	if err != nil {
		return err
	}
	keySet := keys.PublicKeySet{signer.KeyID(): signer.Public()}

	// ---- 1. run the saga -------------------------------------------------
	step("1", "run the saga, recording every transition before it takes effect")

	app, err := evidence.Open(evidence.Options{
		Dir:      evidenceDir,
		Signer:   signer,
		SyncMode: segment.SyncModeFull,
		Tenant:   tenancy.Tenant{ID: "demo", Jurisdiction: "DE"},
	})
	if err != nil {
		return err
	}

	live, err := runSaga(context.Background(), app, sagaID)
	if err != nil {
		_ = app.Close()
		return err
	}
	if err := app.Close(); err != nil {
		return fmt.Errorf("close evidence log: %w", err)
	}

	fmt.Printf("   saga %s reached %s after %d events (head seq %d)\n",
		live.SagaID, live.Status, live.EventCount, live.LastSeq)
	for _, id := range live.Order {
		s := live.Steps[id]
		fmt.Printf("   step %-18s %-10s %s\n", s.ID, s.Status, shortClass(s.EffectClass))
	}
	if live.Status != saga.StatusCommitted {
		return fmt.Errorf("saga ended in %s, want COMMITTED", live.Status)
	}

	// ---- 2. replay -------------------------------------------------------
	step("2", "replay the saga from the log and compare against the live projection")

	replayed, err := saga.ReplaySaga(evidenceDir, sagaID)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	if diff := saga.Diff(live, replayed); len(diff) > 0 {
		for _, d := range diff {
			fmt.Printf("   DIVERGENCE: %s\n", d)
		}
		return fmt.Errorf("replay produced a different projection (%d differences)", len(diff))
	}
	fmt.Printf("   replayed %d events; projection is identical (invariant I5)\n", replayed.EventCount)

	// ---- 3. export -------------------------------------------------------
	step("3", "export an evidence bundle with inclusion proofs for this saga")

	m, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: evidenceDir,
		Dest:       bundleDir,
		Keys:       keySet,
		Producer:   "janus-skeleton/" + version,
		Partition:  "default",
		SagaID:     sagaID,
		Rationale:  "Phase 0 walking skeleton demonstration",
	})
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	fmt.Printf("   %d events in %d segment(s), %d inclusion proofs\n", m.Events, len(m.Segments), len(m.Selection))
	fmt.Printf("   head chain %s\n", m.HeadChain)

	// ---- 4. verify offline ----------------------------------------------
	step("4", "verify the bundle the way an auditor would: offline, from the bytes")

	rep, err := verify.Bundle(bundleDir, verify.Options{
		Keys:            keySet,
		ExpectHeadChain: m.HeadChain,
		Version:         version,
	})
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Print(indent(rep.Text(), "   "))
	if !rep.OK {
		return fmt.Errorf("bundle verification failed")
	}

	// ---- 5. prove the verifier is not just saying yes --------------------
	step("5", "tamper with one byte and confirm the same verifier rejects it")

	if err := proveTamperDetection(bundleDir, keySet); err != nil {
		return err
	}

	fmt.Printf("\nPhase 0 exit gate: PASS\n")
	fmt.Printf("  saga ran, replayed identically, exported, verified offline, and a\n")
	fmt.Printf("  single-byte edit was rejected by the same verifier.\n")
	if keep {
		fmt.Printf("\nartifacts kept in %s\n", workDir)
	}
	return nil
}

// runSaga executes begin → one PURE step → seal → commit.
func runSaga(ctx context.Context, app *evidence.Appender, sagaID string) (saga.State, error) {
	r := saga.NewRunner(app, evidence.ParticipantRef{
		ID:              "ag_skeleton",
		ManifestVersion: "0.1.0",
		Principal:       "pr_demo",
		Kind:            "AGENT",
	}).WithTrace("4bf92f3577b34da6a3ce929d0e0e4736")

	const stepID = "st_summarise"

	if _, err := r.Begin(ctx, &janusv1.SagaBegin{
		SagaId: sagaID,
		Mode:   "supervised",
		Intent: &janusv1.Intent{
			IntentId:           "in_demo_0001",
			Principal:          "pr_demo",
			Originator:         "human:analyst@demo",
			MandateRef:         "policy:P-12",
			Scope:              "summarise one document",
			ExpiresAtUnixNanos: time.Now().Add(time.Hour).UnixNano(),
		},
		Plan: []*janusv1.PlannedStep{{
			StepId:      stepID,
			Participant: "ag_skeleton",
			Action:      "documents.summarise",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		}},
		ManifestPins: map[string]string{"ag_skeleton": "0.1.0"},
	}); err != nil {
		return saga.State{}, fmt.Errorf("begin: %w", err)
	}

	argsHash := evidence.HashPayload([]byte(`{"document":"demo.pdf"}`))
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{
		SagaId:      sagaID,
		StepId:      stepID,
		Participant: &janusv1.ParticipantRef{Id: "ag_skeleton", ManifestVersion: "0.1.0", Principal: "pr_demo"},
		Action:      "documents.summarise",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		ArgsHash:    argsHash[:],
		IdemKey:     "demo.pdf/summarise/1",
	}); err != nil {
		return saga.State{}, fmt.Errorf("prepare: %w", err)
	}

	// The "why" behind the step. A PURE step still gets a provenance record:
	// the grounds are what a GDPR Art. 15 or CFPB adverse-action export is
	// generated from later, and they have to exist from the first phase or they
	// never get retrofitted.
	outputHash := evidence.HashPayload([]byte("The document describes a loan application."))
	if _, err := r.RecordDPR(ctx, &janusv1.DecisionProvenanceRecord{
		DprId:        "dpr_0001",
		SagaId:       sagaID,
		StepId:       stepID,
		DecisionKind: janusv1.DecisionProvenanceRecord_DECISION_KIND_ACT,
		Model: &janusv1.DecisionProvenanceRecord_ModelRef{
			Id: "demo-model", Version: "1.0", ServingFingerprint: "sha256:demo", Temperature: 0,
		},
		Output: &janusv1.DecisionProvenanceRecord_Output{
			Hash: outputHash[:], SchemaId: "summary/v1", ParseStatus: "OK",
		},
		Grounds: []*janusv1.DecisionProvenanceRecord_Ground{{
			Claim:  "the document is a loan application",
			Source: "document",
		}},
		IntentRef: "in_demo_0001",
	}); err != nil {
		return saga.State{}, fmt.Errorf("dpr: %w", err)
	}

	resultHash := outputHash
	if _, err := r.StepResult(ctx, &janusv1.StepResult{
		SagaId:     sagaID,
		StepId:     stepID,
		Outcome:    &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		ResultHash: resultHash[:],
		Touches: []*janusv1.ResourceTouch{{
			ResourceId: "doc:demo.pdf",
			Mode:       janusv1.ResourceTouch_MODE_READ,
		}},
	}); err != nil {
		return saga.State{}, fmt.Errorf("result: %w", err)
	}

	if _, err := r.Seal(ctx, &janusv1.SealRequest{SagaId: sagaID}); err != nil {
		return saga.State{}, fmt.Errorf("seal: %w", err)
	}

	commitRef, err := r.Commit(ctx, &janusv1.Commit{SagaId: sagaID})
	if err != nil {
		return saga.State{}, fmt.Errorf("commit: %w", err)
	}
	_ = commitRef

	return r.State(), nil
}

// proveTamperDetection edits one byte of the exported bundle and requires the
// verifier to reject it. A verifier that has never been seen to say no is not
// evidence of anything.
func proveTamperDetection(bundleDir string, keySet keys.PublicKeySet) error {
	m, err := bundle.LoadManifest(bundleDir)
	if err != nil {
		return err
	}
	target := filepath.Join(bundleDir, filepath.FromSlash(m.Segments[0].File))
	original, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	defer func() { _ = os.WriteFile(target, original, 0o640) }()

	mutated := append([]byte(nil), original...)
	off := len(mutated) / 2
	mutated[off] ^= 0x01
	if err := os.WriteFile(target, mutated, 0o640); err != nil {
		return err
	}

	rep, err := verify.Bundle(bundleDir, verify.Options{Keys: keySet, Version: version})
	if err != nil {
		// Refusing to parse is a rejection too.
		fmt.Printf("   flipped one bit at offset %d — verifier refused the artifact: %v\n", off, err)
		return nil
	}
	if rep.OK {
		return fmt.Errorf("flipping bit at offset %d went undetected: the verifier cannot be trusted", off)
	}
	fmt.Printf("   flipped one bit at offset %d of %s\n", off, filepath.Base(target))
	for _, f := range rep.Findings {
		if f.Severity == verify.Critical {
			fmt.Printf("   verifier rejected it: [%s] %s\n", f.Severity, f.Code)
			break
		}
	}
	return nil
}

func step(n, title string) {
	fmt.Printf("── %s. %s\n", n, title)
}

func indent(s, prefix string) string {
	out := prefix
	for i, r := range s {
		out += string(r)
		if r == '\n' && i != len(s)-1 {
			out += prefix
		}
	}
	return out
}

func shortClass(c janusv1.EffectClass) string {
	const p = "EFFECT_CLASS_"
	n := c.String()
	if len(n) > len(p) {
		return n[len(p):]
	}
	return n
}
