package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// backupFixture writes a log, backs it up, and returns the paths.
//
// The log is left *open* while the backup is taken, which is the case that
// matters: a backup of a quiesced log has no unsealed tail and would not
// exercise the half of this that is new.
func backupFixture(t *testing.T, records int) (evidenceDir, backupDir, keyPath, pubPath string, signer *keys.Signer) {
	t.Helper()
	root := t.TempDir()
	evidenceDir = filepath.Join(root, "evidence")
	backupDir = filepath.Join(root, "backup")
	keyPath = filepath.Join(root, "writer.key")
	pubPath = filepath.Join(root, "public.json")

	var err error
	signer, err = keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Save(keyPath); err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(keys.PublicKeySet{signer.KeyID(): signer.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, blob, 0o640); err != nil {
		t.Fatal(err)
	}

	a, err := evidence.Open(evidence.Options{
		Dir: evidenceDir, Signer: signer, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range records {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: fmt.Sprintf("sg_%03d", i/5),
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_backup", ManifestVersion: "1.0.0"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Left open on purpose: a backup is taken from a *live* log, whose newest
	// segment is unsealed. Closing here would seal everything and quietly turn
	// this into a fixture for the case that was already easy.
	t.Cleanup(func() { _ = a.Close() })

	if err := backup([]string{"-evidence", evidenceDir, "-out", backupDir,
		"-key", keyPath, "-keys", pubPath}); err != nil {
		t.Fatalf("backing up: %v", err)
	}
	return evidenceDir, backupDir, keyPath, pubPath, signer
}

// TestAWriterContinuesTheChainAcrossARestore is proof continuity's third claim,
// and the one a well-meaning implementation breaks.
//
// The first two claims — byte identity and a chain that verifies from the
// original root — are about the artifact. This one is about what happens *next*:
// an appender opened on a restored directory has to continue the same chain, so
// that records from before the backup and after the restore verify as one log.
// An implementation that re-chained from zero, or that derived its next segment
// id wrongly, would satisfy both other claims and produce a log an auditor
// cannot follow across the boundary.
func TestAWriterContinuesTheChainAcrossARestore(t *testing.T) {
	_, backupDir, keyPath, pubPath, signer := backupFixture(t, 40)
	target := filepath.Join(t.TempDir(), "restored")

	if err := restore([]string{"-backup", backupDir, "-evidence", target, "-keys", pubPath}); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	m, err := bundle.LoadManifest(backupDir)
	if err != nil {
		t.Fatal(err)
	}

	// Write on the restored directory, exactly as a promoted region would.
	reopened, err := keys.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := evidence.Open(evidence.Options{
		Dir: target, Signer: reopened, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatalf("opening the restored directory: %v", err)
	}
	ref, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindStepResult, SagaID: "sg_after_restore", StepID: "st_00",
		Participant: evidence.ParticipantRef{ID: "ag_backup", ManifestVersion: "1.0.0"},
		Payload:     []byte(`{"after":true}`),
	})
	if err != nil {
		t.Fatalf("appending after the restore: %v", err)
	}
	// The next sequence, not necessarily m.LastSeq+1: opening a directory whose
	// last segment is unsealed makes the appender record a RECOVERY event first,
	// and a backup always ends in an unsealed segment. That record is a feature
	// rather than noise — the restore boundary is *in the log*, where an auditor
	// asking "what happened here" can find it — and it is asserted below rather
	// than tolerated.
	if ref.Seq <= m.LastSeq {
		t.Errorf("the first record after the restore is sequence %d and the backup ended "+
			"at %d: the chain went backwards", ref.Seq, m.LastSeq)
	}
	var recovery bool
	if err := evidence.Walk(target, func(h evidence.EventHeader, _ segment.Record) error {
		if h.Seq > m.LastSeq && h.Kind == evidence.KindRecovery {
			recovery = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !recovery {
		t.Error("no RECOVERY event marks the restore boundary; an auditor reading this " +
			"log would find the seam only by noticing the timestamps jump")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// The whole thing must verify as one log, from the original root.
	rep, err := verify.SegmentDir(target, verify.Options{
		Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()}, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		for _, f := range rep.Findings {
			t.Errorf("finding: %s %s — %s", f.Severity, f.Code, f.Message)
		}
		t.Fatal("the restored-and-extended log does not verify as one log")
	}
}

// TestARestoreRefusesAnUnsignedBackup is what separates a backup from an audit
// bundle.
//
// A backup includes the open tail, which carries no footer, so the manifest's
// signature is the only thing authenticating it — and the manifest is also the
// segment list, which an attacker who can rewrite it can shorten. Restoring from
// an unsigned bundle would be restoring from an attacker's arithmetic.
func TestARestoreRefusesAnUnsignedBackup(t *testing.T) {
	_, backupDir, _, pubPath, _ := backupFixture(t, 20)
	if err := os.Remove(filepath.Join(backupDir, bundle.SignatureName)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")

	err := restore([]string{"-backup", backupDir, "-evidence", target, "-keys", pubPath})
	if err == nil {
		t.Fatal("an unsigned backup was restored")
	}
	if !errors.Is(err, bundle.ErrUnsigned) {
		t.Fatalf("got %v, want it to wrap ErrUnsigned", err)
	}
}

// TestARestoreCatchesATamperedSegment is claim one, checked rather than trusted.
//
// A copy is where bytes get lost, and the manifest already says what each file
// should hash to — so the digest comparison is free and its absence would be a
// restore that quietly produced a shorter log.
func TestARestoreCatchesATamperedSegment(t *testing.T) {
	_, backupDir, _, pubPath, _ := backupFixture(t, 40)

	m, err := bundle.LoadManifest(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(backupDir, m.Segments[0].File)
	blob, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)/2] ^= 0xFF
	if err := os.WriteFile(victim, blob, 0o640); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "restored")
	err = restore([]string{"-backup", backupDir, "-evidence", target, "-keys", pubPath})
	if err == nil {
		t.Fatal("a backup with an altered segment was restored")
	}
	if !strings.Contains(err.Error(), "does not match the manifest") {
		t.Fatalf("got %v, want a digest mismatch", err)
	}
}

// TestARestoreRefusesADirectoryThatAlreadyHoldsALog is the three-in-the-morning
// operator error.
//
// Restoring over a live directory, or over a previous restore, would interleave
// two logs' segments and produce a directory whose sequence numbers jump — which
// the verifier calls damage, correctly, long after the cause is gone.
func TestARestoreRefusesADirectoryThatAlreadyHoldsALog(t *testing.T) {
	evidenceDir, backupDir, _, pubPath, _ := backupFixture(t, 20)

	err := restore([]string{"-backup", backupDir, "-evidence", evidenceDir, "-keys", pubPath})
	if err == nil {
		t.Fatal("a restore over a directory that already holds a log was allowed")
	}
	if !strings.Contains(err.Error(), "already contains segment files") {
		t.Fatalf("got %v, want a refusal naming the existing segments", err)
	}
}

// TestABackupIncludesTheOpenTail is the RPO claim.
//
// An audit bundle omits the unsealed segment because it carries no signature. A
// backup that did the same would lose everything since the last rotation — up to
// a whole segment of acknowledged evidence, which is exactly what a backup
// exists to preserve.
func TestABackupIncludesTheOpenTail(t *testing.T) {
	evidenceDir, backupDir, _, _, _ := backupFixture(t, 40)

	m, err := bundle.LoadManifest(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	var unsealed int
	for _, e := range m.Segments {
		if !e.Sealed {
			unsealed++
		}
	}
	if unsealed == 0 {
		t.Fatal("the backup contains no unsealed segment, so either the fixture never " +
			"left one open or the open tail was dropped")
	}

	// And the tail's records are actually in it: the last sequence in the
	// backup must equal the last sequence in the log.
	var last uint64
	if err := evidence.Walk(evidenceDir, func(h evidence.EventHeader, _ segment.Record) error {
		last = h.Seq
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if m.LastSeq != last {
		t.Errorf("the backup ends at sequence %d and the log ends at %d: the open tail's "+
			"records were not captured", m.LastSeq, last)
	}
}

// TestABackupOfABusyLogRestores is the race the torn-tail cap also closes.
//
// `Export` inspects a segment and then copies it: two separate reads of a file a
// writer may be appending to. Without a cap at the inspected end, records written
// between the two land in the copy while the manifest's Records, LastSeq and
// HeadChain still describe the earlier state — so the backup fails its **own**
// head check at restore, which is the classic backup failure: discovered at the
// worst possible moment, from an artifact that looked fine when it was made.
//
// The guarantee is the cap, and the torn-tail test pins that deterministically.
// This exercises the race probabilistically, which is the honest description: a
// pass is evidence, not proof.
func TestABackupOfABusyLogRestores(t *testing.T) {
	root := t.TempDir()
	evidenceDir := filepath.Join(root, "evidence")
	keyPath := filepath.Join(root, "writer.key")
	pubPath := filepath.Join(root, "public.json")

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Save(keyPath); err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(keys.PublicKeySet{signer.KeyID(): signer.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, blob, 0o640); err != nil {
		t.Fatal(err)
	}

	a, err := evidence.Open(evidence.Options{
		Dir: evidenceDir, Signer: signer, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	// A writer that does not stop while the backups are taken.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := a.Append(context.Background(), evidence.Request{
				Kind: evidence.KindStepResult, SagaID: "sg_busy",
				StepID:      fmt.Sprintf("st_%05d", i),
				Participant: evidence.ParticipantRef{ID: "ag_backup", ManifestVersion: "1.0.0"},
				Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
			}); err != nil {
				return
			}
			// Throttled, but only just. An unthrottled writer produces a log
			// that grows faster than the backups can copy it and the test
			// becomes a long measurement of nothing; too slow and the writer
			// never moves between two of Export's per-segment inspections,
			// which is the race this exists to catch. This rate rotates a
			// 4 KiB segment every few backups, which is where the hole appears.
			time.Sleep(200 * time.Microsecond)
		}
	}()

	for round := range 12 {
		backupDir := filepath.Join(root, fmt.Sprintf("backup-%d", round))
		if err := backup([]string{"-evidence", evidenceDir, "-out", backupDir,
			"-key", keyPath, "-keys", pubPath}); err != nil {
			close(stop)
			<-done
			t.Fatalf("round %d: backing up a busy log: %v", round, err)
		}
		target := filepath.Join(root, fmt.Sprintf("restored-%d", round))
		if err := restore([]string{"-backup", backupDir, "-evidence", target,
			"-keys", pubPath}); err != nil {
			close(stop)
			<-done
			t.Fatalf("round %d: a backup taken from a busy log does not restore: %v", round, err)
		}
	}
	close(stop)
	<-done
}

// TestASweepCatchesWhatTheRestoreSkipped is the other half of the decision to
// defer the sweep until after a restore, and without it that decision is a promise rather than a design.
//
// A restore checks signatures on the *manifest* and digests on the files, then
// starts serving — the full per-segment signature and Merkle sweep is left until
// afterwards, because verifying 100M events takes 254.5 s of a 300 s RTO budget.
// That is only defensible if the sweep actually catches what the fast path lets
// through.
//
// So: tamper with a segment *after* it has been restored, in a way the digest
// check has already passed over, and require the sweep to find it. If it did
// not, the window would not be a window — it would be a hole.
func TestASweepCatchesWhatTheRestoreSkipped(t *testing.T) {
	_, backupDir, _, pubPath, _ := backupFixture(t, 60)
	target := filepath.Join(t.TempDir(), "restored")

	if err := restore([]string{"-backup", backupDir, "-evidence", target, "-keys", pubPath}); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	// Clean first, so a failure below is the tamper and not the restore.
	if err := sweep([]string{"-evidence", target, "-keys", pubPath}); err != nil {
		t.Fatalf("a freshly restored log does not sweep clean: %v", err)
	}

	// Alter a *sealed* segment's records after the restore. Its footer still
	// signs the original bytes, so only a signature or Merkle check finds this —
	// which is exactly the class of damage the fast path skips.
	ids, err := segment.ScanComplete(target)
	if err != nil {
		t.Fatal(err)
	}
	var victim string
	for _, id := range ids {
		sealed, err := segment.IsSealed(segment.Path(target, id))
		if err != nil {
			t.Fatal(err)
		}
		if sealed {
			victim = segment.Path(target, id)
			break
		}
	}
	if victim == "" {
		t.Fatal("no sealed segment was restored, so this proves nothing about the sweep")
	}
	blob, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)/2] ^= 0x01
	if err := os.WriteFile(victim, blob, 0o640); err != nil {
		t.Fatal(err)
	}

	if err := sweep([]string{"-evidence", target, "-keys", pubPath}); err == nil {
		t.Fatal("the sweep passed over a tampered sealed segment: the window a deferred sweep " +
			"opens would be a hole rather than a window")
	}
}

// TestTheSweepCatchesCorruptionTheRestoreCannot is the test that makes the
// deferred sweep's whole shape defensible rather than merely stated.
//
// The restore reads no records. It checks that the manifest is the writer's and
// that the files are the ones it names — which is sufficient against an attacker
// without the writer's key, and says nothing about whether the source log was
// internally sound when the backup was taken. Corruption faithfully bundled is
// faithfully restored, and the sweep is what closes that window.
//
// So this corrupts an **early sealed** segment of the source log *before* the
// backup. The framing still parses, so `Export` bundles it; the digest is
// computed over the corrupt bytes, so it is self-consistent; the restore
// therefore passes. Only the sweep, which recomputes chain hashes and Merkle
// roots, can find it.
//
// Early, and sealed, on purpose: `evidence.Open` walks the tail when it recovers,
// so damage there would be caught by the appender at start-up — which is a
// different gate, and testing it would prove nothing about this one.
//
// Under the pre-start verification this PR removed, this test failed at *restore*.
// That it now passes restore and fails the sweep is the whole correction.
func TestTheSweepCatchesCorruptionTheRestoreCannot(t *testing.T) {
	root := t.TempDir()
	evidenceDir := filepath.Join(root, "evidence")
	keyPath := filepath.Join(root, "writer.key")
	pubPath := filepath.Join(root, "public.json")

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Save(keyPath); err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(keys.PublicKeySet{signer.KeyID(): signer.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, blob, 0o640); err != nil {
		t.Fatal(err)
	}

	a, err := evidence.Open(evidence.Options{
		Dir: evidenceDir, Signer: signer, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 80 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_corrupt",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_backup", ManifestVersion: "1.0.0"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// The first sealed segment: early enough that recovery never looks at it.
	ids, err := segment.ScanComplete(evidenceDir)
	if err != nil {
		t.Fatal(err)
	}
	var victim string
	for _, id := range ids {
		sealed, err := segment.IsSealed(segment.Path(evidenceDir, id))
		if err != nil {
			t.Fatal(err)
		}
		if sealed {
			victim = segment.Path(evidenceDir, id)
			break
		}
	}
	if victim == "" {
		t.Fatal("no sealed segment, so this proves nothing")
	}
	raw, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(victim, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	// The framing must still parse, or Export would refuse and this would be a
	// test of Inspect rather than of the restore/sweep split.
	if _, err := segment.Inspect(victim); err != nil {
		t.Skipf("the flip broke framing rather than content (%v); this test needs "+
			"damage that parses and does not verify", err)
	}

	backupDir := filepath.Join(root, "backup")
	if err := backup([]string{"-evidence", evidenceDir, "-out", backupDir,
		"-key", keyPath, "-keys", pubPath}); err != nil {
		t.Fatalf("backing up a log with faithful corruption in it: %v", err)
	}

	target := filepath.Join(root, "restored")
	if err := restore([]string{"-backup", backupDir, "-evidence", target, "-keys", pubPath}); err != nil {
		t.Fatalf("the restore refused corruption it cannot see: %v — either it is reading "+
			"records after all, or the corruption was not faithful", err)
	}

	if err := sweep([]string{"-evidence", target, "-keys", pubPath}); err == nil {
		t.Fatal("the sweep passed over corruption the restore deliberately did not look " +
			"for: the deferred sweep's window would be a hole")
	}
}
