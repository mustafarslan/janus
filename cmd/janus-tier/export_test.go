package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// exportFixture writes a log with one saga spanning several segments and leaves
// it open, so that the saga has events in the unsealed tail.
//
// Left open on purpose, for the same reason the backup fixture is: an export
// from a quiesced log has no tail to omit, and the omission is the thing this
// command has to be honest about.
func exportFixture(t *testing.T, records int) (dir, pubPath string, signer *keys.Signer) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "evidence")
	pubPath = filepath.Join(root, "public.json")

	var err error
	signer, err = keys.Generate()
	if err != nil {
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
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range records {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_audited",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_export", ManifestVersion: "1.0.0"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = a.Close() })
	return dir, pubPath, signer
}

// capture runs fn with stdout redirected, and returns what it printed.
//
// The warnings this command prints are the deliverable, not decoration — an
// auditor who is not told the bundle is partial concludes it is whole — so they
// are asserted like any other behaviour.
func capture(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = saved
	_ = w.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := r.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	_ = r.Close()
	return sb.String(), runErr
}

// TestAnExportedBundleVerifiesTheWayAnAuditorRunsIt is the whole point of the
// command: the artifact janus-verify documents as its input, produced by
// something a deployment actually runs.
func TestAnExportedBundleVerifiesTheWayAnAuditorRunsIt(t *testing.T) {
	dir, pubPath, signer := exportFixture(t, 60)
	dest := filepath.Join(t.TempDir(), "bundle")

	out, err := capture(t, func() error {
		return export([]string{"-evidence", dir, "-out", dest, "-keys", pubPath,
			"-saga", "sg_audited", "-reason", "mock supervisory inspection"})
	})
	if err != nil {
		t.Fatalf("exporting: %v\n%s", err, out)
	}

	m, err := bundle.LoadManifest(dest)
	if err != nil {
		t.Fatal(err)
	}
	// Assert the fixture produced the situation, not just that the code ran. A
	// log that never rotated would have no sealed segment, and this test would
	// be checking an export of nothing.
	if len(m.Segments) < 2 {
		t.Fatalf("the fixture did not rotate: %d segment(s) in the bundle, so this test "+
			"is not exercising a multi-segment export", len(m.Segments))
	}
	for _, seg := range m.Segments {
		if !seg.Sealed {
			t.Errorf("segment %d is unsealed; an audit bundle carries only segments a "+
				"footer signs", seg.SegmentID)
		}
	}
	if len(m.Selection) == 0 {
		t.Fatal("no inclusion proofs, though -saga named a saga with events in the bundle")
	}
	if m.Scope == nil || m.Scope.Rationale != "mock supervisory inspection" {
		t.Errorf("the manifest does not record why the export was made: %+v", m.Scope)
	}

	// The auditor's command, with roots supplied out of band and the head the
	// export printed.
	rep, err := verify.Bundle(dest, verify.Options{
		Keys:            keys.PublicKeySet{signer.KeyID(): signer.Public()},
		ExpectHeadChain: m.HeadChain,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("an exported bundle did not verify:\n%s", rep.Text())
	}
}

// TestAnExportSaysWhenItIsMissingTheSagasTail is the incomplete-bundle failure mode, caught
// at the point it would be created.
//
// Every claim in a sealed-only bundle is true. The bundle is still not the whole
// saga while the log is being written, and an auditor handed proofs for some of
// a saga's events, with nothing saying so, concludes they have the saga.
func TestAnExportSaysWhenItIsMissingTheSagasTail(t *testing.T) {
	dir, pubPath, _ := exportFixture(t, 60)
	dest := filepath.Join(t.TempDir(), "bundle")

	out, err := capture(t, func() error {
		return export([]string{"-evidence", dir, "-out", dest, "-keys", pubPath,
			"-saga", "sg_audited"})
	})
	if err != nil {
		t.Fatalf("exporting: %v\n%s", err, out)
	}
	m, err := bundle.LoadManifest(dest)
	if err != nil {
		t.Fatal(err)
	}
	// Assert the setup: there must actually be events in the open tail, or this
	// test passes for the wrong reason.
	if len(m.Selection) >= 60 {
		t.Fatalf("the bundle holds proofs for %d of 60 events, so nothing was left in "+
			"the open tail and this test is not exercising the omission", len(m.Selection))
	}
	if !strings.Contains(out, "are in the open tail and are NOT") {
		t.Errorf("the export did not say that part of the saga is missing:\n%s", out)
	}
	if want := fmt.Sprintf("this covers %d of 60", len(m.Selection)); !strings.Contains(out, want) {
		t.Errorf("the export did not say %q:\n%s", want, out)
	}
}

// TestATamperedInclusionProofIsNamed asserts on the finding code rather than on
// rep.OK, because a bundle broken in some unrelated way would also make OK false
// and would prove nothing about whether the proof itself was checked.
func TestATamperedInclusionProofIsNamed(t *testing.T) {
	dir, pubPath, signer := exportFixture(t, 60)
	dest := filepath.Join(t.TempDir(), "bundle")
	if _, err := capture(t, func() error {
		return export([]string{"-evidence", dir, "-out", dest, "-keys", pubPath,
			"-saga", "sg_audited"})
	}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dest, bundle.ManifestName)
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatal(err)
	}
	sel, ok := raw["selection"].([]any)
	if !ok || len(sel) == 0 {
		t.Fatal("the exported manifest carries no selection, so there is no inclusion " +
			"proof to doctor and this test cannot check that one is verified")
	}
	first := sel[0].(map[string]any)
	proof, ok := first["merkle_proof"].([]any)
	if !ok || len(proof) == 0 {
		t.Fatal("the first selected event carries an empty proof; nothing to doctor")
	}
	// One element of one proof, changed to another valid-looking hash.
	proof[0] = strings.Repeat("ab", 32)
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o640); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.Bundle(dest, verify.Options{
		Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(rep, "SELECTION_PROOF_INVALID") {
		t.Fatalf("a doctored inclusion proof was not named; findings:\n%s", rep.Text())
	}
}

func hasCode(rep *verify.Report, code string) bool {
	for _, f := range rep.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// TestAnExportRefusesWithoutAKeySet keeps the manifest from naming no keys at
// all, which would leave an auditor checking the bundle against itself.
func TestAnExportRefusesWithoutAKeySet(t *testing.T) {
	dir, _, _ := exportFixture(t, 20)
	err := export([]string{"-evidence", dir, "-out", filepath.Join(t.TempDir(), "b")})
	if err == nil {
		t.Fatal("an export with no -keys was accepted")
	}
	if !strings.Contains(err.Error(), "checked only against itself") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// TestAnExportRefusesToOverwrite: a bundle may already have been handed to
// somebody, and rewriting it in place changes what they were given.
func TestAnExportRefusesToOverwrite(t *testing.T) {
	dir, pubPath, _ := exportFixture(t, 20)
	dest := filepath.Join(t.TempDir(), "bundle")
	if _, err := capture(t, func() error {
		return export([]string{"-evidence", dir, "-out", dest, "-keys", pubPath})
	}); err != nil {
		t.Fatal(err)
	}
	if err := export([]string{"-evidence", dir, "-out", dest, "-keys", pubPath}); err == nil {
		t.Fatal("an export over an existing bundle was accepted")
	}
}

// TestAnExportOfALogWithNoSealedSegmentSaysSo. The tail is not exported, so a
// young log produces nothing — and the message has to explain that rather than
// leaving an operator with an empty directory.
func TestAnExportOfALogWithNoSealedSegmentSaysSo(t *testing.T) {
	dir, pubPath, _ := exportFixture(t, 2)
	err := export([]string{"-evidence", dir, "-out", filepath.Join(t.TempDir(), "b"),
		"-keys", pubPath})
	if err == nil {
		t.Fatal("an export from a log with no sealed segment was accepted")
	}
	if !strings.Contains(err.Error(), "no sealed segments") {
		t.Errorf("the refusal does not explain what is missing: %v", err)
	}
}

// TestASignedExportMeetsARequiredSignature: with the writer's key, an audit
// bundle's manifest is signed, so an auditor can require it and a bundle cut
// off at its end fails from its own bytes. Without the key
// the bundle is unsigned and the requirement is not met.
func TestASignedExportMeetsARequiredSignature(t *testing.T) {
	dir, pubPath, signer := exportFixture(t, 60)
	keyPath := filepath.Join(t.TempDir(), "writer.key")
	if err := signer.Save(keyPath); err != nil {
		t.Fatal(err)
	}
	roots := keys.PublicKeySet{signer.KeyID(): signer.Public()}
	required := verify.Options{Keys: roots, RequireSignedManifest: true}

	signed := filepath.Join(t.TempDir(), "signed")
	if out, err := capture(t, func() error {
		return export([]string{"-evidence", dir, "-out", signed, "-keys", pubPath, "-key", keyPath})
	}); err != nil {
		t.Fatalf("exporting: %v\n%s", err, out)
	}
	rep, err := verify.Bundle(signed, required)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("an export signed with the writer's key did not meet a required signature:\n%s",
			rep.Text())
	}

	unsigned := filepath.Join(t.TempDir(), "unsigned")
	if out, err := capture(t, func() error {
		return export([]string{"-evidence", dir, "-out", unsigned, "-keys", pubPath})
	}); err != nil {
		t.Fatalf("exporting: %v\n%s", err, out)
	}
	if rep, err = verify.Bundle(unsigned, required); err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("an export made without a key met a required signature")
	}
}
