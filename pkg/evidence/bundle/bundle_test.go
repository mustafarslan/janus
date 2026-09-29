package bundle_test

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// writeLog produces a small log containing two sagas and returns its directory
// and the writer's key set.
func writeLog(t *testing.T) (string, *keys.Signer) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 12 {
		saga := "sg_loan_0001"
		if i%3 == 0 {
			saga = "sg_other"
		}
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      saga,
			StepID:      fmt.Sprintf("st_%02d", i),
			Participant: evidence.ParticipantRef{ID: "ag_intake", ManifestVersion: "1.0.0"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, signer
}

func TestExportThenVerifyOffline(t *testing.T) {
	dir, signer := writeLog(t)
	dest := filepath.Join(t.TempDir(), "bundle")

	m, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir,
		Dest:       dest,
		Keys:       keys.PublicKeySet{signer.KeyID(): signer.Public()},
		Producer:   "janus-test",
		SagaID:     "sg_loan_0001",
		Rationale:  "unit test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Events != 12 {
		t.Fatalf("manifest declares %d events, want 12", m.Events)
	}
	if len(m.Selection) != 8 {
		t.Fatalf("selected %d events for sg_loan_0001, want 8", len(m.Selection))
	}
	for _, s := range m.Selection {
		if s.SagaID != "sg_loan_0001" {
			t.Fatalf("selection contains an event from %s", s.SagaID)
		}
		if len(s.MerkleProof) == 0 && s.TreeSize > 1 {
			t.Fatalf("event seq %d has no inclusion proof", s.Seq)
		}
	}

	rep, err := verify.Bundle(dest, verify.Options{
		Keys:    keys.PublicKeySet{signer.KeyID(): signer.Public()},
		Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("exported bundle did not verify:\n%s", rep.Text())
	}
	if rep.Events != 12 {
		t.Fatalf("verifier counted %d events, want 12", rep.Events)
	}
}

// TestVerifyWithoutSuppliedKeysIsNoted: a bundle that vouches for itself is
// weaker evidence, and the report has to say so rather than printing a bare PASS.
func TestVerifyWithoutSuppliedKeysIsNoted(t *testing.T) {
	dir, signer := writeLog(t)
	dest := filepath.Join(t.TempDir(), "bundle")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest,
		Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()},
	}); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.Bundle(dest, verify.Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("bundle should verify against its own keys:\n%s", rep.Text())
	}
	if !hasCode(rep, "KEYS_FROM_BUNDLE") {
		t.Fatal("report did not disclose that the keys came from the artifact being checked")
	}
	if !hasCode(rep, "MANIFEST_UNSIGNED") {
		t.Fatal("report did not disclose that the manifest is unsigned")
	}
}

func TestVerifyDetectsEditedSegmentInBundle(t *testing.T) {
	dir, signer := writeLog(t)
	dest := filepath.Join(t.TempDir(), "bundle")
	m, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest,
		Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(dest, filepath.FromSlash(m.Segments[0].File))
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.Bundle(dest, verify.Options{
		Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()}, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatalf("an edited segment passed bundle verification:\n%s", rep.Text())
	}
	if !hasCode(rep, "SEGMENT_DIGEST_MISMATCH") {
		t.Fatalf("expected the manifest digest to catch this, got:\n%s", rep.Text())
	}
}

// TestVerifyDetectsForgedInclusionProof: an attacker who wants to claim an event
// was in the log has to defeat the Merkle root, not just edit the manifest.
func TestVerifyDetectsForgedInclusionProof(t *testing.T) {
	dir, signer := writeLog(t)
	dest := filepath.Join(t.TempDir(), "bundle")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest,
		Keys:   keys.PublicKeySet{signer.KeyID(): signer.Public()},
		SagaID: "sg_loan_0001",
	}); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(dest, bundle.ManifestName)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	sel := m["selection"].([]any)
	first := sel[0].(map[string]any)
	// Claim a different event was covered by this proof.
	first["chain_hash"] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	patched, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, patched, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.Bundle(dest, verify.Options{
		Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()}, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatalf("a forged inclusion proof verified:\n%s", rep.Text())
	}
	if !hasCode(rep, "SELECTION_PROOF_INVALID") {
		t.Fatalf("expected SELECTION_PROOF_INVALID, got:\n%s", rep.Text())
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

// writeTenantLog produces a log written under a tenant binding, optionally
// switching binding partway through — which is how a mixed log gets made in
// practice, by pointing a second daemon at a directory that already holds
// somebody else's evidence.
func writeTenantLog(t *testing.T, dir string, tenants ...tenancy.Tenant) *keys.Signer {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range tenants {
		a, err := evidence.Open(evidence.Options{
			Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Tenant: tn,
		})
		if err != nil {
			t.Fatal(err)
		}
		for i := range 4 {
			if _, err := a.Append(context.Background(), evidence.Request{
				Kind:        evidence.KindStepResult,
				SagaID:      "sg_" + tn.ID,
				StepID:      fmt.Sprintf("st_%02d", i),
				Participant: evidence.ParticipantRef{ID: "ag_intake", ManifestVersion: "1.0.0"},
				Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return signer
}

// TestManifestNamesTheTenantItReadFromTheEvents checks the field an auditor
// opening a bundle reads first. It is derived from the records rather than set
// by whoever ran the export, so it is a statement about the bundle instead of a
// claim about it.
func TestManifestNamesTheTenantItReadFromTheEvents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer := writeTenantLog(t, dir, tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})

	dest := filepath.Join(t.TempDir(), "bundle")
	m, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest,
		Keys:            keys.PublicKeySet{signer.KeyID(): signer.Public()},
		IncludeUnsealed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Tenant == nil {
		t.Fatal("the manifest does not say whose evidence this is")
	}
	if m.Tenant.ID != "bank_a" || m.Tenant.Jurisdiction != "DE" {
		t.Fatalf("manifest names tenant %+v", *m.Tenant)
	}
	if m.Tenant.Unlabelled != 0 {
		t.Fatalf("manifest reports %d unlabelled events in a fully bound log", m.Tenant.Unlabelled)
	}

	// And the manifest on disk says it too, which is the copy an auditor has.
	loaded, err := bundle.LoadManifest(dest)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Tenant == nil || loaded.Tenant.ID != "bank_a" {
		t.Fatalf("the written manifest names tenant %+v", loaded.Tenant)
	}
}

// TestExportRefusesToBundleTwoTenants is the disclosure this stops.
//
// Every other property of the artifact would be perfect: the chain intact, the
// footers signed, the inclusion proofs sound. It would also be one bank's
// evidence handed to another, and no amount of correct signing makes that a
// smaller problem.
func TestExportRefusesToBundleTwoTenants(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer := writeTenantLog(t, dir,
		tenancy.Tenant{ID: "bank_a"}, tenancy.Tenant{ID: "bank_b"})

	dest := filepath.Join(t.TempDir(), "bundle")
	_, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest,
		Keys:            keys.PublicKeySet{signer.KeyID(): signer.Public()},
		IncludeUnsealed: true,
	})
	if !errors.Is(err, bundle.ErrMixedTenants) {
		t.Fatalf("a two-tenant log exported as one bundle: %v", err)
	}
}

// TestUnlabelledEventsAreCountedNotHidden covers the log that was bound to a
// tenant partway through its life. Refusing to export it would make the check
// useless on exactly the logs a migration produces; calling it wholly bank_a's
// evidence would be a stronger claim than the records support. So the manifest
// says how much of it does not say.
func TestUnlabelledEventsAreCountedNotHidden(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer := writeTenantLog(t, dir, tenancy.Tenant{}, tenancy.Tenant{ID: "bank_a"})

	dest := filepath.Join(t.TempDir(), "bundle")
	m, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest,
		Keys:            keys.PublicKeySet{signer.KeyID(): signer.Public()},
		IncludeUnsealed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Tenant == nil || m.Tenant.ID != "bank_a" {
		t.Fatalf("manifest names tenant %+v", m.Tenant)
	}
	if m.Tenant.Unlabelled != 4 {
		t.Fatalf("manifest reports %d unlabelled events, want 4", m.Tenant.Unlabelled)
	}
}

// TestAnUnsealedSegmentIsBundledWithoutItsTear is the difference between an
// audit bundle and a backup.
//
// An audit bundle is normally taken from a log nobody is writing to, so its
// segments are sealed and the question does not arise. A *backup* has to include
// the open tail — leaving it out costs a whole segment of RPO — and the open
// tail of a live log routinely ends in a partial record, because the writer's
// buffer flushes on byte boundaries.
//
// Copying those bytes would put content into the artifact that was never
// acknowledged and that nothing can verify: the manifest's own record count
// stops at the last complete record, so the file would carry a tail the manifest
// does not describe. The restored copy would then need recovery before it could
// be read, and the digest that was checked at restore would no longer match the
// bytes on disk.
func TestAnUnsealedSegmentIsBundledWithoutItsTear(t *testing.T) {
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_backup",
			StepID:      fmt.Sprintf("st_%02d", i),
			Participant: evidence.ParticipantRef{ID: "ag_intake", ManifestVersion: "1.0.0"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// The appender stays open on purpose: an *unsealed* segment is the case, and
	// closing would seal it and turn the bytes below into "data after a footer",
	// which is a different fault with a different answer.
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		t.Fatal(err)
	}
	open := segment.Path(dir, ids[0])
	info, err := os.Stat(open)
	if err != nil {
		t.Fatal(err)
	}
	// Cut into the last record, which is what a crash between a write and its
	// barrier leaves. Random bytes would be *corruption* and Inspect says so;
	// a torn tail is a record that stops early, and Inspect reports that as Torn
	// with the last good offset — which is the case a backup has to handle.
	if err := os.Truncate(open, info.Size()-40); err != nil {
		t.Fatal(err)
	}
	insp, err := segment.Inspect(open)
	if err != nil {
		t.Fatal(err)
	}
	if !insp.Torn {
		t.Fatalf("the segment is not torn, so this test proves nothing: %s", insp.TornDetail)
	}
	complete := insp.LastGoodOffset

	dest := filepath.Join(t.TempDir(), "backup")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest, Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()},
		IncludeUnsealed: true,
	}); err != nil {
		t.Fatalf("exporting with the open tail: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "segments", segment.FileName(ids[0])))
	if err != nil {
		t.Fatalf("the open segment was not included: %v", err)
	}
	if int64(len(got)) != complete {
		t.Errorf("the bundled segment is %d bytes and the last complete record ends at "+
			"%d: the torn tail was copied into the artifact", len(got), complete)
	}
}

// TestASignedManifestCatchesADroppedSegment is what the signature is for.
//
// Every segment's own footer is signed, so an attacker cannot alter a segment's
// contents. What they *can* do without a manifest signature is remove a segment
// from the bundle and adjust the manifest's counts to match — producing an
// artifact that is internally consistent and incomplete, which is precisely the
// gap an out-of-band head-chain anchor, not built, would close.
func TestASignedManifestCatchesADroppedSegment(t *testing.T) {
	dir, signer := writeLog(t)
	dest := filepath.Join(t.TempDir(), "backup")
	trusted := keys.PublicKeySet{signer.KeyID(): signer.Public()}

	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest, Keys: trusted,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bundle.SignManifest(dest, signer); err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyManifestSignature(dest, trusted); err != nil {
		t.Fatalf("a manifest just signed does not verify: %v", err)
	}

	// Rewrite the manifest, as somebody dropping a segment would have to.
	blob, err := os.ReadFile(filepath.Join(dest, bundle.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(blob), `"events"`, `"events_was"`, 1)
	if edited == string(blob) {
		t.Fatal("the manifest was not edited, so this proves nothing")
	}
	if err := os.WriteFile(filepath.Join(dest, bundle.ManifestName), []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}

	err = bundle.VerifyManifestSignature(dest, trusted)
	if !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("an altered manifest verified: %v", err)
	}
}

// TestAnUnsignedBundleIsDistinguishableFromABadlySignedOne keeps two different
// situations from collapsing into one answer.
//
// "Nobody signed this" and "somebody signed this and it does not check out" call
// for different responses: the first is an ordinary audit bundle, which is a
// supported artifact; the second is tampering. A caller that could not tell them
// apart would either treat every old bundle as an attack or treat an attack as a
// missing feature.
func TestAnUnsignedBundleIsDistinguishableFromABadlySignedOne(t *testing.T) {
	dir, signer := writeLog(t)
	dest := filepath.Join(t.TempDir(), "bundle")
	trusted := keys.PublicKeySet{signer.KeyID(): signer.Public()}

	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest, Keys: trusted,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyManifestSignature(dest, trusted); !errors.Is(err, bundle.ErrUnsigned) {
		t.Fatalf("an unsigned bundle reported %v, want ErrUnsigned", err)
	}

	// Signed by somebody else: not unsigned, and not acceptable.
	stranger, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.SignManifest(dest, stranger); err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyManifestSignature(dest, trusted); !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("a manifest signed by an untrusted key reported %v, want ErrBadSignature", err)
	}
}

// findingCode reports whether a report carries a code, and at what severity.
func findingCode(rep *verify.Report, code string) (verify.Finding, bool) {
	for _, f := range rep.Findings {
		if f.Code == code {
			return f, true
		}
	}
	return verify.Finding{}, false
}

// TestTheReportSaysWhetherTheManifestIsSigned is the regression for a report
// that told an auditor something false.
//
// `bundle.SignManifest` arrived in Phase 6 and `janus-tier backup` began signing.
// The verifier's note did not move: it was added unconditionally and said "the
// bundle manifest is not itself signed", so every signed backup verified with a
// report stating nobody had signed it. Every other line of that report was true,
// which is what made it dangerous — an auditor reads a summary, not a call graph.
//
// The mechanism was tested where it lives (see the two tests above) and the
// whole path was not. That is the gap: `VerifyManifestSignature` worked
// perfectly and `verify.Bundle` never called it.
func TestTheReportSaysWhetherTheManifestIsSigned(t *testing.T) {
	dir, signer := writeLog(t)
	trusted := keys.PublicKeySet{signer.KeyID(): signer.Public()}

	unsigned := filepath.Join(t.TempDir(), "audit")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: unsigned, Keys: trusted,
	}); err != nil {
		t.Fatal(err)
	}
	rep, err := verify.Bundle(unsigned, verify.Options{Keys: trusted})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingCode(rep, "MANIFEST_UNSIGNED"); !ok {
		t.Errorf("an unsigned bundle was not reported as unsigned:\n%s", rep.Text())
	}
	if !rep.OK {
		t.Errorf("an unsigned audit bundle is a supported artifact and must still pass:\n%s",
			rep.Text())
	}

	signed := filepath.Join(t.TempDir(), "backup")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: signed, Keys: trusted,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bundle.SignManifest(signed, signer); err != nil {
		t.Fatal(err)
	}
	rep, err = verify.Bundle(signed, verify.Options{Keys: trusted})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingCode(rep, "MANIFEST_UNSIGNED"); ok {
		t.Errorf("a SIGNED bundle was reported as unsigned — the report states something "+
			"false about the artifact:\n%s", rep.Text())
	}
	f, ok := findingCode(rep, "MANIFEST_SIGNED")
	if !ok {
		t.Fatalf("a signed bundle's report does not mention the signature:\n%s", rep.Text())
	}
	if !strings.Contains(f.Message, "supplied out of band") {
		t.Errorf("the report does not say the signature was checked against the caller's "+
			"roots: %s", f.Message)
	}
	if !rep.OK {
		t.Errorf("a correctly signed bundle did not pass:\n%s", rep.Text())
	}
}

// TestVerifyCatchesADroppedSegmentFromASignedBackup is what the fix buys beyond
// a truer sentence.
//
// Prefix truncation is invisible from inside an unsigned bundle: drop the
// trailing segments, adjust the manifest to match, and what remains is a valid
// prefix of a hash chain, which is a valid hash chain. Only an out-of-band head
// catches that. A *signed* manifest catches it without one — but only if
// something checks the signature, and until now nothing an auditor runs did.
func TestVerifyCatchesADroppedSegmentFromASignedBackup(t *testing.T) {
	dir, signer := rotatingLog(t, 60)
	trusted := keys.PublicKeySet{signer.KeyID(): signer.Public()}
	dest := filepath.Join(t.TempDir(), "backup")
	m, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest, Keys: trusted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.SignManifest(dest, signer); err != nil {
		t.Fatal(err)
	}
	// Assert the setup rather than skipping past it. A one-segment bundle has no
	// trailing segment to drop, so a skip here would look like coverage and be
	// none — which is how the fork comparison shipped a bug behind a test that
	// compared two identical directories.
	if len(m.Segments) < 2 {
		t.Fatalf("the fixture produced %d segment(s), so there is nothing to truncate and "+
			"this test is not exercising prefix truncation", len(m.Segments))
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
	segs := raw["segments"].([]any)
	gone := segs[len(segs)-1].(map[string]any)
	raw["segments"] = segs[:len(segs)-1]
	if err := os.Remove(filepath.Join(dest, gone["file"].(string))); err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o640); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.Bundle(dest, verify.Options{Keys: trusted})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findingCode(rep, "MANIFEST_SIGNATURE_INVALID")
	if !ok {
		t.Fatalf("a segment was dropped from a signed backup and the signature check did "+
			"not name it — no out-of-band head was supplied, so nothing else would:\n%s",
			rep.Text())
	}
	if f.Severity != verify.Critical {
		t.Errorf("a manifest that does not match its signature is reported as %v, want Critical",
			f.Severity)
	}
}

// TestASignatureByARotatedKeyStillVerifies is the trap this fix had to be
// designed around, and it is the reason the check runs after the segment walk.
//
// Writer trust extends *forward*: a new key is declared in a
// segment the old one signed, so an auditor holding only the original root can
// follow the rotation. A backup taken after a rotation carries a manifest signed
// by the NEW key. Checking that against the caller's roots alone would report a
// perfectly legitimate signature as invalid — replacing one false statement with
// a worse one, since this one is Critical and would send somebody looking for an
// attacker who does not exist.
func TestASignatureByARotatedKeyStillVerifies(t *testing.T) {
	first, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: first, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := range 6 {
		if _, err := a.Append(ctx, evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_rot",
			StepID:      fmt.Sprintf("st_%02d", i),
			Participant: evidence.ParticipantRef{ID: "ag_intake", ManifestVersion: "1.0.0"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// The declaration goes in a segment the FIRST key signs, which is what makes
	// the rotation followable from the first root alone.
	if _, err := a.RecordWriterKey(ctx, evidence.WriterKeyDeclaration{
		Kind: evidence.WriterKeyTrusted, KeyID: second.KeyID(), PublicKey: second.Public(),
	}, evidence.ParticipantRef{ID: "sys_orchd", Kind: "SYSTEM"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// Only the FIRST key, which is all an auditor should need.
	roots := keys.PublicKeySet{first.KeyID(): first.Public()}
	dest := filepath.Join(t.TempDir(), "backup")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest, Keys: roots,
	}); err != nil {
		t.Fatal(err)
	}
	// Signed by the key the log rotated to, as a backup taken after a rotation is.
	if err := bundle.SignManifest(dest, second); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.Bundle(dest, verify.Options{Keys: roots})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findingCode(rep, "MANIFEST_SIGNATURE_INVALID"); ok {
		t.Fatalf("a signature by a key the log properly introduced was called invalid, so "+
			"forward trust stops at the manifest: %s", f.Message)
	}
	if _, ok := findingCode(rep, "MANIFEST_SIGNED"); !ok {
		t.Errorf("a signature by a rotated key was not recognised:\n%s", rep.Text())
	}
}

// TestASignatureCheckedAgainstTheBundlesOwnKeysSaysSo keeps the weaker check
// from reading like the stronger one.
//
// With no roots supplied, the manifest's own key set stands in — so a signature
// verifying proves the artifact is internally consistent, which is exactly what
// somebody who rewrote the manifest and the key set together would also produce.
func TestASignatureCheckedAgainstTheBundlesOwnKeysSaysSo(t *testing.T) {
	dir, signer := writeLog(t)
	dest := filepath.Join(t.TempDir(), "backup")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest,
		Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()},
	}); err != nil {
		t.Fatal(err)
	}
	if err := bundle.SignManifest(dest, signer); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.Bundle(dest, verify.Options{}) // no roots
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findingCode(rep, "MANIFEST_SIGNED")
	if !ok {
		t.Fatalf("the signature was not reported at all:\n%s", rep.Text())
	}
	if !strings.Contains(f.Message, "internally consistent") {
		t.Errorf("the report does not say the check was against keys the bundle carries, "+
			"so it reads as strong as one against out-of-band roots: %s", f.Message)
	}
}

// rotatingLog writes enough events under a small segment target to seal several
// segments, for the tests that need a bundle with a droppable tail.
func rotatingLog(t *testing.T, records int) (string, *keys.Signer) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range records {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_loan_0001",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_intake", ManifestVersion: "1.0.0"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, signer
}

// TestASelectionNamesTheEventItsProofCovers: an inclusion proof binds a chain
// hash to a leaf; the id, sequence number, saga, step and kind the manifest
// prints beside it are claims about that leaf. In an unsigned bundle nothing
// else vouches for them, so each must be checked against the record the proof
// covers -- or the list of "this saga's events" can name anything.
func TestASelectionNamesTheEventItsProofCovers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		patch func(first map[string]any, all []any)
	}{
		{"another event id", func(first map[string]any, _ []any) { first["event_id"] = "forged-event-id" }},
		{"another seq", func(first map[string]any, _ []any) { first["seq"] = 999999 }},
		{"another saga, on every entry", func(_ map[string]any, all []any) {
			for _, e := range all {
				e.(map[string]any)["saga_id"] = "sg_someone_else"
			}
		}},
		{"another kind", func(first map[string]any, _ []any) { first["kind"] = "EFFECT_RELEASED" }},
		{"another step", func(first map[string]any, _ []any) { first["step_id"] = "st_elsewhere" }},
		{"a leaf past the end", func(first map[string]any, _ []any) { first["leaf_index"] = 999999 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, signer := writeLog(t)
			dest := filepath.Join(t.TempDir(), "bundle")
			trusted := keys.PublicKeySet{signer.KeyID(): signer.Public()}
			if _, err := bundle.Export(bundle.ExportOptions{
				SegmentDir: dir, Dest: dest, Keys: trusted, SagaID: "sg_loan_0001",
			}); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(dest, bundle.ManifestName)
			raw, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			sel := m["selection"].([]any)
			tc.patch(sel[0].(map[string]any), sel)
			patched, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, patched, 0o600); err != nil {
				t.Fatal(err)
			}
			rep, err := verify.Bundle(dest, verify.Options{Keys: trusted, Version: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK {
				t.Fatalf("a selection relabelled (%s) verified:\n%s", tc.name, rep.Text())
			}
			if tc.name != "a leaf past the end" && !hasCode(rep, "SELECTION_LABEL_MISMATCH") {
				t.Fatalf("expected SELECTION_LABEL_MISMATCH, got:\n%s", rep.Text())
			}
		})
	}
}

// TestASagaBundleSelectsTheWholeSagaAndNothingElse: a bundle exported for one
// saga selects every record of that saga in the segments it carries, once.
// The segments are in the bundle in full, so an entry dropped, repeated or
// borrowed from another saga can be seen -- and in an unsigned bundle nothing
// else would show it.
func TestASagaBundleSelectsTheWholeSagaAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		patch      func(m map[string]any)
	}{
		{"an entry dropped", "SELECTION_INCOMPLETE", func(m map[string]any) {
			m["selection"] = m["selection"].([]any)[1:]
		}},
		{"an entry repeated", "SELECTION_DUPLICATE", func(m map[string]any) {
			sel := m["selection"].([]any)
			m["selection"] = append(sel, sel[0])
		}},
		{"the scope names another saga", "SELECTION_OUT_OF_SCOPE", func(m map[string]any) {
			m["scope"].(map[string]any)["saga_id"] = "sg_someone_else"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, signer := writeLog(t)
			dest := filepath.Join(t.TempDir(), "bundle")
			trusted := keys.PublicKeySet{signer.KeyID(): signer.Public()}
			if _, err := bundle.Export(bundle.ExportOptions{
				SegmentDir: dir, Dest: dest, Keys: trusted, SagaID: "sg_loan_0001",
			}); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(dest, bundle.ManifestName)
			raw, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			tc.patch(m)
			patched, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, patched, 0o600); err != nil {
				t.Fatal(err)
			}
			rep, err := verify.Bundle(dest, verify.Options{Keys: trusted, Version: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK || !hasCode(rep, tc.code) {
				t.Fatalf("%s: want %s, got:\n%s", tc.name, tc.code, rep.Text())
			}
		})
	}
}
