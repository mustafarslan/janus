package bundle_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// An unsigned audit bundle cut off at its end is a valid
// prefix of a hash chain, and verifies. The artifact cannot say otherwise; an
// auditor who requires a signed manifest can.

// dropLastSegment shortens a bundle the way an attacker would: the last segment
// removed, and the manifest made to agree with what is left.
func dropLastSegment(t *testing.T, dest string) {
	t.Helper()
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
	if len(segs) < 2 {
		t.Fatalf("the fixture produced %d segment(s); there is no tail to drop", len(segs))
	}
	gone := segs[len(segs)-1].(map[string]any)
	raw["segments"] = segs[:len(segs)-1]
	raw["last_seq"] = segs[len(segs)-2].(map[string]any)["last_seq"]
	raw["events"] = raw["events"].(float64) - gone["records"].(float64)
	// The head the shortened chain really has: a careful attacker verifies
	// their own work once and writes down what the verifier computes.
	delete(raw, "head_chain")
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
	rep, err := verify.Bundle(dest, verify.Options{Version: "attacker"})
	if err != nil {
		t.Fatal(err)
	}
	raw["head_chain"] = rep.HeadChain
	if out, err = json.MarshalIndent(raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o640); err != nil {
		t.Fatal(err)
	}
}

// TestAnUnsignedTruncatedBundlePassesUnlessASignatureIsRequired: the premise
// and the close, side by side.
func TestAnUnsignedTruncatedBundlePassesUnlessASignatureIsRequired(t *testing.T) {
	dir, signer := rotatingLog(t, 60)
	trusted := keys.PublicKeySet{signer.KeyID(): signer.Public()}
	dest := filepath.Join(t.TempDir(), "audit")
	if _, err := bundle.Export(bundle.ExportOptions{SegmentDir: dir, Dest: dest, Keys: trusted}); err != nil {
		t.Fatal(err)
	}
	dropLastSegment(t, dest)

	rep, err := verify.Bundle(dest, verify.Options{Keys: trusted})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("the premise: an unsigned bundle cut at its end is a valid prefix and "+
			"verifies without a required signature:\n%s", rep.Text())
	}

	rep, err = verify.Bundle(dest, verify.Options{Keys: trusted, RequireSignedManifest: true})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findingCode(rep, "MANIFEST_UNSIGNED")
	if !ok || f.Severity != verify.Critical || rep.OK {
		t.Fatalf("an auditor required a signed manifest, was handed an unsigned bundle cut "+
			"at its end, and the report passed it:\n%s", rep.Text())
	}
}

// TestARequiredSignatureMustVerifyAgainstRootsSuppliedOutOfBand: a signature
// checked only against the keys the bundle carries shows the artifact agrees
// with itself, which a forger who rewrote both would also produce. It does not
// satisfy a requirement for a signed manifest.
func TestARequiredSignatureMustVerifyAgainstRootsSuppliedOutOfBand(t *testing.T) {
	dir, signer := rotatingLog(t, 60)
	trusted := keys.PublicKeySet{signer.KeyID(): signer.Public()}
	dest := filepath.Join(t.TempDir(), "audit")
	if _, err := bundle.Export(bundle.ExportOptions{SegmentDir: dir, Dest: dest, Keys: trusted}); err != nil {
		t.Fatal(err)
	}
	if err := bundle.SignManifest(dest, signer); err != nil {
		t.Fatal(err)
	}
	rep, err := verify.Bundle(dest, verify.Options{RequireSignedManifest: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatalf("a manifest signature checked only against the bundle's own keys satisfied "+
			"a required signature:\n%s", rep.Text())
	}
	rep, err = verify.Bundle(dest, verify.Options{Keys: trusted, RequireSignedManifest: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a signed bundle checked against the roots it was signed under failed the "+
			"requirement:\n%s", rep.Text())
	}
}
