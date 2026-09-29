package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
)

// run is a committed model run: a signed log and the writer's public key, the
// two things an auditor is handed.
const run = "../../docs/bench/agentic/2026-09-27T140840Z"

// TestTheAuditAuthenticatesTheLogBeforeReDerivingIt: a log re-sealed under a
// key of the forger's own re-derives exactly as well as the real one, so the
// only thing that tells them apart is the key the auditor trusts. Audited
// against a key that did not write it, the log must be refused and nothing
// re-derived; against the right key, it must be audited.
func TestTheAuditAuthenticatesTheLogBeforeReDerivingIt(t *testing.T) {
	var out bytes.Buffer
	if err := audit([]string{"-keys", filepath.Join(run, "pub.json"), filepath.Join(run, "evidence")}, &out); err != nil {
		t.Fatalf("the run's own key: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "log authenticated") || !strings.Contains(out.String(), "verdicts across") {
		t.Fatalf("the run's own key should authenticate the log and then audit it:\n%s", out.String())
	}

	stranger, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(keys.PublicKeySet{stranger.KeyID(): stranger.Public()})
	if err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(t.TempDir(), "pub.json")
	if err := os.WriteFile(wrong, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err = audit([]string{"-keys", wrong, filepath.Join(run, "evidence")}, &out)
	if !errors.Is(err, errNotAuthenticated) {
		t.Fatalf("a log the trusted key did not write was not refused: err=%v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "verdicts across") {
		t.Fatalf("a log that does not authenticate was audited anyway:\n%s", out.String())
	}
}

// TestAnUnauthenticatedAuditSaysSo: without -keys the audit still runs --
// every existing caller depends on that -- but it must not read as if it
// knew who wrote the log.
func TestAnUnauthenticatedAuditSaysSo(t *testing.T) {
	var out bytes.Buffer
	if err := audit([]string{filepath.Join(run, "evidence")}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "log not authenticated") {
		t.Fatalf("an audit with no key did not say the log was not authenticated:\n%s", out.String())
	}
}

func runKeys(t *testing.T) keys.PublicKeySet {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join(run, "pub.json"))
	if err != nil {
		t.Fatal(err)
	}
	var set keys.PublicKeySet
	if err := json.Unmarshal(blob, &set); err != nil {
		t.Fatal(err)
	}
	return set
}

// TestABundleIsAuditedThroughItsSegments: a bundle keeps its segments under
// segments/, so an audit pointed at the bundle as it stands would find no
// sagas and pass vacuously. It must verify the bundle and audit what it holds.
func TestABundleIsAuditedThroughItsSegments(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "bundle")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: filepath.Join(run, "evidence"), Dest: dest, Keys: runKeys(t), SagaID: "sg_ag_app_35",
	}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := audit([]string{"-keys", filepath.Join(run, "pub.json"), dest}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "log authenticated") || strings.Contains(out.String(), "across 0 sagas") {
		t.Fatalf("the bundle was not verified and audited:\n%s", out.String())
	}
}

// TestAnAuditOfNothingIsNotAPass: a directory with no sagas in it -- a wrong
// path, an empty bundle -- must not read "every recorded verdict follows".
func TestAnAuditOfNothingIsNotAPass(t *testing.T) {
	var out bytes.Buffer
	if err := audit([]string{t.TempDir()}, &out); err == nil {
		t.Fatalf("an empty directory was audited as a pass:\n%s", out.String())
	}
}

// TestAnExpectedHeadTheLogDoesNotReachIsRefused: -expect-head is how an
// auditor catches a log cut off at its end; it must reach the verifier.
func TestAnExpectedHeadTheLogDoesNotReachIsRefused(t *testing.T) {
	var out bytes.Buffer
	err := audit([]string{"-keys", filepath.Join(run, "pub.json"), "-expect-head",
		"blake3:0000000000000000000000000000000000000000000000000000000000000000",
		filepath.Join(run, "evidence")}, &out)
	if !errors.Is(err, errNotAuthenticated) {
		t.Fatalf("a head the log does not reach was not refused: %v\n%s", err, out.String())
	}
}

// TestAnUnsignedBundleFailsARequiredSignature: -require-signed-manifest must
// reach the verifier, or an auditor who asked for it reads a pass as meeting a
// requirement nothing checked.
func TestAnUnsignedBundleFailsARequiredSignature(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "bundle")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: filepath.Join(run, "evidence"), Dest: dest, Keys: runKeys(t), SagaID: "sg_ag_app_35",
	}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := audit([]string{"-keys", filepath.Join(run, "pub.json"), "-require-signed-manifest", dest}, &out)
	if !errors.Is(err, errNotAuthenticated) {
		t.Fatalf("an unsigned bundle met a required signature: %v\n%s", err, out.String())
	}
}
