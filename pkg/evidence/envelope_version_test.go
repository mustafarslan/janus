package evidence_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// v2Dir is a log written by a build whose envelope version is 2 and which put a
// CBOR key this build has never seen on every header. See its README: it is real
// output from a real writer, not bytes a test assembled, because the failure it
// pins is one that only appears when something else did the writing.
func v2Dir(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata", "envelope-v2", "evidence")
}

// TestALogFromANewerBuildIsRefusedRatherThanRead is the whole of the envelope version gate.
//
// Before it, this directory read *silently and completely*: Walk returned six
// events and no error, the saga folded to COMMITTED, and the registry replayed.
// CBOR ignores keys it does not know, so whatever the newer build considered
// load-bearing was simply absent, and nothing about the result looked wrong.
// That is the same failure `saga.ErrUnsupportedSemantics` refuses one layer up.
func TestALogFromANewerBuildIsRefusedRatherThanRead(t *testing.T) {
	var seen int
	err := evidence.Walk(v2Dir(t), func(evidence.EventHeader, segment.Record) error {
		seen++
		return nil
	})
	if err == nil {
		t.Fatalf("Walk read %d events from a log written under a newer envelope version "+
			"and reported no error: the fields it does not know are absent rather than "+
			"wrong, so every answer built on this is quietly incomplete", seen)
	}
	if !errors.Is(err, evidence.ErrUnsupportedEnvelope) {
		t.Fatalf("Walk failed with %v, which is not ErrUnsupportedEnvelope: a caller cannot "+
			"tell a version it does not have from a corrupt one", err)
	}
	// The refusal has to say both numbers, or an operator cannot tell whether to
	// upgrade this build or to stop the one that wrote the log.
	for _, want := range []string{"envelope version 2", "understands 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestTheRefusalCarriesTheHeaderItRefused: the verifier is the one caller that
// reports rather than reads, and it needs the sequence number to say which
// record it could not vouch for.
func TestTheRefusalCarriesTheHeaderItRefused(t *testing.T) {
	raw := firstHeaderBytes(t, v2Dir(t))
	h, err := evidence.DecodeHeader(raw)
	if !errors.Is(err, evidence.ErrUnsupportedEnvelope) {
		t.Fatalf("DecodeHeader returned %v, want ErrUnsupportedEnvelope", err)
	}
	if h.V != 2 {
		t.Errorf("the refused header reports version %d, want 2: it was not populated", h.V)
	}
	if h.Seq == 0 || h.Kind == "" {
		t.Errorf("the refused header is empty (%+v): a reporting caller has nothing to name", h)
	}
}

// TestAnOlderOrCurrentEnvelopeIsAccepted keeps the refusal one-directional.
//
// Replaying a history written by an earlier build is the compatibility this
// exists to protect, so a gate that refused anything but an exact match would
// have broken the thing it was added to defend.
func TestAnOlderOrCurrentEnvelopeIsAccepted(t *testing.T) {
	h := evidence.EventHeader{
		V: evidence.EnvelopeVersion, EventID: "e1", Seq: 1, Kind: evidence.KindControl,
	}
	raw, err := evidence.EncodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.DecodeHeader(raw); err != nil {
		t.Fatalf("a header at this build's own version was refused: %v", err)
	}

	// Version 1 is the first and only one ever written, so "older" cannot be
	// produced by any real writer. Constructed here so the branch is at least
	// exercised, and named so nobody reads it as evidence that a downgrade path
	// has been tested against real bytes.
	older := h
	older.V = 0
	raw, err = evidence.EncodeHeader(older)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.DecodeHeader(raw); err != nil {
		t.Fatalf("a header from an older envelope version was refused: %v", err)
	}
}

// firstHeaderBytes reads the first record's raw header out of a segment
// directory, without going through the reader that is being tested.
func firstHeaderBytes(t *testing.T, dir string) []byte {
	t.Helper()
	ids, err := segment.ScanComplete(dir)
	if err != nil || len(ids) == 0 {
		t.Fatalf("listing %s: %v (%d segments)", dir, err, len(ids))
	}
	insp, err := segment.Inspect(segment.Path(dir, ids[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(insp.Records) == 0 {
		t.Fatal("the fixture segment holds no records")
	}
	return insp.Records[0].Header
}

// TestTheVerifierWillNotVouchForAShapeItDoesNotHave is the finding that made
// this worth building.
//
// Run against the bundle fixture before the version gate, `janus-verify` printed
// **`result: PASS`** with six warnings — a verifier telling an auditor that a
// log is sound when it had read only the parts of each record it recognised.
// Everything the verifier checks is over raw bytes, so the chain and the
// signature genuinely did hold; what it could not do was say what the records
// meant, and PASS is a claim about both.
func TestTheVerifierWillNotVouchForAShapeItDoesNotHave(t *testing.T) {
	rep, err := verify.Bundle(filepath.Join("testdata", "envelope-v2", "bundle"), verify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("the verifier passed a bundle written under an envelope version it does not " +
			"have: it vouched for records it had only partly read")
	}

	var found *verify.Finding
	for i, f := range rep.Findings {
		if f.Code == "ENVELOPE_VERSION" {
			found = &rep.Findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no ENVELOPE_VERSION finding: the verifier failed for some other reason, so " +
			"this test is not exercising what it claims")
	}
	if found.Severity != verify.Critical {
		t.Errorf("the envelope-version finding is %v, want Critical: a warning is what let "+
			"this print PASS", found.Severity)
	}
	for _, want := range []string{"envelope version 2", "understands 1"} {
		if !strings.Contains(found.Message, want) {
			t.Errorf("the finding does not mention %q: %s", want, found.Message)
		}
	}

	// And the report must not overstate what broke. The chain arithmetic is
	// over raw bytes and it held; a verifier that failed this bundle by claiming
	// the chain was damaged would be reaching the right verdict with a false
	// reason, and an operator would go looking for corruption that is not there.
	for _, seg := range rep.Segments {
		if !seg.ChainOK {
			t.Errorf("segment %d is reported as chain-broken: the bytes are intact and the "+
				"finding is about a shape this build does not have, not about damage",
				seg.SegmentID)
		}
		if !seg.SignatureOK {
			t.Errorf("segment %d is reported as unsigned: the signature is over raw bytes "+
				"and it verified", seg.SegmentID)
		}
	}
}
