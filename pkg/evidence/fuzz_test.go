package evidence_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// signedSegment writes a small real log through the real append path and
// returns one sealed segment's bytes.
//
// Through the appender rather than assembled by hand, for the same reason the
// envelope-v2 fixture is a committed real log: bytes a test builds
// itself are bytes that agree with the test's idea of the format, and the
// question here is whether the *reader* agrees with the *writer*.
func signedSegment(tb testing.TB) []byte {
	tb.Helper()
	signer, err := keys.Generate()
	if err != nil {
		tb.Fatal(err)
	}
	dir := filepath.Join(tb.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		tb.Fatal(err)
	}
	for i := range 3 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_fuzz",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_fuzz", ManifestVersion: "1.0.0", Principal: "pr_fuzz", Kind: "AGENT"},
			Payload:     fmt.Appendf(nil, `{"step":%d,"outcome":"OK"}`, i),
		}); err != nil {
			tb.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		tb.Fatal(err)
	}
	raw, err := os.ReadFile(segment.Path(dir, 1))
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

// FuzzDecodeHeaderSurvivesAnything covers the other half: not "is it detected"
// but "does the process live".
//
// `DecodeHeader` is where untrusted bytes become a struct (the version gate
// is here for that reason), and `janus-verify` is software an auditor
// points at an artifact somebody else produced. A panic there is not a
// correctness bug, it is the verifier declining to answer — and an attacker who
// can make the verifier crash has made the log unverifiable without touching a
// single signature.
func FuzzDecodeHeaderSurvivesAnything(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xa0})                   // empty CBOR map
	f.Add([]byte{0xbf, 0xff})             // indefinite-length map
	f.Add(bytes.Repeat([]byte{0x9f}, 64)) // deeply nested indefinite arrays
	original := signedSegment(f)
	f.Add(original)

	f.Fuzz(func(t *testing.T, in []byte) {
		// The contract is an error or a header, never a panic and never a hang.
		// Nothing is asserted about *which* error: a decoder is entitled to
		// dislike arbitrary bytes for any reason it likes.
		_, _ = evidence.DecodeHeader(in)
	})
}

// FuzzASegmentReaderSurvivesAnything is the same contract one layer down, at the
// framing rather than the envelope.
//
// This is where a four-byte length prefix decides an allocation
// (`body := make([]byte, recLen)` in Reader.Next), which is the classic shape of
// a decoder that can be made to exhaust memory by a file that is four bytes
// long. `MaxRecordLen` is the bound that makes it survivable; this is the test
// that would notice if that bound were removed or moved above what a machine
// has.
func FuzzASegmentReaderSurvivesAnything(f *testing.F) {
	original := signedSegment(f)
	f.Add(original)
	f.Add(original[:32])
	f.Add([]byte("JANUSSEG"))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	// Per worker process, not per input -- see the note in
	// FuzzAMutatedSegmentNeverVerifies.
	path := filepath.Join(f.TempDir(), segment.FileName(1))

	f.Fuzz(func(t *testing.T, in []byte) {
		if err := os.WriteFile(path, in, 0o600); err != nil {
			t.Fatal(err)
		}
		rd, err := segment.Open(path)
		if err != nil {
			return
		}
		defer rd.Close()
		// Bounded: a reader that returns records forever is as broken as one
		// that panics, and a fuzzer cannot tell an infinite loop from a slow
		// input without a bound to exceed.
		for i := 0; i < 1_000_000; i++ {
			_, ok, err := rd.Next()
			if err != nil || !ok {
				return
			}
		}
		t.Fatal("the reader returned a million records from a fuzzed file without ending")
	})
}
