package evidence_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// TestCASDigestIsNotThePayloadHash: both cover the same bytes, so if they were
// equal a value computed for addressing could be presented as the chain's
// commitment to content. Domain separation is what keeps the two roles apart.
func TestCASDigestIsNotThePayloadHash(t *testing.T) {
	body := []byte("same bytes, two roles")
	payloadHash := evidence.HashPayload(body)
	casDigest := cas.Sum(body)
	if string(payloadHash[:]) == string(casDigest[:]) {
		t.Fatal("the CAS address and the chained payload hash are the same value")
	}
}

func offloadLog(t *testing.T, threshold int) (*evidence.Appender, string, *keys.Signer, *cas.FileStore) {
	t.Helper()
	signer := mustSigner(t)
	root := t.TempDir()
	store, err := cas.NewFileStore(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := evidence.Open(evidence.Options{
		Dir:               filepath.Join(root, "evidence"),
		Signer:            signer,
		SyncMode:          segment.SyncModeNone,
		CAS:               store,
		CASThresholdBytes: threshold,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, filepath.Join(root, "evidence"), signer, store
}

// TestLargePayloadLeavesTheChain is the point of the offload: the segment holds
// the envelope and nothing else, while the chain still commits to the content.
func TestLargePayloadLeavesTheChain(t *testing.T) {
	a, dir, signer, store := offloadLog(t, 1024)
	ctx := context.Background()

	big := []byte(strings.Repeat("a retrieved document. ", 500)) // ~11 KiB
	small := []byte(`{"outcome":"OK"}`)

	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg_off", StepID: "st_big",
		Participant: evidence.ParticipantRef{ID: "ag"}, Payload: big,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindStepResult, SagaID: "sg_off", StepID: "st_small",
		Participant: evidence.ParticipantRef{ID: "ag"}, Payload: small,
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	records := allRecords(t, dir)
	var sawBig, sawSmall bool
	for _, rec := range records {
		h, err := evidence.DecodeHeader(rec.Header)
		if err != nil {
			t.Fatal(err)
		}
		switch h.StepID {
		case "st_big":
			sawBig = true
			if len(rec.Payload) != 0 {
				t.Fatalf("a %d-byte payload stayed in the segment; %d bytes inline", len(big), len(rec.Payload))
			}
			if h.PayloadRef == "" {
				t.Fatal("offloaded event has no payload reference")
			}
			// The chain must still commit to the real content.
			if h.PayloadHash != evidence.HashPayload(big) {
				t.Fatal("the chained payload hash does not cover the original bytes")
			}
			body, err := cas.GetByRef(context.Background(), store, h.PayloadRef)
			if err != nil {
				t.Fatalf("payload not retrievable at %s: %v", h.PayloadRef, err)
			}
			if string(body) != string(big) {
				t.Fatal("the blob store returned different bytes")
			}
		case "st_small":
			sawSmall = true
			if len(rec.Payload) == 0 {
				t.Fatal("a small payload was offloaded; the threshold is not being respected")
			}
			if h.PayloadRef != "" {
				t.Fatalf("a small payload got a reference: %s", h.PayloadRef)
			}
		}
	}
	if !sawBig || !sawSmall {
		t.Fatalf("expected both events in the log (big=%v small=%v)", sawBig, sawSmall)
	}

	if rep := verifyDir(t, dir, signer); !rep.OK {
		t.Fatalf("log with an offloaded payload did not verify:\n%s", rep.Text())
	}
}

// TestVerifierSaysWhenItCouldNotCheckAPayload: an offloaded body is only as good
// as the store holding it, and a report that stayed silent about that would be
// claiming more than it checked.
func TestVerifierSaysWhenItCouldNotCheckAPayload(t *testing.T) {
	a, dir, signer, store := offloadLog(t, 512)
	big := []byte(strings.Repeat("x", 4096))
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"}, Payload: big,
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// Without a store the verifier must say the content went unchecked.
	rep := verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("verification should still pass:\n%s", rep.Text())
	}
	if !hasFinding(rep, "PAYLOAD_UNCHECKED") {
		t.Fatalf("report did not disclose an unchecked payload:\n%s", rep.Text())
	}

	// With the store, it resolves and confirms.
	withStore, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(signer), CAS: store, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !withStore.OK {
		t.Fatalf("verification with a store failed:\n%s", withStore.Text())
	}
	if !hasFinding(withStore, "PAYLOAD_RESOLVED") {
		t.Fatalf("report did not record that the payload was resolved:\n%s", withStore.Text())
	}
}

// TestVerifierDetectsAMissingBlob: a reference into a store that no longer has
// the bytes is a hole in the audit trail, and must fail rather than pass quietly.
func TestVerifierDetectsAMissingBlob(t *testing.T) {
	a, dir, signer, store := offloadLog(t, 512)
	big := []byte(strings.Repeat("y", 4096))
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"}, Payload: big,
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// An empty store stands in for blobs that were lost or never replicated.
	empty, err := cas.NewFileStore(filepath.Join(t.TempDir(), "empty"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(signer), CAS: empty, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatalf("a dangling payload reference verified clean:\n%s", rep.Text())
	}
	if !hasFinding(rep, "PAYLOAD_MISSING") {
		t.Fatalf("expected PAYLOAD_MISSING, got:\n%s", rep.Text())
	}
	_ = store
}

// TestOffloadFailureFailsTheAppendNotTheLog: if the blob store is unavailable
// the event cannot be acknowledged, but the chain is untouched, so other
// callers must keep working.
func TestOffloadFailureFailsTheAppendNotTheLog(t *testing.T) {
	signer := mustSigner(t)
	root := t.TempDir()
	dir := filepath.Join(root, "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir:               dir,
		Signer:            signer,
		SyncMode:          segment.SyncModeNone,
		CAS:               brokenStore{},
		CASThresholdBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_, err = a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
		Payload: []byte(strings.Repeat("z", 4096)),
	})
	if err == nil {
		t.Fatal("an append succeeded while the blob store was unavailable")
	}
	if !errors.Is(err, evidence.ErrPayloadStore) {
		t.Fatalf("got %v, want it to wrap ErrPayloadStore", err)
	}
	// Crucially not sticky: the log is fine, only that one payload could not be
	// stored, so small events must still go through.
	if errors.Is(err, evidence.ErrWritePathFailed) {
		t.Fatal("a blob store outage was reported as a write-path failure")
	}

	for i := range 5 {
		if _, err := a.Append(ctx, evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
			Payload: fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatalf("small append %d failed after a blob store outage: %v", i, err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if rep := verifyDir(t, dir, signer); !rep.OK {
		t.Fatalf("log did not verify after a blob store outage:\n%s", rep.Text())
	}
}

// brokenStore stands in for object storage that is down.
type brokenStore struct{}

func (brokenStore) Put(context.Context, []byte) (cas.Digest, error) {
	return cas.Digest{}, errors.New("connection refused")
}
func (brokenStore) Get(context.Context, cas.Digest) ([]byte, error) {
	return nil, errors.New("connection refused")
}
func (brokenStore) Has(context.Context, cas.Digest) (bool, error) {
	return false, errors.New("connection refused")
}
func (brokenStore) Describe() string { return "broken" }

func allRecords(t *testing.T, dir string) []segment.Record {
	t.Helper()
	var out []segment.Record
	for _, id := range mustScan(t, dir) {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, insp.Records...)
	}
	return out
}

// TestCallerSuppliedRefStillCommitsToContent is the property a reference must
// not quietly lose. When a caller places the blob itself and passes only a
// reference, the chain has to commit to the real bytes — otherwise every such
// event carries the hash of nothing, and the first audit that resolves the
// reference reports them all as tampered.
func TestCallerSuppliedRefStillCommitsToContent(t *testing.T) {
	signer := mustSigner(t)
	root := t.TempDir()
	store, err := cas.NewFileStore(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		CAS: store, CASThresholdBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// The caller uploads the document itself, then references it.
	body := []byte(strings.Repeat("a pre-uploaded document. ", 400))
	digest, err := store.Put(ctx, body)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg_pre", StepID: "st",
		Participant: evidence.ParticipantRef{ID: "ag"},
		Payload:     body,
		PayloadRef:  digest.Ref(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// Verification that actually resolves the reference must pass.
	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys: keySet(signer), CAS: store, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("an event with a caller-supplied reference did not verify against the store:\n%s", rep.Text())
	}
	if hasFinding(rep, "PAYLOAD_HASH_MISMATCH") {
		t.Fatalf("the chain does not commit to the referenced content:\n%s", rep.Text())
	}
}

// TestReferenceWithNoContentIsRefused: a reference with no bytes leaves the
// chain committing to emptiness, which is worse than refusing the append.
func TestReferenceWithNoContentIsRefused(t *testing.T) {
	a, _, _, store := offloadLog(t, 512)
	defer a.Close()

	digest, err := store.Put(context.Background(), []byte("content placed out of band"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
		PayloadRef: digest.Ref(),
	})
	if err == nil {
		t.Fatal("an event was accepted with a reference but no content, so the chain committed to nothing")
	}
}
