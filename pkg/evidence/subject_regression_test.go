package evidence_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/crypto"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// A reader that has the log and the key ring, but no memory of who each event
// was about, must still be able to decrypt. Anything else makes encrypted
// payloads write-only.
func TestSubjectIsRecoverableFromTheLogAlone(t *testing.T) {
	signer := mustSigner(t)
	root := t.TempDir()
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := crypto.NewFileKeyRing(filepath.Join(root, "keyring"), master)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Sealer: crypto.NewSealer(ring),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"iban":"DE89370400440532013000"}`)
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", StepID: "st",
		Participant: evidence.ParticipantRef{ID: "ag"},
		Subject:     "cust_42", Payload: want,
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// Fresh reader: only the segments and the key ring. Nothing remembers
	// "cust_42".
	sealer := crypto.NewSealer(ring)
	var decrypted int
	for _, rec := range allRecords(t, dir) {
		h, err := evidence.DecodeHeader(rec.Header)
		if err != nil {
			t.Fatal(err)
		}
		if !crypto.IsEncrypted(rec.Payload) {
			continue
		}
		subject := h.Subject
		if subject == "" {
			t.Fatal("the record does not say which data subject it concerns, " +
				"so nothing can decrypt it without out-of-band knowledge")
		}
		got, err := evidence.OpenPayload(sealer, rec.Payload, h)
		if err != nil {
			t.Fatalf("could not decrypt using only what the log records: %v", err)
		}
		if string(got) != string(want) {
			t.Fatal("decrypted payload does not match")
		}
		decrypted++
	}
	if decrypted != 1 {
		t.Fatalf("decrypted %d encrypted payloads, want 1", decrypted)
	}
}
