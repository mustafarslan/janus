package evidence_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/crypto"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

func sealedLog(t *testing.T) (*evidence.Appender, string, *keys.Signer, *crypto.FileKeyRing, *crypto.Sealer) {
	t.Helper()
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
	sealer := crypto.NewSealer(ring)

	dir := filepath.Join(root, "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir:      dir,
		Signer:   signer,
		SyncMode: segment.SyncModeNone,
		Sealer:   sealer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, dir, signer, ring, sealer
}

// TestErasureLeavesTheChainIntact is the whole point of crypto-shredding. After
// a subject's data is erased the log must still verify completely, because the
// records were never removed — only the key that made them readable.
func TestErasureLeavesTheChainIntact(t *testing.T) {
	a, dir, signer, ring, sealer := sealedLog(t)
	ctx := context.Background()

	secret := []byte(`{"name":"Jane Doe","iban":"DE89370400440532013000","decision":"declined"}`)
	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg_loan", StepID: "st_decide",
		Participant: evidence.ParticipantRef{ID: "ag_credit"},
		Subject:     "cust_42",
		Payload:     secret,
	}); err != nil {
		t.Fatal(err)
	}
	// An unrelated subject, to confirm erasure is surgical.
	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg_other", StepID: "st_decide",
		Participant: evidence.ParticipantRef{ID: "ag_credit"},
		Subject:     "cust_99",
		Payload:     []byte(`{"name":"Someone Else"}`),
	}); err != nil {
		t.Fatal(err)
	}

	// Before erasure, the content is readable.
	rec := recordForSubject(t, dir, "sg_loan")
	h, err := evidence.DecodeHeader(rec.Header)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := evidence.OpenPayload(sealer, rec.Payload, h)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(secret) {
		t.Fatal("decrypted payload does not match what was written")
	}

	// Erase.
	ref, receipt, err := evidence.Erase(ctx, a, ring, "cust_42", "GDPR Art. 17 request", "dpo@bank")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Seq == 0 || receipt.KeyFingerprint == "" {
		t.Fatalf("erasure returned an incomplete result: %+v %+v", ref, receipt)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// The chain still verifies over the records whose content is now gone.
	rep := verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("the log did not verify after an erasure:\n%s", rep.Text())
	}

	// The erased subject's content is unrecoverable.
	rec = recordForSubject(t, dir, "sg_loan")
	h, err = evidence.DecodeHeader(rec.Header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.OpenPayload(sealer, rec.Payload, h); !errors.Is(err, crypto.ErrKeyDestroyed) {
		t.Fatalf("erased content was still readable (err %v)", err)
	}

	// The other subject is untouched: erasure must be surgical, or fulfilling
	// one request would destroy records the bank is required to keep.
	other := recordForSubject(t, dir, "sg_other")
	oh, err := evidence.DecodeHeader(other.Header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.OpenPayload(sealer, other.Payload, oh); err != nil {
		t.Fatalf("an unrelated subject's data became unreadable: %v", err)
	}
}

// TestShredEventExplainsTheGap: unreadable records with no explanation are
// indistinguishable from damage, so the erasure has to be on the record.
func TestShredEventExplainsTheGap(t *testing.T) {
	a, dir, _, ring, _ := sealedLog(t)
	ctx := context.Background()

	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
		Subject: "cust_7", Payload: []byte(`{"personal":"data"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := evidence.Erase(ctx, a, ring, "cust_7", "KVKK erasure request", "dpo@bank"); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, rec := range allRecords(t, dir) {
		h, err := evidence.DecodeHeader(rec.Header)
		if err != nil {
			t.Fatal(err)
		}
		if h.Kind != evidence.KindShred {
			continue
		}
		found = true
		body := string(rec.Payload)
		for _, want := range []string{"cust_7", "KVKK erasure request", "dpo@bank", "key_fingerprint"} {
			if !strings.Contains(body, want) {
				t.Errorf("SHRED event does not record %q: %s", want, body)
			}
		}
		if h.Labels["subject"] != "cust_7" {
			t.Errorf("SHRED event is not labelled with its subject: %v", h.Labels)
		}
	}
	if !found {
		t.Fatal("no SHRED event was written")
	}
}

// TestShredEventStaysReadableAfterErasure: the record explaining why content is
// unreadable must not itself become unreadable.
func TestShredEventStaysReadableAfterErasure(t *testing.T) {
	a, dir, _, ring, _ := sealedLog(t)
	ctx := context.Background()

	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
		Subject: "cust_1", Payload: []byte(`{"personal":"data"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := evidence.Erase(ctx, a, ring, "cust_1", "reason", "dpo"); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	for _, rec := range allRecords(t, dir) {
		h, err := evidence.DecodeHeader(rec.Header)
		if err != nil {
			t.Fatal(err)
		}
		if h.Kind == evidence.KindShred && crypto.IsEncrypted(rec.Payload) {
			t.Fatal("the SHRED event was encrypted under the key it records the destruction of")
		}
	}
}

// TestChainCommitsToCiphertextNotPlaintext is the property that makes erasure
// complete. If the chain held a hash of the plaintext, that hash would outlive
// the erasure as a verifiable fingerprint — and for low-entropy personal data,
// confirming a guess against it is a practical attack, not a theoretical one.
func TestChainCommitsToCiphertextNotPlaintext(t *testing.T) {
	a, dir, _, _, _ := sealedLog(t)
	plaintext := []byte(`{"iban":"DE89370400440532013000"}`)

	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
		Subject: "cust_42", Payload: plaintext,
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	rec := recordForSubject(t, dir, "sg")
	h, err := evidence.DecodeHeader(rec.Header)
	if err != nil {
		t.Fatal(err)
	}

	if h.PayloadHash == evidence.HashPayload(plaintext) {
		t.Fatal("the chain committed to the plaintext hash; erasure would leave a fingerprint of the erased content")
	}
	if h.PayloadHash != evidence.HashPayload(rec.Payload) {
		t.Fatal("the chain does not commit to the stored ciphertext")
	}
	if !crypto.IsEncrypted(rec.Payload) {
		t.Fatal("the payload was stored in the clear")
	}
	if strings.Contains(string(rec.Payload), "DE89370400440532013000") {
		t.Fatal("the plaintext is visible in the stored record")
	}
}

// TestCiphertextCannotBeMovedBetweenEvents: without binding, someone able to
// edit the hot tier could paste a customer's encrypted decision onto a
// different saga and the chain would attest to the result.
func TestCiphertextCannotBeMovedBetweenEvents(t *testing.T) {
	_, _, _, ring, sealer := sealedLog(t)

	body := []byte(`{"decision":"approved"}`)
	sealed, err := sealer.Seal(body, crypto.Context{
		Subject: "cust_1", SagaID: "sg_a", StepID: "st_1", Kind: "DPR",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Same key, same subject, different saga.
	if _, err := sealer.Open(sealed, crypto.Context{
		Subject: "cust_1", SagaID: "sg_b", StepID: "st_1", Kind: "DPR",
	}); !errors.Is(err, crypto.ErrWrongContext) {
		t.Fatalf("a ciphertext decrypted under a different saga (err %v)", err)
	}
	// And it still opens in its own context.
	if _, err := sealer.Open(sealed, crypto.Context{
		Subject: "cust_1", SagaID: "sg_a", StepID: "st_1", Kind: "DPR",
	}); err != nil {
		t.Fatalf("the ciphertext did not open in its own context: %v", err)
	}
	_ = ring
}

// TestShreddedSubjectCannotGetAFreshKey: writing new records for an erased
// subject under a new key would place data beyond the reach of the erasure
// receipt that was already issued.
func TestShreddedSubjectCannotGetAFreshKey(t *testing.T) {
	a, _, _, ring, _ := sealedLog(t)
	ctx := context.Background()

	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
		Subject: "cust_5", Payload: []byte(`{"a":1}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := evidence.Erase(ctx, a, ring, "cust_5", "reason", "dpo"); err != nil {
		t.Fatal(err)
	}

	_, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
		Subject: "cust_5", Payload: []byte(`{"a":2}`),
	})
	if !errors.Is(err, evidence.ErrEncryption) {
		t.Fatalf("got %v, want the append to be refused for an erased subject", err)
	}
	if !errors.Is(err, crypto.ErrKeyDestroyed) {
		t.Fatalf("the refusal did not name the destroyed key: %v", err)
	}
	_ = a.Close()
}

func TestErasureIsNotRepeatable(t *testing.T) {
	a, _, _, ring, _ := sealedLog(t)
	ctx := context.Background()
	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
		Subject: "cust_3", Payload: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := evidence.Erase(ctx, a, ring, "cust_3", "reason", "dpo"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := evidence.Erase(ctx, a, ring, "cust_3", "reason", "dpo"); !errors.Is(err, crypto.ErrAlreadyShredded) {
		t.Fatalf("got %v, want ErrAlreadyShredded; a duplicate request must not write a second misleading SHRED event", err)
	}
	_ = a.Close()
}

func TestErasureRequiresReasonAndApprover(t *testing.T) {
	a, _, _, ring, _ := sealedLog(t)
	ctx := context.Background()
	if _, err := a.Append(ctx, evidence.Request{
		Kind: evidence.KindDPR, SagaID: "sg", Participant: evidence.ParticipantRef{ID: "ag"},
		Subject: "cust_8", Payload: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := evidence.Erase(ctx, a, ring, "cust_8", "", "dpo"); err == nil {
		t.Fatal("an erasure with no reason was accepted")
	}
	if _, _, err := evidence.Erase(ctx, a, ring, "cust_8", "reason", ""); err == nil {
		t.Fatal("an erasure with nobody accountable was accepted")
	}
	_ = a.Close()
}

// TestKeyRingSurvivesRestart: a key ring that forgot its tombstones on restart
// would let an erased subject be written again.
func TestKeyRingSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "keyring")

	ring, err := crypto.NewFileKeyRing(dir, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.EnsureKey("live"); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.EnsureKey("gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Shred("gone", "reason", "dpo", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	reopened, err := crypto.NewFileKeyRing(dir, master)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.State("live"); got != crypto.KeyLive {
		t.Fatalf("live subject came back as %q", got)
	}
	if got := reopened.State("gone"); got != crypto.KeyShredded {
		t.Fatalf("shredded subject came back as %q", got)
	}
	if got := reopened.State("never"); got != crypto.KeyUnknown {
		t.Fatalf("unknown subject came back as %q", got)
	}
	if _, err := reopened.Key("gone"); !errors.Is(err, crypto.ErrKeyDestroyed) {
		t.Fatalf("a destroyed key was readable after restart: %v", err)
	}
	if _, err := reopened.Key("live"); err != nil {
		t.Fatalf("a live key was not readable after restart: %v", err)
	}
}

// TestKeyRingDoesNotLeakSubjectsInFileNames: a directory listing of a key store
// should not be a list of the people a bank holds data about.
func TestKeyRingDoesNotLeakSubjectsInFileNames(t *testing.T) {
	root := t.TempDir()
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := crypto.NewFileKeyRing(filepath.Join(root, "keyring"), master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.EnsureKey("jane.doe@example.com"); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(filepath.Join(root, "keyring", "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no key files were written")
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "jane") || strings.Contains(e.Name(), "example.com") {
			t.Fatalf("key file name leaks the subject: %s", e.Name())
		}
	}
}

func recordForSubject(t *testing.T, dir, sagaID string) segment.Record {
	t.Helper()
	for _, rec := range allRecords(t, dir) {
		h, err := evidence.DecodeHeader(rec.Header)
		if err != nil {
			t.Fatal(err)
		}
		if h.SagaID == sagaID && h.Kind == evidence.KindDPR {
			return rec
		}
	}
	t.Fatalf("no DPR record found for saga %s", sagaID)
	return segment.Record{}
}
