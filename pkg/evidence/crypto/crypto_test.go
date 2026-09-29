package crypto_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/crypto"
)

// The behaviour of this package under normal use is exercised from
// pkg/evidence, where it is integrated with the appender. What lives here are
// the error paths that integration never reaches: malformed input, a wrong
// master key, and the boundaries of the envelope format. They matter because
// each one is a place where failing quietly would be worse than failing at all.

func newRing(t *testing.T) (*crypto.FileKeyRing, []byte) {
	t.Helper()
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := crypto.NewFileKeyRing(filepath.Join(t.TempDir(), "ring"), master)
	if err != nil {
		t.Fatal(err)
	}
	return ring, master
}

func ctx(subject string) crypto.Context {
	return crypto.Context{Subject: subject, SagaID: "sg", StepID: "st", Kind: "DPR"}
}

func TestSealOpenRoundTrip(t *testing.T) {
	ring, _ := newRing(t)
	s := crypto.NewSealer(ring)

	body := []byte("personal data of some kind")
	sealed, err := s.Seal(body, ctx("cust_1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, body) {
		t.Fatal("the plaintext is visible inside the ciphertext")
	}
	if !crypto.IsEncrypted(sealed) {
		t.Fatal("a sealed payload was not recognised as encrypted")
	}

	got, err := s.Open(sealed, ctx("cust_1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %q, want %q", got, body)
	}
}

// TestNonceIsFresh: reusing a nonce under the same key breaks GCM completely,
// leaking the XOR of two plaintexts. Identical inputs must still produce
// different ciphertexts.
func TestNonceIsFresh(t *testing.T) {
	ring, _ := newRing(t)
	s := crypto.NewSealer(ring)

	body := []byte("the same message twice")
	seen := map[string]bool{}
	for i := range 50 {
		sealed, err := s.Seal(body, ctx("cust_1"))
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(sealed)] {
			t.Fatalf("iteration %d produced a ciphertext seen before; the nonce is being reused", i)
		}
		seen[string(sealed)] = true
	}
}

func TestSealRequiresASubject(t *testing.T) {
	ring, _ := newRing(t)
	s := crypto.NewSealer(ring)
	if _, err := s.Seal([]byte("x"), crypto.Context{SagaID: "sg"}); err == nil {
		t.Fatal("a payload was sealed with no data subject, so it could never be erased")
	}
}

func TestMalformedCiphertextIsRejected(t *testing.T) {
	ring, _ := newRing(t)
	s := crypto.NewSealer(ring)
	good, err := s.Seal([]byte("body"), ctx("cust_1"))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":                 {},
		"shorter than overhead": make([]byte, crypto.Overhead-1),
		"unknown version":       append([]byte{99}, good[1:]...),
	}
	for name, input := range cases {
		if _, err := s.Open(input, ctx("cust_1")); !errors.Is(err, crypto.ErrCiphertextMalformed) {
			t.Errorf("%s: got %v, want ErrCiphertextMalformed", name, err)
		}
	}

	// A flipped bit inside the body is an authentication failure rather than a
	// format problem, and must never decrypt to anything.
	damaged := append([]byte(nil), good...)
	damaged[len(damaged)-1] ^= 0x01
	if _, err := s.Open(damaged, ctx("cust_1")); err == nil {
		t.Fatal("a ciphertext with a flipped bit decrypted successfully")
	}
}

func TestIsEncryptedDoesNotClaimPlainPayloads(t *testing.T) {
	for name, payload := range map[string][]byte{
		"nil":        nil,
		"short json": []byte(`{"a":1}`),
		"long json":  []byte(strings.Repeat(`{"outcome":"OK"}`, 20)),
	} {
		if crypto.IsEncrypted(payload) {
			t.Errorf("%s: a plain payload was reported as encrypted", name)
		}
	}
}

// TestWrongMasterKeyCannotUnwrap: the master key is the one secret everything
// else hangs off, and a wrong one must fail loudly rather than produce
// plausible garbage.
func TestWrongMasterKeyCannotUnwrap(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ring")
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := crypto.NewFileKeyRing(dir, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.EnsureKey("cust_1"); err != nil {
		t.Fatal(err)
	}

	other, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := crypto.NewFileKeyRing(dir, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Key("cust_1"); err == nil {
		t.Fatal("a key ring opened with the wrong master key handed back a key")
	}
}

func TestMasterKeyValidation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ring")
	if _, err := crypto.NewFileKeyRing(dir, []byte("too short")); err == nil {
		t.Fatal("a short master key was accepted")
	}
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.NewFileKeyRing("", master); err == nil {
		t.Fatal("a key ring was created with no directory")
	}
}

func TestLoadOrCreateMasterKeyIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "master.key")
	first, err := crypto.LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != crypto.KeySize {
		t.Fatalf("master key is %d bytes, want %d", len(first), crypto.KeySize)
	}
	second, err := crypto.LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("reloading produced a different master key, which would orphan every wrapped key")
	}
}

// TestUnknownSubjectIsDistinctFromShredded: an auditor needs to tell "never had
// data here" apart from "data was erased", because only the second has a SHRED
// event explaining it.
func TestUnknownSubjectIsDistinctFromShredded(t *testing.T) {
	ring, _ := newRing(t)

	if got := ring.State("never_seen"); got != crypto.KeyUnknown {
		t.Fatalf("unknown subject reported as %q", got)
	}
	if _, err := ring.Key("never_seen"); !errors.Is(err, crypto.ErrNoKey) {
		t.Fatalf("got %v, want ErrNoKey", err)
	}

	if _, err := ring.EnsureKey("cust_1"); err != nil {
		t.Fatal(err)
	}
	if got := ring.State("cust_1"); got != crypto.KeyLive {
		t.Fatalf("live subject reported as %q", got)
	}
	if _, err := ring.Shred("cust_1", "reason", "dpo", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := ring.State("cust_1"); got != crypto.KeyShredded {
		t.Fatalf("shredded subject reported as %q", got)
	}
	if _, err := ring.Key("cust_1"); !errors.Is(err, crypto.ErrKeyDestroyed) {
		t.Fatalf("got %v, want ErrKeyDestroyed", err)
	}
}

func TestShredRequiresReasonAndApprover(t *testing.T) {
	ring, _ := newRing(t)
	if _, err := ring.EnsureKey("cust_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Shred("cust_1", "", "dpo", time.Now()); err == nil {
		t.Fatal("an erasure with no reason was accepted")
	}
	if _, err := ring.Shred("cust_1", "reason", "", time.Now()); err == nil {
		t.Fatal("an erasure with nobody accountable was accepted")
	}
	if _, err := ring.Shred("never_seen", "reason", "dpo", time.Now()); !errors.Is(err, crypto.ErrNoKey) {
		t.Fatalf("got %v, want ErrNoKey when erasing a subject that never existed", err)
	}
}

func TestSubjectsListsLiveAndShredded(t *testing.T) {
	ring, _ := newRing(t)
	for _, s := range []string{"a", "b", "c"} {
		if _, err := ring.EnsureKey(s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ring.Shred("b", "reason", "dpo", time.Now()); err != nil {
		t.Fatal(err)
	}

	got := ring.Subjects()
	if len(got) != 3 {
		t.Fatalf("Subjects returned %v, want all three including the shredded one", got)
	}
	for i, want := range []string{"a", "b", "c"} {
		if got[i] != want {
			t.Fatalf("Subjects returned %v, want sorted order", got)
		}
	}
}

func TestShredReceiptPayloadIsStable(t *testing.T) {
	ring, _ := newRing(t)
	if _, err := ring.EnsureKey("cust_1"); err != nil {
		t.Fatal(err)
	}
	receipt, err := ring.Shred("cust_1", "GDPR Art. 17", "dpo@bank", time.Unix(1753430400, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}

	first, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := receipt.Payload()
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("the receipt does not encode deterministically, so it cannot be chained")
		}
	}
	for _, want := range []string{"cust_1", "GDPR Art. 17", "dpo@bank", "key_fingerprint"} {
		if !strings.Contains(string(first), want) {
			t.Errorf("receipt is missing %q: %s", want, first)
		}
	}
}

// TestOverheadMatchesReality guards the constant callers use to size buffers
// and to recognise an envelope.
func TestOverheadMatchesReality(t *testing.T) {
	ring, _ := newRing(t)
	s := crypto.NewSealer(ring)
	for _, size := range []int{0, 1, 100, 4096} {
		sealed, err := s.Seal(make([]byte, size), ctx("cust_1"))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(sealed) - size; got != crypto.Overhead {
			t.Fatalf("payload of %d bytes grew by %d, but Overhead says %d", size, got, crypto.Overhead)
		}
	}
}
