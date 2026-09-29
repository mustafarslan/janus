package keys_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/keys"
)

// The key id is derived from the public key rather than assigned. That is what
// stops a key set from claiming a trusted identity while carrying different key
// material — the case these tests exist for, because if the binding broke, an
// auditor could be handed a key file whose id looks familiar and whose bytes
// belong to whoever forged the log.

func TestKeyIDIsDerivedFromTheKey(t *testing.T) {
	a, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}

	if a.KeyID() == b.KeyID() {
		t.Fatal("two independent keys share an id")
	}
	if a.KeyID() != keys.KeyIDFor(a.Public()) {
		t.Fatal("a signer's id does not match the id derived from its public key")
	}
	if !strings.HasPrefix(a.KeyID(), "ed25519-") {
		t.Fatalf("unexpected key id format: %s", a.KeyID())
	}
}

func TestSignAndVerify(t *testing.T) {
	s, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("a segment footer preimage")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(s.Public(), msg, sig) {
		t.Fatal("a signature did not verify under its own key")
	}
	if ed25519.Verify(s.Public(), append(msg, '!'), sig) {
		t.Fatal("a signature verified over different bytes")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "writer.key")
	original, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Save(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("a private key was written with mode %o, want 600", perm)
	}

	loaded, err := keys.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KeyID() != original.KeyID() {
		t.Fatalf("loaded key id %s, saved %s", loaded.KeyID(), original.KeyID())
	}
	if !loaded.Public().Equal(original.Public()) {
		t.Fatal("the loaded key is not the one that was saved")
	}
}

// TestLoadRejectsAMislabelledKeyFile is the security property: the id in the
// file is checked against the key material rather than believed.
func TestLoadRejectsAMislabelledKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.key")
	real, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := real.Save(path); err != nil {
		t.Fatal(err)
	}

	// Relabel the file with a different, plausible-looking key id.
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var kf map[string]any
	if err := json.Unmarshal(blob, &kf); err != nil {
		t.Fatal(err)
	}
	other, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	kf["key_id"] = other.KeyID()
	patched, err := json.Marshal(kf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, patched, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := keys.Load(path); !errors.Is(err, keys.ErrKeyMismatch) {
		t.Fatalf("got %v, want ErrKeyMismatch: a key file claimed an id its material does not derive", err)
	}
}

func TestLoadRejectsMalformedKeyFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := map[string]string{
		"not json":        "this is not json",
		"wrong algorithm": `{"key_id":"x","alg":"rsa","seed_hex":"00"}`,
		"seed not hex":    `{"alg":"ed25519","seed_hex":"zzzz"}`,
		"seed too short":  `{"alg":"ed25519","seed_hex":"00112233"}`,
	}
	for name, body := range cases {
		if _, err := keys.Load(write(name, body)); err == nil {
			t.Errorf("%s: the key file was accepted", name)
		}
	}
	if _, err := keys.Load(filepath.Join(dir, "absent")); err == nil {
		t.Error("loading a missing key file succeeded")
	}
}

func TestLoadOrCreateIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.key")
	first, err := keys.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := keys.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyID() != second.KeyID() {
		t.Fatal("LoadOrCreate produced a new key on the second call, which would orphan everything already signed")
	}
}

// TestPublicKeySetRejectsAMislabelledEntry is the same binding on the verifier's
// side. A key set is what an auditor is told to trust; an entry whose id does
// not derive from its bytes would let a forged log validate under a familiar
// name.
func TestPublicKeySetRejectsAMislabelledEntry(t *testing.T) {
	real, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	impostor, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// The trusted id, pointing at somebody else's key.
	forged := map[string]string{
		real.KeyID(): hex.EncodeToString(impostor.Public()),
	}
	blob, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}

	var set keys.PublicKeySet
	if err := json.Unmarshal(blob, &set); !errors.Is(err, keys.ErrKeyMismatch) {
		t.Fatalf("got %v, want ErrKeyMismatch: an entry claimed a trusted id while holding another key", err)
	}
}

func TestPublicKeySetRoundTrip(t *testing.T) {
	a, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	original := keys.PublicKeySet{a.KeyID(): a.Public(), b.KeyID(): b.Public()}

	blob, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var got keys.PublicKeySet
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("round trip produced %d keys, want 2", len(got))
	}
	for id, want := range original {
		if !got[id].Equal(want) {
			t.Fatalf("key %s did not survive the round trip", id)
		}
	}
}

func TestPublicKeySetRejectsMalformedEntries(t *testing.T) {
	for name, body := range map[string]string{
		"not hex":       `{"ed25519-aaaa":"zzzz"}`,
		"wrong length":  `{"ed25519-aaaa":"00112233"}`,
		"not an object": `["ed25519-aaaa"]`,
	} {
		var set keys.PublicKeySet
		if err := json.Unmarshal([]byte(body), &set); err == nil {
			t.Errorf("%s: the key set was accepted", name)
		}
	}
}
