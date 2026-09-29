package evidence

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// TestKindsMatchProto guards the one duplication in the schema: event kinds
// exist as Go constants (used for the canonical CBOR envelope) and as a protobuf
// enum (used on the wire). If the two drift, a wire message can name a kind the
// log cannot record, or vice versa.
func TestKindsMatchProto(t *testing.T) {
	const prefix = "EVENT_KIND_"

	goKinds := map[Kind]bool{}
	for _, k := range AllKinds() {
		if goKinds[k] {
			t.Fatalf("duplicate Go kind %q in AllKinds", k)
		}
		goKinds[k] = true
	}

	protoKinds := map[Kind]bool{}
	for value, name := range janusv1.EventKind_name {
		if value == 0 {
			continue // UNSPECIFIED has no Go counterpart by design
		}
		if !strings.HasPrefix(name, prefix) {
			t.Fatalf("proto EventKind value %q does not use the %q prefix", name, prefix)
		}
		protoKinds[Kind(strings.TrimPrefix(name, prefix))] = true
	}

	for k := range protoKinds {
		if !goKinds[k] {
			t.Errorf("proto declares kind %q with no Go constant in AllKinds()", k)
		}
	}
	for k := range goKinds {
		if !protoKinds[k] {
			t.Errorf("Go declares kind %q with no value in the proto EventKind enum", k)
		}
	}
}

func sampleHeader() EventHeader {
	return EventHeader{
		V:       EnvelopeVersion,
		EventID: "0190c3f1-0000-7000-8000-000000000001",
		Seq:     42,
		SagaID:  "sg_loan_0001",
		StepID:  "st_book_payment",
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		Kind:    KindStepResult,
		Participant: ParticipantRef{
			ID:              "ag_intake",
			ManifestVersion: "3.2.1",
			Principal:       "pr_bank_x",
			Kind:            "AGENT",
		},
		TS:          Timestamps{HLC: 0x1234567800000001, WallUnixNanos: time.Unix(1753430400, 123456789).UnixNano()},
		PayloadHash: HashPayload([]byte(`{"outcome":"OK"}`)),
		Labels:      map[string]string{"tenant": "bank_x", "jurisdiction": "DE", "data_class": "personal"},
	}
}

// TestCanonicalEncodingIsByteStable is the property the whole chain rests on: the
// same logical header must always produce the same bytes, or the chain hash would
// depend on the encoder rather than the event.
func TestCanonicalEncodingIsByteStable(t *testing.T) {
	h := sampleHeader()

	first, err := EncodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		again, err := EncodeHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("encoding %d differs from the first; canonical encoding is not stable", i)
		}
	}

	// Labels is a map, so a non-canonical encoder would leak Go's randomized
	// iteration order into the bytes. Rebuild it in a different insertion order
	// and require the same output.
	shuffled := sampleHeader()
	shuffled.Labels = map[string]string{}
	for _, k := range []string{"jurisdiction", "data_class", "tenant"} {
		shuffled.Labels[k] = h.Labels[k]
	}
	reordered, err := EncodeHeader(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if string(reordered) != string(first) {
		t.Fatal("map insertion order changed the canonical encoding")
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	h := sampleHeader()
	raw, err := EncodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeHeader(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(reencoded) != string(raw) {
		t.Fatal("decode then re-encode did not reproduce the original bytes")
	}
	if got.Seq != h.Seq || got.Kind != h.Kind || got.Participant != h.Participant {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if got.PayloadHash != h.PayloadHash {
		t.Fatal("payload hash did not survive the round trip")
	}
}

func TestDecodeHeaderRejectsGarbage(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty":     {},
		"truncated": {0xa5, 0x01},
		"text":      []byte("not cbor at all"),
	} {
		if _, err := DecodeHeader(input); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestChainHashSensitivity checks that the chain hash actually depends on every
// term it is supposed to bind.
func TestChainHashSensitivity(t *testing.T) {
	h := sampleHeader()
	raw, err := EncodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	prev := HashPayload([]byte("previous"))
	payload := HashPayload([]byte("body"))
	base := ComputeChainHash(prev, payload, raw)

	otherPrev := prev
	otherPrev[0] ^= 0x01
	if ComputeChainHash(otherPrev, payload, raw) == base {
		t.Error("chain hash ignores the previous hash")
	}

	otherPayload := payload
	otherPayload[31] ^= 0x80
	if ComputeChainHash(prev, otherPayload, raw) == base {
		t.Error("chain hash ignores the payload hash")
	}

	moved := sampleHeader()
	moved.Seq++
	movedRaw, err := EncodeHeader(moved)
	if err != nil {
		t.Fatal(err)
	}
	if ComputeChainHash(prev, payload, movedRaw) == base {
		t.Error("chain hash ignores the sequence number")
	}
}

// TestPayloadHashDomainSeparation makes sure a payload digest cannot be
// substituted for a chain digest computed over the same bytes.
func TestPayloadHashDomainSeparation(t *testing.T) {
	body := []byte("same bytes, different role")
	if HashPayload(body) == ComputeChainHash(GenesisHash, GenesisHash, body) {
		t.Fatal("payload and chain hashes are interchangeable; domain separation is missing")
	}
}

func TestHLCIsMonotonicAcrossClockRegression(t *testing.T) {
	now := time.Unix(1753430400, 0)
	c := NewClockWithSource(func() time.Time { return now })

	var last uint64
	for range 5 {
		got := c.Now()
		if got <= last {
			t.Fatalf("HLC did not advance while the wall clock stood still: %d after %d", got, last)
		}
		last = got
	}

	// A wall clock that jumps backwards — an NTP step, a VM migration — must not
	// be able to make the log appear to go back in time.
	now = now.Add(-time.Hour)
	for range 5 {
		got := c.Now()
		if got <= last {
			t.Fatalf("HLC went backwards with the wall clock: %d after %d", got, last)
		}
		last = got
	}

	now = now.Add(2 * time.Hour)
	if got := c.Now(); got <= last {
		t.Fatalf("HLC failed to follow the wall clock forward: %d after %d", got, last)
	}
}

func TestHLCObserveAdoptsRemoteTime(t *testing.T) {
	now := time.Unix(1753430400, 0)
	c := NewClockWithSource(func() time.Time { return now })
	local := c.Now()

	remote := local + 1<<20
	c.Observe(remote)
	if got := c.Now(); got <= remote {
		t.Fatalf("after observing %d the clock returned %d; causality is not preserved", remote, got)
	}
}

func TestSplitHLC(t *testing.T) {
	now := time.Unix(1753430400, 0).UTC()
	c := NewClockWithSource(func() time.Time { return now })
	first := c.Now()
	second := c.Now()

	p1, l1 := SplitHLC(first)
	p2, l2 := SplitHLC(second)
	if !p1.Equal(now) || !p2.Equal(now) {
		t.Fatalf("physical parts %s / %s do not match the source clock %s", p1, p2, now)
	}
	if l2 != l1+1 {
		t.Fatalf("logical counter went %d -> %d, want consecutive", l1, l2)
	}
}

// frozenV1Envelope is the canonical CBOR encoding of frozenHeader, byte for
// byte, as this build produces it.
//
// Read the first bytes rather than trusting the string: `ad` opens a map of 13
// pairs, `01 01` is key 1 (V) holding 1, `03 182a` is key 3 (Seq) holding 42,
// and it ends `0d 67 637573745f3432` — key 13 (Subject) holding "cust_42".
// Those key numbers are the whole point: they are what every log Janus has ever
// written is encoded against.
const frozenV1Envelope = "ad010102782430313930633366312d303030302d373030302d383030302d30303030303030303030303103182a046c73675f6c6f616e5f30303031056f73745f626f6f6b5f7061796d656e740678203462663932663335373762333464613661336365393239643065306534373336076b535445505f524553554c5408a4016961675f696e74616b650265332e322e31036970725f62616e6b5f7804654147454e5409a3011b1234567800000001021b18556fa8a9bacd1503782430313930633366312d303030302d373030302d383030302d3030303030303030303061610a5820c58dd1e01bae6b2f76026d37e84c86b1fa88731571fe7b65219d955cffc353ea0b7847626c616b65333a303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030310ca36674656e616e746662616e6b5f786a646174615f636c61737368706572736f6e616c6c6a7572697364696374696f6e6244450d67637573745f3432"

// frozenHeader exercises every field the v1 envelope has, so that the golden
// bytes below pin every CBOR key number and not only the ones a typical event
// happens to set.
func frozenHeader() EventHeader {
	h := sampleHeader()
	h.PayloadRef = "blake3:0000000000000000000000000000000000000000000000000000000000000001"
	h.Subject = "cust_42"
	h.TS.ClockAttestationRef = "0190c3f1-0000-7000-8000-0000000000aa"
	return h
}

// TestTheV1EnvelopeShapeIsFrozen is what makes "envelope version 1" a checked
// claim rather than a comment.
//
// Every other encoding test here is about self-consistency: the same header
// encodes to the same bytes, and a round trip reproduces them. All of them pass
// after somebody renumbers a CBOR key — and renumbering `Seq` from 3 to 14 would
// make every log Janus has ever written decode with `Seq = 0`, silently, because
// an absent key leaves the zero value and the chain hash is computed over the
// raw header bytes and so still verifies. The suite would be green and the
// history unreadable.
//
// So the bytes are pinned. This is the CBOR analogue of `buf breaking` in CI,
// which guards the protobuf payloads and cannot see this struct at all.
//
// **When this test fails, regenerating the constant is almost always the wrong
// fix.** It fails for two reasons and they want opposite responses. Adding an
// optional field an older reader may ignore without misreading changes these
// bytes and is legitimate: update the constant, leave EnvelopeVersion alone.
// Anything a reader must understand to read a record correctly — a renumbered
// key, a changed type, a field that changes what a record means — requires
// bumping EnvelopeVersion, and old readers then refuse the new logs rather than
// misreading them.
func TestTheV1EnvelopeShapeIsFrozen(t *testing.T) {
	got, err := EncodeHeader(frozenHeader())
	if err != nil {
		t.Fatal(err)
	}
	if want := frozenV1Envelope; hex.EncodeToString(got) != want {
		t.Fatalf("the v1 envelope encoding changed.\n got  %s\n want %s\n\n"+
			"If this is a new optional field an older reader may ignore, update "+
			"frozenV1Envelope. If it is anything a reader must understand — a "+
			"renumbered key, a changed type, a field that changes what a record "+
			"means — bump EnvelopeVersion instead, so old readers refuse the new "+
			"logs rather than misreading them.",
			hex.EncodeToString(got), want)
	}

	// And the bytes have to still decode to the header they came from, or the
	// constant would be pinning something nothing reads.
	back, err := DecodeHeader(got)
	if err != nil {
		t.Fatal(err)
	}
	if back.Seq != frozenHeader().Seq || back.Subject != frozenHeader().Subject {
		t.Fatalf("the frozen bytes do not decode to the header that produced them: %+v", back)
	}
}
