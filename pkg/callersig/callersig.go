// Package callersig is how a participant signs what it asks Janus to record,
// and how that signature is checked.
//
// Before it, janus-orchd took every caller at its word: an answer's actor, a
// step's reporter and a saga's principal were whatever the message said, so a
// gated agent that could reach the daemon could answer its own gate as the
// validator. The fix is not a transport property. A signature by the
// participant's own key, over what is being recorded, is kept *in* the record,
// so an auditor holding the log can check that the validator gave the answer
// without trusting the daemon that said so -- the property every other Janus
// control has.
//
// # What is signed
//
// Not the protobuf wire bytes: two languages need not serialise a message
// alike, and a signature that verifies only in the language that made it is a
// signature nobody else can check. Each signed message has a canonical encoding
// defined here and, byte for byte, in the Python SDK (janus/_callersig.py). A
// shared vector file (testdata/vectors.json) is checked by both test suites, so
// the two cannot drift apart silently.
//
// The encoding is a domain string followed by fields, each written as its
// decimal byte length, a colon, the bytes, and a semicolon. Lists are a count
// followed by their items; facts and touches are sorted first, because their
// order is not part of what they mean. Enums are written by name.
//
// # Where the keys come from
//
// A participant's registered manifest declares them, as "ed25519:<hex>" in
// identity.public_keys. The manifest is a record in the log, signed under the
// principal's trusted key, so the list of who may sign as a participant is
// itself evidence. A participant whose manifest declares no key cannot be
// checked and is not; that is a deployment's choice, recorded where an auditor
// can see it (see Verify).
package callersig

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// The domains. A signature over one kind of message can never be presented as
// a signature over another, because the first field differs.
const (
	domainAnswer  = "janus/answer/v1"
	domainResult  = "janus/result/v1"
	domainPrepare = "janus/prepare/v1"
	domainBegin   = "janus/begin/v1"
)

const keyPrefix = "ed25519:"

var (
	// ErrUnsigned means a signature was required and none was sent.
	ErrUnsigned = errors.New("callersig: unsigned")
	// ErrWrongSigner means the signature names a participant other than the
	// one the message is on behalf of.
	ErrWrongSigner = errors.New("callersig: signed by another participant")
	// ErrUndeclaredKey means the signing key is not one the participant's
	// manifest declares.
	ErrUndeclaredKey = errors.New("callersig: key not declared by the participant")
	// ErrBadSignature means the signature does not verify over the message.
	ErrBadSignature = errors.New("callersig: signature does not verify")
)

// EncodeKey renders a public key the way a manifest declares it.
func EncodeKey(pub ed25519.PublicKey) string { return keyPrefix + hex.EncodeToString(pub) }

// ParseKey reads a key as a manifest declares it.
func ParseKey(s string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(s, keyPrefix) {
		return nil, fmt.Errorf("callersig: key %q is not \"ed25519:<hex>\"", s)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(s, keyPrefix))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("callersig: key %q is not a %d-byte Ed25519 key", s, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

type enc struct{ b []byte }

func (e *enc) s(v string) {
	e.b = strconv.AppendInt(e.b, int64(len(v)), 10)
	e.b = append(e.b, ':')
	e.b = append(e.b, v...)
	e.b = append(e.b, ';')
}
func (e *enc) u(v uint64)  { e.s(strconv.FormatUint(v, 10)) }
func (e *enc) i(v int64)   { e.s(strconv.FormatInt(v, 10)) }
func (e *enc) x(v []byte)  { e.s(hex.EncodeToString(v)) }
func (e *enc) n(count int) { e.u(uint64(count)) }

func (e *enc) facts(in []*janusv1.Fact) {
	fs := make([][]string, 0, len(in))
	for _, f := range in {
		kind, val := "none", ""
		switch v := f.GetValue().(type) {
		case *janusv1.Fact_Text:
			kind, val = "text", v.Text
		case *janusv1.Fact_Number:
			kind, val = "number", strconv.FormatInt(v.Number, 10)
		case *janusv1.Fact_Flag:
			kind, val = "flag", strconv.FormatBool(v.Flag)
		}
		fs = append(fs, []string{f.GetKey(), kind, val})
	}
	slices.SortFunc(fs, func(a, b []string) int { return slices.Compare(a, b) })
	e.n(len(fs))
	for _, f := range fs {
		e.s(f[0])
		e.s(f[1])
		e.s(f[2])
	}
}

func (e *enc) touches(in []*janusv1.ResourceTouch) {
	ts := make([][]string, 0, len(in))
	for _, t := range in {
		ts = append(ts, []string{t.GetResourceId(), t.GetMode().String(),
			strconv.FormatUint(t.GetFrontierSeq(), 10)})
	}
	slices.SortFunc(ts, func(a, b []string) int { return slices.Compare(a, b) })
	e.n(len(ts))
	for _, t := range ts {
		e.s(t[0])
		e.s(t[1])
		e.s(t[2])
	}
}

func (e *enc) spawn(c *janusv1.ChildSaga) {
	e.s(c.GetSagaId())
	e.s(c.GetCommitMode().String())
}

// Answer is the canonical encoding of an answer, without its signature.
func Answer(a *janusv1.GateAnswer) []byte {
	e := &enc{}
	e.s(domainAnswer)
	e.s(a.GetSagaId())
	e.s(a.GetStepId())
	e.s(a.GetRequirementId())
	e.u(uint64(a.GetAttempt()))
	e.s(a.GetActor().GetParticipant().GetId())
	e.s(a.GetActor().GetHumanSubject())
	e.s(a.GetVerdict().String())
	e.s(a.GetReason())
	e.n(len(a.GetRoles()))
	for _, r := range a.GetRoles() {
		e.s(r)
	}
	e.s(a.GetAuthRef())
	return e.b
}

// Result is the canonical encoding of a step's result, without its signature.
// The decision provenance record that travels beside it is not covered: it is
// the participant's account of *why*, reported with the result and cited by
// it, and signing it would need a canonical form for a message a model's
// output fills. That remains unsigned.
func Result(r *janusv1.StepResult) []byte {
	e := &enc{}
	e.s(domainResult)
	e.s(r.GetSagaId())
	e.s(r.GetStepId())
	e.u(uint64(r.GetAttempt()))
	e.s(r.GetOutcome().GetStatus().String())
	e.s(r.GetOutcome().GetCode())
	e.s(r.GetOutcome().GetMessage())
	e.x(r.GetResultHash())
	e.s(r.GetResultRef())
	e.facts(r.GetFacts())
	e.touches(r.GetTouches())
	return e.b
}

// Prepare is the canonical encoding of a step's declaration.
func Prepare(saga, step string, facts []*janusv1.Fact, spawns *janusv1.ChildSaga) []byte {
	e := &enc{}
	e.s(domainPrepare)
	e.s(saga)
	e.s(step)
	e.facts(facts)
	e.spawn(spawns)
	return e.b
}

// Begin is the canonical encoding of the saga a caller asks to begin: what it
// is, for whom, and what it plans to do. The gate plan and the semantics version
// are the daemon's to stamp, and are not the caller's to sign.
func Begin(b *janusv1.SagaBegin) []byte {
	e := &enc{}
	e.s(domainBegin)
	e.s(b.GetSagaId())
	in := b.GetIntent()
	e.s(in.GetIntentId())
	e.s(in.GetPrincipal())
	e.s(in.GetOriginator())
	e.s(in.GetMandateRef())
	e.s(in.GetScope())
	e.i(in.GetExpiresAtUnixNanos())
	e.s(b.GetMode())
	e.s(b.GetParent().GetSagaId())
	e.s(b.GetParent().GetStepId())
	e.s(b.GetParent().GetCommitMode().String())
	e.n(len(b.GetPlan()))
	for _, st := range b.GetPlan() {
		e.s(st.GetStepId())
		e.s(st.GetParticipant())
		e.s(st.GetAction())
		e.s(st.GetEffectClass().String())
		e.n(len(st.GetDependsOn()))
		for _, d := range st.GetDependsOn() {
			e.s(d)
		}
		e.s(st.GetCompensationAction())
		e.u(uint64(st.GetMaxRetries()))
	}
	pins := make([]string, 0, len(b.GetManifestPins()))
	for k := range b.GetManifestPins() {
		pins = append(pins, k)
	}
	slices.Sort(pins)
	e.n(len(pins))
	for _, k := range pins {
		e.s(k)
		e.s(b.GetManifestPins()[k])
	}
	return e.b
}

// Signer is what signs as a participant: a private key and the participant it
// belongs to.
type Signer struct {
	Participant string
	Key         ed25519.PrivateKey
}

// Sign signs a canonical encoding.
func (s Signer) Sign(canonical []byte) *janusv1.ParticipantSignature {
	return &janusv1.ParticipantSignature{
		ParticipantId: s.Participant,
		PublicKey:     EncodeKey(s.Key.Public().(ed25519.PublicKey)),
		Signature:     ed25519.Sign(s.Key, canonical),
	}
}

// Verify checks that sig is `participant`'s signature over canonical, by a key
// its manifest declares.
//
// It reports ErrUnsigned for a nil signature and leaves the decision about
// whether that is acceptable to the caller: a participant whose manifest
// declares no key has nothing to be checked against, and whether a deployment
// accepts such participants at all is the daemon's -require-caller-signatures.
func Verify(sig *janusv1.ParticipantSignature, participant string, declared []string,
	canonical []byte) error {

	if sig == nil || len(sig.GetSignature()) == 0 {
		return ErrUnsigned
	}
	if sig.GetParticipantId() != participant {
		return fmt.Errorf("%w: the message is on behalf of %q and the signature is by %q",
			ErrWrongSigner, participant, sig.GetParticipantId())
	}
	if !slices.Contains(declared, sig.GetPublicKey()) {
		return fmt.Errorf("%w: %q does not declare %s", ErrUndeclaredKey, participant, sig.GetPublicKey())
	}
	pub, err := ParseKey(sig.GetPublicKey())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUndeclaredKey, err)
	}
	if !ed25519.Verify(pub, canonical, sig.GetSignature()) {
		return fmt.Errorf("%w: by %s for %q", ErrBadSignature, sig.GetPublicKey(), participant)
	}
	return nil
}

// LoadSigner reads a participant's key from a file `janus-keys gen` wrote: the
// same format as a writer key, which is Ed25519 and nothing more.
func LoadSigner(participant, path string) (Signer, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return Signer{}, err
	}
	var kf struct {
		Alg  string `json:"alg"`
		Seed string `json:"seed_hex"`
	}
	if err := json.Unmarshal(blob, &kf); err != nil {
		return Signer{}, fmt.Errorf("callersig: reading %s: %w", path, err)
	}
	if kf.Alg != "ed25519" {
		return Signer{}, fmt.Errorf("callersig: %s holds a %q key, not ed25519", path, kf.Alg)
	}
	seed, err := hex.DecodeString(kf.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return Signer{}, fmt.Errorf("callersig: %s does not hold a %d-byte seed", path, ed25519.SeedSize)
	}
	return Signer{Participant: participant, Key: ed25519.NewKeyFromSeed(seed)}, nil
}
