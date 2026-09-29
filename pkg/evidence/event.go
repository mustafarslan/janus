// Package evidence implements the Janus evidence log: the append-only,
// hash-chained record that is the system of record for everything an agent does.
//
// The canonical form of an event envelope is deterministic CBOR, defined by the
// Go types in this file. The JTP protobuf messages are carried as the event's
// opaque payload — one grammar for wire and record, with a single source of
// truth for the bytes that get hashed.
package evidence

import (
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/zeebo/blake3"
)

// Kind names the payload an event carries. These values mirror the EventKind
// enum in proto/janus/v1/evidence.proto; TestKindsMatchProto enforces that they
// stay in lockstep.
type Kind string

// Event kinds. Each JTP message has a kind of the same name.
const (
	KindSagaBegin   Kind = "SAGA_BEGIN"
	KindStepPrepare Kind = "STEP_PREPARE"
	KindStepResult  Kind = "STEP_RESULT"
	KindGateVerdict Kind = "GATE_VERDICT"
	KindSealRequest Kind = "SEAL_REQUEST"
	KindCommit      Kind = "COMMIT"
	KindCompensate  Kind = "COMPENSATE"
	KindAbort       Kind = "ABORT"
	KindQuarantine  Kind = "QUARANTINE"

	KindDPR     Kind = "DPR"
	KindControl Kind = "CONTROL"

	KindMCPMessage Kind = "MCP_MESSAGE"
	KindA2AMessage Kind = "A2A_MESSAGE"

	KindRecovery         Kind = "RECOVERY"
	KindShred            Kind = "SHRED"
	KindClockAttestation Kind = "CLOCK_ATTESTATION"

	// Outbox lifecycle for an irreversible effect held until commit.
	KindEffectHeld        Kind = "EFFECT_HELD"
	KindEffectReleasing   Kind = "EFFECT_RELEASING"
	KindEffectDelivered   Kind = "EFFECT_DELIVERED"
	KindEffectQuarantined Kind = "EFFECT_QUARANTINED"

	// KindGateAnswer is an answer to a gate from outside Janus: a validator's
	// opinion or a human's approval.
	KindGateAnswer Kind = "GATE_ANSWER"

	// KindRegistry is a mutation of the participant registry: a manifest
	// registered, evaluated, activated, suspended or retired.
	KindRegistry Kind = "REGISTRY"

	// KindIdentityTrust records who this deployment is willing to believe about
	// a person: an OIDC issuer's signing key, or a WebAuthn credential bound to
	// a subject. It is in the log so that an approval can be re-verified later
	// against the keys that were trusted when it was given.
	KindIdentityTrust Kind = "IDENTITY_TRUST"

	// KindWriterKey declares which key signs this log's segments, and withdraws
	// one. See writerkey.go for what the chain of them establishes and, just as
	// importantly, what it does not.
	KindWriterKey Kind = "WRITER_KEY"
	// KindWriterTenure records a replica becoming the writer: the point it
	// continues from, the key it will sign with, and the operator who decided.
	KindWriterTenure Kind = "WRITER_TENURE"

	// KindLegalHold records a legal hold being placed on disposal, and released
	// again. Both are evidence: Janus's own administration is
	// evidence too, and a hold is the clearest case of it — the fact a lawyer
	// needs is not that records still exist but that somebody accountable
	// stopped them being destroyed, on a date, for a named matter.
	KindLegalHold Kind = "LEGAL_HOLD"
)

// AllKinds returns every kind this build knows about.
func AllKinds() []Kind {
	return []Kind{
		KindSagaBegin, KindStepPrepare, KindStepResult, KindGateVerdict,
		KindSealRequest, KindCommit, KindCompensate, KindAbort, KindQuarantine,
		KindDPR, KindControl, KindMCPMessage, KindA2AMessage,
		KindRecovery, KindShred, KindClockAttestation, KindWriterTenure,
		KindEffectHeld, KindEffectReleasing, KindEffectDelivered, KindEffectQuarantined,
		KindGateAnswer, KindRegistry, KindIdentityTrust, KindWriterKey,
		KindLegalHold,
	}
}

// EnvelopeVersion is the envelope schema version written by this build, and the
// highest one it will read.
//
// **The rule for bumping it**: any change a reader must understand to
// read a record correctly. A renumbered CBOR key, a changed type, a field that
// changes what a record means — including a payload field, since the envelope
// version is the one gate covering everything in a record. An optional field an
// older reader may ignore without misreading does *not* bump it, which is why
// `Subject` (key 13) was added under version 1.
//
// `TestTheV1EnvelopeShapeIsFrozen` pins the v1 encoding byte for byte, so the
// first half of that rule is checked rather than remembered.
const EnvelopeVersion uint32 = 1

// HashSize is the length of every hash in the evidence log.
const HashSize = 32

// Hash is a BLAKE3-256 digest.
type Hash [HashSize]byte

// ParticipantRef pins the actor of an event to an exact manifest version, so
// replay can resolve the same capability declaration it ran under (invariant I8).
type ParticipantRef struct {
	ID              string `cbor:"1,keyasint"`
	ManifestVersion string `cbor:"2,keyasint,omitempty"`
	Principal       string `cbor:"3,keyasint,omitempty"`
	Kind            string `cbor:"4,keyasint,omitempty"`
}

// Timestamps carries both a hybrid logical clock — which orders events even
// when wall clocks disagree — and a wall-clock reading. ClockAttestationRef
// points at the NTP/PTP attestation record covering that reading, which is what
// MiFID II RTS 25 clock discipline resolves to operationally.
type Timestamps struct {
	HLC                 uint64 `cbor:"1,keyasint"`
	WallUnixNanos       int64  `cbor:"2,keyasint"`
	ClockAttestationRef string `cbor:"3,keyasint,omitempty"`
}

// Wall returns the wall-clock reading as a time.Time in UTC.
func (t Timestamps) Wall() time.Time {
	return time.Unix(0, t.WallUnixNanos).UTC()
}

// EventHeader is the canonical, hashed form of an event envelope.
//
// Integer CBOR keys keep the encoding compact and stable across field renames.
// PrevHash and ChainHash are deliberately absent: they are stored beside the
// header in the segment record and enter the hash as explicit terms, so the
// header stays a pure description of the event itself.
type EventHeader struct {
	V           uint32            `cbor:"1,keyasint"`
	EventID     string            `cbor:"2,keyasint"`
	Seq         uint64            `cbor:"3,keyasint"`
	SagaID      string            `cbor:"4,keyasint,omitempty"`
	StepID      string            `cbor:"5,keyasint,omitempty"`
	TraceID     string            `cbor:"6,keyasint,omitempty"`
	Kind        Kind              `cbor:"7,keyasint"`
	Participant ParticipantRef    `cbor:"8,keyasint"`
	TS          Timestamps        `cbor:"9,keyasint"`
	PayloadHash Hash              `cbor:"10,keyasint"`
	PayloadRef  string            `cbor:"11,keyasint,omitempty"`
	Labels      map[string]string `cbor:"12,keyasint,omitempty"`
	// Subject names the data subject whose personal data the payload concerns,
	// when there is one.
	//
	// It has to be here rather than only in the writer's memory. The payload is
	// encrypted under this subject's key *and* bound to the subject as
	// additional authenticated data, so a reader that does not know it can
	// neither find the right key nor decrypt with it. Leaving it out would make
	// encrypted payloads write-only.
	//
	// It is stored in the clear, and survives erasure. That is a deliberate
	// trade recorded in docs/compliance/DPIA-crypto-shredding.md: a deployment
	// treating the identifier itself as personal data should use a pseudonym
	// and hold the mapping outside Janus.
	Subject string `cbor:"13,keyasint,omitempty"`
}

// Event is a header plus the chain linkage and payload as stored.
type Event struct {
	Header  EventHeader
	Prev    Hash
	Chain   Hash
	Payload []byte
}

// canonicalEnc and strictDec are the only codecs used for evidence envelopes.
//
// CoreDetEncOptions is RFC 8949 §4.2.1 Core Deterministic Encoding: sorted map
// keys, shortest-form integers, no indefinite-length items. Two writers
// encoding the same header must produce identical bytes, or the chain hash
// would depend on the encoder rather than the event.
var (
	canonicalEnc cbor.EncMode
	strictDec    cbor.DecMode
)

func init() {
	var err error
	if canonicalEnc, err = cbor.CoreDetEncOptions().EncMode(); err != nil {
		panic(fmt.Sprintf("evidence: build canonical CBOR encoder: %v", err))
	}
	// Duplicate map keys are how a tampered header smuggles two values past a
	// lenient parser; refuse them.
	if strictDec, err = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode(); err != nil {
		panic(fmt.Sprintf("evidence: build strict CBOR decoder: %v", err))
	}
}

// EncodeHeader renders an event header in canonical CBOR.
func EncodeHeader(h EventHeader) ([]byte, error) {
	return canonicalEnc.Marshal(h)
}

// ErrUnsupportedEnvelope means a record was written under an envelope schema
// this build does not have.
//
// It is refused rather than read. CBOR ignores keys it does not know, so a v2
// record decodes into the v1 struct without complaint and whatever the newer
// build put there is simply absent — the reader then folds a saga, rebuilds a
// projection, or answers a compliance question from a record it only partly
// understood, and nothing about the result looks wrong. That is the same
// failure `saga.ErrUnsupportedSemantics` refuses one layer up, and it
// was demonstrated one layer down here before this existed: a log written by a
// synthetic v2 build walked cleanly, folded to COMMITTED, and `janus-verify`
// reported **PASS**.
var ErrUnsupportedEnvelope = errors.New("evidence: unsupported envelope version")

// DecodeHeader parses a canonical CBOR event header.
//
// A header from a newer build is returned *with* ErrUnsupportedEnvelope, fully
// populated as far as this build's shape goes, so a caller that reports rather
// than reads — `janus-verify` — can name the version in a finding. Every other
// caller returns on the error and is refused, which is the point: there is one
// decode path and no unchecked variant for a reader to reach for.
//
// Older versions are accepted: replaying a history written by an earlier build
// is the compatibility this exists to protect. No older version exists today —
// version 1 is the first and only one ever written — so that branch is a
// promise about the future rather than a path anything exercises.
func DecodeHeader(b []byte) (EventHeader, error) {
	var h EventHeader
	if err := strictDec.Unmarshal(b, &h); err != nil {
		return h, fmt.Errorf("decode event header: %w", err)
	}
	if h.V > EnvelopeVersion {
		return h, fmt.Errorf("%w: record %d was written under envelope version %d and this "+
			"build understands %d — it is refused rather than read, because the fields it "+
			"does not know would be silently absent", ErrUnsupportedEnvelope, h.Seq, h.V,
			EnvelopeVersion)
	}
	return h, nil
}

// Domain separation strings. Every hash Janus computes is prefixed with the
// purpose it is computed for, so a digest produced in one role can never be
// substituted into another.
const (
	payloadDomain = "JANUS/payload/1\x00"
	chainDomain   = "JANUS/chain/1\x00"
)

// HashPayload returns the digest of an event payload. Payload bytes are stored
// and hashed verbatim — they are never re-serialized, so a non-canonical
// protobuf encoding cannot change the digest after the fact.
func HashPayload(payload []byte) Hash {
	h := blake3.New()
	_, _ = h.Write([]byte(payloadDomain))
	_, _ = h.Write(payload)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeChainHash implements h_i = H(h_{i-1} || payload_hash || header).
// Because the header contains the sequence number,
// participant, and payload hash, altering any of them — or reordering the log —
// breaks every subsequent link.
func ComputeChainHash(prev Hash, payloadHash Hash, header []byte) Hash {
	h := blake3.New()
	_, _ = h.Write([]byte(chainDomain))
	_, _ = h.Write(prev[:])
	_, _ = h.Write(payloadHash[:])
	_, _ = h.Write(header)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// GenesisHash is the predecessor of the first event in a partition.
var GenesisHash Hash
