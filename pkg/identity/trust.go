package identity

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"time"

	"google.golang.org/protobuf/proto"
)

// The trust anchor, and the assertion, both in the log.
//
// This is the half that was missing. Verification is only worth
// something if a third party reaches the same answer: the keys have to be
// recorded, and the assertion has to be retrievable rather than summarised.
//
// So a deployment records which issuer keys and which authenticators it
// believes, an approval carries the assertion's content address in auth_ref,
// and anybody holding the bundle can fetch the assertion, fold the trust store
// as it stood, and check the signature themselves.

// Recorder appends trust decisions.
type Recorder struct {
	app *evidence.Appender
	by  evidence.ParticipantRef
}

// NewRecorder returns a recorder for identity trust events.
func NewRecorder(app *evidence.Appender, by evidence.ParticipantRef) *Recorder {
	return &Recorder{app: app, by: by}
}

// TrustIssuerKey admits one signing key of one OIDC issuer.
func (r *Recorder) TrustIssuerKey(ctx context.Context, issuer, keyID, algorithm string,
	key crypto.PublicKey) error {

	encoded, err := encodeKey(key)
	if err != nil {
		return err
	}
	return r.append(ctx, &janusv1.IdentityTrustEvent{
		Kind:      janusv1.IdentityTrustEvent_KIND_ISSUER_KEY_TRUSTED,
		Issuer:    issuer,
		KeyId:     keyID,
		PublicKey: encoded,
		Algorithm: algorithm,
	})
}

// RevokeIssuerKey withdraws one.
//
// The reason is required. A revocation without one leaves a reader unable to
// tell a routine rotation from a compromise, and those call for opposite
// responses to every approval the key ever verified.
func (r *Recorder) RevokeIssuerKey(ctx context.Context, issuer, keyID, reason string) error {
	if reason == "" {
		return fmt.Errorf("identity: a revocation needs a reason; a rotation and a " +
			"compromise look identical without one, and they call for opposite responses " +
			"to every approval this key verified")
	}
	return r.append(ctx, &janusv1.IdentityTrustEvent{
		Kind:   janusv1.IdentityTrustEvent_KIND_ISSUER_KEY_REVOKED,
		Issuer: issuer, KeyId: keyID, Reason: reason,
	})
}

// RegisterCredential binds a WebAuthn authenticator to a person.
func (r *Recorder) RegisterCredential(ctx context.Context, credentialID, subject string,
	key crypto.PublicKey) error {

	encoded, err := encodeKey(key)
	if err != nil {
		return err
	}
	return r.append(ctx, &janusv1.IdentityTrustEvent{
		Kind:         janusv1.IdentityTrustEvent_KIND_CREDENTIAL_REGISTERED,
		CredentialId: credentialID, Subject: subject, PublicKey: encoded,
	})
}

// RevokeCredential withdraws one — a lost or stolen authenticator.
func (r *Recorder) RevokeCredential(ctx context.Context, credentialID, reason string) error {
	if reason == "" {
		return fmt.Errorf("identity: a revocation needs a reason")
	}
	return r.append(ctx, &janusv1.IdentityTrustEvent{
		Kind:         janusv1.IdentityTrustEvent_KIND_CREDENTIAL_REVOKED,
		CredentialId: credentialID, Reason: reason,
	})
}

func (r *Recorder) append(ctx context.Context, event *janusv1.IdentityTrustEvent) error {
	payload, err := proto.Marshal(event)
	if err != nil {
		return fmt.Errorf("identity: encoding the trust event: %w", err)
	}
	_, err = r.app.Append(ctx, evidence.Request{
		Kind: evidence.KindIdentityTrust, Participant: r.by, Payload: payload,
	})
	return err
}

// LoadTrust folds the trust store out of an evidence directory.
//
// Folded rather than cached, and folded to *now* by default. A caller
// re-verifying a historical approval wants FoldTrustUntil instead: an approval
// given on a key that was later revoked was valid when it was given, and
// treating it otherwise would rewrite history every time somebody rotated.
func LoadTrust(dir string) (TrustStore, error) {
	return FoldTrustUntil(dir, 0)
}

// FoldTrustUntil folds the trust store as it stood at a sequence. Zero means
// the whole log.
func FoldTrustUntil(dir string, until uint64) (TrustStore, error) {
	store := TrustStore{
		Issuers:     map[string]map[string]crypto.PublicKey{},
		Credentials: map[string]Credential{},
	}
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return store, fmt.Errorf("identity: reading the log: %w", err)
	}
	for _, id := range ids {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			return store, fmt.Errorf("identity: reading segment %d: %w", id, err)
		}
		for _, record := range insp.Records {
			header, err := evidence.DecodeHeader(record.Header)
			if err != nil {
				return store, fmt.Errorf("identity: unreadable event header: %w", err)
			}
			if header.Kind != evidence.KindIdentityTrust {
				continue
			}
			if until > 0 && header.Seq > until {
				return store, nil
			}
			var event janusv1.IdentityTrustEvent
			if err := proto.Unmarshal(record.Payload, &event); err != nil {
				return store, fmt.Errorf("identity: unreadable trust event at seq %d: %w",
					header.Seq, err)
			}
			if err := store.apply(&event); err != nil {
				return store, err
			}
		}
	}
	return store, nil
}

func (t TrustStore) apply(e *janusv1.IdentityTrustEvent) error {
	switch e.GetKind() {
	case janusv1.IdentityTrustEvent_KIND_ISSUER_KEY_TRUSTED:
		key, err := decodeKey(e.GetPublicKey())
		if err != nil {
			return err
		}
		if t.Issuers[e.GetIssuer()] == nil {
			t.Issuers[e.GetIssuer()] = map[string]crypto.PublicKey{}
		}
		t.Issuers[e.GetIssuer()][e.GetKeyId()] = key
	case janusv1.IdentityTrustEvent_KIND_ISSUER_KEY_REVOKED:
		delete(t.Issuers[e.GetIssuer()], e.GetKeyId())
	case janusv1.IdentityTrustEvent_KIND_CREDENTIAL_REGISTERED:
		key, err := decodeKey(e.GetPublicKey())
		if err != nil {
			return err
		}
		t.Credentials[e.GetCredentialId()] = Credential{Subject: e.GetSubject(), PublicKey: key}
	case janusv1.IdentityTrustEvent_KIND_CREDENTIAL_REVOKED:
		delete(t.Credentials, e.GetCredentialId())
	}
	return nil
}

// ---- the assertion itself --------------------------------------------------

// PutAssertion stores an assertion content-addressed and returns the reference
// to put in an answer's auth_ref.
//
// Stored verbatim, because the signature is over the bytes: an assertion
// re-serialised on the way in cannot be verified on the way out.
func PutAssertion(ctx context.Context, store cas.Store, a *Assertion) (string, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("identity: encoding the assertion: %w", err)
	}
	digest, err := store.Put(ctx, raw)
	if err != nil {
		return "", fmt.Errorf("identity: storing the assertion: %w", err)
	}
	return digest.Ref(), nil
}

// GetAssertion reads one back.
func GetAssertion(ctx context.Context, store cas.Store, ref string) (*Assertion, error) {
	raw, err := cas.GetByRef(ctx, store, ref)
	if err != nil {
		return nil, fmt.Errorf("identity: reading the assertion at %s: %w", ref, err)
	}
	var a Assertion
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("identity: unreadable assertion at %s: %w", ref, err)
	}
	return &a, nil
}

// Resolver returns the function a gate uses to establish what an answer proved.
//
// It closes over the trust store and the binding, so the gate does not have to
// know where either comes from — and so a gate cannot be handed a resolver that
// verifies against something other than the log.
func Resolver(ctx context.Context, store cas.Store, trust TrustStore, binding Binding,
	now func() time.Time) func(string) (*Established, error) {

	return func(ref string) (*Established, error) {
		assertion, err := GetAssertion(ctx, store, ref)
		if err != nil {
			return nil, err
		}
		return Verify(assertion, trust, binding, now())
	}
}

// EncodePublicKey renders a public key the way this package stores it, so that a
// caller comparing a configured key against a folded one compares the same bytes
// the log would. Two keys are the same key exactly when the log cannot tell them
// apart.
func EncodePublicKey(key crypto.PublicKey) ([]byte, error) { return encodeKey(key) }

func encodeKey(key crypto.PublicKey) ([]byte, error) {
	if ed, ok := key.(ed25519.PublicKey); ok {
		return ed, nil
	}
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("identity: encoding the public key: %w", err)
	}
	return encoded, nil
}

func decodeKey(raw []byte) (crypto.PublicKey, error) {
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	key, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("identity: unreadable public key: %w", err)
	}
	return key, nil
}
