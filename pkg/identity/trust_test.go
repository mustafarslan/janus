package identity_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/identity"
)

// TestAnApprovalIsReVerifiableFromTheBundleAlone is what an established identity
// actually requires.
//
// Nothing is configured here. The trust store is folded out of the same log the
// approval is in, and the assertion is fetched from the blob store by the
// reference the answer recorded. A third party holding the bundle does exactly
// this and reaches the same answer — which is the difference between a claim
// that was checked and a claim that was checked by somebody you have to trust.
func TestAnApprovalIsReVerifiableFromTheBundleAlone(t *testing.T) {
	dir, blobs := newLog(t)
	signer := newSigner(t)
	credential, stepUp := newStepUp(t, binding, subject)

	record(t, dir, func(r *identity.Recorder) {
		ctx := context.Background()
		if err := r.TrustIssuerKey(ctx, issuer, kid, "ES256", signer.key.Public()); err != nil {
			t.Fatal(err)
		}
		if err := r.RegisterCredential(ctx, "cred-1", subject, credential.PublicKey); err != nil {
			t.Fatal(err)
		}
	})

	assertion := &identity.Assertion{
		IDToken: signer.token(t, claims(time.Now().Add(time.Hour))), StepUp: stepUp,
	}
	ref, err := identity.PutAssertion(context.Background(), blobs, assertion)
	if err != nil {
		t.Fatal(err)
	}

	// From here on: only the directory and the reference.
	trust, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolve := identity.Resolver(context.Background(), blobs, trust, binding, time.Now)
	established, err := resolve(ref)
	if err != nil {
		t.Fatalf("an approval could not be re-verified from the bundle: %v", err)
	}
	if established.Subject != subject {
		t.Fatalf("established %q, want %q", established.Subject, subject)
	}
	if len(established.Roles) != 1 || established.Roles[0] != "credit-officer" {
		t.Fatalf("established roles %v; these are the roles a gate will check, so they "+
			"have to be the ones the provider signed for", established.Roles)
	}
	if !established.SteppedUp {
		t.Fatal("the step-up did not verify against the credential the log registered")
	}
}

// TestRevokingAKeyStopsFutureApprovalsAndLeavesPastOnesAlone.
//
// A key revoked today does not make yesterday's approval fraudulent. The
// approval was given against a key that was trusted at the time, and treating
// it otherwise would rewrite history every time somebody rotated a certificate.
// So the store folds to a sequence, and a reader asking about a historical
// approval asks as of when it was given.
func TestRevokingAKeyStopsFutureApprovalsAndLeavesPastOnesAlone(t *testing.T) {
	dir, blobs := newLog(t)
	signer := newSigner(t)

	record(t, dir, func(r *identity.Recorder) {
		if err := r.TrustIssuerKey(context.Background(), issuer, kid, "ES256",
			signer.key.Public()); err != nil {
			t.Fatal(err)
		}
	})

	assertion := &identity.Assertion{IDToken: signer.token(t, claims(time.Now().Add(time.Hour)))}
	ref, err := identity.PutAssertion(context.Background(), blobs, assertion)
	if err != nil {
		t.Fatal(err)
	}
	asOf := lastSeq(t, dir)

	record(t, dir, func(r *identity.Recorder) {
		if err := r.RevokeIssuerKey(context.Background(), issuer, kid,
			"rotated at the end of the quarter"); err != nil {
			t.Fatal(err)
		}
	})

	// Now: the key is gone, so a new approval on it establishes nothing.
	now, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Resolver(context.Background(), blobs, now, binding, time.Now)(ref); err == nil {
		t.Fatal("a revoked key still verified new approvals")
	}

	// As of when it was given: the approval still stands.
	then, err := identity.FoldTrustUntil(dir, asOf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Resolver(context.Background(), blobs, then, binding, time.Now)(ref); err != nil {
		t.Fatalf("an approval given while the key was trusted stopped verifying when the "+
			"key was later rotated: %v", err)
	}
}

// TestARevocationWithoutAReasonIsRefused. A rotation and a compromise look
// identical without one, and they call for opposite responses to every approval
// the key ever verified.
func TestARevocationWithoutAReasonIsRefused(t *testing.T) {
	dir, _ := newLog(t)
	var got error
	record(t, dir, func(r *identity.Recorder) {
		got = r.RevokeIssuerKey(context.Background(), issuer, kid, "")
	})
	if got == nil {
		t.Fatal("a revocation with no reason was recorded")
	}
}

// TestAnAssertionThatIsNotInTheBlobStoreEstablishesNothing. An auth_ref that
// points at nothing is not a weaker proof; it is no proof.
func TestAnAssertionThatIsNotInTheBlobStoreEstablishesNothing(t *testing.T) {
	dir, blobs := newLog(t)
	signer := newSigner(t)
	record(t, dir, func(r *identity.Recorder) {
		if err := r.TrustIssuerKey(context.Background(), issuer, kid, "ES256",
			signer.key.Public()); err != nil {
			t.Fatal(err)
		}
	})
	trust, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = identity.Resolver(context.Background(), blobs, trust, binding, time.Now)(
		"blake3:0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("a reference to a blob that is not there was accepted")
	}
	if errors.Is(err, identity.ErrNotEstablished) {
		t.Log("reported as not established, which is also fine")
	}
}

// ---- fixtures --------------------------------------------------------------

func newLog(t *testing.T) (string, cas.Store) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "evidence")
	blobs, err := cas.NewFileStore(filepath.Join(root, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	return dir, blobs
}

// record opens the log, runs one recording, and closes it — the way an operator
// tool does, rather than holding it open across a test.
func record(t *testing.T, dir string, do func(*identity.Recorder)) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	do(identity.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_identity", Principal: "pr_bank", Kind: "SYSTEM",
	}))
}

func lastSeq(t *testing.T, dir string) uint64 {
	t.Helper()
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		t.Fatal(err)
	}
	var last uint64
	for _, id := range ids {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range insp.Records {
			header, err := evidence.DecodeHeader(record.Header)
			if err != nil {
				t.Fatal(err)
			}
			if header.Seq > last {
				last = header.Seq
			}
		}
	}
	return last
}
