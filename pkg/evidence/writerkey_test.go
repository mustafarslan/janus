package evidence_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// Rotating the writer key without handing an auditor every key.
//
// The failure this closes is specific and is not about forgery. Withhold the
// key that signed the segments you would rather not be read, and the recipient
// sees UNKNOWN_SIGNING_KEY on exactly those and a clean pass on the rest — which
// reads like a corrupted archive rather than a withheld key. The two are
// indistinguishable from the outside, and only one of them is somebody's fault.

func operator() evidence.ParticipantRef {
	return evidence.ParticipantRef{ID: "sys_keys", Kind: "SYSTEM", Principal: "pr_operator"}
}

// rotatedLog writes events under `first`, declares `second` in a segment the
// first key signs, then writes more under the second. `revoke` additionally
// withdraws the first key at the moment of the rotation.
func rotatedLog(t *testing.T, first, second *keys.Signer, revoke bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")

	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: first, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, a, 6, "sg_before")
	ctx := context.Background()
	if _, err := a.RecordWriterKey(ctx, evidence.WriterKeyDeclaration{
		Kind: evidence.WriterKeyTrusted, KeyID: second.KeyID(), PublicKey: second.Public(),
	}, operator()); err != nil {
		t.Fatal(err)
	}
	if revoke {
		if _, err := a.RecordWriterKey(ctx, evidence.WriterKeyDeclaration{
			Kind: evidence.WriterKeyRevoked, KeyID: first.KeyID(), Reason: "scheduled rotation",
		}, operator()); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: second, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, b, 6, "sg_after")
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestALogSpanningARotationVerifiesFromTheFirstKeyAlone is the whole point.
//
// Before this, an auditor handed a rotated log needed every key it was ever
// written under, out of band, with no way to tell whether they had all of them.
// Now they need the first one, and the log carries the rest.
func TestALogSpanningARotationVerifiesFromTheFirstKeyAlone(t *testing.T) {
	first, second := mustSigner(t), mustSigner(t)
	dir := rotatedLog(t, first, second, false)

	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(first)})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a rotated log did not verify from its first key: %+v", rep.Findings)
	}
	// And the report says where each key came from, so the auditor can see that
	// only one of them had to be trusted.
	if got := rep.SigningKeys[first.KeyID()]; got != "supplied out of band" {
		t.Fatalf("the root's provenance reads %q", got)
	}
	if got := rep.SigningKeys[second.KeyID()]; !strings.HasPrefix(got, "introduced at seq ") {
		t.Fatalf("the rotated key's provenance reads %q", got)
	}
}

// TestSwappingTheKeyWithoutDeclaringItFails is the negative control, and it
// needs no sabotage: it is the property itself.
func TestSwappingTheKeyWithoutDeclaringItFails(t *testing.T) {
	first, second := mustSigner(t), mustSigner(t)
	dir := filepath.Join(t.TempDir(), "evidence")

	for _, signer := range []*keys.Signer{first, second} {
		a, err := evidence.Open(evidence.Options{
			Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 512,
		})
		if err != nil {
			t.Fatal(err)
		}
		appendN(t, a, 6, "sg_1")
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(first)})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a key swapped without a declaration verified from the old root")
	}
	if !hasCritical(rep, "UNKNOWN_SIGNING_KEY") {
		t.Fatalf("no UNKNOWN_SIGNING_KEY finding: %+v", rep.Findings)
	}
}

// TestRevocationIsNotRetroactive is the rule that keeps rotation something
// operators are willing to do.
//
// A key revoked at sequence N keeps its earlier segments verifying. The
// alternative makes every rotation invalidate the history written under the
// previous key — and a key that is never rotated is the problem this was all
// for.
func TestRevocationIsNotRetroactive(t *testing.T) {
	first, second := mustSigner(t), mustSigner(t)
	dir := rotatedLog(t, first, second, true)

	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(first)})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("revoking the old key invalidated the history it signed: %+v", rep.Findings)
	}
	if got := rep.SigningKeys[first.KeyID()]; !strings.Contains(got, "revoked at seq ") {
		t.Fatalf("the report does not say the root was revoked: %q", got)
	}
}

// TestARevokedKeyCannotSignAnythingMore is the other half of the same rule, and
// it is enforced where it can actually stop something: at Open.
//
// A daemon carrying on under a withdrawn key would produce a growing tail that
// fails from the log's own root, and would produce it silently until an audit.
func TestARevokedKeyCannotSignAnythingMore(t *testing.T) {
	first, second := mustSigner(t), mustSigner(t)
	dir := rotatedLog(t, first, second, true)

	_, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: first, SyncMode: segment.SyncModeNone,
	})
	if !errors.Is(err, evidence.ErrWriterKey) {
		t.Fatalf("a writer opened the log with a revoked key: %v", err)
	}
	if !strings.Contains(err.Error(), "scheduled rotation") {
		t.Fatalf("the refusal does not carry the revocation's reason: %v", err)
	}

	// The key that replaced it opens fine, which is the positive control: the
	// check refuses the withdrawn key rather than every key.
	b, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: second, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatalf("the current key was refused: %v", err)
	}
	_ = b.Close()
}

// TestADeclarationCannotIntroduceTheKeyThatSignsItsOwnSegment is the first of
// the two ordering rules, and the one that would be easiest to get wrong by
// applying declarations as they are read.
func TestADeclarationCannotIntroduceTheKeyThatSignsItsOwnSegment(t *testing.T) {
	rogue, root := mustSigner(t), mustSigner(t)
	dir := filepath.Join(t.TempDir(), "evidence")

	// A whole log written by a key nobody trusts, which politely declares
	// itself in its own first segment.
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: rogue, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RecordWriterKey(context.Background(), evidence.WriterKeyDeclaration{
		Kind: evidence.WriterKeyTrusted, KeyID: rogue.KeyID(), PublicKey: rogue.Public(),
	}, operator()); err != nil {
		t.Fatal(err)
	}
	appendN(t, a, 4, "sg_1")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(root)})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a segment introduced the key that signed it, and verified")
	}
	if !hasCritical(rep, "UNKNOWN_SIGNING_KEY") {
		t.Fatalf("no UNKNOWN_SIGNING_KEY finding: %+v", rep.Findings)
	}
}

// TestABundleSpanningARotationVerifiesOffline covers the artifact an auditor is
// actually handed, since that is the path where "you were given every key" was
// hardest to check.
func TestABundleSpanningARotationVerifiesOffline(t *testing.T) {
	first, second := mustSigner(t), mustSigner(t)
	dir := rotatedLog(t, first, second, true)

	dest := filepath.Join(t.TempDir(), "bundle")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir, Dest: dest, Keys: keySet(first), Producer: "test",
	}); err != nil {
		t.Fatal(err)
	}
	rep, err := verify.Bundle(dest, verify.Options{Keys: keySet(first)})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a bundle spanning a rotation did not verify from the first key: %+v",
			rep.Findings)
	}
}

// TestADeclarationNamingTheWrongKeyIsRefused. A declaration naming one key and
// carrying another would put footers in the log pointing at the wrong entry in
// an auditor's set, and they would fail in that auditor's hands rather than
// here.
func TestADeclarationNamingTheWrongKeyIsRefused(t *testing.T) {
	a, _ := newAppender(t, mustSigner(t), nil)
	other := mustSigner(t)

	_, err := a.RecordWriterKey(context.Background(), evidence.WriterKeyDeclaration{
		Kind: evidence.WriterKeyTrusted, KeyID: "ed25519-0000000000000000",
		PublicKey: other.Public(),
	}, operator())
	if !errors.Is(err, evidence.ErrWriterKey) {
		t.Fatalf("a declaration naming the wrong key was recorded: %v", err)
	}

	// And a revocation with no reason, which is the whole content of the event.
	_, err = a.RecordWriterKey(context.Background(), evidence.WriterKeyDeclaration{
		Kind: evidence.WriterKeyRevoked, KeyID: other.KeyID(),
	}, operator())
	if !errors.Is(err, evidence.ErrWriterKey) {
		t.Fatalf("a revocation with no reason was recorded: %v", err)
	}
	_ = a.Close()
}

// TestATrustedKeyCanDeclareItsOwnSuccessor is the chain being a chain, and it is
// the case a second failover needs.
//
// Every other test here rotates once: the root declares a successor and that
// successor signs. A deployment that fails over twice does something stronger —
// the *promoted* writer, whose own key the log introduced, declares the standby
// for the failover after it. Nothing in `WriterTrust.Apply` distinguishes a root
// from a key it learned, which is what makes this work, and until now nothing
// said so.
//
// The property to hold is the one an auditor cares about: **one** key out of
// band, two hops along.
func TestATrustedKeyCanDeclareItsOwnSuccessor(t *testing.T) {
	root, second, third := mustSigner(t), mustSigner(t), mustSigner(t)
	dir := filepath.Join(t.TempDir(), "evidence")
	ctx := context.Background()

	// The root introduces the second key.
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: root, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, a, 6, "sg_root")
	if _, err := a.RecordWriterKey(ctx, evidence.WriterKeyDeclaration{
		Kind: evidence.WriterKeyTrusted, KeyID: second.KeyID(), PublicKey: second.Public(),
	}, operator()); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// The second key — which the root introduced and nobody handed over —
	// introduces the third.
	b, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: second, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, b, 6, "sg_second")
	if _, err := b.RecordWriterKey(ctx, evidence.WriterKeyDeclaration{
		Kind: evidence.WriterKeyTrusted, KeyID: third.KeyID(), PublicKey: third.Public(),
	}, operator()); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	c, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: third, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, c, 6, "sg_third")
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(root)})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a log two rotations from its root did not verify from it: %+v", rep.Findings)
	}
	// Both later keys have to be reported as the log's own, or the report says
	// the auditor had to trust three keys when they trusted one.
	for name, s := range map[string]*keys.Signer{"second": second, "third": third} {
		if got := rep.SigningKeys[s.KeyID()]; !strings.HasPrefix(got, "introduced at seq ") {
			t.Errorf("the %s key's provenance reads %q", name, got)
		}
	}
	if got := rep.SigningKeys[root.KeyID()]; got != "supplied out of band" {
		t.Errorf("the root's provenance reads %q", got)
	}
}
