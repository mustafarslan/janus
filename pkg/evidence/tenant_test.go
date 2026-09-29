package evidence_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// TestACallerCannotStampAnotherTenant is the reason this package exists.
//
// Before the binding, the Appender merged its configured labels first and let a
// request's labels overwrite them. Any caller that could reach the write path
// could therefore write events into this log carrying another tenant's name,
// and the log would record them as that tenant's evidence — signed, chained,
// and wrong. The refusal here is what closes that.
func TestACallerCannotStampAnotherTenant(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, func(o *evidence.Options) {
		o.Tenant = tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"}
	})

	_, err := a.Append(context.Background(), evidence.Request{
		Kind:        evidence.KindStepResult,
		SagaID:      "sg_1",
		Participant: evidence.ParticipantRef{ID: "ag_test", Principal: "pr_test", Kind: "AGENT"},
		Labels:      map[string]string{tenancy.LabelTenant: "bank_b"},
		Payload:     []byte(`{}`),
	})
	if !errors.Is(err, tenancy.ErrReservedLabel) {
		t.Fatalf("a caller stamped another tenant's name: %v", err)
	}

	// And nothing was written. A refusal that still appends is not a refusal.
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys: keySet(signer), AllowUnsealedTail: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events != 0 {
		t.Fatalf("the refused append left %d event(s) in the log", rep.Events)
	}
}

// TestTheBindingStampsEventsNobodyLabelled is the other half of the same
// problem: a tenant that has to be passed at each call site is a tenant that
// some call site will forget. The A2A proxy did forget it, and recorded every
// intercepted message under no tenant at all.
//
// Putting the binding on the writer means no call site can forget, because no
// call site is involved.
func TestTheBindingStampsEventsNobodyLabelled(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, func(o *evidence.Options) {
		o.Tenant = tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"}
	})
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind:        evidence.KindA2AMessage,
		SagaID:      "sg_1",
		Participant: evidence.ParticipantRef{ID: "ag_test", Principal: "pr_test", Kind: "AGENT"},
		Labels:      map[string]string{"direction": "inbound"},
		Payload:     []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys: keySet(signer), IncludeEvents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.EventList) != 1 {
		t.Fatalf("expected one event, got %d", len(rep.EventList))
	}
	got := rep.EventList[0].Labels
	if got[tenancy.LabelTenant] != "bank_a" || got[tenancy.LabelJurisdiction] != "DE" {
		t.Fatalf("the binding did not reach the event: %v", got)
	}
	// The caller's own descriptive label survives. The binding overrides the
	// reserved keys, not the whole label set.
	if got["direction"] != "inbound" {
		t.Fatalf("the binding ate the caller's labels: %v", got)
	}
}

// TestOptionsLabelsCannotNameATenant keeps the deployment honest too. A tenant
// set through the generic label bag would give one log two answers to the same
// question, and which one won would depend on the order of a map merge.
func TestOptionsLabelsCannotNameATenant(t *testing.T) {
	_, err := evidence.Open(evidence.Options{
		Dir:      filepath.Join(t.TempDir(), "evidence"),
		Signer:   mustSigner(t),
		SyncMode: segment.SyncModeNone,
		Labels:   map[string]string{tenancy.LabelTenant: "bank_a"},
	})
	if !errors.Is(err, tenancy.ErrReservedLabel) {
		t.Fatalf("a tenant set through Options.Labels was accepted: %v", err)
	}
}

// TestVerificationRefusesAnotherTenantsEvidence is the check that catches the
// case where the keys are right and the contents are not: a restored backup
// from the wrong directory, a daemon started on a neighbour's log.
func TestVerificationRefusesAnotherTenantsEvidence(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, func(o *evidence.Options) {
		o.Tenant = tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"}
	})
	appendN(t, a, 3, "sg_1")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys:   keySet(signer),
		Tenant: tenancy.Tenant{ID: "bank_b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("bank_a's log verified as bank_b's evidence")
	}
	if !hasCritical(rep, "TENANT_MISMATCH") {
		t.Fatalf("no TENANT_MISMATCH finding: %+v", rep.Findings)
	}

	// The same log verified as its own tenant passes, and says whose it is.
	rep, err = verify.SegmentDir(dir, verify.Options{
		Keys:   keySet(signer),
		Tenant: tenancy.Tenant{ID: "bank_a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("bank_a's log failed as bank_a's evidence: %+v", rep.Findings)
	}
	if len(rep.Tenants) != 1 || rep.Tenants[0] != "bank_a" {
		t.Fatalf("report names tenants %v", rep.Tenants)
	}
}

// TestOneDirectoryHoldingTwoTenantsIsCritical covers the shape a leak actually
// takes. It cannot be produced through the write path — that is what the
// refusal above is for — so it is produced the way an operator would produce
// it by accident: by pointing a second daemon, bound to a different tenant, at
// a directory that already holds somebody else's log.
func TestOneDirectoryHoldingTwoTenantsIsCritical(t *testing.T) {
	signer := mustSigner(t)
	dir := filepath.Join(t.TempDir(), "evidence")

	for _, id := range []string{"bank_a", "bank_b"} {
		a, err := evidence.Open(evidence.Options{
			Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
			Tenant: tenancy.Tenant{ID: id},
		})
		if err != nil {
			t.Fatal(err)
		}
		appendN(t, a, 2, "sg_"+id)
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(signer)})
	if err != nil {
		t.Fatal(err)
	}
	// Note what is *not* wrong here: the chain is intact, every footer verifies,
	// the sequence is contiguous. Every existing check passes. Without the
	// tenant check this log reads as sound evidence, and it is two banks' data
	// in one artifact.
	if rep.OK {
		t.Fatal("a log holding two tenants verified as sound")
	}
	if !hasCritical(rep, "MIXED_TENANTS") {
		t.Fatalf("no MIXED_TENANTS finding: %+v", rep.Findings)
	}
	if len(rep.Tenants) != 2 {
		t.Fatalf("report names tenants %v", rep.Tenants)
	}
}

// TestATenantsKeysDoNotEstablishAnotherTenantsLog is the isolation that does
// not depend on anybody remembering to pass a filter.
//
// The label checks above catch mistakes. This catches everything else: tenant
// B's auditor, holding tenant B's keys, cannot establish tenant A's segments at
// all — not because a check declined to show them, but because the signature
// over them was made by a key B does not have. A filter that leaks yields
// somebody else's data; a key that is absent yields a failed verification.
func TestATenantsKeysDoNotEstablishAnotherTenantsLog(t *testing.T) {
	signerA, signerB := mustSigner(t), mustSigner(t)

	a, dirA := newAppender(t, signerA, func(o *evidence.Options) {
		o.Tenant = tenancy.Tenant{ID: "bank_a"}
	})
	appendN(t, a, 3, "sg_a")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.SegmentDir(dirA, verify.Options{Keys: keySet(signerB)})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("bank_a's log verified under bank_b's keys")
	}
	if !hasCritical(rep, "UNKNOWN_SIGNING_KEY") {
		t.Fatalf("no UNKNOWN_SIGNING_KEY finding: %+v", rep.Findings)
	}
}

// hasCritical is stricter than the shared hasFinding: these checks are only
// worth anything if they disqualify the log, so a finding at any lower severity
// is a failure of the test.
func hasCritical(r *verify.Report, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code && f.Severity == verify.Critical {
			return true
		}
	}
	return false
}
