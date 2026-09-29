package evidence_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// placedStore is a blob store that declares where its bytes rest, which is what
// an S3 bucket configured with a jurisdiction looks like from here.
type placedStore struct {
	cas.Store
	where string
}

func (s placedStore) Jurisdiction() string { return s.where }

func fileStore(t *testing.T) cas.Store {
	t.Helper()
	s, err := cas.NewFileStore(filepath.Join(t.TempDir(), "cas"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestPinnedEvidenceRefusesABlobStoreNobodyHasPlaced is the gap that makes
// evidence-directory residency insufficient on its own.
//
// The payloads that go to content-addressed storage are the large ones — whole
// documents, model outputs, the material a residency rule is actually about. A
// deployment can be scrupulous about where its segment directory lives and
// still send the substance of it elsewhere, because the two are configured in
// different places and only one of them looks like "the data".
func TestPinnedEvidenceRefusesABlobStoreNobodyHasPlaced(t *testing.T) {
	_, err := evidence.Open(evidence.Options{
		Dir:      filepath.Join(t.TempDir(), "evidence"),
		Signer:   mustSigner(t),
		SyncMode: segment.SyncModeNone,
		Tenant:   tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"},
		CAS:      fileStore(t),
	})
	if err == nil {
		t.Fatal("a pinned tenant accepted a blob store that declares no jurisdiction")
	}
	if !strings.Contains(err.Error(), "declares no jurisdiction") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

func TestPinnedEvidenceRefusesABlobStoreSomewhereElse(t *testing.T) {
	_, err := evidence.Open(evidence.Options{
		Dir:      filepath.Join(t.TempDir(), "evidence"),
		Signer:   mustSigner(t),
		SyncMode: segment.SyncModeNone,
		Tenant:   tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"},
		CAS:      placedStore{Store: fileStore(t), where: "US"},
	})
	if err == nil {
		t.Fatal("a tenant pinned to DE accepted a blob store resting in US")
	}
	if !strings.Contains(err.Error(), "rests in US") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

func TestAMatchingStoreIsAccepted(t *testing.T) {
	a, err := evidence.Open(evidence.Options{
		Dir:      filepath.Join(t.TempDir(), "evidence"),
		Signer:   mustSigner(t),
		SyncMode: segment.SyncModeNone,
		Tenant:   tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"},
		CAS:      placedStore{Store: fileStore(t), where: "DE"},
	})
	if err != nil {
		t.Fatalf("a store in the tenant's own jurisdiction was refused: %v", err)
	}
	_ = a.Close()

	// And an unpinned tenant is unaffected, which is every deployment that has
	// not made the declaration.
	b, err := evidence.Open(evidence.Options{
		Dir:      filepath.Join(t.TempDir(), "evidence2"),
		Signer:   mustSigner(t),
		SyncMode: segment.SyncModeNone,
		CAS:      fileStore(t),
	})
	if err != nil {
		t.Fatalf("an unpinned deployment was refused an undeclared store: %v", err)
	}
	_ = b.Close()
}

// TestTenantOfDirReadsTheCurrentBinding is what makes the compliance linter's
// pin a fact about the deployment rather than a claim by whoever ran it.
//
// Newest first, so a log bound to a tenant partway through its life answers
// with the binding it has now rather than the absence it started with.
func TestTenantOfDirReadsTheCurrentBinding(t *testing.T) {
	signer := mustSigner(t)
	dir := filepath.Join(t.TempDir(), "evidence")

	for _, tn := range []tenancy.Tenant{{}, {ID: "bank_a", Jurisdiction: "DE"}} {
		a, err := evidence.Open(evidence.Options{
			Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Tenant: tn,
		})
		if err != nil {
			t.Fatal(err)
		}
		appendN(t, a, 2, "sg_1")
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	}

	got, err := evidence.TenantOfDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "bank_a" || got.Jurisdiction != "DE" {
		t.Fatalf("read binding %+v, want bank_a/DE", got)
	}

	// A log that was never bound answers with the unbound tenant rather than
	// an error: not every deployment is multi-tenant, and a linter reading one
	// should get "no pin", not a failure.
	plain := filepath.Join(t.TempDir(), "plain")
	a, err := evidence.Open(evidence.Options{
		Dir: plain, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, a, 2, "sg_1")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	got, err = evidence.TenantOfDir(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got.Bound() {
		t.Fatalf("an unbound log reported tenant %+v", got)
	}
}
