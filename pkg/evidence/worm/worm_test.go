package worm_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/objstore"
	"github.com/mustafarslan/janus/pkg/evidence/objstore/objstoretest"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/worm"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// bucketSeq gives each test its own bucket. Object Lock cannot be enabled after
// creation and locked objects cannot be removed, so tests can neither share a
// bucket nor clean up after themselves.
var bucketSeq = time.Now().UnixNano()

func nextBucket(prefix string) string {
	bucketSeq++
	return objstoretest.BucketName(prefix, bucketSeq)
}

// writeLog produces a small sealed log and returns its directory.
func writeLog(t *testing.T, events int) (string, *keys.Signer) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir:                dir,
		Signer:             signer,
		SyncMode:           segment.SyncModeNone,
		SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range events {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_worm",
			Participant: evidence.ParticipantRef{ID: "ag"},
			Payload:     []byte("event payload for the archive tier"),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, signer
}

func newUploader(t *testing.T, bucket string, retention time.Duration) *worm.Uploader {
	t.Helper()
	client := objstoretest.Client(t, bucket, true)
	u, err := worm.New(worm.Config{Client: client, Retention: retention})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestUploadAndReadBack is the basic archive path: sealed segments go up, come
// back byte-identical, and carry a compliance-mode retention.
func TestUploadAndReadBack(t *testing.T) {
	dir, _ := writeLog(t, 40)
	u := newUploader(t, nextBucket("janus-worm"), time.Hour)
	ctx := context.Background()

	results, err := u.UploadAll(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("nothing was archived")
	}

	for _, res := range results {
		if res.Mode != "COMPLIANCE" {
			t.Fatalf("segment %d was stored in %s mode", res.SegmentID, res.Mode)
		}
		if res.RetainUntil.Before(time.Now()) {
			t.Fatalf("segment %d has a retention date in the past: %s", res.SegmentID, res.RetainUntil)
		}

		local, err := os.ReadFile(segment.Path(dir, res.SegmentID))
		if err != nil {
			t.Fatal(err)
		}
		remote, err := u.Fetch(ctx, res.SegmentID)
		if err != nil {
			t.Fatalf("fetch segment %d: %v", res.SegmentID, err)
		}
		if string(local) != string(remote) {
			t.Fatalf("segment %d differs between disk and the archive", res.SegmentID)
		}
	}
}

// TestArchivedObjectCannotBeDeleted is the claim the WORM tier exists to make.
// A hash chain proves tampering is detectable; only this proves it is refused.
func TestArchivedObjectCannotBeDeleted(t *testing.T) {
	dir, _ := writeLog(t, 20)
	u := newUploader(t, nextBucket("janus-worm-lock"), time.Hour)
	ctx := context.Background()

	results, err := u.UploadAll(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("nothing was archived")
	}

	if err := u.ProveImmutable(ctx, results[0].SegmentID); err != nil {
		t.Fatalf("the immutability drill failed: %v", err)
	}
}

// TestUnsealedSegmentIsRefused: an open segment is still growing, and pinning a
// partial one under a retention lock would hold incomplete bytes for the whole
// retention period.
func TestUnsealedSegmentIsRefused(t *testing.T) {
	dir, _ := writeLog(t, 20)
	u := newUploader(t, nextBucket("janus-worm-unsealed"), time.Hour)

	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Strip the footer from one segment to make it look open.
	path := segment.Path(dir, ids[0])
	unseal(t, path)

	if _, err := u.Upload(context.Background(), dir, ids[0]); !errors.Is(err, worm.ErrNotSealed) {
		t.Fatalf("got %v, want ErrNotSealed", err)
	}
}

// TestUploadIsIdempotent: re-uploading must not rewrite the object. Under a
// retention lock a rewrite would not merely waste bandwidth, it would restart
// the retention clock and pin the object longer than policy calls for.
func TestUploadIsIdempotent(t *testing.T) {
	dir, _ := writeLog(t, 20)
	u := newUploader(t, nextBucket("janus-worm-idem"), time.Hour)
	ctx := context.Background()

	first, err := u.UploadAll(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("nothing was archived")
	}
	for _, res := range first {
		if res.AlreadyPresent {
			t.Fatalf("segment %d reported as already present on its first upload", res.SegmentID)
		}
	}

	second, err := u.UploadAll(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range second {
		if !res.AlreadyPresent {
			t.Fatalf("segment %d was uploaded twice; the retention clock would have restarted", res.SegmentID)
		}
	}
	if len(second) != len(first) {
		t.Fatalf("second pass covered %d segments, first covered %d", len(second), len(first))
	}
}

// TestDifferentContentUnderTheSameKeyIsRefused: two segments with the same id
// but different bytes means one of them is not what it claims to be, and under
// a compliance lock the archived one cannot be replaced anyway.
func TestDifferentContentUnderTheSameKeyIsRefused(t *testing.T) {
	bucket := nextBucket("janus-worm-conflict")
	u := newUploader(t, bucket, time.Hour)
	ctx := context.Background()

	dirA, _ := writeLog(t, 20)
	idsA, err := segment.ScanDir(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Upload(ctx, dirA, idsA[0]); err != nil {
		t.Fatal(err)
	}

	// A different log, whose segment 1 holds different events.
	dirB, _ := writeLog(t, 30)
	if _, err := u.Upload(ctx, dirB, idsA[0]); !errors.Is(err, worm.ErrContentDiffers) {
		t.Fatalf("got %v, want ErrContentDiffers", err)
	}
}

// TestGovernanceModeMustBeAcknowledged: the weaker lock can be removed by a
// privileged user, so a deployment must not be able to fall into it by
// accident.
func TestGovernanceModeMustBeAcknowledged(t *testing.T) {
	if _, err := worm.New(worm.Config{
		Client:     nil,
		Retention:  time.Hour,
		Governance: true,
	}); err == nil {
		t.Fatal("a nil client was accepted")
	}

	// With a client, governance without acknowledgement is still refused.
	client := objstoretest.Client(t, nextBucket("janus-worm-gov"), true)
	if _, err := worm.New(worm.Config{
		Client: client, Retention: time.Hour, Governance: true,
	}); !errors.Is(err, worm.ErrGovernanceNotAllowed) {
		t.Fatalf("got %v, want ErrGovernanceNotAllowed", err)
	}
	if _, err := worm.New(worm.Config{
		Client: client, Retention: time.Hour, Governance: true, AllowGovernance: true,
	}); err != nil {
		t.Fatalf("explicitly acknowledged governance mode was refused: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := worm.New(worm.Config{}); err == nil {
		t.Fatal("expected an error with no client")
	}
	client := objstoretest.Client(t, nextBucket("janus-worm-cfg"), true)
	if _, err := worm.New(worm.Config{Client: client}); err == nil {
		t.Fatal("expected an error with no retention")
	}
}

// unseal truncates a segment back past its footer.
func unseal(t *testing.T, path string) {
	t.Helper()
	rd, err := segment.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var lastRecordEnd int64
	for {
		_, ok, err := rd.Next()
		if err != nil {
			_ = rd.Close()
			t.Fatal(err)
		}
		if !ok {
			break
		}
		lastRecordEnd = rd.LastGoodOffset()
	}
	_ = rd.Close()
	if err := segment.Truncate(path, lastRecordEnd); err != nil {
		t.Fatal(err)
	}
}

// pinnedLog writes a small sealed log bound to a tenant.
func pinnedLog(t *testing.T, tenant tenancy.Tenant) string {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 1024, Tenant: tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 12 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_worm",
			Participant: evidence.ParticipantRef{ID: "ag"},
			Payload:     []byte("event payload for the archive tier"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// offlineUploader builds an uploader against a bucket nothing is serving.
//
// That is deliberate and is half the assertion: the residency refusal has to
// happen before anything is sent, so these tests pass without an object store
// and would fail with a network error if the check moved after the upload.
func offlineUploader(t *testing.T, jurisdiction string) *worm.Uploader {
	t.Helper()
	client, err := objstore.New(context.Background(), objstore.Config{
		Endpoint: "http://127.0.0.1:1", Bucket: "archive", Region: "eu-central-1",
		AccessKey: "x", SecretKey: "y", UsePathStyle: true,
		Jurisdiction: jurisdiction,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := worm.New(worm.Config{Client: client, Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestArchivingOutsideThePinIsRefused closes the gap jurisdiction pinning would otherwise
// have left in the copy that matters most.
//
// The archive is the longest-lived copy of the evidence: under a compliance
// lock it cannot be deleted for years by design. A segment sent to the wrong
// bucket is therefore not a mistake that can be tidied up — the lock that makes
// the tier trustworthy is the same lock that makes the error permanent.
func TestArchivingOutsideThePinIsRefused(t *testing.T) {
	dir := pinnedLog(t, tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})

	_, err := offlineUploader(t, "US").UploadAll(context.Background(), dir)
	if !errors.Is(err, worm.ErrResidency) {
		t.Fatalf("a DE-pinned log was archived to a US bucket: %v", err)
	}

	// And a bucket nobody has placed is refused too — the same asymmetry as
	// everywhere else in the pin. An undeclared store is every store configured
	// before anybody asked the question.
	_, err = offlineUploader(t, "").UploadAll(context.Background(), dir)
	if !errors.Is(err, worm.ErrResidency) {
		t.Fatalf("a DE-pinned log was archived to an undeclared bucket: %v", err)
	}

	// Upload of a single segment is checked too, not only the bulk path.
	_, err = offlineUploader(t, "US").Upload(context.Background(), dir, 1)
	if !errors.Is(err, worm.ErrResidency) {
		t.Fatalf("a single segment reached a US bucket from a DE-pinned log: %v", err)
	}
}

// TestAnUnpinnedLogArchivesAnywhere: a deployment that has not declared a
// jurisdiction is unaffected, which is every deployment before Phase 5c. The
// upload fails here for want of an object store — a network error, not a
// residency one, which is the distinction being asserted.
func TestAnUnpinnedLogArchivesAnywhere(t *testing.T) {
	dir, _ := writeLog(t, 12)
	_, err := offlineUploader(t, "").UploadAll(context.Background(), dir)
	if errors.Is(err, worm.ErrResidency) {
		t.Fatalf("an unpinned log was refused on residency grounds: %v", err)
	}
}
