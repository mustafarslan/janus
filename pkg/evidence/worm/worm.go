// Package worm pushes sealed segments into write-once storage.
//
// This is the write-once storage tier and the mechanism behind the strongest
// claim Janus makes to a regulator: that a record, once written, cannot be
// altered or removed by anyone — not an administrator, not the account root,
// not the storage provider — until its retention expires. That is what SEC
// 17a-4(f) means by non-rewriteable and non-erasable, and what BaFin's
// Revisionssicherheit and BDDK's audit-trail rules resolve to operationally.
//
// The hash chain already makes tampering *detectable*. Object Lock in
// compliance mode makes it *impossible*, which is a different and stronger
// claim. Janus needs both: detection catches an insider who edits the hot tier,
// prevention means there is an authoritative copy they could not have touched.
//
// Only sealed segments are uploaded. An open segment is still growing, and
// writing a partial one under a retention lock would pin bytes that will never
// be complete for as long as the lock lasts.
package worm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/objstore"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/zeebo/blake3"
)

// Config configures an uploader.
type Config struct {
	// Client is the object store, whose bucket must have Object Lock enabled.
	Client *objstore.Client
	// Retention is how long an uploaded segment cannot be deleted. It should
	// come from the retention policy for the record class being stored;
	// choosing it here rather than per-record is a deliberate simplification of
	// this version, and Retention must therefore be the longest any record in
	// the log could require.
	Retention time.Duration
	// Governance uses GOVERNANCE rather than COMPLIANCE mode. It exists for
	// test environments where objects have to be cleanable, and is refused for
	// anything claiming to be a WORM tier unless AllowGovernance is set.
	Governance bool
	// AllowGovernance must be set explicitly alongside Governance, so that a
	// deployment cannot end up in the weaker mode by accident.
	AllowGovernance bool
}

// Uploader copies sealed segments to write-once storage.
type Uploader struct {
	cfg Config
}

// ErrGovernanceNotAllowed means the caller asked for the weaker retention mode
// without acknowledging what it gives up.
var ErrGovernanceNotAllowed = errors.New("worm: governance mode requires AllowGovernance, " +
	"because a privileged user can shorten or remove a governance lock and the tier then " +
	"proves nothing a regulator would accept")

// New returns an uploader.
func New(cfg Config) (*Uploader, error) {
	if cfg.Client == nil {
		return nil, errors.New("worm: Client is required")
	}
	if cfg.Retention <= 0 {
		return nil, errors.New("worm: Retention must be positive")
	}
	if cfg.Governance && !cfg.AllowGovernance {
		return nil, ErrGovernanceNotAllowed
	}
	return &Uploader{cfg: cfg}, nil
}

// Key returns the object key a segment is stored under.
func Key(segmentID uint64) string {
	return "segments/" + segment.FileName(segmentID)
}

// Result describes one segment's upload.
type Result struct {
	SegmentID   uint64    `json:"segment_id"`
	Key         string    `json:"key"`
	Bytes       int64     `json:"bytes"`
	Digest      string    `json:"digest"`
	RetainUntil time.Time `json:"retain_until"`
	Mode        string    `json:"mode"`
	// AlreadyPresent means the object was there with matching content, so
	// nothing was written. Re-uploading is not merely wasteful under Object
	// Lock: the retention clock would restart, pinning the object for longer
	// than the policy calls for.
	AlreadyPresent bool `json:"already_present"`
}

// Errors returned by Upload.
var (
	// ErrNotSealed means the segment has no footer and must not be archived.
	ErrNotSealed = errors.New("worm: refusing to archive an unsealed segment")
	// ErrContentDiffers means an object with this key already exists with
	// different bytes. Under a compliance lock it cannot be replaced, and the
	// mismatch means one of the two copies is not what it claims to be.
	ErrContentDiffers = errors.New("worm: an object under this key holds different content")
)

// ErrResidency means the archive bucket is not where this log's evidence is
// allowed to rest.
var ErrResidency = errors.New("worm: the archive is outside the log's jurisdiction")

// Upload copies one sealed segment into write-once storage.
func (u *Uploader) Upload(ctx context.Context, dir string, segmentID uint64) (Result, error) {
	if err := u.residencyAllows(dir); err != nil {
		return Result{}, err
	}
	return u.upload(ctx, dir, segmentID)
}

// residencyAllows refuses to archive a jurisdictionally pinned log to a bucket
// that has not been declared to be in that jurisdiction.
//
// This is the copy that outlives everything else. A segment archived under a
// compliance lock cannot be deleted for years by design, so a segment
// sent to the wrong bucket is not a mistake that can be tidied up — the lock
// that makes the tier trustworthy is the same lock that makes the error
// permanent. If any residency check has to hold, it is this one.
//
// The tenant is read from the log rather than passed in, for the same reason
// the compliance linter reads it there: a jurisdiction supplied by whoever ran
// the archive is a claim about the deployment, and one read out of its evidence
// is a fact about it.
func (u *Uploader) residencyAllows(dir string) error {
	tenant, err := evidence.TenantOfDir(dir)
	if err != nil {
		return fmt.Errorf("reading the tenant binding from %s: %w", dir, err)
	}
	if !tenant.Pinned() {
		return nil
	}
	where := u.cfg.Client.Jurisdiction()
	switch where {
	case tenant.Jurisdiction:
		return nil
	case "":
		return fmt.Errorf("%w: this log is pinned to %s and bucket %s declares no jurisdiction; "+
			"an archived segment is under a retention lock for years, so a copy sent to the "+
			"wrong store cannot be withdrawn", ErrResidency, tenant.Jurisdiction,
			u.cfg.Client.Bucket())
	default:
		return fmt.Errorf("%w: this log is pinned to %s and bucket %s is declared to rest in %s",
			ErrResidency, tenant.Jurisdiction, u.cfg.Client.Bucket(), where)
	}
}

// upload is Upload without the residency check, for UploadAll, which has
// already made it once for the whole directory.
func (u *Uploader) upload(ctx context.Context, dir string, segmentID uint64) (Result, error) {
	path := segment.Path(dir, segmentID)

	sealed, err := segment.IsSealed(path)
	if err != nil {
		return Result{}, err
	}
	if !sealed {
		return Result{}, fmt.Errorf("%w: segment %d", ErrNotSealed, segmentID)
	}

	body, err := readFile(path)
	if err != nil {
		return Result{}, err
	}
	digest := digestOf(body)
	key := Key(segmentID)

	res := Result{
		SegmentID: segmentID,
		Key:       key,
		Bytes:     int64(len(body)),
		Digest:    digest,
		Mode:      u.mode(),
	}

	// An object already under a retention lock cannot be overwritten, so an
	// upload has to be idempotent by checking rather than by retrying.
	existing, err := u.cfg.Client.Get(ctx, key)
	switch {
	case err == nil:
		if digestOf(existing) != digest {
			return res, fmt.Errorf("%w: segment %d", ErrContentDiffers, segmentID)
		}
		info, err := u.cfg.Client.Head(ctx, key)
		if err == nil {
			res.RetainUntil = info.RetainUntil
		}
		res.AlreadyPresent = true
		return res, nil
	case !errors.Is(err, objstore.ErrNotFound):
		return res, err
	}

	res.RetainUntil = time.Now().UTC().Add(u.cfg.Retention)
	err = u.cfg.Client.Put(ctx, key, body, objstore.PutOptions{
		RetainUntil:    res.RetainUntil,
		ComplianceMode: !u.cfg.Governance,
		ContentType:    "application/vnd.janus.segment",
		Metadata: map[string]string{
			"janus-segment-id": fmt.Sprintf("%d", segmentID),
			"janus-digest":     digest,
		},
	})
	if err != nil {
		return res, err
	}

	// Read the object back before reporting success. An archive tier that
	// silently dropped a write would be discovered at audit time, which is the
	// worst possible moment.
	if err := u.confirm(ctx, key, digest); err != nil {
		return res, err
	}
	return res, nil
}

// confirm re-reads an uploaded object and checks it byte for byte.
func (u *Uploader) confirm(ctx context.Context, key, digest string) error {
	body, err := u.cfg.Client.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("worm: could not read back %s after uploading it: %w", key, err)
	}
	if got := digestOf(body); got != digest {
		return fmt.Errorf("worm: %s reads back as %s but was uploaded as %s", key, got, digest)
	}
	info, err := u.cfg.Client.Head(ctx, key)
	if err != nil {
		return fmt.Errorf("worm: could not read the lock state of %s: %w", key, err)
	}
	if info.RetainUntil.IsZero() {
		return fmt.Errorf("worm: %s was stored without a retention lock; the bucket accepted the "+
			"object but is not holding it write-once", key)
	}
	if !u.cfg.Governance && !info.ComplianceMode {
		return fmt.Errorf("worm: %s was stored in governance mode although compliance was requested; "+
			"a privileged user could still remove it", key)
	}
	return nil
}

func (u *Uploader) mode() string {
	if u.cfg.Governance {
		return "GOVERNANCE"
	}
	return "COMPLIANCE"
}

// UploadAll archives every sealed segment in a directory that is not already
// there, and reports what it did.
func (u *Uploader) UploadAll(ctx context.Context, dir string) ([]Result, error) {
	// Once for the directory rather than once per segment: the answer is a
	// property of the log and the bucket, and reading it per segment would
	// re-scan the whole directory for every file it archives.
	if err := u.residencyAllows(dir); err != nil {
		return nil, err
	}
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return nil, err
	}
	var out []Result
	for _, id := range ids {
		sealed, err := segment.IsSealed(segment.Path(dir, id))
		if err != nil {
			return out, err
		}
		if !sealed {
			// The open tail is not an error; it simply is not ready yet.
			continue
		}
		res, err := u.upload(ctx, dir, id)
		if err != nil {
			return out, fmt.Errorf("segment %d: %w", id, err)
		}
		out = append(out, res)
	}
	return out, nil
}

// Fetch retrieves an archived segment.
func (u *Uploader) Fetch(ctx context.Context, segmentID uint64) ([]byte, error) {
	return u.cfg.Client.Get(ctx, Key(segmentID))
}

// ProveImmutable tries to destroy an archived record and reports whether the
// store refused.
//
// This is a drill, not a routine operation. A WORM claim that has never been
// tested against the actual bucket is a configuration hope: Object Lock has to
// have been enabled when the bucket was created, compliance mode has to be the
// mode actually in use, and the retention date has to be in the future. Running
// the operation is the only way to know all three hold in this deployment
// rather than in the documentation.
//
// It deletes the specific *version*, not the key. On a versioned bucket — which
// Object Lock requires — deleting a key merely writes a delete marker: the call
// succeeds, a later read returns nothing, and yet the record was never
// destroyed. Only a versioned delete attempts real destruction, so only a
// versioned delete tests the lock. Using the key form would also leave a delete
// marker behind and break the archive for every later read, which is why this
// drill is safe to run against production.
func (u *Uploader) ProveImmutable(ctx context.Context, segmentID uint64) error {
	key := Key(segmentID)

	info, err := u.cfg.Client.Head(ctx, key)
	if err != nil {
		return fmt.Errorf("worm: cannot run the immutability drill, %s is not readable: %w", key, err)
	}
	if info.VersionID == "" {
		return fmt.Errorf("worm: %s has no version id, so the bucket is not versioned and cannot "+
			"be holding Object Lock retentions", key)
	}
	if info.RetainUntil.IsZero() {
		return fmt.Errorf("worm: %s carries no retention date; it is stored, but not write-once", key)
	}
	if !u.cfg.Governance && !info.ComplianceMode {
		return fmt.Errorf("worm: %s is under a governance lock, which a privileged user can remove", key)
	}

	before, err := u.cfg.Client.GetVersion(ctx, key, info.VersionID)
	if err != nil {
		return fmt.Errorf("worm: cannot read %s version %s: %w", key, info.VersionID, err)
	}

	delErr := u.cfg.Client.DeleteVersion(ctx, key, info.VersionID)
	if delErr == nil {
		return fmt.Errorf("worm: IMMUTABILITY VIOLATION: version %s of %s was destroyed despite a "+
			"retention lock until %s", info.VersionID, key, info.RetainUntil.Format(time.RFC3339))
	}
	if !objstore.IsRetentionViolation(delErr) {
		return fmt.Errorf("worm: the versioned delete of %s failed for an unexpected reason, so the "+
			"lock is unproven: %w", key, delErr)
	}

	after, err := u.cfg.Client.GetVersion(ctx, key, info.VersionID)
	if err != nil {
		return fmt.Errorf("worm: IMMUTABILITY VIOLATION: %s became unreadable after a refused "+
			"delete: %w", key, err)
	}
	if digestOf(after) != digestOf(before) {
		return fmt.Errorf("worm: IMMUTABILITY VIOLATION: %s changed content across a refused delete", key)
	}
	return nil
}

// digestOf renders a content digest in the same form the manifest uses.
func digestOf(b []byte) string {
	sum := blake3.Sum256(b)
	return "blake3:" + hex.EncodeToString(sum[:])
}
