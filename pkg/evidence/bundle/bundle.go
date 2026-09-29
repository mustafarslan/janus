// Package bundle packages evidence for export: the self-contained, offline
// verifiable artifact an auditor or regulator receives.
//
// A bundle always carries whole segments, never a filtered subset of records.
// That is deliberate: the hash chain is only checkable if it is unbroken, so
// cherry-picking the events of one saga would produce an artifact that cannot be
// verified. A saga slice is expressed instead as a *selection* — the segments in
// full, plus the selected events' Merkle inclusion proofs — which proves both
// that those events are in the log and that the log around them is intact.
package bundle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/merkle"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/tenancy"
	"github.com/zeebo/blake3"
)

// ManifestName is the bundle manifest's file name.
const ManifestName = "janus-bundle.json"

// Version is the bundle layout version.
const Version = 1

// SegmentEntry describes one segment file inside a bundle.
type SegmentEntry struct {
	SegmentID uint64 `json:"segment_id"`
	File      string `json:"file"`
	Digest    string `json:"digest"`
	Records   int    `json:"records"`
	FirstSeq  uint64 `json:"first_seq"`
	LastSeq   uint64 `json:"last_seq"`
	Sealed    bool   `json:"sealed"`
}

// Selection is one highlighted event plus its inclusion proof against the
// Merkle root of the segment it lives in.
type Selection struct {
	Seq         uint64   `json:"seq"`
	EventID     string   `json:"event_id"`
	Kind        string   `json:"kind"`
	SagaID      string   `json:"saga_id,omitempty"`
	StepID      string   `json:"step_id,omitempty"`
	SegmentID   uint64   `json:"segment_id"`
	LeafIndex   int      `json:"leaf_index"`
	TreeSize    int      `json:"tree_size"`
	ChainHash   string   `json:"chain_hash"`
	MerkleProof []string `json:"merkle_proof"`
}

// Scope records what the bundle was exported for, so the artifact says on its
// face what question it was produced to answer.
type Scope struct {
	SagaID    string `json:"saga_id,omitempty"`
	FromSeq   uint64 `json:"from_seq,omitempty"`
	ToSeq     uint64 `json:"to_seq,omitempty"`
	Rationale string `json:"rationale,omitempty"`
}

// Manifest is the bundle's table of contents.
//
// The manifest itself is not signed in this version: authenticity comes from the
// per-segment footer signatures it points at. Consequently HeadChain must be
// compared against an out-of-band anchor (an RFC 3161 timestamp or a ledger
// checkpoint) before a bundle can be trusted to be
// complete rather than merely internally consistent. The verifier says so in its
// report rather than leaving the reader to assume otherwise.
type Manifest struct {
	BundleVersion int               `json:"bundle_version"`
	CreatedAt     time.Time         `json:"created_at"`
	Producer      string            `json:"producer"`
	Partition     string            `json:"partition,omitempty"`
	Keys          keys.PublicKeySet `json:"keys"`
	Segments      []SegmentEntry    `json:"segments"`
	FirstSeq      uint64            `json:"first_seq"`
	LastSeq       uint64            `json:"last_seq"`
	Events        int               `json:"events"`
	HeadChain     string            `json:"head_chain"`
	Tenant        *Tenancy          `json:"tenant,omitempty"`
	Scope         *Scope            `json:"scope,omitempty"`
	Selection     []Selection       `json:"selection,omitempty"`
}

// Tenancy records whose evidence a bundle is.
//
// It is read from the events, never from whoever asked for the export. A
// manifest field the exporter can set is a claim about the bundle; a field
// derived from the records is a statement about them, and the second one is
// what an auditor opening the manifest first needs.
type Tenancy struct {
	ID           string `json:"id"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
	// Unlabelled counts events in this bundle written before the log was bound
	// to a tenant. Nonzero means the bundle is one tenant's evidence plus some
	// evidence that does not say which tenant it is — worth knowing before
	// treating the bundle as a complete answer about that tenant.
	Unlabelled int `json:"unlabelled_events,omitempty"`
}

// ErrMixedTenants is returned when the segments hold more than one tenant's
// events. Exporting them as one artifact would produce a bundle that discloses
// one tenant's evidence to another, which no amount of correct signing fixes.
var ErrMixedTenants = errors.New("bundle: segments hold more than one tenant")

// ExportOptions configures an export.
type ExportOptions struct {
	// SegmentDir is the live evidence directory to export from.
	SegmentDir string
	// Dest is the bundle directory to create.
	Dest string
	// Keys are the public keys an auditor needs to check the footers.
	Keys keys.PublicKeySet
	// Producer identifies the exporting build.
	Producer string
	// Partition labels the log partition.
	Partition string
	// SagaID, when set, adds inclusion proofs for that saga's events.
	SagaID string
	// Rationale records why the export was made (audit request, DORA exit, ...).
	Rationale string
	// IncludeUnsealed copies the open tail segment too. Off by default: an
	// unsealed segment carries no signature, so including one silently weakens
	// the artifact.
	IncludeUnsealed bool
}

// Contiguous reports whether the manifest's segments describe an unbroken
// sequence range.
//
// It is a property of the *set*, not of any one segment, and that is exactly how
// it gets broken: Export inspects segments one at a time, so on a log that is
// being written each snapshot is valid at its own instant and the collection can
// still have a hole — segment N capped before the writer finished filling it,
// segment N+1 read after the writer had moved on. Every file is sound; the
// manifest is not.
func (m Manifest) Contiguous() error {
	for i := 1; i < len(m.Segments); i++ {
		prev, cur := m.Segments[i-1], m.Segments[i]
		// An empty segment carries no sequences to compare. The writer creates
		// the next file ahead of a rotation, so one can legitimately
		// be in a bundle with nothing in it.
		if cur.Records == 0 || prev.Records == 0 {
			continue
		}
		if cur.FirstSeq != prev.LastSeq+1 {
			return fmt.Errorf("the manifest has a hole: segment %d ends at sequence %d "+
				"and segment %d begins at %d", prev.SegmentID, prev.LastSeq,
				cur.SegmentID, cur.FirstSeq)
		}
	}
	return nil
}

// exportAttempts bounds how many times Export will retry a bundle whose segments
// did not line up.
//
// A retry converges because the window is the time between two inspections, and
// each attempt re-reads a log that has only grown. Three, because a log busy
// enough to lose three attempts in a row is one where the operator should be
// told rather than have the tool keep trying.
const exportAttempts = 3

// Export writes a bundle and returns its manifest.
//
// When the open tail is included — which is what a backup needs — the result is
// checked for contiguity and rebuilt if the writer moved underneath it. See
// Manifest.Contiguous.
func Export(opts ExportOptions) (Manifest, error) {
	if !opts.IncludeUnsealed {
		return export(opts)
	}
	var last error
	for attempt := range exportAttempts {
		m, err := export(opts)
		if err != nil {
			return m, err
		}
		if err := m.Contiguous(); err == nil {
			return m, nil
		} else {
			last = err
		}
		// Start the next attempt from an empty destination, so a shorter
		// segment cannot be left behind by a longer one.
		if attempt < exportAttempts-1 {
			if err := os.RemoveAll(opts.Dest); err != nil {
				return Manifest{}, err
			}
		}
	}
	return Manifest{}, fmt.Errorf("bundle: after %d attempts the segments still did not "+
		"line up (%w). The log is being written faster than it can be snapshotted; "+
		"back up from a quieter moment or from a replica", exportAttempts, last)
}

func export(opts ExportOptions) (Manifest, error) {
	var m Manifest
	if opts.SegmentDir == "" || opts.Dest == "" {
		return m, fmt.Errorf("bundle: SegmentDir and Dest are required")
	}
	ids, err := segment.ScanComplete(opts.SegmentDir)
	if err != nil {
		return m, err
	}
	if len(ids) == 0 {
		return m, fmt.Errorf("bundle: no segments in %s", opts.SegmentDir)
	}
	segDir := filepath.Join(opts.Dest, "segments")
	if err := os.MkdirAll(segDir, 0o750); err != nil {
		return m, err
	}

	producer := opts.Producer
	if producer == "" {
		producer = "janus-evidence"
	}
	m = Manifest{
		BundleVersion: Version,
		CreatedAt:     time.Now().UTC(),
		Producer:      producer,
		Partition:     opts.Partition,
		Keys:          opts.Keys,
	}
	if opts.SagaID != "" || opts.Rationale != "" {
		m.Scope = &Scope{SagaID: opts.SagaID, Rationale: opts.Rationale}
	}

	var headChain evidence.Hash
	// The tenant is collected while the records are already being walked for
	// sequence bounds, so it costs nothing to read and cannot be forgotten.
	var tenant tenancy.Tenant
	unlabelled := 0
	for _, id := range ids {
		src := segment.Path(opts.SegmentDir, id)
		insp, err := segment.Inspect(src)
		if err != nil {
			return m, fmt.Errorf("inspect %s: %w", src, err)
		}
		if !insp.Sealed() && !opts.IncludeUnsealed {
			continue
		}
		name := segment.FileName(id)
		dst := filepath.Join(segDir, name)
		// An unsealed segment is copied only as far as the records that were
		// just inspected, and that cap does two jobs.
		//
		// It cuts off a torn tail. The open segment of a live log routinely ends
		// in a partial record — the writer's buffer flushes on byte boundaries —
		// and those bytes were never acknowledged, are not described by this
		// manifest's record count, and cannot be verified by anything. Copying
		// them would put content into the artifact that a verifier must recover
		// away before reading, after which the digest checked at restore no
		// longer matches the bytes on disk.
		//
		// And it closes a race that the torn case alone would leave open. The
		// inspection above and the copy below are two separate reads of a file a
		// writer may be appending to. Without the cap, records written between
		// them land in the copy while the manifest's Records, LastSeq and
		// HeadChain describe the earlier state — so the backup fails its *own*
		// head check at restore, discovered at the worst possible moment. The
		// cap makes the copy a snapshot of exactly what was inspected.
		//
		// Never applied to a sealed segment: LastGoodOffset is the end of the
		// last record, and a sealed segment's footer sits after it, so capping
		// there would amputate the signature that authenticates the whole file.
		//
		// This only arises with IncludeUnsealed, which is what a *backup* needs
		// and an audit bundle does not: leaving the open segment out costs a
		// whole segment of RPO.
		limit := int64(-1)
		if !insp.Sealed() {
			limit = insp.LastGoodOffset
		}
		digest, err := copyFile(src, dst, limit)
		if err != nil {
			return m, err
		}

		entry := SegmentEntry{
			SegmentID: id,
			File:      filepath.Join("segments", name),
			Digest:    digest,
			Records:   len(insp.Records),
			Sealed:    insp.Sealed(),
		}
		if insp.Sealed() {
			entry.FirstSeq = insp.Footer.FirstSeq
			entry.LastSeq = insp.Footer.LastSeq
		}

		// Walk the records to fill in sequence bounds for unsealed segments and
		// to collect the requested saga's inclusion proofs.
		leaves := make([][merkle.Size]byte, len(insp.Records))
		for i, r := range insp.Records {
			leaves[i] = merkle.HashLeaf(r.Chain[:])
		}
		for i, r := range insp.Records {
			h, err := evidence.DecodeHeader(r.Header)
			if err != nil {
				return m, fmt.Errorf("%s record %d: %w", src, i, err)
			}
			if !insp.Sealed() {
				if i == 0 {
					entry.FirstSeq = h.Seq
				}
				entry.LastSeq = h.Seq
			}
			if m.FirstSeq == 0 || h.Seq < m.FirstSeq {
				m.FirstSeq = h.Seq
			}
			if h.Seq > m.LastSeq {
				m.LastSeq = h.Seq
				headChain = r.Chain
			}
			m.Events++

			switch found := tenancy.Of(h.Labels); {
			case !found.Bound():
				unlabelled++
			case !tenant.Bound():
				tenant = found
			case found.ID != tenant.ID:
				return m, fmt.Errorf("%w: %q and %q", ErrMixedTenants, tenant.ID, found.ID)
			}

			if opts.SagaID != "" && h.SagaID == opts.SagaID {
				proof, err := merkle.InclusionProof(leaves, i)
				if err != nil {
					return m, fmt.Errorf("%s record %d: inclusion proof: %w", src, i, err)
				}
				hexProof := make([]string, len(proof))
				for j, p := range proof {
					hexProof[j] = hex.EncodeToString(p[:])
				}
				m.Selection = append(m.Selection, Selection{
					Seq:         h.Seq,
					EventID:     h.EventID,
					Kind:        string(h.Kind),
					SagaID:      h.SagaID,
					StepID:      h.StepID,
					SegmentID:   id,
					LeafIndex:   i,
					TreeSize:    len(leaves),
					ChainHash:   hex.EncodeToString(r.Chain[:]),
					MerkleProof: hexProof,
				})
			}
		}
		m.Segments = append(m.Segments, entry)
	}

	if len(m.Segments) == 0 {
		return m, fmt.Errorf("bundle: nothing to export from %s (no sealed segments; pass IncludeUnsealed to include the open tail)", opts.SegmentDir)
	}
	m.HeadChain = "blake3:" + hex.EncodeToString(headChain[:])
	if tenant.Bound() {
		m.Tenant = &Tenancy{
			ID:           tenant.ID,
			Jurisdiction: tenant.Jurisdiction,
			Unlabelled:   unlabelled,
		}
	}

	blob, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	if err := os.WriteFile(filepath.Join(opts.Dest, ManifestName), append(blob, '\n'), 0o640); err != nil {
		return m, err
	}
	return m, nil
}

// LoadManifest reads a bundle manifest from a bundle directory.
func LoadManifest(dir string) (Manifest, error) {
	var m Manifest
	blob, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(blob, &m); err != nil {
		return m, fmt.Errorf("parse %s: %w", ManifestName, err)
	}
	if m.BundleVersion != Version {
		return m, fmt.Errorf("unsupported bundle version %d (this build reads %d)", m.BundleVersion, Version)
	}
	return m, nil
}

// copyFile copies src to dst and returns the digest of the bytes written.
// copyFile copies src to dst and returns the digest of what it wrote.
//
// limit caps the copy at that many bytes; a negative limit copies the whole
// file. The cap exists for the torn tail of a live log's open segment — see the
// call site.
func copyFile(src, dst string, limit int64) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	defer func() { _ = out.Close() }()

	h := blake3.New()
	var reader io.Reader = in
	if limit >= 0 {
		reader = io.LimitReader(in, limit)
	}
	if _, err := io.Copy(io.MultiWriter(out, h), reader); err != nil {
		return "", err
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	return "blake3:" + hex.EncodeToString(h.Sum(nil)), nil
}

// FileDigest returns the digest of a file, in the manifest's format.
func FileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := blake3.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "blake3:" + hex.EncodeToString(h.Sum(nil)), nil
}
