// Package verify checks an evidence log or exported bundle without any running
// Janus service.
//
// This is the component an auditor is asked to trust, so it is written to be
// readable and to hold nothing back: every check it performs appears in the
// report, and anything it could not check is stated as a limitation rather than
// left as an absence. It re-derives every hash, every Merkle root, and every
// signature from the bytes on disk and from a public key set supplied by the
// caller — it never reads a key out of the artifact it is checking.
package verify

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/merkle"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// Severity ranks a finding.
type Severity string

const (
	// Critical means the evidence is not trustworthy: verification fails.
	Critical Severity = "CRITICAL"
	// Warning means something is irregular but not disqualifying.
	Warning Severity = "WARNING"
	// Note records a limitation of what could be checked.
	Note Severity = "NOTE"
)

// Finding is one thing the verifier observed.
type Finding struct {
	Severity  Severity `json:"severity"`
	Code      string   `json:"code"`
	Message   string   `json:"message"`
	SegmentID *uint64  `json:"segment_id,omitempty"`
	Seq       *uint64  `json:"seq,omitempty"`
}

// SegmentResult is the per-segment outcome.
type SegmentResult struct {
	SegmentID   uint64 `json:"segment_id"`
	Path        string `json:"path"`
	Records     int    `json:"records"`
	FirstSeq    uint64 `json:"first_seq"`
	LastSeq     uint64 `json:"last_seq"`
	Sealed      bool   `json:"sealed"`
	Torn        bool   `json:"torn"`
	MerkleRoot  string `json:"merkle_root,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
	SignatureOK bool   `json:"signature_ok"`
	ChainOK     bool   `json:"chain_ok"`
	// LastChain is the chain hash this segment ends on, which is what a
	// partial verification anchors the next range to.
	LastChain string `json:"last_chain,omitempty"`
}

// EventSummary describes one verified event, for tooling that needs to see what
// is in a log rather than only whether it is intact.
type EventSummary struct {
	Seq         uint64 `json:"seq"`
	SegmentID   uint64 `json:"segment_id"`
	EventID     string `json:"event_id"`
	Kind        string `json:"kind"`
	SagaID      string `json:"saga_id,omitempty"`
	StepID      string `json:"step_id,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Participant string `json:"participant,omitempty"`
	// ManifestVersion is the manifest the participant acted under. It is
	// listed because "which declaration permitted this" is an audit question,
	// and an event with no version pins itself to nothing (invariant I8).
	ManifestVersion string            `json:"manifest_version,omitempty"`
	Wall            time.Time         `json:"wall"`
	PayloadSize     int               `json:"payload_size"`
	Labels          map[string]string `json:"labels,omitempty"`
}

// Report is the full verification outcome.
type Report struct {
	Target    string          `json:"target"`
	Kind      string          `json:"kind"` // "segment-dir" or "bundle"
	OK        bool            `json:"ok"`
	Events    int             `json:"events"`
	EventList []EventSummary  `json:"event_list,omitempty"`
	FirstSeq  uint64          `json:"first_seq"`
	LastSeq   uint64          `json:"last_seq"`
	HeadChain string          `json:"head_chain"`
	Segments  []SegmentResult `json:"segments"`
	// Tenants lists every tenant the log's events were written under, sorted.
	// A log holding more than one is a broken boundary, not a busy log:
	// one tenant, one directory, one writer, one key (pkg/tenancy).
	Tenants []string `json:"tenants,omitempty"`
	// SigningKeys says which keys signed these segments and where each one came
	// from — supplied out of band, or introduced by the log itself. An auditor
	// told "three keys were used" needs to know they only had to trust one.
	SigningKeys map[string]string `json:"signing_keys,omitempty"`
	// TrustedKeys is the set this pass ended up accepting: the roots the caller
	// supplied, plus every key the log introduced and did not revoke.
	//
	// It exists for the one caller shape that cannot work without it — a
	// verification that continues where the last one stopped. Each pass builds
	// its trust from `Options.Keys` alone, so a WRITER_KEY declaration in a
	// segment an *earlier* pass read is invisible to this one, and the segment
	// the rotation signed reports UNKNOWN_SIGNING_KEY. Carrying this into the
	// next pass's roots is what makes forward-extending writer trust work
	// incrementally as well as end to end.
	//
	// Not serialised: a report is a statement about a log, and a public key set
	// in it would read as part of that statement rather than as the caller's
	// own bookkeeping.
	TrustedKeys keys.PublicKeySet `json:"-"`
	Findings    []Finding         `json:"findings"`
	CheckedAt   time.Time         `json:"checked_at"`
	DurationMS  int64             `json:"duration_ms"`
	VerifierVer string            `json:"verifier_version"`
}

// Options configures verification.
type Options struct {
	// Keys are the writer public keys the caller trusts *as roots*. A footer
	// signed by a key outside the set — and not introduced by a WRITER_KEY
	// declaration in a segment that already verified — is a critical finding,
	// not a pass.
	//
	// "As roots" is the part Phase 5 changed. A log that rotates its writer key
	// records the new one in a segment the old one signed, so an auditor needs
	// the first key rather than all of them (pkg/evidence/writerkey.go). Passing
	// every key still works and is what an incremental verification anchored
	// mid-log has to do, since the declarations that introduced them are in
	// segments this pass is not reading.
	Keys keys.PublicKeySet
	// Scan lists the directory's complete segments. Nil means
	// `segment.ScanComplete`, which stats every file on every call.
	//
	// It is a hook because the cost is the stats and the fix belongs to the
	// caller: a verification that runs once should pay them, and one that runs
	// three times a second forever should hold a `segment.Scanner` and pass its
	// Complete here. At 10,000 segments
	// that is 21.5 ms a call against 4.2 ms.
	Scan func(dir string) ([]uint64, error)
	// KeysOrigin names where Keys came from, for the report's SigningKeys map.
	// Empty means "supplied out of band", which is true of an auditor's roots
	// and false of a set carried forward from an earlier incremental pass —
	// that one should say so, or the report claims an auditor had to trust
	// several keys directly when they trusted one.
	KeysOrigin string
	// AllowUnsealedTail permits the final segment to lack a footer, which is the
	// normal state of a log that is still being written.
	AllowUnsealedTail bool
	// ExpectHeadChain, when set, is compared against the computed head. This is
	// how an out-of-band anchor is brought into the check.
	ExpectHeadChain string
	// RequireSignedManifest makes an unsigned bundle manifest -- or one whose
	// signature verifies only against keys the bundle itself carries -- a
	// critical finding rather than a note.
	//
	// It is the auditor's half of end-truncation. A bundle
	// cut off at its end is a valid prefix of a hash chain, so nothing inside
	// an unsigned one can show records are missing; a manifest signature
	// covers the segment list, so a signed one can. An auditor who
	// will only accept a signed bundle says so here, and an unsigned one then
	// fails instead of passing with a note. Without it, end-truncation of an
	// unsigned bundle is caught only by ExpectHeadChain.
	RequireSignedManifest bool
	// IncludeEvents populates Report.EventList. Off by default because a report
	// on a production log would otherwise be unusably large.
	IncludeEvents bool
	// OnEvent, when set, is handed every verified event instead of the report
	// accumulating them, and IncludeEvents is ignored.
	//
	// It exists because a caller that wants a handful of matching events had no
	// way to say so: `IncludeEvents` builds a summary for every record in the
	// log and hands back the whole slice, so the console's evidence search
	// allocated about 2.6 KB per event scanned — 261 MiB on a 100,000-event log,
	// to return 200 rows. The walk is the same walk either way; what
	// changes is whether the caller's filter runs during it or after it.
	//
	// It does not make a search cheaper in *work*: every record is still read
	// and verified, because that is what makes an answer from this package an
	// answer somebody can rely on. It makes the memory the caller's own
	// business, which is the difference between slow and falling over.
	OnEvent func(EventSummary)
	// CAS, when supplied, lets the verifier resolve payloads that live in
	// content-addressed storage instead of in the chain, and check that their
	// bytes hash to what the envelope recorded. Without it those payloads are
	// reported as unchecked rather than assumed good.
	CAS cas.Store
	// Version labels the verifier build in the report.
	Version string
	// Tenant, when bound, is the tenant the caller believes this log belongs
	// to. Every event that says otherwise is a critical finding.
	//
	// This is the cheap half of tenant isolation and it is worth being clear
	// that it is the cheap half. The expensive half — the one an attacker
	// cannot talk their way past — is that a verifier holding tenant A's keys
	// cannot establish tenant B's segments at all, because it does not have
	// the key they were signed with. This check catches the case where the
	// keys are right and the contents are not: a misrouted write, a restored
	// backup from the wrong directory, a daemon started on a neighbour's log.
	Tenant tenancy.Tenant
}

// Findings that carry no segment or sequence context.
func (r *Report) add(sev Severity, code, msg string) {
	r.Findings = append(r.Findings, Finding{Severity: sev, Code: code, Message: msg})
}

func (r *Report) addSeg(sev Severity, code string, segID uint64, msg string) {
	id := segID
	r.Findings = append(r.Findings, Finding{Severity: sev, Code: code, Message: msg, SegmentID: &id})
}

func (r *Report) addSeq(sev Severity, code string, segID, seq uint64, msg string) {
	id, s := segID, seq
	r.Findings = append(r.Findings, Finding{Severity: sev, Code: code, Message: msg, SegmentID: &id, Seq: &s})
}

// Critical reports whether any finding is disqualifying.
func (r *Report) hasCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == Critical {
			return true
		}
	}
	return false
}

// Anchor is a known point in the chain that a partial verification continues
// from: the hash the previous segment ended on and the sequence it reached.
//
// Supplying one is what makes incremental verification possible. Without it a
// verifier reading only the newest segments could not tell whether they
// continue the log or belong to a different one.
type Anchor struct {
	Chain evidence.Hash
	Seq   uint64
	// Known distinguishes "the log starts here" from "we have no anchor".
	Known bool
}

// Range verifies the segments from fromSegment through throughSegment
// (inclusive; zero means to the end), continuing from a known chain position.
//
// This exists for the continuous verifier, which cannot re-read the whole log
// every few seconds. It is a weaker check than SegmentDir by construction: it
// says the new segments are sound and continue from where the anchor says the
// log was, and says nothing about whether the earlier segments still hold the
// bytes they held when the anchor was taken. Anything relying on it needs a
// full sweep as well.
func Range(dir string, fromSegment, throughSegment uint64, anchor Anchor, opts Options) (*Report, error) {
	start := time.Now()
	r := &Report{
		Target:      dir,
		Kind:        "segment-range",
		CheckedAt:   start.UTC(),
		VerifierVer: opts.Version,
	}
	all, err := opts.scan(dir)
	if err != nil {
		return nil, err
	}
	var ids []uint64
	var paths []string
	for _, id := range all {
		if id < fromSegment {
			continue
		}
		if throughSegment != 0 && id > throughSegment {
			break
		}
		ids = append(ids, id)
		paths = append(paths, segment.Path(dir, id))
	}
	if len(ids) == 0 {
		r.finish(start)
		return r, nil
	}
	r.TrustedKeys = verifySegmentsFrom(r, ids, paths, opts, anchor)
	r.finish(start)
	return r, nil
}

// SegmentDir verifies a live evidence directory.
func SegmentDir(dir string, opts Options) (*Report, error) {
	start := time.Now()
	r := &Report{
		Target:      dir,
		Kind:        "segment-dir",
		CheckedAt:   start.UTC(),
		VerifierVer: opts.Version,
	}
	ids, err := opts.scan(dir)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		r.add(Critical, "NO_SEGMENTS", fmt.Sprintf("no segment files found in %s", dir))
		r.finish(start)
		return r, nil
	}
	paths := make([]string, len(ids))
	for i, id := range ids {
		paths[i] = segment.Path(dir, id)
	}
	r.TrustedKeys = verifySegments(r, ids, paths, opts)
	r.finish(start)
	return r, nil
}

// scan lists dir's complete segments, through the caller's hook if it gave one.
func (o Options) scan(dir string) ([]uint64, error) {
	if o.Scan != nil {
		return o.Scan(dir)
	}
	return segment.ScanComplete(dir)
}

func (o Options) rootOrigin() string {
	if o.KeysOrigin != "" {
		return o.KeysOrigin
	}
	return "supplied out of band"
}

// Bundle verifies an exported bundle directory. The bundle's own key set is used
// only when the caller supplies none, and the report says which happened —
// trusting keys shipped inside the artifact proves authorship of the bundle, not
// of the log.
func Bundle(dir string, opts Options) (*Report, error) {
	start := time.Now()
	r := &Report{
		Target:      dir,
		Kind:        "bundle",
		CheckedAt:   start.UTC(),
		VerifierVer: opts.Version,
	}
	m, err := bundle.LoadManifest(dir)
	if err != nil {
		return nil, err
	}
	rootsSupplied := len(opts.Keys) > 0
	if !rootsSupplied {
		opts.Keys = m.Keys
		r.add(Note, "KEYS_FROM_BUNDLE", "no key set supplied, so the manifest's own keys were used: "+
			"this proves the bundle is internally consistent, not that it came from a trusted writer. "+
			"Supply the writer's public key out of band to close this gap.")
	}

	ids := make([]uint64, 0, len(m.Segments))
	paths := make([]string, 0, len(m.Segments))
	for _, e := range m.Segments {
		path := filepath.Join(dir, filepath.FromSlash(e.File))
		got, err := bundle.FileDigest(path)
		if err != nil {
			r.addSeg(Critical, "SEGMENT_MISSING", e.SegmentID, fmt.Sprintf("manifest lists %s but it could not be read: %v", e.File, err))
			continue
		}
		if got != e.Digest {
			r.addSeg(Critical, "SEGMENT_DIGEST_MISMATCH", e.SegmentID,
				fmt.Sprintf("%s digest is %s, manifest says %s", e.File, got, e.Digest))
			continue
		}
		ids = append(ids, e.SegmentID)
		paths = append(paths, path)
	}
	// The keys the segment walk ended up trusting, which is what the manifest
	// signature must be checked against. Starting from the caller's roots and
	// extended by whatever the log introduced: a backup signed after a
	// key rotation carries a signature by the *new* key, and checking it against
	// the roots alone would call a legitimate signature untrusted.
	trusted := opts.Keys
	if len(paths) > 0 {
		trusted = verifySegments(r, ids, paths, opts)
		r.TrustedKeys = trusted
	}

	if r.Events != m.Events {
		r.add(Critical, "EVENT_COUNT_MISMATCH", fmt.Sprintf("manifest declares %d events, segments contain %d", m.Events, r.Events))
	}
	if m.HeadChain != "" && r.HeadChain != "" && m.HeadChain != r.HeadChain {
		r.add(Critical, "HEAD_CHAIN_MISMATCH", fmt.Sprintf("manifest head chain %s, computed %s", m.HeadChain, r.HeadChain))
	}
	verifySelection(r, dir, m, ids, paths)

	checkManifestSignature(r, dir, trusted, rootsSupplied, opts.RequireSignedManifest)

	r.finish(start)
	return r, nil
}

// checkManifestSignature reports whether the manifest is signed, and whether the
// signature checks out.
//
// # Why this is not one line
//
// The note this replaces was added unconditionally and said "the bundle manifest
// is not itself signed". That was true when it was written and stopped being
// true in Phase 6, when `janus-tier backup` began signing. From then until now a
// signed backup verified with a report stating, in the auditor's own summary,
// that nobody had signed it — a false sentence about the artifact, next to advice
// that happened to be sound. It is a known failure mode: a report a
// reader draws a false conclusion from, which no unit test looks for because a
// unit test asserts what a function returns rather than what a person concludes.
//
// # What each outcome means
//
// A missing signature is a **Note**, not a finding against the bundle. An audit
// bundle is sealed segments, each authenticated by its own footer, and it is not
// defective for lacking a signature it was never supposed to carry. What no
// signature covers — signed or not — is the *list*: drop trailing segments and
// what remains is a valid prefix of a hash chain, which is a valid hash chain.
// Only a head compared against something obtained out of band closes that, which
// is why the advice is attached to every outcome and not only to the unsigned
// one.
//
// A signature that does not verify is **Critical**, and the distinction from
// unsigned is the whole reason `bundle` returns two errors rather than one:
// "nobody signed this" and "somebody signed this and it does not check out" call
// for opposite responses from the person reading the report.
func checkManifestSignature(r *Report, dir string, trusted keys.PublicKeySet, rootsSupplied,
	required bool) {
	const anchorAdvice = " Either way, compare the head chain against an out-of-band anchor " +
		"(RFC 3161 timestamp or ledger checkpoint): no signature inside a bundle can show that " +
		"records were not dropped from its end."

	err := bundle.VerifyManifestSignature(dir, trusted)
	switch {
	case errors.Is(err, bundle.ErrUnsigned) && required:
		r.add(Critical, "MANIFEST_UNSIGNED", "a signed manifest was required and this bundle "+
			"carries none. An unsigned bundle cut off at its end is a valid prefix of a hash "+
			"chain and verifies, so without the signature over its segment list nothing here "+
			"can show that no records were dropped from the end."+anchorAdvice)
	case errors.Is(err, bundle.ErrUnsigned):
		r.add(Note, "MANIFEST_UNSIGNED", "this bundle carries no manifest signature; its segment "+
			"footers are signed. An audit bundle of sealed segments is authenticated record by "+
			"record, so this is expected rather than a defect."+anchorAdvice)
	case errors.Is(err, bundle.ErrBadSignature):
		r.add(Critical, "MANIFEST_SIGNATURE_INVALID", "the bundle carries a manifest signature "+
			"and it does not verify: "+err.Error()+". Somebody signed this artifact and what is "+
			"here is not what they signed.")
	case err != nil:
		r.add(Critical, "MANIFEST_SIGNATURE_UNREADABLE", "the bundle carries a manifest signature "+
			"that could not be read: "+err.Error())
	case !rootsSupplied && required:
		r.add(Critical, "MANIFEST_SIGNATURE_UNANCHORED", "a signed manifest was required, and "+
			"this one verifies only against keys the bundle itself carries, because none were "+
			"supplied out of band. That is what somebody who rewrote both the manifest and the "+
			"key set would also produce; supply the writer's root keys with -keys.")
	case rootsSupplied:
		r.add(Note, "MANIFEST_SIGNED", "the manifest is signed and the signature verifies against "+
			"the keys supplied out of band. The segment list, the digests and the head are "+
			"authenticated against anybody without the writer's key — not against the holder of "+
			"it."+anchorAdvice)
	default:
		r.add(Note, "MANIFEST_SIGNED", "the manifest is signed and the signature verifies — but "+
			"against keys this bundle carries, because none were supplied out of band. That shows "+
			"the artifact is internally consistent, which is what somebody who rewrote both the "+
			"manifest and the key set would also produce. See KEYS_FROM_BUNDLE."+anchorAdvice)
	}
}

// verifySegments walks segments in order, re-deriving every hash, root, and
// signature, and checking that the chain continues across segment boundaries.
func verifySegments(r *Report, ids []uint64, paths []string, opts Options) keys.PublicKeySet {
	return verifySegmentsFrom(r, ids, paths, opts, Anchor{Chain: evidence.GenesisHash, Seq: 0, Known: true})
}

// verifySegmentsFrom is verifySegments continuing from an arbitrary anchor.
// It returns the writer keys the walk ended up trusting — the caller's roots
// plus whatever the log introduced — so that a check outside the walk can accept
// the same set. See WriterTrust.Keys.
func verifySegmentsFrom(r *Report, ids []uint64, paths []string, opts Options, anchor Anchor) keys.PublicKeySet {
	prev := anchor.Chain
	lastSeq := anchor.Seq
	// started says whether lastSeq is a real predecessor, so the first record
	// of a range continuing from an anchor is checked for contiguity too.
	started := anchor.Known && anchor.Seq > 0
	// recordedFirst is separate: the report's FirstSeq is the first sequence
	// this run actually read, which for a range is not the start of the log.
	recordedFirst := false

	// seen collects the tenants the events claim, so the report can say which
	// tenant's evidence this was and refuse a directory holding two. It doubles
	// as the once-per-tenant guard on the mismatch finding: a misconfigured
	// -tenant is uniform across the log, and a finding per event would make a
	// typo produce a report with one line per record.
	seen := map[string]struct{}{}

	// Erasures are counted so the report can say the log contains some. See
	// summariseErasures.
	erasures := 0

	// The writer keys this pass will accept, starting from the roots the caller
	// supplied and extended as the log introduces more. Extended only from a
	// segment that has already verified, and only after its own footer is
	// checked — see pkg/evidence/writerkey.go for why both halves matter.
	trust := evidence.NewWriterTrustFrom(opts.Keys, opts.rootOrigin())
	used := map[string]struct{}{}

	// A log that is still being written has more than one open segment at its
	// end: the one receiving records, the empty one prepared behind it, and
	// possibly one whose background seal has not landed yet. So the
	// allowance is the trailing run of unsealed segments rather than only the
	// final file. An unsealed segment with *sealed* segments after it is not
	// part of that run and stays disqualifying — that is a seal that went
	// missing, which recovery is supposed to have repaired.
	openTailFrom := len(paths)
	if opts.AllowUnsealedTail {
		for i := len(paths) - 1; i >= 0; i-- {
			sealed, err := segment.IsSealed(paths[i])
			if err != nil || sealed {
				break
			}
			openTailFrom = i
		}
	}

	for i, path := range paths {
		id := ids[i]
		res := SegmentResult{SegmentID: id, Path: path, ChainOK: true}

		if i > 0 && ids[i] != ids[i-1]+1 {
			// A gap is legitimate when a segment was opened and closed without
			// any records, so this is not disqualifying on its own — the chain
			// and sequence checks below are what actually catch a removal.
			r.addSeg(Warning, "SEGMENT_ID_GAP", id,
				fmt.Sprintf("segment id jumps from %d to %d", ids[i-1], id))
		}

		insp, err := segment.Inspect(path)
		if err != nil {
			r.addSeg(Critical, "SEGMENT_UNREADABLE", id, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			res.ChainOK = false
			r.Segments = append(r.Segments, res)
			continue
		}
		res.Records = len(insp.Records)
		res.Sealed = insp.Sealed()
		res.Torn = insp.Torn

		tailMayBeOpen := opts.AllowUnsealedTail && i >= openTailFrom

		if insp.Torn {
			// A torn tail on the open segment is what a crash looks like and is
			// recoverable; anywhere else it is missing evidence.
			sev := Critical
			if tailMayBeOpen {
				sev = Warning
			}
			r.addSeg(sev, "SEGMENT_TORN", id, "segment ends in an incomplete record: "+insp.TornDetail)
		}
		if !insp.Sealed() && !tailMayBeOpen {
			r.addSeg(Critical, "SEGMENT_UNSEALED", id, "segment has no signed footer, so nothing authenticates its contents")
		}

		if insp.Header.HashAlg != segment.HashAlgBLAKE3 {
			r.addSeg(Critical, "UNKNOWN_HASH_ALG", id, fmt.Sprintf("hash algorithm %d is not supported by this verifier", insp.Header.HashAlg))
			res.ChainOK = false
			r.Segments = append(r.Segments, res)
			continue
		}
		if insp.Header.SegmentID != id {
			r.addSeg(Critical, "SEGMENT_ID_MISMATCH", id,
				fmt.Sprintf("file is named for segment %d but its header says %d", id, insp.Header.SegmentID))
		}

		leaves := make([][merkle.Size]byte, 0, len(insp.Records))
		// Declarations found in this segment. Held rather than applied, because
		// a segment must not introduce the key that signs it.
		var declared []declaration
		for j, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil && !errors.Is(err, evidence.ErrUnsupportedEnvelope) {
				r.addSeg(Critical, "HEADER_UNDECODABLE", id, fmt.Sprintf("record %d: %v", j, err))
				res.ChainOK = false
				// Breaks the record loop, not a switch: a segment whose records
				// stop decoding has nothing further worth saying about it.
				break
			}
			switch {
			case err != nil:
				// Reported rather than returned. This is the one caller that
				// wants to say precisely *what* it could not vouch for, so
				// DecodeHeader hands it a populated header alongside the error
				// and the loop continues: the chain arithmetic below is over
				// raw bytes and stays meaningful, and an auditor gets the
				// sequence numbers rather than "record 3: undecodable".
				//
				// Critical, which is what makes the verdict FAIL — `OK` is
				// `!hasCritical()`. It used to be a Warning, and a bundle
				// written by a newer build therefore printed **PASS**: a
				// verifier vouching for records it had only partly read, which
				// is the strongest form of the failure this project exists to
				// prevent.
				//
				// `ChainOK` is deliberately *not* cleared. The chain arithmetic
				// is over raw bytes and it held; saying otherwise would put a
				// false claim in the segment table to reach a verdict the
				// finding already reaches. What failed is narrower and the
				// report should say exactly that — signature yes, chain yes,
				// and the verifier still will not vouch for it.
				r.addSeq(Critical, "ENVELOPE_VERSION", id, h.Seq,
					fmt.Sprintf("envelope version %d, this verifier understands %d: it cannot "+
						"vouch for a record shape it does not have, because the fields it does "+
						"not know are absent rather than wrong",
						h.V, evidence.EnvelopeVersion))
			case h.V < evidence.EnvelopeVersion:
				// Older is readable and is the compatibility this exists to
				// protect. Unexercised today — version 1 is the first and only
				// one ever written — so this branch is a promise about the
				// future, not a path anything runs.
				r.addSeq(Warning, "ENVELOPE_VERSION", id, h.Seq,
					fmt.Sprintf("envelope version %d, this verifier understands %d; an older "+
						"shape is still readable", h.V, evidence.EnvelopeVersion))
			}

			// The payload is present inline unless it lives in content-addressed
			// storage, in which case only its hash is in the chain and the
			// content itself is out of scope for this check.
			if len(rec.Payload) > 0 {
				if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
					r.addSeq(Critical, "PAYLOAD_HASH_MISMATCH", id, h.Seq,
						fmt.Sprintf("stored payload hashes to %s but the header claims %s",
							short(got), short(h.PayloadHash)))
					res.ChainOK = false
				}
			} else if h.PayloadRef != "" {
				checkExternalPayload(r, opts, id, h)
			}

			if rec.Prev != prev {
				r.addSeq(Critical, "CHAIN_BREAK", id, h.Seq,
					fmt.Sprintf("record's previous hash is %s but the preceding record chained to %s", short(rec.Prev), short(prev)))
				res.ChainOK = false
			}
			if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
				r.addSeq(Critical, "CHAIN_HASH_MISMATCH", id, h.Seq,
					fmt.Sprintf("stored chain hash %s does not match the hash recomputed from this record (%s)", short(rec.Chain), short(want)))
				res.ChainOK = false
			}
			if started && h.Seq != lastSeq+1 {
				r.addSeq(Critical, "SEQUENCE_GAP", id, h.Seq,
					fmt.Sprintf("sequence jumps from %d to %d", lastSeq, h.Seq))
				res.ChainOK = false
			}

			if j == 0 {
				res.FirstSeq = h.Seq
			}
			res.LastSeq = h.Seq
			if !recordedFirst {
				r.FirstSeq = h.Seq
				recordedFirst = true
			}
			checkTenant(r, opts, seen, id, h)
			checkTimestamp(r, id, h)
			if h.Kind == evidence.KindShred {
				erasures++
			}
			// A tenure claims the point it continues from. Checked
			// against the record that actually precedes it, because a promotion
			// is the one seam in a log where the writer changed without a
			// handover, and a claim about that seam that nothing checks is a
			// claim an auditor has to take on trust.
			//
			// This is the *in-log* half. It cannot see a fork — two promotions
			// from the same point live in two different directories, and a
			// verifier reading one of them has nothing to compare against. What
			// it catches is a tenure that misdescribes its own log, which is
			// what a forged history would have to do to look continuous.
			if h.Kind == evidence.KindWriterTenure && len(rec.Payload) > 0 {
				t, terr := evidence.DecodeTenure(rec.Payload)
				switch {
				case terr != nil:
					r.addSeq(Critical, "TENURE_UNREADABLE", id, h.Seq, terr.Error())
					res.ChainOK = false
				case t.InheritedSeq != lastSeq:
					r.addSeq(Critical, "DIVERGENT_TENURE", id, h.Seq, fmt.Sprintf(
						"the tenure claims to continue from sequence %d, and the record "+
							"before it is %d", t.InheritedSeq, lastSeq))
					res.ChainOK = false
				case t.InheritedChain != "blake3:"+hex.EncodeToString(prev[:]):
					r.addSeq(Critical, "DIVERGENT_TENURE", id, h.Seq, fmt.Sprintf(
						"the tenure claims to continue from chain %s, and the record "+
							"before it chained to blake3:%s", t.InheritedChain, hex.EncodeToString(prev[:])))
					res.ChainOK = false
				}
			}
			if h.Kind == evidence.KindWriterKey && len(rec.Payload) > 0 {
				d, derr := evidence.DecodeWriterKey(rec.Payload)
				if derr != nil {
					r.addSeq(Critical, "WRITER_KEY_UNREADABLE", id, h.Seq, derr.Error())
					res.ChainOK = false
				} else {
					declared = append(declared, declaration{d: d, seq: h.Seq})
				}
			}

			started = true
			lastSeq = h.Seq
			prev = rec.Chain
			res.LastChain = "blake3:" + hex.EncodeToString(rec.Chain[:])
			leaves = append(leaves, merkle.HashLeaf(rec.Chain[:]))
			r.Events++

			if opts.IncludeEvents || opts.OnEvent != nil {
				summary := EventSummary{
					Seq:             h.Seq,
					SegmentID:       id,
					EventID:         h.EventID,
					Kind:            string(h.Kind),
					SagaID:          h.SagaID,
					StepID:          h.StepID,
					Subject:         h.Subject,
					Participant:     h.Participant.ID,
					ManifestVersion: h.Participant.ManifestVersion,
					Wall:            h.TS.Wall(),
					PayloadSize:     len(rec.Payload),
					Labels:          h.Labels,
				}
				// The callback wins, and the list is not also built: a caller
				// that asked for both would be asking for the allocation the
				// callback exists to avoid.
				if opts.OnEvent != nil {
					opts.OnEvent(summary)
				} else {
					r.EventList = append(r.EventList, summary)
				}
			}
		}

		root := merkle.Root(leaves)
		res.MerkleRoot = hex.EncodeToString(root[:])

		if insp.Sealed() {
			f := insp.Footer
			res.KeyID = f.KeyID
			if int(f.Count) != len(insp.Records) {
				r.addSeg(Critical, "FOOTER_COUNT_MISMATCH", id,
					fmt.Sprintf("footer claims %d records, segment holds %d", f.Count, len(insp.Records)))
			}
			if f.MerkleRoot != root {
				r.addSeg(Critical, "MERKLE_ROOT_MISMATCH", id,
					fmt.Sprintf("footer root %s, recomputed %s", hex.EncodeToString(f.MerkleRoot[:8]), hex.EncodeToString(root[:8])))
			}
			if len(insp.Records) > 0 {
				if f.FirstSeq != res.FirstSeq || f.LastSeq != res.LastSeq {
					r.addSeg(Critical, "FOOTER_RANGE_MISMATCH", id,
						fmt.Sprintf("footer covers seq %d..%d, records span %d..%d", f.FirstSeq, f.LastSeq, res.FirstSeq, res.LastSeq))
				}
				if f.LastChain != insp.Records[len(insp.Records)-1].Chain {
					r.addSeg(Critical, "FOOTER_HEAD_MISMATCH", id, "footer's last chain hash is not the last record's chain hash")
				}
			}

			pub, known := trust.Key(f.KeyID)
			used[f.KeyID] = struct{}{}
			switch {
			case !known:
				r.addSeg(Critical, "UNKNOWN_SIGNING_KEY", id,
					fmt.Sprintf("footer is signed by key %s, which was neither supplied as a "+
						"root nor introduced by a WRITER_KEY declaration in a segment that "+
						"verified before it", f.KeyID))
			case len(f.Sig) != ed25519.SignatureSize:
				r.addSeg(Critical, "BAD_SIGNATURE_SIZE", id,
					fmt.Sprintf("signature is %d bytes, want %d", len(f.Sig), ed25519.SignatureSize))
			default:
				preimage := segment.SigPreimage(insp.Header, *f)
				if ed25519.Verify(pub, preimage, f.Sig) {
					res.SignatureOK = true
				} else {
					r.addSeg(Critical, "SIGNATURE_INVALID", id,
						fmt.Sprintf("footer signature does not verify under key %s", f.KeyID))
				}
			}
		}

		// Only now, and only from a segment that verified. A declaration in a
		// segment whose signature did not check out would let a forged segment
		// introduce the key for the next one; applying it after this segment's
		// own footer check is what stops a segment introducing the key it was
		// signed with.
		if res.SignatureOK && res.ChainOK {
			for _, dec := range declared {
				trust.Apply(dec.d, dec.seq)
			}
		} else if len(declared) > 0 {
			r.addSeg(Warning, "WRITER_KEY_IGNORED", id, fmt.Sprintf(
				"%d writer-key declaration(s) in this segment were not applied, because the "+
					"segment did not verify; any later segment relying on them will report an "+
					"unknown signing key", len(declared)))
		}

		r.Segments = append(r.Segments, res)
	}

	summariseTenants(r, seen)
	summariseErasures(r, erasures)
	if len(used) > 0 {
		r.SigningKeys = make(map[string]string, len(used))
		for id := range used {
			origin := trust.Origin(id)
			if origin == "" {
				origin = "not trusted"
			}
			r.SigningKeys[id] = origin
		}
	}

	r.LastSeq = lastSeq
	r.HeadChain = "blake3:" + hex.EncodeToString(prev[:])
	if opts.ExpectHeadChain != "" && opts.ExpectHeadChain != r.HeadChain {
		r.add(Critical, "HEAD_CHAIN_UNEXPECTED",
			fmt.Sprintf("computed head chain %s does not match the expected value %s supplied out of band", r.HeadChain, opts.ExpectHeadChain))
	}
	return trust.Keys()
}

// declaration is one writer-key event, held until the segment carrying it has
// been shown to verify.
type declaration struct {
	d   evidence.WriterKeyDeclaration
	seq uint64
}

// checkTenant records which tenant an event was written under and, when the
// caller said which tenant it expected, refuses any event that says otherwise.
//
// An unlabelled event is not a mismatch. Every log written before Phase 5c has
// no tenant on it, and calling those events foreign would make the check
// useless on exactly the logs that most need reading. What it does do is keep
// them out of Report.Tenants, so a bundle mixing bound and unbound events says
// so instead of reading as one tenant's complete evidence.
// backdateTolerance is how far a record's wall-clock reading may sit from the
// hybrid logical clock assigned beside it before the verifier says so.
//
// Generous on purpose. The two are taken at different moments — the HLC when the
// record is chained, the wall when its batch is assembled — and a clock being
// corrected by NTP legitimately moves the wall while the HLC, which is
// monotonic, does not follow it backwards. A minute swallows all of that and
// nothing an attacker would find useful: back-dating an event to sit inside a
// reporting period, or forward-dating one past a deadline, is measured in hours.
const backdateTolerance = time.Minute

// checkTimestamp compares a record's wall-clock reading against the hybrid
// logical clock recorded beside it.
//
// This is the first adversarial case — back-dating an event — and until it
// existed nothing detected it. The HLC is assigned by the appender and is
// monotonic, so it cannot be moved backwards without breaking the ordering every
// other check depends on. `Request.Wall`, however, is settable by the caller:
// the field exists so a replay or an import can reproduce an existing record,
// and the same door lets a caller write a record claiming to have happened last
// Tuesday.
//
// The chain does not care — ordering comes from the HLC — but the wall reading
// is the *regulatory* timestamp (MiFID II RTS 25), and an evidence log
// whose timestamps can be chosen by whoever writes them is not an audit trail.
// So the two are compared: they were produced moments apart by the same process,
// and a wall far from the HLC beside it is a claim the log's own machinery
// contradicts.
//
// A WARNING rather than a CRITICAL, and the distinction is deliberate. A large
// backwards clock correction is legitimate, rare, and worth an auditor seeing;
// treating it as tampering would make the finding one operators learn to ignore,
// which is how a control stops working. What makes it actionable is the clock
// attestation beside it: a deployment that records what its clock was
// disciplined against can explain the gap, and one that does not, cannot.
func checkTimestamp(r *Report, segID uint64, h evidence.EventHeader) {
	if h.TS.HLC == 0 || h.TS.WallUnixNanos == 0 {
		return
	}
	physical, _ := evidence.SplitHLC(h.TS.HLC)
	skew := h.TS.Wall().Sub(physical)
	if skew < 0 {
		skew = -skew
	}
	if skew <= backdateTolerance {
		return
	}
	r.addSeq(Warning, "TIMESTAMP_IMPLAUSIBLE", segID, h.Seq, fmt.Sprintf(
		"the wall-clock reading is %s from the hybrid logical clock recorded beside it "+
			"(wall %s, hlc %s). The HLC is assigned by the writer and cannot move "+
			"backwards; the wall reading can be supplied by the caller, so a gap this "+
			"size is either a clock correction the deployment should be able to "+
			"explain from its attestations, or a timestamp that was chosen",
		skew.Round(time.Second), h.TS.Wall().Format(time.RFC3339),
		physical.Format(time.RFC3339)))
}

func checkTenant(r *Report, opts Options, seen map[string]struct{}, segID uint64, h evidence.EventHeader) {
	id := h.Labels[tenancy.LabelTenant]
	if id == "" {
		return
	}
	if _, known := seen[id]; known {
		return
	}
	seen[id] = struct{}{}
	if opts.Tenant.Bound() && id != opts.Tenant.ID {
		r.addSeq(Critical, "TENANT_MISMATCH", segID, h.Seq,
			fmt.Sprintf("this log was verified as tenant %q, and seq %d is labelled tenant %q "+
				"(reported once per foreign tenant; -list shows every event's labels)",
				opts.Tenant.ID, h.Seq, id))
	}
}

// summariseTenants reports what the walk found.
//
// Two tenants in one directory is critical rather than a warning. It cannot
// happen through the write path — an Appender stamps its own binding and
// refuses a caller that tries to name another — so a log holding two is a log
// whose segments came from somewhere. Which is the case where "this evidence is
// tenant A's" is exactly the claim that must not be made.
// summariseErasures qualifies a clean bill that would otherwise be unqualified.
//
// This is the adversarial case "shredding-then-claiming-integrity", and until the adversarial
// suite performed the attack for real, nothing reported it. Crypto-shredding
// destroys a data subject's key and leaves the ciphertext in the chain:
// every hash still checks out, the chain still verifies, and the verifier
// returned PASS with nothing said about the fact that some of what it verified
// can no longer be read by anyone.
//
// That report is true and it is not the whole truth. An auditor handed "this log
// is intact" would reasonably understand it to mean the contents are available,
// and here some are not — lawfully, deliberately, and recorded in the log itself
// as a SHRED event, which is what makes this reportable at all.
//
// A Note rather than a Warning. An erasure is a control working, not a problem,
// and a warning on every lawful deletion is one operators learn to scroll past —
// which is how a real finding gets missed. The point is that the report *says
// something*, not that it complains.
func summariseErasures(r *Report, erasures int) {
	if erasures == 0 {
		return
	}
	r.add(Note, "ERASURES_RECORDED", fmt.Sprintf(
		"this log records %d erasure(s) by crypto-shredding: the affected events are present and "+
			"their hashes verify, and their payloads are ciphertext whose keys have been "+
			"destroyed. Integrity here means the records are unaltered, not that their "+
			"contents can be read", erasures))
}

func summariseTenants(r *Report, seen map[string]struct{}) {
	if len(seen) == 0 {
		return
	}
	r.Tenants = make([]string, 0, len(seen))
	for id := range seen {
		r.Tenants = append(r.Tenants, id)
	}
	sort.Strings(r.Tenants)
	if len(r.Tenants) > 1 {
		r.add(Critical, "MIXED_TENANTS",
			fmt.Sprintf("events for %d tenants are in one log (%s); one tenant, one directory, one writer key",
				len(r.Tenants), strings.Join(r.Tenants, ", ")))
	}
}

// checkExternalPayload resolves a payload that lives outside the chain and
// confirms it still hashes to what the envelope committed to.
//
// Offloading a body to content-addressed storage does not weaken the chain —
// the hash is still chained — but it does mean the bytes can go missing
// independently. An audit trail whose evidence points at a blob nobody kept is
// worse than one that says so, hence a finding either way.
func checkExternalPayload(r *Report, opts Options, segID uint64, h evidence.EventHeader) {
	if opts.CAS == nil {
		r.addSeq(Note, "PAYLOAD_UNCHECKED", segID, h.Seq,
			"payload is content-addressed at "+h.PayloadRef+"; its hash is chained, but no blob store "+
				"was supplied so the content itself was not checked")
		return
	}

	body, err := cas.GetByRef(context.Background(), opts.CAS, h.PayloadRef)
	if err != nil {
		sev := Critical
		code := "PAYLOAD_UNREADABLE"
		if errors.Is(err, cas.ErrNotFound) {
			code = "PAYLOAD_MISSING"
		}
		r.addSeq(sev, code, segID, h.Seq,
			fmt.Sprintf("payload %s could not be read from %s: %v", h.PayloadRef, opts.CAS.Describe(), err))
		return
	}
	if got := evidence.HashPayload(body); got != h.PayloadHash {
		r.addSeq(Critical, "PAYLOAD_HASH_MISMATCH", segID, h.Seq,
			fmt.Sprintf("payload fetched from %s hashes to %s but the header claims %s",
				h.PayloadRef, short(got), short(h.PayloadHash)))
		return
	}
	r.addSeq(Note, "PAYLOAD_RESOLVED", segID, h.Seq,
		"payload was fetched from "+h.PayloadRef+" and matches its recorded hash")
}

// verifySelection re-checks each highlighted event's Merkle inclusion proof
// against the root recomputed from the segment it claims to live in.
func verifySelection(r *Report, dir string, m bundle.Manifest, ids []uint64, paths []string) {
	if len(m.Selection) == 0 && scopedSaga(m) == "" {
		return
	}
	roots := map[uint64][merkle.Size]byte{}
	sizes := map[uint64]int{}
	records := map[uint64][]segment.Record{}
	for i, path := range paths {
		insp, err := segment.Inspect(path)
		if err != nil {
			continue
		}
		leaves := make([][merkle.Size]byte, len(insp.Records))
		for j, rec := range insp.Records {
			leaves[j] = merkle.HashLeaf(rec.Chain[:])
		}
		roots[ids[i]] = merkle.Root(leaves)
		sizes[ids[i]] = len(leaves)
		records[ids[i]] = insp.Records
	}

	for _, sel := range m.Selection {
		root, ok := roots[sel.SegmentID]
		if !ok {
			r.addSeq(Critical, "SELECTION_SEGMENT_ABSENT", sel.SegmentID, sel.Seq,
				fmt.Sprintf("selected event %s claims segment %d, which is not in the bundle", sel.EventID, sel.SegmentID))
			continue
		}
		if sel.TreeSize != sizes[sel.SegmentID] {
			r.addSeq(Critical, "SELECTION_TREE_SIZE", sel.SegmentID, sel.Seq,
				fmt.Sprintf("proof was made against a tree of %d leaves, segment has %d", sel.TreeSize, sizes[sel.SegmentID]))
			continue
		}
		chainRaw, err := hex.DecodeString(sel.ChainHash)
		if err != nil || len(chainRaw) != merkle.Size {
			r.addSeq(Critical, "SELECTION_CHAIN_HASH", sel.SegmentID, sel.Seq, "selected event's chain hash is not a 32-byte hex value")
			continue
		}
		var leafData [merkle.Size]byte
		copy(leafData[:], chainRaw)
		proof := make([][merkle.Size]byte, 0, len(sel.MerkleProof))
		bad := false
		for _, p := range sel.MerkleProof {
			raw, err := hex.DecodeString(p)
			if err != nil || len(raw) != merkle.Size {
				r.addSeq(Critical, "SELECTION_PROOF_MALFORMED", sel.SegmentID, sel.Seq, "inclusion proof element is not a 32-byte hex value")
				bad = true
				break
			}
			var node [merkle.Size]byte
			copy(node[:], raw)
			proof = append(proof, node)
		}
		if bad {
			continue
		}
		if !merkle.VerifyInclusion(merkle.HashLeaf(leafData[:]), sel.LeafIndex, sel.TreeSize, proof, root) {
			r.addSeq(Critical, "SELECTION_PROOF_INVALID", sel.SegmentID, sel.Seq,
				fmt.Sprintf("inclusion proof for event %s does not verify against segment %d's Merkle root", sel.EventID, sel.SegmentID))
			continue
		}
		// The proof binds a chain hash to a position; it says nothing about the
		// labels the manifest puts beside it. Without this, an unsigned bundle's
		// list of "this saga's events" could name any event id, sequence
		// number, saga or kind over a valid proof and still pass.
		checkSelectionLabels(r, sel, records[sel.SegmentID])
	}
	checkSelectionScope(r, m, ids, records)
}

// scopedSaga is the saga a bundle was exported for, or "".
func scopedSaga(m bundle.Manifest) string {
	if m.Scope == nil {
		return ""
	}
	return m.Scope.SagaID
}

// checkSelectionScope holds a saga-scoped bundle's selection to what the
// exporter promises: every record in the bundled segments that belongs to the
// saga, each once, and nothing else. The segments are in the bundle in full, so
// an entry left out, repeated or borrowed from another saga is visible here --
// and in an unsigned bundle nothing else would show it.
func checkSelectionScope(r *Report, m bundle.Manifest, ids []uint64, records map[uint64][]segment.Record) {
	saga := scopedSaga(m)
	if saga == "" {
		return
	}
	type leaf struct {
		seg uint64
		idx int
	}
	selected := map[leaf]bool{}
	for _, sel := range m.Selection {
		k := leaf{sel.SegmentID, sel.LeafIndex}
		if selected[k] {
			r.addSeq(Critical, "SELECTION_DUPLICATE", sel.SegmentID, sel.Seq,
				fmt.Sprintf("leaf %d of segment %d is selected more than once", sel.LeafIndex, sel.SegmentID))
		}
		selected[k] = true
		if sel.SagaID != saga {
			r.addSeq(Critical, "SELECTION_OUT_OF_SCOPE", sel.SegmentID, sel.Seq,
				fmt.Sprintf("the bundle is scoped to saga %s and selects event %s of saga %q", saga, sel.EventID, sel.SagaID))
		}
	}
	for _, id := range ids {
		for i, rec := range records[id] {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil || h.SagaID != saga || selected[leaf{id, i}] {
				continue
			}
			r.addSeq(Critical, "SELECTION_INCOMPLETE", id, h.Seq,
				fmt.Sprintf("event %s of saga %s is in the bundle and missing from its selection", h.EventID, saga))
		}
	}
}

// checkSelectionLabels compares what a selection entry says about its event
// with the header of the record its proof covers.
func checkSelectionLabels(r *Report, sel bundle.Selection, recs []segment.Record) {
	if sel.LeafIndex < 0 || sel.LeafIndex >= len(recs) {
		r.addSeq(Critical, "SELECTION_LABEL_MISMATCH", sel.SegmentID, sel.Seq,
			fmt.Sprintf("selected event %s claims leaf %d of a segment with %d records", sel.EventID, sel.LeafIndex, len(recs)))
		return
	}
	h, err := evidence.DecodeHeader(recs[sel.LeafIndex].Header)
	if err != nil {
		r.addSeq(Critical, "SELECTION_LABEL_MISMATCH", sel.SegmentID, sel.Seq,
			fmt.Sprintf("the record under selected event %s has an unreadable header: %v", sel.EventID, err))
		return
	}
	for _, c := range []struct{ field, claimed, recorded string }{
		{"event id", sel.EventID, h.EventID},
		{"sequence number", strconv.FormatUint(sel.Seq, 10), strconv.FormatUint(h.Seq, 10)},
		{"saga", sel.SagaID, h.SagaID},
		{"step", sel.StepID, h.StepID},
		{"kind", sel.Kind, string(h.Kind)},
	} {
		if c.claimed != c.recorded {
			r.addSeq(Critical, "SELECTION_LABEL_MISMATCH", sel.SegmentID, sel.Seq,
				fmt.Sprintf("selected event %s names %s %q, and the record its proof covers has %q",
					sel.EventID, c.field, c.claimed, c.recorded))
		}
	}
}

func (r *Report) finish(start time.Time) {
	r.DurationMS = time.Since(start).Milliseconds()
	r.OK = !r.hasCritical()
}

func short(h evidence.Hash) string { return hex.EncodeToString(h[:6]) }

// Text renders a human-readable report, which is what an auditor actually reads.
func (r *Report) Text() string {
	var b strings.Builder
	status := "PASS"
	if !r.OK {
		status = "FAIL"
	}
	fmt.Fprintf(&b, "janus-verify %s\n", r.VerifierVer)
	fmt.Fprintf(&b, "target:    %s (%s)\n", r.Target, r.Kind)
	fmt.Fprintf(&b, "checked:   %s in %d ms\n", r.CheckedAt.Format(time.RFC3339), r.DurationMS)
	fmt.Fprintf(&b, "result:    %s\n", status)
	fmt.Fprintf(&b, "events:    %d (seq %d..%d)\n", r.Events, r.FirstSeq, r.LastSeq)
	fmt.Fprintf(&b, "head:      %s\n", r.HeadChain)
	if len(r.Tenants) > 0 {
		fmt.Fprintf(&b, "tenant:    %s\n", strings.Join(r.Tenants, ", "))
	}
	if len(r.SigningKeys) > 0 {
		ids := make([]string, 0, len(r.SigningKeys))
		for id := range r.SigningKeys {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for i, id := range ids {
			label := "keys:"
			if i > 0 {
				label = "     "
			}
			fmt.Fprintf(&b, "%-10s %s (%s)\n", label, id, r.SigningKeys[id])
		}
	}
	fmt.Fprintf(&b, "segments:  %d\n\n", len(r.Segments))

	fmt.Fprintf(&b, "%-10s %8s %14s %8s %8s %8s  %s\n", "SEGMENT", "RECORDS", "SEQ RANGE", "SEALED", "SIG", "CHAIN", "KEY")
	for _, s := range r.Segments {
		fmt.Fprintf(&b, "%-10d %8d %6d..%-6d %8s %8s %8s  %s\n",
			s.SegmentID, s.Records, s.FirstSeq, s.LastSeq,
			yesNo(s.Sealed), yesNo(s.SignatureOK), yesNo(s.ChainOK), s.KeyID)
	}

	if len(r.EventList) > 0 {
		fmt.Fprintf(&b, "\n%-6s %-18s %-18s %-16s  %s\n", "SEQ", "KIND", "SAGA", "PARTICIPANT", "LABELS")
		for _, e := range r.EventList {
			keys := make([]string, 0, len(e.Labels))
			for k := range e.Labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			pairs := make([]string, 0, len(keys))
			for _, k := range keys {
				pairs = append(pairs, k+"="+e.Labels[k])
			}
			fmt.Fprintf(&b, "%-6d %-18s %-18s %-16s  %s\n",
				e.Seq, e.Kind, truncate(e.SagaID, 18), truncate(e.Participant, 16), strings.Join(pairs, " "))
		}
	}

	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "\nno findings\n")
		return b.String()
	}
	fmt.Fprintf(&b, "\nfindings (%d):\n", len(r.Findings))
	for _, f := range r.Findings {
		loc := ""
		if f.SegmentID != nil {
			loc = fmt.Sprintf(" segment=%d", *f.SegmentID)
		}
		if f.Seq != nil {
			loc += fmt.Sprintf(" seq=%d", *f.Seq)
		}
		fmt.Fprintf(&b, "  [%s] %s%s\n      %s\n", f.Severity, f.Code, loc, f.Message)
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
