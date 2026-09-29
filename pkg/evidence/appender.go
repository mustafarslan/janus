package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/crypto"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// Appender is the evidence write path: the single place where events enter the
// log, get chained, and become durable.
//
// One goroutine owns the segment writer and the chain state. That is not an
// implementation detail but the mechanism that makes the chain totally ordered
// without locks around the hash computation. Callers hand over an event and
// block until the group commit covering it has hit the durability barrier —
// which is what lets a caller treat a successful Append as permission to
// release a side effect.
type Appender struct {
	opts   Options
	signer segment.Signer
	clock  *Clock

	// submitMu makes the closing check and the send on reqs atomic with respect
	// to Close. Without it a producer can pass the check, be delayed in
	// encryption or a blob-store round trip, and then send on a channel Close
	// has already closed — which panics, in the component whose whole purpose
	// is to fail closed rather than fall over.
	submitMu sync.RWMutex

	reqs      chan *appendReq
	nextSeg   chan preparedSegment
	wg        sync.WaitGroup
	sealWG    sync.WaitGroup
	prepWG    sync.WaitGroup
	closeOnce sync.Once
	closeErr  error

	// mu guards submission state shared with callers. The chain state below it
	// belongs to the writer goroutine alone.
	mu      sync.Mutex
	closing bool
	failed  error

	statsMu sync.Mutex
	stats   Stats
	phases  AppendPhases

	// index remembers where each saga's records are, so a reader does not walk
	// the whole directory to find eight of them.
	index *sagaIndex

	// lock is the one-writer-per-directory interlock, held from Open to Close.
	lock *dirLock

	// Writer-goroutine-owned state.
	seg       *segment.Writer
	seq       uint64
	prev      Hash
	nextSegID uint64
}

// Options configures an Appender.
type Options struct {
	// Dir is the segment directory. Created if absent.
	Dir string
	// KeyPath is where the writer's Ed25519 key lives. Ignored when Signer is
	// set. Defaults to <Dir>/../keys/writer.key.
	KeyPath string
	// Signer overrides on-disk key custody (for a KMS or a test).
	Signer segment.Signer
	// SyncMode selects the durability barrier. Defaults to the strongest.
	SyncMode segment.SyncMode
	// SegmentTargetBytes triggers rotation once a segment reaches this size.
	// Defaults to 16 MiB.
	SegmentTargetBytes int64
	// MaxBatchEvents and MaxBatchBytes cap one group commit.
	MaxBatchEvents int
	MaxBatchBytes  int
	// Linger, when positive, makes the writer wait this long for more events
	// before syncing. Zero — the default — syncs as soon as the writer is free,
	// which self-tunes: batches grow under load because arrivals queue during
	// the previous sync, and stay small when idle so latency stays low.
	Linger time.Duration
	// QueueDepth sizes the submission queue. It must be large enough that
	// producers can keep filling it while a sync is in flight.
	//
	// It counts units of submission, not records: AppendPair puts two records
	// on the queue with one slot. The difference is bounded by two and only
	// matters if a queue this deep were ever sized against MaxBatchEvents,
	// which nothing does.
	QueueDepth int

	// LocatorSagas bounds how many sagas the record locator remembers, so that
	// a reader can find one saga's events without walking the directory.
	// Zero takes the default, which covers the target of
	// 10k concurrent sagas per node several times over. Forgetting a saga costs
	// the reader a scan, never a wrong answer.
	LocatorSagas int
	// Clock supplies HLC timestamps. Defaults to a system clock.
	Clock *Clock
	// ClockAttestationRef returns the evidence reference of the most recent
	// clock attestation, which is stamped onto every event's wall-clock
	// reading. A timestamp nobody can vouch for does not establish when
	// something happened (MiFID II RTS 25).
	ClockAttestationRef func() string
	// BeforeSeal is consulted before a segment is signed, and a non-nil error
	// fails the write path permanently (ErrWritePathFailed is sticky).
	//
	// This is where a writer lease is checked (pkg/evidence/fence).
	// Sealing rather than appending, for two reasons. An append is the most
	// latency-sensitive operation here and a per-append check would put an
	// object-store round trip in front of every one of them. And sealing is the
	// moment a segment becomes *history*: a signed, footer-closed unit that a
	// verifier will read and an auditor will be handed. A writer that has lost
	// its lease may still have appended to an open segment, and the honest
	// statement of what the fence bounds is that it stops divergence becoming
	// sealed history — not that it stops divergence.
	//
	// **It runs on the background seal goroutine**, which has two consequences
	// for whatever is passed here. It must be safe to call from a goroutine
	// other than the one that opened the appender — the race detector found
	// exactly this in the first version of this package's own test. And it must
	// not block for long: `fence.Lease.Check` reads state a renewal goroutine
	// maintains and does no I/O of its own, for that reason.
	BeforeSeal func() error
	// OpenFile creates segment files. Defaults to the real filesystem; the
	// fault-injection harness substitutes one that fails on demand.
	OpenFile segment.OpenFunc
	// CAS, when set, receives payloads at or above CASThresholdBytes. The
	// envelope then carries the payload's hash and a reference instead of the
	// bytes, which keeps the segment files small enough to read and verify
	// quickly even when agents exchange whole documents.
	CAS cas.Store
	// CASThresholdBytes is the size at which a payload is offloaded.
	// Defaults to 64 KiB. Ignored when CAS is nil.
	CASThresholdBytes int
	// Sealer, when set, encrypts the payload of any event that names a data
	// subject, so the subject's data can later be erased by destroying their
	// key rather than by removing records from the chain (crypto-shredding).
	Sealer *crypto.Sealer
	// Labels are merged into every event's labels. A caller's own labels win
	// over these, which is right for descriptive metadata and wrong for the
	// tenant — see Tenant.
	Labels map[string]string
	// Tenant binds this log to one tenant, and is what makes the tenant a
	// boundary rather than a label somebody remembered to pass (pkg/tenancy).
	//
	// The binding's labels are stamped after the caller's and cannot be
	// overridden: a Request carrying a reserved label is refused. The zero
	// value is a single-tenant deployment and stamps nothing, which is what
	// every log written before Phase 5c is.
	Tenant tenancy.Tenant
}

// residencyAllows refuses a pinned tenant a blob store that does not rest in
// its jurisdiction.
//
// The payloads that go to content-addressed storage are the large ones — whole
// documents, model outputs, the material a data-residency rule is actually
// about. A deployment can therefore be scrupulous about where its evidence
// directory lives and still send the substance of it somewhere else, because
// the two are configured in different places and only one of them is obviously
// "the data".
//
// A store that declares nothing is refused rather than assumed local, for the
// same reason an unassessed participant is (pkg/registry.jurisdictionAllows):
// the undeclared store is every store configured before anybody asked the
// question, which is the population the pin exists for.
func residencyAllows(opts Options) error {
	if !opts.Tenant.Pinned() || opts.CAS == nil {
		return nil
	}
	where := cas.JurisdictionOf(opts.CAS)
	if where == opts.Tenant.Jurisdiction {
		return nil
	}
	if where == "" {
		return fmt.Errorf("evidence: tenant %s is pinned to %s, and the blob store %s declares no "+
			"jurisdiction; a store nobody has placed cannot hold pinned evidence",
			opts.Tenant.ID, opts.Tenant.Jurisdiction, opts.CAS.Describe())
	}
	return fmt.Errorf("evidence: tenant %s is pinned to %s, and the blob store %s rests in %s",
		opts.Tenant.ID, opts.Tenant.Jurisdiction, opts.CAS.Describe(), where)
}

func (o *Options) setDefaults() {
	if o.SegmentTargetBytes <= 0 {
		o.SegmentTargetBytes = 16 << 20
	}
	if o.MaxBatchEvents <= 0 {
		o.MaxBatchEvents = 4096
	}
	if o.MaxBatchBytes <= 0 {
		o.MaxBatchBytes = 4 << 20
	}
	if o.QueueDepth <= 0 {
		o.QueueDepth = 8192
	}
	if o.CASThresholdBytes <= 0 {
		o.CASThresholdBytes = 64 << 10
	}
	if o.KeyPath == "" {
		o.KeyPath = filepath.Join(filepath.Dir(filepath.Clean(o.Dir)), "keys", "writer.key")
	}
}

// Stats reports write-path counters.
type Stats struct {
	Events         uint64
	Batches        uint64
	Bytes          uint64
	SegmentsSealed uint64
	// LastSeq and LastChain describe the head of the log.
	LastSeq   uint64
	LastChain Hash
	// LocatorFilterFill is the fraction of the record locator's saga filter
	// that is set, and LocatorFilterFPR the false-positive rate that implies.
	//
	// Reported because the filter's decay is the one thing here that degrades
	// without producing a wrong answer: reads for a saga with no records fall
	// back to a full scan at this rate, everything stays correct, and the only
	// symptom is that starting a saga gets slower over the log's lifetime. The
	// appender says so once at each of two thresholds; this is for anything
	// that would rather poll.
	LocatorFilterFill float64
	LocatorFilterFPR  float64
}

// AppendPhases is where a caller's time inside Append goes.
//
// "The appends cost 14 ms" is not actionable, and the two things it can mean
// argue for opposite designs. If the time is Wait, the writer is saturated and
// every caller is queued behind somebody else's group commit — which is an
// argument for more logs. If it is Barrier, the writer is idle enough and the
// cost is the durability barrier itself, paid once per append — which is an
// argument for making a saga's sequential appends ride fewer barriers, and no
// argument for more logs at all. Counting them apart is the only way to know
// which, and Batch is the corroborating witness: a saturated writer builds
// large batches, an idle one writes batches of one.
//
// The three are per-append sums, so a mean is a division by Appends. They do
// not add up to the caller's wall time exactly — the reply still has to travel
// a channel — but the remainder is nanoseconds against milliseconds.
type AppendPhases struct {
	// Appends counts *calls*, not records: an AppendPair contributes one, the
	// same as an Append, because one caller waited once. Counting its two
	// records separately would attribute the shared barrier twice and report a
	// merged pair as costing exactly what two separate appends cost, which is
	// the opposite of what happened. Stats.Events is the record
	// count.
	Appends uint64
	// Prep is encryption, hashing and any blob offload, done on the caller's
	// goroutine before the request is queued. It is here to be ruled out, not
	// because it is expected to matter.
	Prep time.Duration
	// Wait is from the moment the request joins the queue to the moment the
	// writer starts the group commit carrying it.
	Wait time.Duration
	// Barrier is chaining, writing, flushing and syncing that group commit —
	// the part every caller in a batch pays in full and shares with the rest.
	Barrier time.Duration
	// Batch is the sum, over appends, of the size of the batch each one rode
	// in. Dividing by Appends gives the batch a typical *caller* was part of,
	// which is the number that explains its latency; Stats.Events/Stats.Batches
	// gives the mean batch, which is a different and less useful figure because
	// it weights a batch of one as heavily as a batch of five hundred.
	Batch uint64
}

// Phases reports where callers' time inside Append has gone.
func (a *Appender) Phases() AppendPhases {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	return a.phases
}

// Request is an event submitted for appending. The Appender fills in the
// sequence number, chain linkage, event id, and timestamps; everything else is
// the caller's to state.
type Request struct {
	Kind        Kind
	SagaID      string
	StepID      string
	TraceID     string
	Participant ParticipantRef
	Labels      map[string]string
	// Payload is stored and hashed verbatim, typically a marshalled JTP
	// message. Large bodies belong in content-addressed storage with only
	// PayloadRef here (Phase 1).
	Payload    []byte
	PayloadRef string
	// Subject names the data subject whose personal data this payload contains.
	// Setting it — with a Sealer configured — is what makes the payload
	// erasable: it is encrypted under that subject's key, and destroying the
	// key destroys the content while leaving the chain intact.
	//
	// It is deliberately the caller's decision. Janus cannot tell whether a
	// tool result contains personal data, and guessing either way would be
	// worse than being told.
	Subject string
	// EventID and Wall are normally left zero and assigned by the Appender.
	// Replay and import paths set them to reproduce an existing record.
	EventID string
	Wall    time.Time
}

// Ref identifies an appended event and its position in the chain.
type Ref struct {
	EventID   string
	Seq       uint64
	SegmentID uint64
	ChainHash Hash
	HLC       uint64
	Wall      time.Time
}

type appendReq struct {
	req  Request
	resp chan appendResp
	size int
	// payload is what actually goes into the segment. It is empty when the
	// body was offloaded to content-addressed storage.
	payload []byte
	// payloadHash always covers the caller's original bytes, offloaded or not,
	// so the chain commits to the content either way.
	payloadHash Hash
	// at is where this record was written in its segment, captured before the
	// write and used only after the batch is durable.
	at int64
	// enter and queued are the caller's side of the clock: when Append was
	// called, and when the request joined the writer's queue. The writer reads
	// them after the barrier to attribute the caller's wait (AppendPhases).
	enter, queued time.Time
	// ref is filled while chaining and handed to the caller only after the
	// durability barrier passes.
	ref Ref
	// unit is every request submitted alongside this one, this one included,
	// or nil for an ordinary single-record Append. The writer picks a unit up
	// whole, so its records cannot be split across two group commits and cannot
	// be acknowledged separately: no caller in a unit gets a Ref until the
	// barrier covering all of them has passed.
	unit []*appendReq
	// done records that this request's caller has already been answered. It is
	// set when a partner in the same unit was refused, which refuses this one
	// too, and read by the writer so it does not send twice on a channel with
	// one slot.
	done bool
}

// unitHead reports whether ar is the request its caller is accounted under.
// A single append is its own head; a pair is accounted under its first record,
// because one caller submitted both and waited once.
func (ar *appendReq) unitHead() bool {
	return ar.unit == nil || ar.unit[0] == ar
}

// members returns the requests that must be written with ar, ar included.
func (ar *appendReq) members() []*appendReq {
	if ar.unit == nil {
		return []*appendReq{ar}
	}
	return ar.unit
}

type appendResp struct {
	ref Ref
	err error
}

// ErrClosed is returned once the Appender is shutting down.
var ErrClosed = errors.New("evidence: appender closed")

// ErrWritePathFailed wraps a durability failure. It is sticky: once the write
// path cannot guarantee durability, every subsequent Append fails rather than
// returning a success the caller might act on. Fail-closed is a compliance
// feature, not an outage.
var ErrWritePathFailed = errors.New("evidence: write path failed")

// Open starts an Appender over opts.Dir, recovering whatever is already there.
func Open(opts Options) (a *Appender, retErr error) {
	if opts.Dir == "" {
		return nil, errors.New("evidence: Options.Dir is required")
	}
	if err := opts.Tenant.Validate(); err != nil {
		return nil, err
	}
	// A deployment says its tenant once, in the binding. Letting the generic
	// label bag say it too would give a log two answers to the same question,
	// and the one that wins would depend on the order of a map merge.
	if err := tenancy.CheckLabels(opts.Labels); err != nil {
		return nil, fmt.Errorf("evidence: Options.Labels: %w (use Options.Tenant)", err)
	}
	if err := residencyAllows(opts); err != nil {
		return nil, err
	}
	opts.setDefaults()
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, err
	}

	// Before anything is read or written: one writer per directory (lock.go).
	// This is taken ahead of recovery because recovery *writes* — it seals
	// segments the previous writer left open — and two processes recovering the
	// same directory at once is the worst version of the problem, not an
	// exception to it.
	lock, err := lockDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = lock.release()
		}
	}()

	signer := opts.Signer
	if signer == nil {
		s, err := keys.LoadOrCreate(opts.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("writer key: %w", err)
		}
		signer = s
	}
	// And beside the lock, the durable half of the same invariant: this
	// directory is a writer's, which is the question `replica.New` and
	// `janus-replicad promote` both have to answer and which the log itself
	// cannot (writermark.go). After the lock, so a directory somebody else is
	// writing is not stamped by a process that lost the race.
	if err := markWriter(opts.Dir, signer.KeyID()); err != nil {
		return nil, err
	}

	clock := opts.Clock
	if clock == nil {
		clock = NewClock()
	}

	a = &Appender{
		opts:    opts,
		signer:  signer,
		clock:   clock,
		lock:    lock,
		reqs:    make(chan *appendReq, opts.QueueDepth),
		nextSeg: make(chan preparedSegment, 1),
		prev:    GenesisHash,
		index:   newSagaIndex(opts.LocatorSagas),
	}

	// A daemon started on a key this log has withdrawn would keep signing
	// segments an auditor will reject, and nothing would say so until the
	// audit. Refusing costs one fold of the directory, which recovery is about
	// to walk anyway.
	if err := refuseRevokedSigner(opts.Dir, signer.KeyID()); err != nil {
		return nil, err
	}

	rec, err := a.restore()
	if err != nil {
		return nil, err
	}
	// Publish the head recovery established, before anything is appended.
	//
	// What this head *means* after a restart is worth being exact about, because
	// a follower treats it as "durably acknowledged":
	// recovery keeps every complete record, including any that no barrier
	// covered, so this head can include records that were never acknowledged to
	// a caller. Reporting it is still right — the appender has adopted them and
	// will build on them, so they are what it continues from and cannot now be
	// discarded. The rule is about records a primary *might still drop*, and
	// after recovery it will not.
	//
	// Without this, Stats() reports sequence zero on a directory holding a
	// million records until this process happens to write one — and every
	// caller that asks an appender for the log's head gets a wrong answer in the
	// window where it matters most. `janus-replicad promote` reads exactly this
	// to record what a tenure inherited, and the daemon's live-read bound is
	// built from it. Found by a promotion test that inherited sequence 0.
	a.statsMu.Lock()
	a.stats.LastSeq, a.stats.LastChain = a.seq, a.prev
	a.statsMu.Unlock()

	seg, err := segment.Create(opts.Dir, a.nextSegID, a.writerOptions())
	if err != nil {
		return nil, err
	}
	a.seg = seg
	a.nextSegID++
	// Start preparing the following segment immediately, so the first rotation
	// is already a pointer swap.
	a.prepareNext()

	a.wg.Add(1)
	go a.run()

	// Record the custody break before anything else can be appended, so the
	// log itself says a segment was sealed by a process that did not open it.
	if rec != nil {
		if _, err := a.Append(context.Background(), Request{
			Kind:        KindRecovery,
			Participant: ParticipantRef{ID: "janus-evidence", Kind: "SYSTEM"},
			Payload:     rec.payload(),
		}); err != nil {
			_ = a.Close()
			return nil, fmt.Errorf("record recovery event: %w", err)
		}
	}
	return a, nil
}

// recoveryNote describes what recovery had to repair. It becomes the payload of
// the RECOVERY event, so the repair is itself on the record.
type recoveryNote struct {
	// SealedSegments were closed out by this process rather than the one that
	// wrote them — a break in custody.
	SealedSegments []uint64 `json:"sealed_segments,omitempty"`
	// RemovedEmpty were prepared ahead of time but never written to, so they
	// were deleted rather than signed.
	RemovedEmpty []uint64 `json:"removed_empty,omitempty"`
	// TornSegment ended in an incomplete record and was truncated.
	TornSegment    uint64 `json:"torn_segment,omitempty"`
	TruncatedTo    int64  `json:"truncated_to,omitempty"`
	TornDetail     string `json:"torn_detail,omitempty"`
	ResumedFromSeq uint64 `json:"resumed_from_seq"`
}

// empty reports whether recovery found nothing to repair, in which case there is
// nothing to confess and no RECOVERY event is written.
func (n recoveryNote) empty() bool {
	// Deleting an unused prepared segment is routine bookkeeping after any
	// unclean stop, not a repair worth an event of its own.
	return len(n.SealedSegments) == 0 && n.TruncatedTo == 0 && n.TornDetail == ""
}

func (n recoveryNote) payload() []byte {
	// Marshalling a struct is deterministic in field order and slice order, so
	// this payload hashes stably — which matters because it goes into the chain.
	b, err := json.Marshal(n)
	if err != nil {
		// The struct contains only integers, strings, and a slice of integers.
		return fmt.Appendf(nil, `{"marshal_error":%q}`, err.Error())
	}
	return b
}

// restore rebuilds chain state from the segment directory. It returns a note
// when the previous writer left work behind, and refuses to start at all if the
// existing chain does not verify — starting a fresh chain on top of a broken one
// would hide the break.
func (a *Appender) restore() (*recoveryNote, error) {
	ids, err := segment.ScanDir(a.opts.Dir)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		a.nextSegID = 1
		a.seq = 0
		a.prev = GenesisHash
		// An empty directory is trivially fully known: there is no saga in it
		// this index has not heard of, so a miss can be answered "no records"
		// straight away rather than by scanning nothing.
		a.index.markComplete()
		return nil, nil
	}

	// Classify cheaply first. Because sealing runs in the background
	// an unsealed segment can be anywhere, not only at the end — a
	// crash can take the seal of segment N while segment N+1's seal already
	// landed. Reading every segment to find out would make startup scale with
	// the size of the whole log, so the trailing-magic check does the sweep and
	// only the segments that need attention are read.
	firstUnsealed := -1
	for i, id := range ids {
		sealed, err := segment.IsSealed(segment.Path(a.opts.Dir, id))
		if err != nil {
			return nil, fmt.Errorf("classify segment %d: %w", id, err)
		}
		if !sealed {
			firstUnsealed = i
			break
		}
	}

	// Start one segment earlier than the first damaged one so continuity across
	// that boundary can be checked. With everything sealed, the last segment
	// still has to be read for the chain head.
	start := len(ids) - 1
	if firstUnsealed >= 0 {
		start = max(firstUnsealed-1, 0)
	}

	// Segment ids are never reused, even for one that is about to be deleted,
	// so this is read before any removal below.
	maxSeen := ids[len(ids)-1]

	note := &recoveryNote{}
	prev := GenesisHash
	var lastSeq uint64
	// haveChain records whether prev is a real predecessor rather than the
	// genesis placeholder. It is false for the first segment read unless that
	// segment is genuinely the start of the log.
	haveChain := start == 0

	for i := start; i < len(ids); i++ {
		id := ids[i]
		path := segment.Path(a.opts.Dir, id)

		// Discard placeholders before trying to parse them. A segment prepared
		// ahead of time holds no evidence, and if the disk filled while it was
		// being created it may not even contain a complete header — which is not
		// damage to report, just a file that never became a segment. Either way
		// nothing was acknowledged on its authority, so removing it is safe.
		empty, err := segment.IsEmpty(path)
		if err != nil {
			return nil, fmt.Errorf("stat segment %s: %w", path, err)
		}
		if empty {
			if err := os.Remove(path); err != nil {
				return nil, fmt.Errorf("remove empty segment %s: %w", path, err)
			}
			note.RemovedEmpty = append(note.RemovedEmpty, id)
			continue
		}

		insp, err := segment.Inspect(path)
		if err != nil {
			return nil, fmt.Errorf("inspect segment %s: %w", path, err)
		}

		if insp.Torn {
			// A torn tail is discarded wherever it appears, including in a
			// segment that has fully-written segments after it. That happens for
			// real: sealing runs in the background, so a disk can fill while
			// segment N's footer is being written even though segment N+1 is
			// already taking records.
			//
			// Truncating is safe because a torn tail is by construction bytes
			// that were never acknowledged — an acknowledged record passed a
			// durability barrier first, and barriers do not un-happen. What
			// protects against evidence genuinely going missing is not the
			// position of the tear but the chain: verifyChain below requires the
			// next segment to continue from the hash this one ends on, so
			// removing a real record here would surface as a chain break rather
			// than being quietly accepted.
			note.TornSegment = id
			note.TornDetail = insp.TornDetail
			note.TruncatedTo = insp.LastGoodOffset
			if err := segment.Truncate(path, insp.LastGoodOffset); err != nil {
				return nil, fmt.Errorf("truncate torn segment %s: %w", path, err)
			}
			if insp, err = segment.Inspect(path); err != nil {
				return nil, fmt.Errorf("re-inspect truncated segment %s: %w", path, err)
			}
		}

		// Truncating a torn tail can leave a segment with nothing in it.
		if !insp.Sealed() && len(insp.Records) == 0 {
			if err := os.Remove(path); err != nil {
				return nil, fmt.Errorf("remove empty segment %s: %w", path, err)
			}
			note.RemovedEmpty = append(note.RemovedEmpty, id)
			continue
		}

		first, last, head, err := verifyChain(path, insp.Records, prev, haveChain)
		if err != nil {
			return nil, err
		}
		if len(insp.Records) > 0 {
			prev, lastSeq, haveChain = head, last, true
		}

		if !insp.Sealed() {
			if _, err := segment.Seal(path, first, last, a.signer); err != nil && !errors.Is(err, segment.ErrSealed) {
				return nil, fmt.Errorf("seal recovered segment %s: %w", path, err)
			}
			note.SealedSegments = append(note.SealedSegments, id)
		}
	}

	a.nextSegID = maxSeen + 1
	a.seq = lastSeq
	a.prev = prev
	note.ResumedFromSeq = lastSeq

	if note.empty() {
		return nil, nil
	}
	return note, nil
}

// verifyChain re-derives every hash in a segment before its head is trusted.
// Starting a new chain on top of a broken one would hide the break, so this
// returns an error rather than repairing anything.
//
// checkFirst says whether prev is a genuine predecessor; it is false when the
// caller began reading partway through the log and has nothing to compare the
// first record against.
func verifyChain(path string, records []segment.Record, prev Hash, checkFirst bool) (firstSeq, lastSeq uint64, head Hash, err error) {
	head = prev
	for i, r := range records {
		h, err := DecodeHeader(r.Header)
		if err != nil {
			return 0, 0, head, fmt.Errorf("segment %s record %d: %w", path, i, err)
		}
		if i == 0 {
			firstSeq = h.Seq
			if checkFirst && r.Prev != prev {
				return 0, 0, head, fmt.Errorf("segment %s: first record does not continue the previous segment's chain", path)
			}
		} else if r.Prev != head {
			return 0, 0, head, fmt.Errorf("segment %s record %d: chain break (prev hash mismatch)", path, i)
		}
		if want := ComputeChainHash(r.Prev, h.PayloadHash, r.Header); want != r.Chain {
			return 0, 0, head, fmt.Errorf("segment %s record %d (seq %d): chain hash mismatch", path, i, h.Seq)
		}
		if len(r.Payload) > 0 {
			if got := HashPayload(r.Payload); got != h.PayloadHash {
				return 0, 0, head, fmt.Errorf("segment %s record %d (seq %d): payload does not match its recorded hash", path, i, h.Seq)
			}
		}
		head = r.Chain
		lastSeq = h.Seq
	}
	return firstSeq, lastSeq, head, nil
}

// Append durably records one event and returns once the group commit covering
// it has passed the durability barrier.
//
// ctx cancellation applies only up to the point of submission. Once an event is
// queued it will be written, so Append waits for the outcome rather than
// returning an ambiguous "maybe recorded" to a caller that is about to decide
// whether it may act.
func (a *Appender) Append(ctx context.Context, r Request) (Ref, error) {
	enter := time.Now()
	if err := a.currentFailure(); err != nil {
		return Ref{}, err
	}
	ar, err := a.prepare(ctx, r, enter)
	if err != nil {
		return Ref{}, err
	}
	if err := a.submit(ctx, ar); err != nil {
		return Ref{}, err
	}
	resp := <-ar.resp
	return resp.ref, resp.err
}

// AppendPair records two events under one durability barrier and returns once
// that barrier has passed for both.
//
// It exists for a pair of records with no decision between them: nothing reads
// the first one's Ref, and nothing acts on it, before the second is written. A
// saga's decision-provenance record and the gate verdict that cites it are the
// case it was built for — the verdict's DprRef is the DPR's event id, which the
// caller can choose before either is written, so the only thing the second
// record needed from the first was a value, not an acknowledgement.
//
// Both records ride one group commit, and the contract is about what a caller
// is told, not about what a crash leaves on disk:
//
//   - No Ref is returned for either record until the barrier covering both has
//     passed. Nothing downstream can act on the first while the second is still
//     unwritten, which is the property worth having.
//   - If either record is refused, both callers are told no.
//   - A crash can still leave the first record's bytes on disk without the
//     second. A shared barrier changes when callers are told, not what the
//     platter holds mid-batch; the recovery case is the same one a crash
//     between two separate appends produced, and the saga resumes from it the
//     same way.
//
// It takes exactly two requests rather than a slice on purpose. A general batch
// API is a standing invitation to submit records that *do* have a decision
// between them, and the caller would get back something that looks like
// permission to act on the first before the second exists. Two is the number
// the measurement justified; widening it needs its own case.
func (a *Appender) AppendPair(ctx context.Context, first, second Request) (Ref, Ref, error) {
	enter := time.Now()
	if err := a.currentFailure(); err != nil {
		return Ref{}, Ref{}, err
	}
	f, err := a.prepare(ctx, first, enter)
	if err != nil {
		return Ref{}, Ref{}, err
	}
	sc, err := a.prepare(ctx, second, enter)
	if err != nil {
		return Ref{}, Ref{}, err
	}
	// Both members point at the same slice, so the writer can refuse the unit
	// from whichever member it was looking at when it decided to.
	unit := []*appendReq{f, sc}
	f.unit, sc.unit = unit, unit

	// One send. The writer takes a unit off the queue whole, so there is no
	// window in which the first record is in a batch and the second is not —
	// which is what a second send would have left open, Linger or no Linger.
	if err := a.submit(ctx, f); err != nil {
		return Ref{}, Ref{}, err
	}
	fr, sr := <-f.resp, <-sc.resp
	if fr.err != nil {
		return Ref{}, Ref{}, fr.err
	}
	if sr.err != nil {
		return Ref{}, Ref{}, sr.err
	}
	return fr.ref, sr.ref, nil
}

// prepare does the per-event work that belongs to the caller's goroutine.
//
// Encrypt, hash, and offload happen here rather than on the writer's goroutine.
// All three are per-event work with no ordering requirement, so doing them here
// keeps them parallel across callers and leaves the single writer to do only
// what has to be serial: chaining and the barrier.
//
// The order matters. Encryption happens before hashing so that the chain
// commits to the ciphertext: a hash of plaintext would outlive erasure as a
// verifiable fingerprint of the erased content, which for low-entropy personal
// data is a practical way to confirm a guess (see pkg/evidence/crypto).
func (a *Appender) prepare(ctx context.Context, r Request, enter time.Time) (*appendReq, error) {
	if r.Kind == "" {
		return nil, errors.New("evidence: Request.Kind is required")
	}
	// The tenant is the writer's, not the caller's. A request that tries to
	// name one is refused here rather than corrected silently on the way in.
	if err := tenancy.CheckLabels(r.Labels); err != nil {
		return nil, err
	}
	payload, err := a.encrypt(r)
	if err != nil {
		return nil, err
	}
	ar := &appendReq{
		req:         r,
		resp:        make(chan appendResp, 1),
		payload:     payload,
		payloadHash: HashPayload(payload),
		size:        len(payload) + 256, // payload plus a header estimate
		enter:       enter,
	}
	if err := a.offload(ctx, ar); err != nil {
		return nil, err
	}
	return ar, nil
}

// submit puts one unit of submission on the writer's queue.
//
// Hold the read side of submitMu across both the closing check and the send.
// Close takes the write side before closing the channel, so a producer that
// gets this far is guaranteed the channel is still open. A full queue parks the
// producer here holding the read lock, which is safe: the writer goroutine
// keeps draining, so the send completes and Close proceeds.
func (a *Appender) submit(ctx context.Context, ar *appendReq) error {
	a.submitMu.RLock()
	if a.closingLocked() {
		a.submitMu.RUnlock()
		return ErrClosed
	}
	// Stamped before the send rather than after it: a send that blocks is a
	// full queue, and a full queue is waiting for the writer by another name.
	// Stamping after would hide exactly the backpressure this is here to find.
	now := time.Now()
	for _, m := range ar.members() {
		m.queued = now
	}
	select {
	case a.reqs <- ar:
		a.submitMu.RUnlock()
		return nil
	case <-ctx.Done():
		a.submitMu.RUnlock()
		return ctx.Err()
	}
}

// closingLocked reports whether Close has begun. It must be called with
// submitMu held, which is what ties the answer to the channel's state.
func (a *Appender) closingLocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closing
}

// ErrEncryption means a payload naming a data subject could not be encrypted.
// Like a blob-store failure it fails the one append: the chain is fine, but
// writing this event in the clear would put personal data beyond the reach of a
// later erasure request, which is worse than refusing it.
var ErrEncryption = errors.New("evidence: payload encryption failed")

// encrypt seals a payload under its data subject's key, when one is named.
func (a *Appender) encrypt(r Request) ([]byte, error) {
	if a.opts.Sealer == nil || r.Subject == "" || len(r.Payload) == 0 {
		return r.Payload, nil
	}
	sealed, err := a.opts.Sealer.Seal(r.Payload, crypto.Context{
		Subject: r.Subject,
		SagaID:  r.SagaID,
		StepID:  r.StepID,
		Kind:    string(r.Kind),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: subject %s: %w", ErrEncryption, r.Subject, err)
	}
	return sealed, nil
}

// ErrPayloadStore means a payload could not be placed in content-addressed
// storage. It fails the one append rather than the whole write path: the chain
// is intact and the segment files are fine, so blocking every other caller
// would be an overreaction. The caller still gets no acknowledgement, so
// nothing may act on the event.
var ErrPayloadStore = errors.New("evidence: payload store unavailable")

// offload moves a large payload out of the chain and into content-addressed
// storage, leaving the envelope with the payload's hash and a reference.
//
// The hash was already computed over the original bytes, so the chain commits
// to the content whether or not the bytes travel with it. The store must accept
// the blob before the event is queued: an envelope that referenced a blob which
// was never written would be a dangling pointer in an audit trail.
func (a *Appender) offload(ctx context.Context, ar *appendReq) error {
	// A reference with no bytes behind it would leave the chain committing to
	// the hash of nothing — the same constant for every such event — while the
	// reference pointed at real content. The commitment would be worthless, and
	// the failure would stay invisible until an audit resolved the reference
	// and found every one of those events reporting a hash mismatch. Callers
	// that place a blob themselves still pass the bytes; the appender hashes
	// them and then drops the inline copy.
	if ar.req.PayloadRef != "" && len(ar.payload) == 0 {
		return fmt.Errorf("evidence: a payload reference was supplied with no content, so the chain "+
			"would commit to nothing; pass the bytes as well (ref %s)", ar.req.PayloadRef)
	}

	// The caller placed it: keep the hash of the real bytes, drop the copy.
	if ar.req.PayloadRef != "" {
		ar.payload = nil
		ar.size = 256
		return nil
	}

	if a.opts.CAS == nil || len(ar.payload) < a.opts.CASThresholdBytes {
		return nil
	}

	d, err := a.opts.CAS.Put(ctx, ar.payload)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrPayloadStore, a.opts.CAS.Describe(), err)
	}
	ar.req.PayloadRef = d.Ref()
	ar.payload = nil
	ar.size = 256
	return nil
}

// run is the single writer goroutine.
func (a *Appender) run() {
	defer a.wg.Done()
	batch := make([]*appendReq, 0, a.opts.MaxBatchEvents)

	for {
		first, ok := <-a.reqs
		if !ok {
			a.finalize()
			return
		}
		batch = batch[:0]
		bytes := 0
		for _, m := range first.members() {
			batch = append(batch, m)
			bytes += m.size
		}
		closed := a.fill(&batch, &bytes)
		a.writeBatch(batch)
		if closed {
			a.finalize()
			return
		}
	}
}

// fill extends the batch with whatever else is available, reporting whether the
// request channel closed while collecting.
//
// The caps are checked before a unit is taken, not while it is being unrolled,
// so a multi-record unit may carry the batch a record or two past
// MaxBatchEvents. That is the cost of the unit being indivisible, and it is the
// right way round: splitting one would hand a Ref to one of its records while
// the other was still unwritten, which is exactly what submitting them together
// is for.
func (a *Appender) fill(batch *[]*appendReq, bytes *int) bool {
	if a.opts.Linger > 0 {
		timer := time.NewTimer(a.opts.Linger)
		defer timer.Stop()
		for len(*batch) < a.opts.MaxBatchEvents && *bytes < a.opts.MaxBatchBytes {
			select {
			case r, ok := <-a.reqs:
				if !ok {
					return true
				}
				for _, m := range r.members() {
					*batch = append(*batch, m)
					*bytes += m.size
				}
			case <-timer.C:
				return false
			}
		}
		return false
	}

	for len(*batch) < a.opts.MaxBatchEvents && *bytes < a.opts.MaxBatchBytes {
		select {
		case r, ok := <-a.reqs:
			if !ok {
				return true
			}
			for _, m := range r.members() {
				*batch = append(*batch, m)
				*bytes += m.size
			}
		default:
			return false
		}
	}
	return false
}

// writeBatch chains, writes, and syncs one group commit, then answers every
// waiter in it.
func (a *Appender) writeBatch(batch []*appendReq) {
	// The moment the writer picks this batch up. Everything before it, from any
	// caller's point of view, was queueing.
	started := time.Now()
	if err := a.currentFailure(); err != nil {
		a.replyAll(batch, err)
		return
	}

	// Phase 1: chain and buffer. A request that cannot be encoded fails on its
	// own without consuming a sequence number, so one malformed event does not
	// put a hole in the log.
	seq, prev := a.seq, a.prev
	written := make([]*appendReq, 0, len(batch))
	var wroteBytes int

	// Read the attestation reference once per batch rather than per event: it
	// changes on a timer measured in minutes, so a batch shares one.
	var clockRef string
	if a.opts.ClockAttestationRef != nil {
		clockRef = a.opts.ClockAttestationRef()
	}
	for i, ar := range batch {
		// A partner in the same unit was refused, which refused this one too.
		// The caller already has its error; a second send on a one-slot channel
		// would park the writer forever.
		if ar.done {
			continue
		}
		payloadHash := ar.payloadHash
		hlc := a.clock.Now()
		wall := ar.req.Wall
		if wall.IsZero() {
			wall = a.clock.Wall()
		}
		eventID := ar.req.EventID
		if eventID == "" {
			id, err := uuid.NewV7()
			if err != nil {
				a.refuseUnit(ar, fmt.Errorf("generate event id: %w", err))
				continue
			}
			eventID = id.String()
		}

		hdr := EventHeader{
			V:           EnvelopeVersion,
			EventID:     eventID,
			Seq:         seq + 1,
			SagaID:      ar.req.SagaID,
			StepID:      ar.req.StepID,
			TraceID:     ar.req.TraceID,
			Kind:        ar.req.Kind,
			Participant: ar.req.Participant,
			TS:          Timestamps{HLC: hlc, WallUnixNanos: wall.UTC().UnixNano(), ClockAttestationRef: clockRef},
			PayloadHash: payloadHash,
			PayloadRef:  ar.req.PayloadRef,
			Subject:     ar.req.Subject,
			Labels:      a.mergeLabels(ar.req.Labels),
		}
		hdrBytes, err := EncodeHeader(hdr)
		if err != nil {
			a.refuseUnit(ar, fmt.Errorf("encode event header: %w", err))
			continue
		}
		chain := ComputeChainHash(prev, payloadHash, hdrBytes)
		rec := segment.Record{Header: hdrBytes, Prev: prev, Chain: chain, Payload: ar.payload}
		// Refused here rather than by the writer, and the difference matters:
		// an AppendRecord failure is a write-path failure and sticky, so one
		// caller with an outsized payload would stop the log for everybody
		// instead of being told no. The writer refuses it too (defence in
		// depth), which is why this check has to come first.
		//
		// Nothing has been written at this point, and `prev` is not advanced
		// until after the append, so declining here leaves the chain exactly
		// where it was.
		if n := segment.EncodedLen(rec); n > segment.MaxRecordLen {
			a.refuseUnit(ar, fmt.Errorf("%w: this event would be %d bytes and the "+
				"segment format tops out at %d. Put the body in content-addressed storage and "+
				"append its PayloadRef instead, which is what that field is for",
				segment.ErrRecordTooLarge, n, segment.MaxRecordLen))
			continue
		}
		// Where this record lands, captured before the write because Bytes()
		// is the offset of the *next* one afterwards. It is not indexed until
		// the batch is durable — see phase 3.
		ar.at = a.seg.Bytes()
		if err := a.seg.AppendRecord(hdr.Seq, rec); err != nil {
			// A write error here is a write-path failure, not a per-event one:
			// the buffer state is no longer trustworthy.
			//
			// Only requests that have not already been answered are replied to.
			// Earlier entries in this batch may have failed to encode and been
			// answered individually, and sending twice on a single-slot channel
			// would block the writer goroutine until the caller happened to
			// read again — which it never does.
			a.fail(fmt.Errorf("%w: %w", ErrWritePathFailed, err))
			a.replyAll(written, a.currentFailure())
			a.replyAll(batch[i:], a.currentFailure())
			return
		}

		seq++
		prev = chain
		wroteBytes += len(hdrBytes) + len(ar.payload)
		ar.ref = Ref{
			EventID:   eventID,
			Seq:       hdr.Seq,
			SegmentID: a.seg.SegmentID(),
			ChainHash: chain,
			HLC:       hlc,
			Wall:      wall.UTC(),
		}
		written = append(written, ar)
	}

	if len(written) == 0 {
		return
	}

	// Phase 2: the durability barrier. One flush and one sync cover the whole
	// batch, which is what makes 50k events/s affordable at fsync latencies.
	if err := a.seg.Flush(); err != nil {
		a.fail(fmt.Errorf("%w: flush: %w", ErrWritePathFailed, err))
		a.replyAll(written, a.currentFailure())
		return
	}
	if err := a.seg.Sync(); err != nil {
		a.fail(fmt.Errorf("%w: sync: %w", ErrWritePathFailed, err))
		a.replyAll(written, a.currentFailure())
		return
	}

	// Phase 3: publish. Only now is the in-memory chain head allowed to move,
	// and only now does any caller learn its event was recorded. A caller that
	// sees success here may release a side effect; one that does not, must not.
	//
	// # Everything observable is updated before anybody is told
	//
	// The order of these two loops is the point.
	// They used to be one loop that indexed a record, answered its caller, and
	// only then took statsMu — so between a caller learning its event was
	// recorded and this appender admitting to it, there was a window. With group
	// commit the window covers the whole batch, and it is not rare: **2,980 of
	// 3,000 concurrent appends** observed a counter below the Ref they had just
	// been handed. Three CI failures came out of it, in two different tests and
	// against two different counters.
	//
	// What it cost in production was worse than a flaky test and pointed the
	// opposite way to how the entry first read. `replica.FromAppender` serves
	// Stats().LastSeq as the head a follower may copy up to, so a primary dying
	// between acknowledging record N and the follower's next poll left an
	// acknowledged record the promoted replica did not have. Publishing first
	// makes the advertised head at worst *ahead* of what a caller has been told,
	// and a record that is durable but unacknowledged is the case a
	// tenure already handles by name (AcknowledgedSeq, and the adopted span).
	//
	// The cost of the reorder is one uncontended statsMu acquire moving from
	// after a loop of channel sends to before it. Measured rather than assumed,
	// because this is the most latency-sensitive code in the repository: three
	// paired `make latency-linux` runs, S4's gated-effect p50 unchanged inside a
	// noise floor of ~1 ms at concurrency 8.
	a.seq, a.prev = seq, prev
	durable := time.Now()
	for _, ar := range written {
		// Indexed here, in the publish phase, and nowhere earlier. An entry
		// added when the record was merely buffered could point into a tail
		// that is still half-written, and the locator path does not consult the
		// torn-tail machinery that would catch it.
		a.index.append(ar.req.SagaID, Location{Segment: ar.ref.SegmentID, Offset: ar.at})
	}

	a.statsMu.Lock()
	a.stats.Events += uint64(len(written))
	a.stats.Batches++
	a.stats.Bytes += uint64(wroteBytes)
	a.stats.LastSeq = seq
	a.stats.LastChain = prev
	// Per call rather than per batch, including Barrier: every caller in a
	// group commit waited the whole of it, so a mean taken over calls is what a
	// caller experienced. Summing it once per batch would report the barrier as
	// cheaper the better it amortised, which is backwards.
	//
	// Per call rather than per record for the same reason, which is what the
	// unit check is doing: the two records of an AppendPair were one caller
	// waiting once, and counting them twice would report a merged pair as
	// costing what two separate appends cost.
	barrier := durable.Sub(started)
	for _, ar := range written {
		if !ar.unitHead() {
			continue
		}
		a.phases.Prep += ar.queued.Sub(ar.enter)
		a.phases.Wait += started.Sub(ar.queued)
		a.phases.Barrier += barrier
		a.phases.Batch += uint64(len(written))
		a.phases.Appends++
	}
	a.statsMu.Unlock()

	// And only now. Nothing above this line can observe a caller's success
	// before this appender reports it.
	for _, ar := range written {
		if ar.done {
			continue
		}
		ar.resp <- appendResp{ref: ar.ref}
	}

	if a.seg.Bytes() >= a.opts.SegmentTargetBytes {
		a.rotate()
	}
}

// rotate swaps in the segment that was prepared in the background and hands the
// outgoing one to a background sealer. Neither the seal nor the file creation
// happens on the writer goroutine, so a rotation costs a pointer swap.
//
// This is what removes the stall Phase 0 measured. Both halves of a rotation
// were expensive: sealing (Merkle root, signature, full fsync) and creating the
// next file (open, header write, fsync, plus an fsync of the directory so the
// new name is durable). Together they showed up as isolated 130–210 ms outliers
// on the append path, and cost about a third of throughput.
//
// Moving the seal off the critical path is safe because a footer adds
// authentication, not durability: the records were already fsynced when their
// batch was acknowledged. A crash before the footer lands loses no acknowledged
// event; recovery seals the orphan and records the custody break.
func (a *Appender) rotate() {
	old := a.seg
	prepared, ok := <-a.nextSeg
	if !ok {
		a.fail(fmt.Errorf("%w: no segment was prepared", ErrWritePathFailed))
		return
	}
	if prepared.err != nil {
		a.fail(fmt.Errorf("%w: open segment: %w", ErrWritePathFailed, prepared.err))
		return
	}
	a.seg = prepared.w
	a.sealInBackground(old)
	a.prepareNext()
}

// preparedSegment is a segment file created ahead of the moment it is needed.
type preparedSegment struct {
	w   *segment.Writer
	err error
}

// prepareNext creates the segment after the current one, in the background.
//
// Exactly one preparation is ever outstanding: Open starts the first and every
// rotate consumes one before starting the next, so the single-slot channel can
// never block the goroutine that fills it.
func (a *Appender) prepareNext() {
	id := a.nextSegID
	a.nextSegID++
	a.prepWG.Add(1)
	go func() {
		defer a.prepWG.Done()
		w, err := segment.Create(a.opts.Dir, id, a.writerOptions())
		a.nextSeg <- preparedSegment{w: w, err: err}
	}()
}

func (a *Appender) writerOptions() segment.WriterOptions {
	return segment.WriterOptions{SyncMode: a.opts.SyncMode, Open: a.opts.OpenFile}
}

// sealInBackground finishes a segment off the writer's critical path. A failure
// here fails the whole write path: an unsigned segment is evidence nobody can
// authenticate, so continuing to accept appends would be accumulating
// unverifiable history.
func (a *Appender) sealInBackground(w *segment.Writer) {
	if w == nil {
		return
	}
	a.sealWG.Add(1)
	go func() {
		defer a.sealWG.Done()
		if err := a.sealAndClose(w); err != nil {
			a.fail(err)
		}
	}()
}

// sealAndClose signs and closes one segment, or discards it if nothing was ever
// written to it.
func (a *Appender) sealAndClose(w *segment.Writer) error {
	if w == nil || w.Sealed() {
		return nil
	}
	if w.Count() == 0 {
		// Nothing was ever written; drop the placeholder rather than sign an
		// empty segment.
		path := w.Path()
		if err := w.Close(); err != nil {
			return err
		}
		return os.Remove(path)
	}
	// Before the signature, not after: a segment that has been signed has been
	// made into history, and asking afterwards whether we were allowed to do
	// that is asking too late.
	if a.opts.BeforeSeal != nil {
		if err := a.opts.BeforeSeal(); err != nil {
			return fmt.Errorf("%w: refusing to seal segment %s: %w", ErrWritePathFailed, w.Path(), err)
		}
	}
	if _, err := w.Seal(a.signer); err != nil {
		return fmt.Errorf("%w: seal segment %s: %w", ErrWritePathFailed, w.Path(), err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("%w: close segment %s: %w", ErrWritePathFailed, w.Path(), err)
	}
	a.statsMu.Lock()
	a.stats.SegmentsSealed++
	a.statsMu.Unlock()
	return nil
}

// finalize seals the open segment when the writer goroutine stops, discards the
// unused segment that was waiting in the wings, and waits for background seals.
func (a *Appender) finalize() {
	err := a.sealAndClose(a.seg)
	a.seg = nil

	// The prepared-but-never-used segment holds no records, so sealAndClose
	// deletes rather than signs it. Waiting first guarantees it has arrived.
	a.prepWG.Wait()
	select {
	case prepared := <-a.nextSeg:
		if prepared.err == nil {
			if derr := a.sealAndClose(prepared.w); derr != nil && err == nil {
				err = derr
			}
		}
	default:
	}

	a.sealWG.Wait()

	if err != nil {
		a.mu.Lock()
		if a.closeErr == nil {
			a.closeErr = err
		}
		a.mu.Unlock()
	}
}

// mergeLabels combines the deployment's labels, the caller's, and the binding's
// — in that order, because that is the order of increasing authority.
//
// The deployment's labels are defaults and the caller may override them. The
// binding's are not defaults: they say which tenant's log this is, and the
// caller has already been refused by Append if it tried to have an opinion.
func (a *Appender) mergeLabels(l map[string]string) map[string]string {
	bound := a.opts.Tenant.Labels()
	if len(a.opts.Labels) == 0 && len(bound) == 0 {
		return l
	}
	out := make(map[string]string, len(a.opts.Labels)+len(l)+len(bound))
	for k, v := range a.opts.Labels {
		out[k] = v
	}
	for k, v := range l {
		out[k] = v
	}
	for k, v := range bound {
		out[k] = v
	}
	return out
}

func (a *Appender) fail(err error) {
	a.mu.Lock()
	if a.failed == nil {
		a.failed = err
	}
	a.mu.Unlock()
}

func (a *Appender) currentFailure() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.failed
}

// replyAll fails every request in batch. Callers must pass only requests that
// have not already been answered: each response channel holds one slot, and a
// second send would park the writer goroutine indefinitely.
func (a *Appender) replyAll(batch []*appendReq, err error) {
	for _, ar := range batch {
		if ar.done {
			continue
		}
		ar.done = true
		ar.resp <- appendResp{err: err}
	}
}

// refuseUnit refuses ar and everything submitted with it.
//
// A unit is refused whole because that is what submitting one together means:
// its records exist to be acted on as a set, and handing a Ref to one of them
// while the other was declined would give the caller permission it asked for
// only in company. AppendPair's contract is that both callers are told yes or
// both are told no.
//
// A partner that was already chained into the segment stays there. It is not
// removed from `written`, so it is indexed and counted like any other record —
// because it is one: it is in the chain, it will pass the barrier, and a reader
// will find it. Only the acknowledgement is withheld, which leaves exactly the
// durable-but-unacknowledged case a tenure already names, and exactly
// what a caller saw before this API existed when the second of two separate
// appends failed.
func (a *Appender) refuseUnit(ar *appendReq, err error) {
	for _, m := range ar.members() {
		if m.done {
			continue
		}
		m.done = true
		m.resp <- appendResp{err: err}
	}
}

// Locate reports where a saga's records are, for a reader that would otherwise
// walk the whole directory to find them.
//
// It answers only for sagas this appender has written or been taught about; a
// false means "scan", never "there are none".
func (a *Appender) Locate(sagaID string) ([]Location, bool) { return a.index.Locate(sagaID) }

// Learn takes what a full scan discovered, so the next reader does not repeat
// it. A cold process resuming many sagas pays one scan rather than one each.
func (a *Appender) Learn(index map[string][]Location, upTo uint64) { a.index.Learn(index, upTo) }

// Stats returns a snapshot of the write-path counters.
func (a *Appender) Stats() Stats {
	a.statsMu.Lock()
	s := a.stats
	a.statsMu.Unlock()
	// Measured on the way out rather than kept current: a popcount over 1 MiB
	// on every append would be a cost paid by the write path for a number
	// nobody is reading most of the time.
	s.LocatorFilterFill, s.LocatorFilterFPR = a.index.Saturation()
	return s
}

// KeyID returns the writer key id signing this log's segments.
func (a *Appender) KeyID() string { return a.signer.KeyID() }

// Tenant reports the binding this log is written under.
func (a *Appender) Tenant() tenancy.Tenant { return a.opts.Tenant }

// Signer exposes the writer's signer, for exporting its public key.
func (a *Appender) Signer() segment.Signer { return a.signer }

// Dir returns the segment directory.
func (a *Appender) Dir() string { return a.opts.Dir }

// Close drains queued events, seals the open segment, and stops the writer.
func (a *Appender) Close() error {
	a.closeOnce.Do(func() {
		// Taking the write side waits for every in-flight producer to finish
		// its send, so nothing can be mid-submission when the channel closes.
		a.submitMu.Lock()
		a.mu.Lock()
		a.closing = true
		a.mu.Unlock()
		close(a.reqs)
		a.submitMu.Unlock()

		a.wg.Wait()

		// Released last, after the writer goroutine has finished sealing. A
		// successor that took the directory while this one was still flushing
		// would be the very race the lock exists to prevent.
		if err := a.lock.release(); err != nil && a.closeErr == nil {
			a.closeErr = err
		}
	})
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closeErr != nil {
		return a.closeErr
	}
	return a.failed
}

// TenantOfDir reads the binding a log is currently written under.
//
// It exists so that a tool asking "what is this deployment pinned to" reads the
// answer out of the evidence rather than being told by whoever ran it. A
// jurisdiction supplied on a command line is a claim about a deployment; one
// read from its log is a fact about it, and a compliance report built on the
// first would be lint against a pin the deployment does not have.
//
// Newest segment first, returning the first labelled event it finds. A log that
// was bound to a tenant partway through its life should answer with the binding
// it has now, not the absence it started with. Whether a log holds *two*
// tenants is not this function's question — that is a critical finding in
// verification, which reads every record; this one stops at the first answer.
func TenantOfDir(dir string) (tenancy.Tenant, error) {
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return tenancy.Tenant{}, err
	}
	for i := len(ids) - 1; i >= 0; i-- {
		path := segment.Path(dir, ids[i])
		insp, err := segment.Inspect(path)
		if err != nil {
			return tenancy.Tenant{}, fmt.Errorf("inspect %s: %w", path, err)
		}
		for j := len(insp.Records) - 1; j >= 0; j-- {
			h, err := DecodeHeader(insp.Records[j].Header)
			if err != nil {
				return tenancy.Tenant{}, fmt.Errorf("%s record %d: %w", path, j, err)
			}
			if t := tenancy.Of(h.Labels); t.Bound() {
				return t, nil
			}
		}
	}
	return tenancy.Tenant{}, nil
}
