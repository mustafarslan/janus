package evidence

import (
	"log"
	"sort"
	"sync"
)

// Finding one saga's events without reading everybody else's.
//
// `LoadEvents` and `EvidenceRoot` each walked the whole segment directory to
// collect the handful of records belonging to one saga, and a saga paid for
// both — once starting and once committing. At 2000 sagas in the log that was
// 47 ms of a 55 ms saga, and it grew with the log rather than with the saga.
//
// Most of that cost is not I/O. Framing 16,000 records in one segment measures
// 3.0 ms; CBOR-decoding all their headers to find the eight that matched takes
// it to 13.5 ms. So the fix is to stop decoding headers nobody wants, and the
// way to do that is to know where the wanted records are before opening the
// file.
//
// # Why the appender owns the index
//
// It wrote the records, so it knows the offsets for nothing. Everything else
// would have to derive them by doing the scan this exists to avoid.
//
// Entries are added at *publish* time, in the same phase that moves the
// acknowledged head — after the flush and the sync, never when the record is
// merely buffered. An index built at buffer time could point at bytes that are
// still half-written, which is the torn-tail problem coming back through a side door: the
// locator path does not consult the torn-tail machinery, so its entries have to
// be durable by construction instead.
//
// # Why a miss is not a failure
//
// A locator answers "I know" or "I do not know", never "there are none". A
// reader that gets "I do not know" falls back to the full scan, which is always
// correct — and, on its way past, learns every saga it saw so the next reader
// does not repeat it. That is what keeps a cold restart affordable: resuming
// 10k in-flight sagas costs one scan in total rather than 10k of them.
//
// # What holds it honest
//
// The risk here is omission, not corruption. Per-record verification still
// happens at every call site, so a record the index points at cannot be a
// forgery; but an index that silently *dropped* an event would yield a short
// history and an evidence root that is wrong and looks valid — fail-open
// shaped. Two things catch that: the equivalence
// test in this package compares a locator-backed read against a full scan under
// concurrent appends, and `janus-spotreplay` recomputes commit roots offline by
// full scan, which is the independent check that notices afterwards.

// Location is where one record sits: which segment, and the byte offset of its
// length prefix within that file.
type Location struct {
	Segment uint64
	Offset  int64
}

// Locator answers where a saga's records are, for readers that would otherwise
// walk the directory to find out.
type Locator interface {
	// Locate returns the locations of sagaID's records in log order. The bool
	// reports whether the answer is authoritative; false means "scan".
	//
	// An authoritative answer may be empty, and that case is the one that
	// matters most: starting a saga that does not exist yet is the commonest
	// read in the system, and without it every new saga pays a full scan to
	// discover it has no history.
	Locate(sagaID string) ([]Location, bool)
	// Learn takes what a full scan discovered, so the scan is paid once. upTo
	// is the sequence the scan reached, which is what lets the locator start
	// answering "no records" for sagas it has never heard of.
	Learn(index map[string][]Location, upTo uint64)
}

// sagaIndex is the appender's locator: saga id to record locations.
//
// # The bound, and why it is a generation swap rather than an LLU
//
// Unbounded, this grows with the log forever — at the plan's 50k events/s that
// is tens of gigabytes a day, which would be a new defect shipped inside a
// performance fix. Evicting on saga completion is the obvious rule and it is
// wrong: the release path reads a *committed* saga (`LogAuthority.Committed`)
// shortly after its commit, so evicting there would send every release to a
// full scan.
//
// So the bound is on count, not on lifecycle. Two generations: writes land in
// the young map, a lookup in the old map promotes into the young one, and when
// the young map fills it becomes the old one and a fresh map takes its place.
// Anything that falls out is not lost, only forgotten — the reader scans, and
// the scan teaches it again. That is a cache in the only sense the design permits: it
// holds nothing that cannot be rebuilt from the segments, and being wrong about
// what it holds costs time rather than truth.
type sagaIndex struct {
	mu       sync.Mutex
	capacity int
	young    map[string][]Location
	old      map[string][]Location

	// seen is every saga id this index has ever written or been taught, kept
	// separately from the locations because it has to outlive them.
	//
	// It exists for one answer: "this saga has no records at all." Without it,
	// starting a saga pays a full scan to discover it is new — which is the
	// commonest read there is. With it, a miss in `seen` is conclusive.
	//
	// A Bloom filter rather than a set, because a set is the unbounded thing
	// the generations exist to avoid. The error is one-sided in the direction
	// that is safe: a saga that *was* written always tests positive, so the
	// only cost of a false positive is a scan that finds what it was looking
	// for. A false negative would be an index claiming a saga is empty when it
	// is not, and this structure cannot produce one.
	//
	// It is never reset. Clearing it would turn ids that were written into ids
	// that test absent, which is exactly the false negative it must not have.
	// As it fills, the false-positive rate rises and more reads fall back to
	// scanning — slower, still correct.
	seen *bloom

	// adds counts insertions since the last saturation check, and warned marks
	// which thresholds have already been reported. Both exist because the
	// filter's decay is the one failure here that produces no wrong answers:
	// as it fills, more reads fall back to scanning, everything stays correct,
	// and the only symptom is that starting a saga gets slower over months.
	// Nobody notices that until it is the incident, so it is said out loud.
	adds   int
	warned int

	// complete reports that `seen` covers the whole directory. Until a full
	// scan establishes that — or the log is empty at open, which establishes it
	// trivially — a miss means "scan", because the records may predate this
	// process.
	complete bool
}

func newSagaIndex(capacity int) *sagaIndex {
	if capacity <= 0 {
		capacity = defaultLocatorSagas
	}
	return &sagaIndex{
		capacity: capacity,
		young:    make(map[string][]Location),
		old:      make(map[string][]Location),
		seen:     newBloom(bloomBits, bloomHashes),
	}
}

// saturationCheckEvery bounds how often the filter is measured.
//
// A popcount over 1 MiB is tens of microseconds and this runs under the index
// lock, so it is not free; once per 65,536 insertions makes it invisible against
// the appends that produced them, and the thing being watched moves over months.
const saturationCheckEvery = 1 << 16

// saturationWarnAt are the false-positive rates worth interrupting somebody for,
// in order.
//
// Two, not a continuum: at 5% one new-saga read in twenty pays a full scan,
// which is a slope somebody should see the start of, and at 25% the fallback is
// the common path rather than the exception. A line per crossing, never repeated
// — a warning that reappears is a warning that gets filtered.
var saturationWarnAt = []float64{0.05, 0.25}

// checkSaturation reports the filter's decay, at most once per threshold.
// Called with the lock held.
func (x *sagaIndex) checkSaturation() {
	x.adds++
	if x.adds%saturationCheckEvery != 0 || x.warned >= len(saturationWarnAt) {
		return
	}
	fill, fpr := x.seen.saturation()
	crossed := x.warned
	for x.warned < len(saturationWarnAt) && fpr >= saturationWarnAt[x.warned] {
		x.warned++
	}
	// Only when this call crossed one. Reporting whenever `warned` is non-zero
	// says the same line every 65,536 appends for the rest of the process's
	// life, which is the repetition the thresholds exist to avoid — and is what
	// this did until its own test counted the lines.
	if x.warned == crossed {
		return
	}
	log.Printf("evidence: the record locator's saga filter is %.1f%% full, a false-positive "+
		"rate of %.1f%%: that share of reads for a saga with no records now pays a full "+
		"scan instead of answering from the index. The filter is fixed at 1 MiB and is "+
		"never reset — it is rebuilt from the log on disk, so this is the log's age and "+
		"not this process's, and a restart does not clear it",
		fill*100, fpr*100)
}

// Saturation reports how full the seen-filter is and the false-positive rate
// that implies, for a caller that would rather poll than wait to be told.
func (x *sagaIndex) Saturation() (fill, falsePositiveRate float64) {
	if x == nil {
		return 0, 0
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.seen.saturation()
}

// markComplete records that this index covers every saga in the directory,
// which an appender opening an empty log knows without reading anything.
func (x *sagaIndex) markComplete() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.complete = true
}

// defaultLocatorSagas bounds the young generation, so at most twice this many
// sagas are remembered. At roughly ten events each it is a few megabytes, and
// it comfortably covers the target of 10k concurrent sagas per node.
const defaultLocatorSagas = 50_000

func (x *sagaIndex) Locate(sagaID string) ([]Location, bool) {
	if x == nil || sagaID == "" {
		return nil, false
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	// Nothing here is authoritative until this index has seen the whole
	// directory. A process that started on an existing log knows only what it
	// has written since, so a saga it has appended one event to would otherwise
	// look like a saga with exactly one event — which is what a restarted
	// coordinator resuming mid-saga does, and the hosted chaos suite found it
	// as "replay event 0 (seq 14): unknown step". An index that returns a
	// saga's tail as its history is the omission failure this whole design is
	// arranged around.
	if !x.complete {
		return nil, false
	}
	if locs, ok := x.young[sagaID]; ok {
		return locs, true
	}
	if locs, ok := x.old[sagaID]; ok {
		// Promote, so a saga still being read does not fall out of the next
		// swap.
		x.young[sagaID] = locs
		return locs, true
	}
	// Not in either generation. Either it was never written, or it aged out.
	// `seen` is what tells those apart, and only in one direction: absent from
	// the filter means it was never written, so there is nothing to find.
	if x.complete && !x.seen.mayContain(sagaID) {
		return nil, true
	}
	return nil, false
}

func (x *sagaIndex) Learn(index map[string][]Location, upTo uint64) {
	if x == nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	for id, locs := range index {
		x.seen.add(id)
		// Union, not replace. The scan holds the whole history as of the moment
		// it ran; the appender may have added more since, and may hold records
		// the scan's prefix stopped short of. Taking either one alone drops the
		// other's, which is the omission this must not have. Locations sort by
		// (segment, offset), which is log order.
		x.young[id] = mergeLocations(x.young[id], locs)
	}
	// Only now: a scan that completed saw every saga in the directory, and this
	// appender is the only writer, so from here the index is current for
	// everything and a miss can be answered rather than re-scanned.
	x.complete = true
	x.swapIfFull()
}

// mergeLocations unions two location lists into log order, dropping duplicates.
func mergeLocations(a, b []Location) []Location {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := make([]Location, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	byOffset(out)
	n := 0
	for i, l := range out {
		if i > 0 && l == out[n-1] {
			continue
		}
		out[n] = l
		n++
	}
	return out[:n]
}

// append records one more location for a saga the appender has just published.
func (x *sagaIndex) append(sagaID string, loc Location) {
	if x == nil || sagaID == "" {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.seen.add(sagaID)
	x.checkSaturation()
	if _, ok := x.young[sagaID]; !ok {
		// Carry forward what the old generation knows, so a saga whose earlier
		// events aged out does not end up with a locator entry holding only its
		// tail — which would be an index that omits records, the one failure
		// this must not have. Absent from both is fine: the reader scans.
		if prior, ok := x.old[sagaID]; ok {
			x.young[sagaID] = append(append([]Location{}, prior...), loc)
			x.swapIfFull()
			return
		}
	}
	x.young[sagaID] = append(x.young[sagaID], loc)
	x.swapIfFull()
}

func (x *sagaIndex) swapIfFull() {
	if len(x.young) < x.capacity {
		return
	}
	x.old, x.young = x.young, make(map[string][]Location, x.capacity/2)
}

// byOffset puts locations into log order: segment first, then position within
// it, which is the order the appender wrote them in.
func byOffset(locs []Location) {
	sort.Slice(locs, func(i, j int) bool {
		if locs[i].Segment != locs[j].Segment {
			return locs[i].Segment < locs[j].Segment
		}
		return locs[i].Offset < locs[j].Offset
	})
}
