package fence

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/objstore"
)

// Flags is the operator-facing surface of the fence.
//
// Off by default, and that is a decision rather than caution. Arming it makes an
// unreachable object store into a stop on the write path, and a
// deployment that would rather risk a fork than an outage is making a defensible
// choice about its own risk. The
// dependency wants to be asked for.
type Flags struct {
	bucket    string
	key       string
	endpoint  string
	accessKey string
	secretKey string
	pathStyle bool
	prefix    string
	epoch     uint64
	establish bool
	ttl       time.Duration
}

// RegisterFlags adds the fence flags to a flag set.
func RegisterFlags(fs *flag.FlagSet) *Flags {
	f := &Flags{}
	fs.StringVar(&f.bucket, "fence-bucket", "", "object-store bucket holding the writer lease. "+
		"Empty leaves the fence off, which is the default: nothing then prevents two writers "+
		"for one log, only names them afterwards.")
	fs.StringVar(&f.key, "fence-key", "tenure/lease.json", "lease object key within the bucket")
	fs.StringVar(&f.endpoint, "fence-endpoint", os.Getenv("JANUS_S3_ENDPOINT"), "S3 endpoint for the lease bucket (empty for AWS)")
	fs.StringVar(&f.accessKey, "fence-access-key", os.Getenv("JANUS_S3_ACCESS_KEY"), "access key (empty uses the ambient credential chain)")
	fs.StringVar(&f.secretKey, "fence-secret-key", os.Getenv("JANUS_S3_SECRET_KEY"), "secret key")
	fs.BoolVar(&f.pathStyle, "fence-path-style", true, "address the bucket as /bucket/key, which MinIO and most appliances need")
	fs.StringVar(&f.prefix, "fence-prefix", "", "key prefix within the bucket")
	fs.Uint64Var(&f.epoch, "fence-epoch", 0, "tenure number this writer serves under.\n"+
		"**Normally not needed.** `janus-replicad promote` records the epoch in this\n"+
		"directory's writer marker when the tenure becomes durable, and janus-orchd reads it\n"+
		"from there. Pass this only to migrate a directory promoted before that\n"+
		"existed; a value contradicting the marker is refused rather than guessed.\n"+
		"**It decides who wins.** A writer at a higher epoch takes the lease from a live\n"+
		"writer at a lower one, which is how a promotion displaces a primary that is\n"+
		"partitioned from its clients but not from the bucket; a writer at a lower epoch is\n"+
		"refused even when the lease has expired. So too high steals a lease that was\n"+
		"legitimately held, and too low refuses a legitimate start. The original writer runs\n"+
		"at 0. `janus-replicad promote` does not accept this flag at all: it derives its own\n"+
		"from the log, because a number that decides who wins should not be one an operator\n"+
		"can mistype.")
	fs.DurationVar(&f.ttl, "fence-ttl", 30*time.Second, "how long the lease stays valid without a renewal.\n"+
		"This is two things at once and both are costs: the floor on how long a takeover must\n"+
		"wait after a writer dies, and the ceiling on how long a partitioned writer can go on\n"+
		"sealing. The default is a guess; the measurement that would justify another is a\n"+
		"deployment's RTO.")
	return f
}

// Establishing overrides -fence-epoch and says this process is taking the epoch
// for the first time rather than serving one it was given.
//
// `janus-replicad promote` is the only caller, and both halves are the same
// decision: the number comes from the log because it decides who wins, and a
// promotion that finds it already taken has nothing to take, however long ago
// that happened. See Config.Establish.
func (f *Flags) Establishing(n uint64) { f.epoch, f.establish = n, true }

// Serving sets the epoch this writer runs at without claiming to be taking it.
//
// `janus-orchd` is the caller, with the number the writer marker on this node
// records. Distinct from Establishing because a restart is not a
// promotion: an expired lease at this epoch is this writer's own, left behind
// by the process that died, and taking it back is exactly right.
func (f *Flags) Serving(n uint64) { f.epoch = n }

// EpochSupplied reports whether the operator passed -fence-epoch, so a caller
// that would otherwise resolve the epoch itself can tell an override from a
// default.
func (f *Flags) EpochSupplied(fs *flag.FlagSet) bool {
	supplied := false
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "fence-epoch" {
			supplied = true
		}
	})
	return supplied
}

// Epoch reports the epoch currently configured.
func (f *Flags) Epoch() uint64 { return f.epoch }

// ResolveEpoch decides which tenure this writer serves and says so, or refuses.
//
// The rule, and every branch of it is a case somebody hits:
//
//   - the marker records an epoch and no flag was given: the marker. This is
//     the normal path after a promotion, and it is why the flag exists to be
//     forgotten rather than remembered.
//   - no marker epoch and no flag: zero, the original writer. Also every
//     directory written before this field existed.
//   - a flag and no marker epoch: the flag. RecordEpoch stamps it later, once
//     the directory is open — this runs before that, because the lease is taken
//     at start-up and before anything touches the log, so a
//     resolution that insisted on writing here would refuse a directory whose
//     marker had been deleted: exactly the case -fence-epoch is the documented
//     way back from, and the one it would then be useless for.
//   - both, agreeing: fine.
//   - both, disagreeing: refused, naming both numbers. One of them is wrong,
//     and the lease cannot arbitrate in time for the direction that matters: a
//     marker at 0 with a stray -fence-epoch 1 takes the log from a writer that
//     legitimately holds it. The escape is to correct the marker, which is
//     operational state an operator may edit.
func (f *Flags) ResolveEpoch(dir string, fs *flag.FlagSet) error {
	if !f.Enabled() {
		return nil
	}
	// ReadWriterMark rather than WriterEpoch, because the two absences are
	// different and one of them used to be invisible here: a directory with no
	// marker at all, and a marker written before this field existed. Only the
	// second is something a supplied flag can contradict.
	mark, _, err := evidence.ReadWriterMark(dir)
	if err != nil {
		return err
	}
	marked := mark.Epoch
	if !f.EpochSupplied(fs) {
		f.Serving(marked)
		return nil
	}
	if marked == 0 {
		return nil
	}
	if marked != f.epoch {
		return fmt.Errorf("fence: -fence-epoch %d contradicts this directory's writer marker, "+
			"which says the writer here serves epoch %d.\n\n"+
			"The epoch decides which writer wins, so the two cannot both be right and this "+
			"will not guess. The marker is written by `janus-replicad promote` when the "+
			"tenure it recorded became durable, so it is usually the one to trust; drop the "+
			"flag and it is what this writer serves. If the marker is the wrong one, it is "+
			"node-local operational state and can be corrected in %s",
			f.epoch, marked, dir)
	}
	return nil
}

// RecordEpoch writes a supplied -fence-epoch into the directory's writer marker,
// so it is needed once rather than at every start.
//
// Called after the log is open, which is when there is a marker to write to.
// Does nothing when the operator supplied nothing, when the fence is off, or
// when the marker already agrees — ResolveEpoch has already refused the case
// where it disagrees.
//
// A failure is reported and not fatal: the daemon is running and fenced at the
// right epoch, and the only cost of not recording it is that the next start
// needs the flag again. Refusing to serve over a bookkeeping write would be the
// larger outage.
//
// The cost worth naming is on the other side. Recording a supplied flag makes a
// mistyped one *persistent*: before, a wrong -fence-epoch was one bad start;
// now it is in the marker, and the contradiction check only guards the next
// disagreement, not the one that put it there. That is the price of the
// deleted-marker recovery path working at all, and it is the right way round —
// the lease still refuses a writer whose epoch is below the log's.
func (f *Flags) RecordEpoch(dir string) error {
	if !f.Enabled() || f.epoch == 0 {
		return nil
	}
	mark, ok, err := evidence.ReadWriterMark(dir)
	if err != nil {
		return err
	}
	if !ok || mark.Epoch == f.epoch {
		return nil
	}
	return evidence.SetWriterEpoch(dir, f.epoch)
}

// Enabled reports whether the operator asked for a fence.
func (f *Flags) Enabled() bool { return f != nil && f.bucket != "" }

// Open builds the lease, probes the bucket, and acquires it.
//
// The order matters and each step refuses rather than warns:
//
//   - probe, because a store that does not enforce conditional writes accepts
//     every write and lets both writers believe they hold the lease;
//   - acquire, because finding out at start-up that another writer holds this
//     log is better than finding out at the first seal, when a whole segment's
//     worth of appends has already happened.
//
// Returns (nil, nil) when the fence is off, so a caller can pass the result
// straight through without branching twice.
func (f *Flags) Open(ctx context.Context, holder string) (*Lease, error) {
	if !f.Enabled() {
		return nil, nil
	}
	store, err := objstore.New(ctx, objstore.Config{
		Endpoint:     f.endpoint,
		Bucket:       f.bucket,
		AccessKey:    f.accessKey,
		SecretKey:    f.secretKey,
		UsePathStyle: f.pathStyle,
		Prefix:       f.prefix,
	})
	if err != nil {
		return nil, fmt.Errorf("fence: opening the lease bucket: %w", err)
	}
	// Without Object Lock: the lease is mutable by design — it is renewed, and
	// stolen when it expires — which is the opposite of what the WORM tier
	// wants from a bucket. Do not point this at the archive bucket.
	if err := store.EnsureBucket(ctx, false); err != nil {
		return nil, fmt.Errorf("fence: preparing the lease bucket %s: %w", f.bucket, err)
	}
	l, err := New(Config{
		Store: store, Key: f.key, Holder: holder, Epoch: f.epoch, TTL: f.ttl,
		Establish: f.establish,
		Notify:    func(msg string) { fmt.Fprintf(os.Stderr, "fence: %s\n", msg) },
	})
	if err != nil {
		return nil, err
	}
	if err := l.Arm(ctx); err != nil {
		return nil, err
	}
	if err := l.Acquire(ctx); err != nil {
		return nil, err
	}
	return l, nil
}

// WarnIfUnfenced prints the one line an operator needs when the fence is off.
//
// It is a warning and not a refusal, because a single-region deployment with one
// writer has nothing to fence and should not be made to configure an object
// store to say so. What it must not do is stay silent: "nothing prevents two
// writers" is the kind of property people assume is handled.
func (f *Flags) WarnIfUnfenced(prog string) {
	if f.Enabled() {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: no writer fence (-fence-bucket unset). Two processes writing "+
		"this log would both succeed and both produce valid history; a fork is detected "+
		"afterwards and not prevented.\n", prog)
}

// CheckOrNil is Check, nil-safe, so a caller can wire it as a hook without
// knowing whether the fence is on. An unfenced deployment passes a nil *Lease
// and every check answers nil, which is the unfenced behaviour.
func (l *Lease) CheckOrNil() error {
	if l == nil {
		return nil
	}
	return l.Check()
}
