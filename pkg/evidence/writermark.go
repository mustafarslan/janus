package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Which directory is a writer's, when the bytes cannot say.
//
// # The problem
//
// Replication makes two directories the same log, and a promotion
// records a tenure *in the log*. Both are deliberate. Together they
// mean that after one failover **every replica carries the promotion's tenure**,
// because a faithful copy copies it.
//
// Two refusals were written against the tenure and meant something else:
//
//   - `replica.New` refused to follow into a directory holding a tenure, to stop
//     a follower overwriting its own promoted history at the old primary's
//     offsets. After a failover that refused every *replica* of the promoted
//     log, so `janus-replicad` could not be restarted — a routine process death
//     became a full re-seed, which at 100M events is a measured 30 GB
//     copy.
//   - `janus-replicad promote` refused a directory holding a tenure, to stop a
//     promotion recording a handover that did not happen. After a failover that
//     refused every replica too, so a deployment could fail over exactly once.
//
// Both asked "does this log contain a tenure" when the question is "is this
// directory a writer's". The log cannot answer the second — by construction, a
// replica's bytes are the writer's bytes.
//
// # What this is
//
// A node-local file beside the writer lock, written when an Appender opens the
// directory. It never enters the log, and it is never replicated: a follower
// copies `*.jseg` and nothing else (`segment.ScanDir`), so the marker stays with
// the node that wrote it.
//
// It says exactly one thing — **an appender has owned this directory** — which
// is the one-writer-per-directory invariant made durable across restarts.
// A follower's mirror has no marker because a follower is not an appender; it
// writes segments with WriteAt and never opens one.
//
// # What it is not
//
// Not evidence. Nothing verifies against it, no auditor reads it, and deleting
// it does not change what the log says — it removes a guard rail, and the two
// refusals above are the guard rail. It is operational state of the same kind as
// `.janus-writer.lock`, and it is a separate file for the same reason that one
// is: the lock is released when a process dies, and this has to outlive that.
const writerMarkFileName = ".janus-writer.json"

// WriterMark is what the marker records.
//
// The fields are for a person reading it at three in the morning to find out
// which node this directory belongs to. Nothing branches on them.
type WriterMark struct {
	// KeyID is the key the appender that most recently opened this directory
	// signs with.
	KeyID string `json:"key_id"`
	// FirstOpened is when a marker was first written here, and is preserved
	// across later opens: the useful question is when this directory became a
	// writer's, not when its daemon last restarted.
	FirstOpened time.Time `json:"first_opened"`
	// LastOpened moves on every open.
	LastOpened time.Time `json:"last_opened"`
	// Host is whatever the kernel calls this machine, best effort.
	Host string `json:"host,omitempty"`
	// Epoch is the tenure number the writer on this node serves, written by
	// `janus-replicad promote` once the tenure it recorded is durable. Zero,
	// and omitted, for a directory that has never been promoted — which is the
	// original writer, and is the right answer for it.
	//
	// It is the one field anything branches on, and it is a different question
	// from the one the log answers. TenureCount says how many promotions *the
	// log* has been through and costs a full walk (254 s at 100M events, and
	// every daemon start would pay it). This says what the promotion performed
	// *on this node* decided, which is what a writer starting here needs and is
	// one file read. The same distinction applies to "is this directory a
	// writer's": the log cannot answer a question about a node, because a
	// replica's bytes are the writer's bytes.
	//
	// Not read from the lease object, and that is the alternative worth naming:
	// the lease remembers the highest epoch it has ever seen, so an old primary
	// coming back would read the epoch that displaced it, claim it, and take
	// the lease back. The epoch has to come from something node-local or the
	// fence inverts.
	Epoch uint64 `json:"epoch,omitempty"`
	// ClockSources and ClockTolerance are what the process that most recently
	// attested its clock here was configured with — `-clock-sources` and
	// `-clock-tolerance`, as the deployment typed them.
	//
	// Nothing configures itself from them and nothing ever should. `-clock-sources`
	// is per process on purpose (an air-gapped install acquires no
	// network dependency it did not ask for), and a one-shot that silently
	// inherited a source list from a file would put an NTP call in the write path
	// of a command whose operator did not type one, using a declaration that may
	// be a month stale. What this is for is *saying which of two deployments this
	// is* when a writer finds no sources configured: one that chose not to attest,
	// or one that attests everywhere else and just lost this invocation's flag.
	//
	// Node-local and not evidence, like every other field here: an auditor reads
	// the attestations in the log, which carry the source name and the declared
	// tolerance per record. This is the hint, those are the record.
	ClockSources   []string `json:"clock_sources,omitempty"`
	ClockTolerance string   `json:"clock_tolerance,omitempty"`
}

// ReadWriterMark reports the marker, and whether there is one.
func ReadWriterMark(dir string) (WriterMark, bool, error) {
	blob, err := os.ReadFile(filepath.Join(dir, writerMarkFileName))
	if os.IsNotExist(err) {
		return WriterMark{}, false, nil
	}
	if err != nil {
		return WriterMark{}, false, fmt.Errorf("evidence: reading the writer marker: %w", err)
	}
	var m WriterMark
	if err := json.Unmarshal(blob, &m); err != nil {
		// A damaged marker still answers the only question anybody asks of it.
		// Refusing to start because a guard rail is unreadable would turn a bad
		// file into an outage, and the guard rail's whole purpose is to refuse.
		return WriterMark{}, true, nil
	}
	return m, true, nil
}

// HasWriterMark reports whether an appender has owned this directory.
func HasWriterMark(dir string) (bool, error) {
	_, ok, err := ReadWriterMark(dir)
	return ok, err
}

// SetWriterEpoch records the tenure this node's writer serves.
//
// Called by `janus-replicad promote` once the tenure record is durable, and
// never before: the epoch is only true when the log says the promotion
// happened. It requires a marker to already exist, which it does, because
// promote opened the directory as a writer to record the tenure.
func SetWriterEpoch(dir string, epoch uint64) error {
	m, ok, err := ReadWriterMark(dir)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("evidence: %s has no writer marker, so there is nothing to record "+
			"an epoch against; a directory gets one when an appender opens it", dir)
	}
	m.Epoch = epoch
	return writeWriterMark(dir, m)
}

// SetWriterClockDeclaration records what this node's writer attests its clock
// against, so a later process that was given no sources can say which kind of
// deployment it is standing in.
//
// Called by `clockwire` when a clock with sources binds to an appender, and only
// then: a process with no sources states nothing rather than recording an empty
// declaration, because "this deployment does not attest" and "this invocation
// was not told to" are the two cases this exists to tell apart.
//
// Best effort in the same sense `markWriter` is. A directory that cannot be
// written to is failing for louder reasons, and a hint is not worth failing a
// write path over.
func SetWriterClockDeclaration(dir string, sources []string, tolerance time.Duration) error {
	if len(sources) == 0 {
		return nil
	}
	m, ok, err := ReadWriterMark(dir)
	if err != nil {
		return err
	}
	if !ok {
		// No marker means no appender has opened this directory, which cannot
		// be true of a caller that just bound one. Nothing to attach the hint
		// to, and nothing worth failing over.
		return nil
	}
	m.ClockSources = sources
	m.ClockTolerance = tolerance.String()
	return writeWriterMark(dir, m)
}

// WriterClockDeclaration reports what a writer here attests against, and whether
// one ever said.
func WriterClockDeclaration(dir string) (sources []string, tolerance string, ok bool, err error) {
	m, found, err := ReadWriterMark(dir)
	if err != nil || !found || len(m.ClockSources) == 0 {
		return nil, "", false, err
	}
	return m.ClockSources, m.ClockTolerance, true, nil
}

// WriterEpoch reports the tenure this node's writer serves, and whether a
// marker said so. A directory with no marker, or a marker written before the
// field existed, answers (0, false) — which the caller reads as the original
// writer's epoch.
func WriterEpoch(dir string) (uint64, bool, error) {
	m, ok, err := ReadWriterMark(dir)
	if err != nil || !ok {
		return 0, false, err
	}
	return m.Epoch, m.Epoch > 0, nil
}

// markWriter stamps the directory, preserving FirstOpened and Epoch if one is
// already there.
//
// Best effort in one respect only: a directory that cannot be written to is
// about to fail for much louder reasons, and returning an error here would make
// this the one that gets reported. Every other failure is returned.
func markWriter(dir, keyID string) error {
	now := time.Now().UTC()
	prev, existed, err := ReadWriterMark(dir)
	if err != nil {
		return err
	}
	m := WriterMark{KeyID: keyID, FirstOpened: now, LastOpened: now}
	if existed {
		if !prev.FirstOpened.IsZero() {
			m.FirstOpened = prev.FirstOpened
		}
		// Carried, and this is the one that matters. Open runs on every daemon
		// start, so an epoch dropped here would survive exactly until the
		// promoted writer was restarted — the moment it is needed — and the
		// fence would refuse a legitimate start because the writer had
		// forgotten which tenure it serves.
		m.Epoch = prev.Epoch
		// Carried for a smaller reason: every writer opens this directory, and
		// most of them have no clock configuration to state. Dropping the
		// declaration on an unattested one-shot would erase the hint at exactly
		// the moment it is being given.
		m.ClockSources, m.ClockTolerance = prev.ClockSources, prev.ClockTolerance
	}
	if host, err := os.Hostname(); err == nil {
		m.Host = host
	}
	return writeWriterMark(dir, m)
}

func writeWriterMark(dir string, m WriterMark) error {
	blob, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, writerMarkFileName), append(blob, '\n'), 0o640)
}
