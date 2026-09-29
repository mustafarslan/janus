// Package fault injects storage failures into the evidence write path.
//
// The Phase 1 exit criterion is that the chain never silently corrupts: under a
// disk that fills up, a write that lands half a record, or a barrier that
// refuses, Janus must either keep going correctly or stop — never continue while
// quietly producing evidence that will not verify. Proving that needs faults
// that can be triggered on demand, which real hardware does not offer.
//
// The injector substitutes segment.File through the same seam production uses,
// so the code exercised during a disk-full drill is the code that runs in a
// bank. It deliberately wraps the real filesystem rather than emulating one: a
// partial write really does leave a partial record on disk, so recovery has
// genuine damage to find.
package fault

import (
	"sync"
	"syscall"

	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// Errors returned by an injected fault. Real errno values are used so that any
// code matching on them behaves as it would against a real filesystem.
var (
	// ErrNoSpace is what a full disk returns.
	ErrNoSpace = syscall.ENOSPC
	// ErrIO is what a failing device returns.
	ErrIO = syscall.EIO
)

// Config describes when to fail. The zero value never fails.
type Config struct {
	// WriteBudgetBytes caps how many bytes may be written across every segment
	// before writes start returning ENOSPC — a disk filling up. The write that
	// crosses the budget is truncated to the bytes that still fit and then
	// fails, which is what leaves a half-written record on disk.
	WriteBudgetBytes int64

	// FailSyncAfter makes every durability barrier from the Nth onwards fail.
	// Counting from one; zero disables.
	FailSyncAfter int

	// FailCreateAfter makes segment creation fail from the Nth onwards.
	// Counting from one; zero disables.
	FailCreateAfter int
}

// FS creates segment files that fail according to a Config.
//
// It is safe for concurrent use: segment creation, background sealing, and the
// writer goroutine all touch it at once.
type FS struct {
	mu      sync.Mutex
	cfg     Config
	stats   Stats
	stopped bool
}

// Stats counts what the injector saw and did.
type Stats struct {
	BytesWritten  int64
	Writes        int
	Syncs         int
	Creates       int
	WriteFailures int
	SyncFailures  int
	ShortWrites   int
}

// New returns an injector configured by cfg.
func New(cfg Config) *FS { return &FS{cfg: cfg} }

// Stats returns a snapshot of the counters.
func (fs *FS) Stats() Stats {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.stats
}

// Stop makes every subsequent write and barrier fail immediately, modelling a
// device that dies mid-flight rather than one that fills up gradually.
func (fs *FS) Stop() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.stopped = true
}

// Open implements segment.OpenFunc.
func (fs *FS) Open(path string) (segment.File, error) {
	fs.mu.Lock()
	fs.stats.Creates++
	n, stopped, limit := fs.stats.Creates, fs.stopped, fs.cfg.FailCreateAfter
	fs.mu.Unlock()

	if stopped || (limit > 0 && n >= limit) {
		return nil, ErrIO
	}
	inner, err := segment.OpenReal(path)
	if err != nil {
		return nil, err
	}
	return &file{fs: fs, inner: inner}, nil
}

// reserve decides how much of a write is allowed through. A return of
// (k, ErrNoSpace) with k > 0 is the interesting case: those bytes really are
// written, so the file ends mid-record exactly as it would on a full disk.
func (fs *FS) reserve(n int) (int, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.stats.Writes++
	if fs.stopped {
		fs.stats.WriteFailures++
		return 0, ErrIO
	}
	if fs.cfg.WriteBudgetBytes <= 0 {
		fs.stats.BytesWritten += int64(n)
		return n, nil
	}
	remaining := fs.cfg.WriteBudgetBytes - fs.stats.BytesWritten
	switch {
	case remaining <= 0:
		fs.stats.WriteFailures++
		return 0, ErrNoSpace
	case int64(n) <= remaining:
		fs.stats.BytesWritten += int64(n)
		return n, nil
	default:
		fs.stats.BytesWritten = fs.cfg.WriteBudgetBytes
		fs.stats.WriteFailures++
		fs.stats.ShortWrites++
		return int(remaining), ErrNoSpace
	}
}

// syncFault reports whether this barrier should fail.
func (fs *FS) syncFault() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.stats.Syncs++
	if fs.stopped {
		fs.stats.SyncFailures++
		return ErrIO
	}
	if fs.cfg.FailSyncAfter > 0 && fs.stats.Syncs >= fs.cfg.FailSyncAfter {
		fs.stats.SyncFailures++
		return ErrIO
	}
	return nil
}

// file is a real segment file with a fault policy in front of it.
type file struct {
	fs    *FS
	inner segment.File
}

func (f *file) Write(p []byte) (int, error) {
	allowed, err := f.fs.reserve(len(p))
	if allowed <= 0 {
		return 0, err
	}
	n, werr := f.inner.Write(p[:allowed])
	if werr != nil {
		return n, werr
	}
	// A short write must report an error, or callers will believe it completed.
	return n, err
}

func (f *file) Sync() error {
	if err := f.fs.syncFault(); err != nil {
		return err
	}
	return f.inner.Sync()
}

func (f *file) SyncData() error {
	if err := f.fs.syncFault(); err != nil {
		return err
	}
	return f.inner.SyncData()
}

func (f *file) Truncate(n int64) error { return f.inner.Truncate(n) }
func (f *file) Close() error           { return f.inner.Close() }
func (f *file) Name() string           { return f.inner.Name() }
