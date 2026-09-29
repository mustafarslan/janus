package evidence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// One writer per evidence directory, enforced by the operating system.
//
// The appender is careful about concurrency inside a process: one writer
// goroutine owns the chain, and everything else queues behind it. Across
// processes there was nothing at all, and until Phase 3 that was survivable
// because every writer was a command somebody ran on its own — a coordinator, a
// benchmark, the registry CLI. The console is the first component designed to
// run *beside* a coordinator, which turns "nobody would do that" into "this is
// the ordinary deployment".
//
// What two writers would do is worse than losing events. Each computes the next
// sequence number and the next segment id by scanning the directory at start-up,
// so both would issue the same sequence numbers, write different payloads under
// them, and chain each other's records into two divergent histories in one
// directory. The verifier would report exactly what happened — duplicated
// sequences, a chain that does not link — but only after the fact, and the log
// is the system of record precisely so that it does not need repairing.
//
// So the directory carries an advisory exclusive lock, taken by Open and held
// until Close. Two properties make this the right mechanism rather than a
// pid file:
//
// The kernel releases it when the process dies, however it dies. `make soak`
// exists to SIGKILL a writer thousands of times and requires the successor to
// pick up the same directory immediately; a lock that needed unwinding by the
// dying process would deadlock that on the first kill, and a stale-pid heuristic
// would eventually guess wrong in the direction of letting a second writer in.
//
// And it is advisory, so it constrains writers without touching readers. The
// verifier, the continuous checker, the console's read paths and every replay
// open segments read-only and are unaffected — which is what should happen,
// because reading a log somebody is writing is normal and is already handled by
// skipping the segment being created.

// lockFileName is the lock's name inside the evidence directory. It is a
// separate file rather than a lock on a segment, because segments come and go
// and the thing being protected is the directory's sequence space.
const lockFileName = ".janus-writer.lock"

// ErrLocked means another process is already writing this evidence directory.
//
// It is a distinct error because the operator response is distinct: this is not
// a corrupt log or a permissions problem, it is a second writer, and the fix is
// to find the first one rather than to repair anything.
var ErrLocked = errors.New("evidence: another process is writing this directory")

// dirLock is an exclusive advisory lock on an evidence directory.
type dirLock struct {
	f *os.File
}

// lockDir takes the writer lock, or returns ErrLocked.
func lockDir(dir string) (*dirLock, error) {
	path := filepath.Join(dir, lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("evidence: open writer lock: %w", err)
	}
	held, err := tryLock(f)
	switch {
	case err != nil:
		_ = f.Close()
		return nil, fmt.Errorf("evidence: take writer lock: %w", err)
	case !held:
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	return &dirLock{f: f}, nil
}

// release drops the lock.
//
// The file is left behind on purpose. Removing it would race a second process
// that had just opened it and was about to lock it: that process would hold a
// lock on a file no longer in the directory, and a third would create a fresh
// one and lock that instead — two writers, each holding a lock, neither wrong
// about it. An empty file is a small price for an interlock that cannot be
// tricked by its own cleanup.
func (l *dirLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unlock(l.f)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}
