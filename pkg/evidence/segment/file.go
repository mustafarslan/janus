package segment

import (
	"fmt"
	"io"
	"os"
)

// File is the subset of *os.File the segment writer depends on.
//
// It exists so the fault-injection harness can substitute a file that fails on
// demand (pkg/evidence/fault). Injecting faults through the same interface
// production uses — rather than through a build tag or a test-only branch in the
// write path — means the code under test during a disk-full drill is exactly the
// code that runs in a bank.
type File interface {
	io.Writer
	io.Closer
	// Sync issues the strongest durability barrier the platform offers.
	Sync() error
	// SyncData issues the weaker data-only barrier.
	SyncData() error
	// Truncate cuts the file to n bytes.
	Truncate(n int64) error
	// Name returns the path, for error messages.
	Name() string
}

// OpenFunc creates the file backing a segment. It must fail if the path already
// exists, so a segment id is never silently reused.
type OpenFunc func(path string) (File, error)

// osFile adapts *os.File to File, routing Sync and SyncData to the
// platform-specific barriers.
type osFile struct{ f *os.File }

func (o osFile) Write(p []byte) (int, error) { return o.f.Write(p) }
func (o osFile) Close() error                { return o.f.Close() }
func (o osFile) Sync() error                 { return syncFull(o.f) }
func (o osFile) SyncData() error             { return syncData(o.f) }
func (o osFile) Truncate(n int64) error      { return o.f.Truncate(n) }
func (o osFile) Name() string                { return o.f.Name() }

// OpenReal is the production OpenFunc: a new file, exclusive create.
func OpenReal(path string) (File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("create segment: %w", err)
	}
	return osFile{f: f}, nil
}
