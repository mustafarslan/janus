//go:build linux

package segment

import (
	"os"
	"syscall"
)

// syncFull issues fsync(2), flushing data and metadata.
func syncFull(f *os.File) error { return f.Sync() }

// syncData issues fdatasync(2): the file data is durable but inode metadata
// other than size may lag. Segments are append-only and preallocation is not
// used, so this is sufficient for record durability.
func syncData(f *os.File) error {
	for {
		err := syscall.Fdatasync(int(f.Fd()))
		if err != syscall.EINTR {
			return err
		}
	}
}
