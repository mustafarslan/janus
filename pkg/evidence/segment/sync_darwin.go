//go:build darwin

package segment

import (
	"os"
	"syscall"
)

// syncFull requests a full barrier flush. On darwin os.File.Sync issues
// F_FULLFSYNC, which waits for the drive to flush its write cache — the only
// mode that actually survives power loss on Apple hardware.
func syncFull(f *os.File) error { return f.Sync() }

// syncData issues a plain fsync(2). On darwin this pushes the data to the
// device but does not force the device cache, so it is faster and weaker than
// syncFull. Benchmarks report both because the difference on this platform is
// an order of magnitude.
func syncData(f *os.File) error {
	for {
		err := syscall.Fsync(int(f.Fd()))
		if err != syscall.EINTR {
			return err
		}
	}
}
