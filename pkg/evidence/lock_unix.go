//go:build unix

package evidence

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes a non-blocking exclusive flock.
//
// Non-blocking is the point: a second writer must be told immediately that it
// cannot have the directory, not queue behind the first one and start writing
// whenever that one happens to stop. By then its idea of the sequence space
// would be however old the scan it did at start-up was.
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EWOULDBLOCK):
		return false, nil
	default:
		return false, err
	}
}

func unlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
