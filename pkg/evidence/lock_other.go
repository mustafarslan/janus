//go:build !unix

package evidence

import (
	"fmt"
	"os"
	"runtime"
)

// tryLock refuses to open a log at all on a platform whose file locking this
// build does not implement.
//
// Returning "locked" or "not locked" would both be lies, and the safer-looking
// lie is the dangerous one: reporting the lock as taken would let every process
// on the platform believe it holds an interlock that does not exist. Janus
// targets Linux and macOS; anything else has to add its own
// implementation here before it can write evidence.
func tryLock(f *os.File) (bool, error) {
	return false, fmt.Errorf("evidence: no writer-lock implementation for %s, so a second "+
		"writer could not be prevented from corrupting the sequence space", runtime.GOOS)
}

func unlock(f *os.File) error { return nil }
