//go:build !darwin && !linux

package segment

import "os"

func syncFull(f *os.File) error { return f.Sync() }
func syncData(f *os.File) error { return f.Sync() }
