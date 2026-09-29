package worm

import "os"

// readFile loads a segment for upload. Segments are bounded by
// SegmentTargetBytes (16 MiB by default), so reading one whole is fine and
// keeps the digest-then-upload sequence simple.
func readFile(path string) ([]byte, error) { return os.ReadFile(path) }
