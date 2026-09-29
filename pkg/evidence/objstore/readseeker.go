package objstore

import "bytes"

// newReadSeeker wraps a byte slice as a seekable reader.
//
// The S3 client needs to rewind a request body to retry or to sign it, and a
// plain bytes.Reader already does that — this exists only to keep the
// construction in one place and to make the requirement explicit rather than
// incidental.
func newReadSeeker(b []byte) *bytes.Reader { return bytes.NewReader(b) }
