package segment

import (
	"errors"
	"fmt"
	"os"

	"github.com/mustafarslan/janus/pkg/evidence/merkle"
)

// Inspection is the structural state of a segment file on disk.
type Inspection struct {
	Path    string
	Header  FileHeader
	Records []Record
	// Offsets is where each record in Records begins, parallel to it. A reader
	// that wants to come back to one record without walking the segment again
	// needs this, and computing it afterwards would mean re-encoding records to
	// measure them.
	Offsets        []int64
	Footer         *Footer
	LastGoodOffset int64
	// Torn reports that the file ends in an incomplete record — the signature
	// of a crash between the write and the durability barrier. Recovery may
	// truncate to LastGoodOffset.
	Torn       bool
	TornDetail string
}

// Sealed reports whether the segment carries a footer.
func (i Inspection) Sealed() bool { return i.Footer != nil }

// IsSealed reports whether a segment file ends with a sealed footer, without
// reading the records.
//
// Recovery uses this to avoid re-reading a whole log at startup: a sealed
// segment needs no attention, and with background sealing the
// segments that do need attention are the last one or two. The check is a stat
// plus an 8-byte read, so classifying a thousand segments costs a thousand tiny
// reads rather than gigabytes.
//
// A true result means the trailing magic is present. It is not a verification —
// that is janus-verify's job — only a cheap classification.
func IsSealed(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() < int64(HeaderSize+len(EndMagic)) {
		return false, nil
	}
	var tail [len(EndMagic)]byte
	if _, err := f.ReadAt(tail[:], info.Size()-int64(len(EndMagic))); err != nil {
		return false, err
	}
	return string(tail[:]) == EndMagic, nil
}

// IsIncomplete reports whether a file is too short to be a segment at all.
//
// This is a narrower question than IsEmpty, and the difference matters to
// readers. A complete-but-empty segment is a real segment that happens to hold
// nothing; a file shorter than a header is a segment that does not exist yet,
// because the appender creates the next one ahead of time and a reader can
// observe it part-way through. Neither holds records, but only the second is a
// file a reader should pretend not to have seen.
func IsIncomplete(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Size() < int64(HeaderSize), nil
}

// IsEmpty reports whether a segment holds no records, by size alone.
//
// A segment of exactly header size was created but never written to: no batch
// was ever flushed into it, so nothing was acknowledged on its authority. That
// makes it safe to discard, which is what recovery does with the placeholder a
// crash leaves behind.
func IsEmpty(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Size() <= int64(HeaderSize), nil
}

// Inspect reads a segment structurally, tolerating a torn tail. It returns an
// error only for damage that is *not* a torn tail, because those two cases have
// opposite correct responses: truncate versus refuse and escalate.
func Inspect(path string) (Inspection, error) {
	insp := Inspection{Path: path}
	rd, err := Open(path)
	if err != nil {
		return insp, err
	}
	defer func() { _ = rd.Close() }()

	insp.Header = rd.FileHeader()
	for {
		// Before Next, because the reader advances past the record it read.
		at := rd.LastGoodOffset()
		rec, ok, err := rd.Next()
		if err != nil {
			if errors.Is(err, ErrTornTail) {
				insp.Torn = true
				insp.TornDetail = err.Error()
				break
			}
			return insp, err
		}
		if !ok {
			break
		}
		insp.Records = append(insp.Records, rec)
		insp.Offsets = append(insp.Offsets, at)
	}
	insp.LastGoodOffset = rd.LastGoodOffset()
	if f, ok := rd.Footer(); ok {
		insp.Footer = &f
	}
	return insp, nil
}

// Truncate cuts a segment file back to offset, discarding a torn tail. It is
// the only operation in Janus that removes evidence bytes, and it is safe only
// because a torn record was never acknowledged as durable: no effect can have
// been released on its authority.
func Truncate(path string, offset int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(offset); err != nil {
		return err
	}
	return syncFull(f)
}

// Seal appends a signed footer to an existing unsealed segment.
//
// This is what crash recovery uses on a segment whose writer died: the segment
// is closed out and signed by whoever recovers it. Because that is a break in
// custody, the caller is expected to record it in the log (a RECOVERY event) so
// the discontinuity is itself evidence.
//
// firstSeq and lastSeq are supplied by the caller because sequence numbers live
// inside the opaque event headers, which this package does not interpret.
func Seal(path string, firstSeq, lastSeq uint64, signer Signer) (Footer, error) {
	insp, err := Inspect(path)
	if err != nil {
		return Footer{}, err
	}
	if insp.Torn {
		return Footer{}, fmt.Errorf("refusing to seal torn segment %s: truncate first (%s)", path, insp.TornDetail)
	}
	if insp.Sealed() {
		return *insp.Footer, ErrSealed
	}

	leaves := make([][merkle.Size]byte, len(insp.Records))
	for i, r := range insp.Records {
		leaves[i] = merkle.HashLeaf(r.Chain[:])
	}
	f := Footer{
		Count:      uint32(len(insp.Records)),
		FirstSeq:   firstSeq,
		LastSeq:    lastSeq,
		MerkleRoot: merkle.Root(leaves),
		KeyID:      signer.KeyID(),
	}
	if len(insp.Records) > 0 {
		f.FirstPrev = insp.Records[0].Prev
		f.LastChain = insp.Records[len(insp.Records)-1].Chain
	}
	sig, err := signer.Sign(SigPreimage(insp.Header, f))
	if err != nil {
		return Footer{}, fmt.Errorf("sign footer: %w", err)
	}
	f.Sig = sig

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return Footer{}, err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(encodeFooterRecord(f)); err != nil {
		return Footer{}, err
	}
	if err := syncFull(file); err != nil {
		return Footer{}, err
	}
	return f, nil
}
