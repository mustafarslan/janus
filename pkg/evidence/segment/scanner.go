package segment

// Scanner lists a growing directory without re-asking what cannot have changed.
//
// `ScanComplete` is one readdir and then a stat per file, and the stats are the
// cost: at 10,000 segments the readdir is 4.1 ms and the whole call is 21.5 ms.
// An earlier measurement recorded this as "that is the readdir", which is what
// made it read as irreducible — a readdir is what a directory listing *is*, and
// four fifths of the call was something else.
//
// The stats answer one question: is this file too short to hold a header? Only
// the newest file can be, because segments are created in id order ahead of a
// rotation, and a crash leaves the placeholder at the tail. So a
// segment that has once been seen complete stays complete: files grow, and a
// file that shrinks below its header has been truncated, which is tampering and
// is caught by the chain rather than by a listing — the argument `ScanComplete`
// already makes for skipping such a file in the first place.
//
// It remembers only the positive answers. It still does the readdir every
// call, because a new segment can appear at any moment and nothing else would
// see it.
//
// # Why the caller owns it
//
// A cache inside `ScanComplete` would be a cache nobody owns, shared by
// twenty-odd call sites with different lifetimes — a verifier that runs once, a
// follower that polls forever, a recovery pass that must see files this
// deliberately hides. Ownership is the design: a caller with a lifetime holds a
// Scanner, and everything else keeps calling `ScanComplete`.
type Scanner struct {
	dir string
	// complete is every id this scanner has already found to hold a header.
	// Only positive answers go in: a follower's own tail file is legitimately
	// below header size while it is being written into, and caching that would
	// hide it from the next pass after it filled.
	complete map[uint64]struct{}
}

// NewScanner returns a Scanner over dir.
func NewScanner(dir string) *Scanner {
	return &Scanner{dir: dir, complete: map[uint64]struct{}{}}
}

// Complete is ScanComplete, skipping the stat for every id already known to be
// complete.
//
// The returned slice is freshly allocated and ascending, the same as
// ScanComplete's, so a caller may keep or mutate it.
func (s *Scanner) Complete() ([]uint64, error) {
	ids, err := ScanDir(s.dir)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(ids))
	for _, id := range ids {
		if _, known := s.complete[id]; known {
			out = append(out, id)
			continue
		}
		incomplete, err := IsIncomplete(Path(s.dir, id))
		if err != nil {
			return nil, err
		}
		if incomplete {
			continue
		}
		s.complete[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// Forget drops what this scanner has learned.
//
// For a caller that has rewound far enough that it would rather pay the stats
// again than trust anything — a follower re-framing from the start of its
// mirror is the one that does this.
func (s *Scanner) Forget() {
	s.complete = map[uint64]struct{}{}
}
