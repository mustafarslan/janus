package evidence

import (
	"hash/maphash"
	"math"
	"math/bits"
)

// A Bloom filter over saga ids, used for one question: has this saga ever been
// written to this directory?
//
// It is deliberately the plainest possible implementation. The properties that
// matter are that it never reports absent for something present, and that its
// size does not grow — everything else about it is uninteresting, and a
// cleverer structure here would be optimising the wrong thing.
//
// See `sagaIndex.seen` for why the error being one-sided is what makes it safe
// to use, and why it is never reset.

const (
	// 2^23 bits is 1 MiB. A million saga ids fill 44.9% of it, which is a
	// false-positive rate of 1.76% — measured, and worth stating because the
	// figure first written here was "around 1%", which is most of a factor of
	// two out at the size the argument rested on. Two million is 16.4% and five
	// million is 77.1%, at which point the filter agrees with almost every
	// question and the fallback scan is back on the common path.
	//
	// A false positive costs a scan that finds what it was looking for, so the
	// rate is a performance knob and not a correctness one. What makes it worth
	// watching is that the knob turns by itself, over the log's lifetime rather
	// than the process's, and nothing about a correct answer looks different.
	bloomBits   = 1 << 23
	bloomHashes = 5
)

type bloom struct {
	bits   []uint64
	nbits  uint64
	hashes int
	seed1  maphash.Seed
	seed2  maphash.Seed
}

func newBloom(nbits uint64, hashes int) *bloom {
	return &bloom{
		bits:   make([]uint64, (nbits+63)/64),
		nbits:  nbits,
		hashes: hashes,
		seed1:  maphash.MakeSeed(),
		seed2:  maphash.MakeSeed(),
	}
}

// positions derives the filter's bit positions by double hashing, so one string
// hash pair yields as many independent-enough indices as needed.
func (b *bloom) positions(s string, fn func(uint64)) {
	h1 := maphash.String(b.seed1, s)
	h2 := maphash.String(b.seed2, s) | 1
	for i := range b.hashes {
		fn((h1 + uint64(i)*h2) % b.nbits)
	}
}

func (b *bloom) add(s string) {
	b.positions(s, func(p uint64) { b.bits[p/64] |= 1 << (p % 64) })
}

// saturation reports the fraction of bits set and the false-positive rate that
// fraction implies.
//
// Estimated from the bits that are actually set rather than from a count of
// insertions, which is the whole reason it is worth having: the filter is never
// reset and is rebuilt from whatever is on disk, so "how many ids went in" is a
// number nothing here knows, while "how full is it" is a popcount. With k
// independent positions, a lookup of an absent id tests k bits and is a false
// positive when all k happen to be set — `fill^k`. Measured against a real
// filter it is accurate to the third decimal.
//
// A popcount over the whole filter: 131,072 words for the 1 MiB size, which is
// tens of microseconds. Cheap to ask and not free, so the caller decides how
// often to ask.
func (b *bloom) saturation() (fill, falsePositiveRate float64) {
	var set uint64
	for _, w := range b.bits {
		set += uint64(bits.OnesCount64(w))
	}
	fill = float64(set) / float64(b.nbits)
	return fill, math.Pow(fill, float64(b.hashes))
}

// mayContain reports false only when s was definitely never added.
func (b *bloom) mayContain(s string) bool {
	ok := true
	b.positions(s, func(p uint64) {
		if b.bits[p/64]&(1<<(p%64)) == 0 {
			ok = false
		}
	})
	return ok
}
