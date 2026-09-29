// Package merkle implements the RFC 6962 (Certificate Transparency) Merkle
// hash tree over BLAKE3.
//
// RFC 6962's construction is used rather than a naive "duplicate the last leaf
// when odd" tree because the latter admits two distinct leaf lists with the same
// root (CVE-2012-2459), which would let a forged bundle claim a genuine root.
// Here a lone subtree is promoted, not duplicated, so the root commits to the
// exact leaf count.
package merkle

import (
	"errors"
	"math/bits"

	"github.com/zeebo/blake3"
)

// Domain-separation prefixes, per RFC 6962 §2.1.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// Size is the length in bytes of every hash this package produces.
const Size = 32

// HashLeaf returns the leaf hash for a record digest: H(0x00 || data).
func HashLeaf(data []byte) [Size]byte {
	h := blake3.New()
	_, _ = h.Write([]byte{leafPrefix})
	_, _ = h.Write(data)
	var out [Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hashNode returns the interior node hash: H(0x01 || left || right).
func hashNode(left, right [Size]byte) [Size]byte {
	h := blake3.New()
	_, _ = h.Write([]byte{nodePrefix})
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	var out [Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// emptyRoot is MTH({}) = H("") — the root of a tree with no leaves.
func emptyRoot() [Size]byte {
	var out [Size]byte
	copy(out[:], blake3.New().Sum(nil))
	return out
}

// splitPoint returns k: the largest power of two strictly less than n.
// Defined for n > 1.
func splitPoint(n int) int {
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// Root computes MTH(leaves), where each element of leaves is already a leaf
// hash as returned by HashLeaf.
func Root(leaves [][Size]byte) [Size]byte {
	switch len(leaves) {
	case 0:
		return emptyRoot()
	case 1:
		return leaves[0]
	}
	k := splitPoint(len(leaves))
	return hashNode(Root(leaves[:k]), Root(leaves[k:]))
}

// ErrIndexOutOfRange is returned when an inclusion proof is requested for a
// leaf index the tree does not contain.
var ErrIndexOutOfRange = errors.New("merkle: leaf index out of range")

// InclusionProof returns the audit path proving that leaves[index] is the
// index-th leaf of a tree of len(leaves) leaves, per RFC 6962 §2.1.1.
// The path is ordered bottom-up: the leaf's immediate sibling first, the
// topmost sibling last.
func InclusionProof(leaves [][Size]byte, index int) ([][Size]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, ErrIndexOutOfRange
	}
	return path(leaves, index), nil
}

// path implements RFC 6962's PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n]),
// which places the deepest sibling first.
func path(leaves [][Size]byte, index int) [][Size]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := splitPoint(len(leaves))
	if index < k {
		return append(path(leaves[:k], index), Root(leaves[k:]))
	}
	return append(path(leaves[k:], index-k), Root(leaves[:k]))
}

// VerifyInclusion recomputes a root from a leaf hash and its audit path and
// reports whether it equals want. treeSize is the leaf count the proof was
// generated against; it is required because the path alone does not determine
// the tree shape.
//
// This is the verification algorithm of RFC 6962 §2.1.2: fn tracks the leaf's
// index within the current subtree and sn the subtree's last index, which
// together say whether the next sibling sits to the left or the right.
func VerifyInclusion(leaf [Size]byte, index, treeSize int, proof [][Size]byte, want [Size]byte) bool {
	if index < 0 || index >= treeSize {
		return false
	}
	fn, sn := index, treeSize-1
	node := leaf
	for _, sibling := range proof {
		if sn == 0 {
			return false // proof longer than the tree is deep
		}
		if fn%2 == 1 || fn == sn {
			node = hashNode(sibling, node)
			for fn != 0 && fn%2 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			node = hashNode(node, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && node == want
}
