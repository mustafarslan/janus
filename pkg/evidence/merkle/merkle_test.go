package merkle

import (
	"fmt"
	"testing"
)

func leaves(n int) [][Size]byte {
	out := make([][Size]byte, n)
	for i := range out {
		out[i] = HashLeaf([]byte(fmt.Sprintf("record-%d", i)))
	}
	return out
}

func TestRootStableAndSizeSensitive(t *testing.T) {
	// The root must commit to the leaf count, not just the leaf contents. This
	// is the CVE-2012-2459 property that motivates RFC 6962 over a
	// duplicate-last-leaf tree.
	seen := map[[Size]byte]int{}
	for n := 1; n <= 64; n++ {
		r := Root(leaves(n))
		if prev, dup := seen[r]; dup {
			t.Fatalf("tree of %d leaves has same root as tree of %d", n, prev)
		}
		seen[r] = n
		if got := Root(leaves(n)); got != r {
			t.Fatalf("root not deterministic for n=%d", n)
		}
	}
}

func TestInclusionProofRoundTrip(t *testing.T) {
	for n := 1; n <= 33; n++ {
		ls := leaves(n)
		root := Root(ls)
		for i := range n {
			proof, err := InclusionProof(ls, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyInclusion(ls[i], i, n, proof, root) {
				t.Fatalf("n=%d i=%d: valid proof rejected", n, i)
			}
		}
	}
}

func TestInclusionProofRejectsTampering(t *testing.T) {
	const n = 17
	ls := leaves(n)
	root := Root(ls)
	proof, err := InclusionProof(ls, 5)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong leaf", func(t *testing.T) {
		if VerifyInclusion(HashLeaf([]byte("forged")), 5, n, proof, root) {
			t.Fatal("accepted a leaf that is not in the tree")
		}
	})
	t.Run("wrong index", func(t *testing.T) {
		if VerifyInclusion(ls[5], 6, n, proof, root) {
			t.Fatal("accepted proof at the wrong index")
		}
	})
	t.Run("wrong root", func(t *testing.T) {
		// The tree size only fixes the shape of the audit path; soundness rests
		// on the root, which the segment footer binds to the leaf count.
		other := Root(leaves(n + 1))
		if VerifyInclusion(ls[5], 5, n, proof, other) {
			t.Fatal("accepted proof against another tree's root")
		}
	})
	t.Run("tree size too small for path", func(t *testing.T) {
		if VerifyInclusion(ls[5], 5, 8, proof, root) {
			t.Fatal("accepted a path deeper than the claimed tree")
		}
	})
	t.Run("mutated sibling", func(t *testing.T) {
		bad := make([][Size]byte, len(proof))
		copy(bad, proof)
		bad[0][0] ^= 0x01
		if VerifyInclusion(ls[5], 5, n, bad, root) {
			t.Fatal("accepted a proof with a flipped bit")
		}
	})
	t.Run("truncated path", func(t *testing.T) {
		if VerifyInclusion(ls[5], 5, n, proof[:len(proof)-1], root) {
			t.Fatal("accepted a truncated path")
		}
	})
	t.Run("extended path", func(t *testing.T) {
		var extra [Size]byte
		if VerifyInclusion(ls[5], 5, n, append(append([][Size]byte{}, proof...), extra), root) {
			t.Fatal("accepted a path with trailing garbage")
		}
	})
}

func TestInclusionProofIndexBounds(t *testing.T) {
	ls := leaves(4)
	for _, i := range []int{-1, 4, 100} {
		if _, err := InclusionProof(ls, i); err == nil {
			t.Fatalf("index %d: expected error", i)
		}
	}
}
