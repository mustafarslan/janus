package segment_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// How much of ScanComplete is the readdir and how much is the per-file stat?
// An earlier measurement said "that is the readdir, not the verification",
// which is a claim about a function that does one readdir and N stats.
func benchDir(b *testing.B, n int) string {
	b.Helper()
	dir := b.TempDir()
	body := make([]byte, segment.HeaderSize+16)
	for i := range n {
		p := filepath.Join(dir, fmt.Sprintf("%016x.jseg", i))
		if err := os.WriteFile(p, body, 0o640); err != nil {
			b.Fatal(err)
		}
	}
	return dir
}

func BenchmarkScanDir(b *testing.B) {
	for _, n := range []int{10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			dir := benchDir(b, n)
			b.ResetTimer()
			for b.Loop() {
				if _, err := segment.ScanDir(dir); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkScanComplete(b *testing.B) {
	for _, n := range []int{10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			dir := benchDir(b, n)
			b.ResetTimer()
			for b.Loop() {
				if _, err := segment.ScanComplete(dir); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkScannerSteadyState is the case the hot callers are in: a directory
// that has not changed since the last pass, or has gained one file.
func BenchmarkScannerSteadyState(b *testing.B) {
	for _, n := range []int{10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			dir := benchDir(b, n)
			s := segment.NewScanner(dir)
			if _, err := s.Complete(); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for b.Loop() {
				if _, err := s.Complete(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
