package cas_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/cas"
)

func newStore(t *testing.T) *cas.FileStore {
	t.Helper()
	s, err := cas.NewFileStore(filepath.Join(t.TempDir(), "cas"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutGetRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	body := []byte("a document an agent read before it decided something")
	d, err := s.Put(ctx, body)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %q, want %q", got, body)
	}

	present, err := s.Has(ctx, d)
	if err != nil || !present {
		t.Fatalf("Has returned (%v, %v), want (true, nil)", present, err)
	}
}

// TestPutIsIdempotent: content addressing means storing the same bytes twice is
// storing them once, which is what makes a retried step free rather than a
// source of duplicate evidence.
func TestPutIsIdempotent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	body := []byte("retry me")

	first, err := s.Put(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		again, err := s.Put(ctx, body)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("the same bytes produced two addresses: %s and %s", first, again)
		}
	}
}

func TestDifferentBytesDifferentAddress(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	a, err := s.Put(ctx, []byte("approve"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Put(ctx, []byte("decline"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two different payloads share an address")
	}
}

func TestGetMissingBlob(t *testing.T) {
	s := newStore(t)
	if _, err := s.Get(context.Background(), cas.Sum([]byte("never stored"))); !errors.Is(err, cas.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// TestTamperedBlobIsRejected is the property that makes a reference safe to put
// in an audit trail: the store cannot substitute different bytes for an address
// without being caught, so no separate integrity check is needed on top.
func TestTamperedBlobIsRejected(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cas")
	s, err := cas.NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	d, err := s.Put(ctx, []byte("the customer is eligible"))
	if err != nil {
		t.Fatal(err)
	}

	// Reach behind the store and rewrite the blob, as an insider with disk
	// access would.
	var target string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			target = path
		}
		return nil
	})
	if err != nil || target == "" {
		t.Fatalf("could not locate the stored blob (err %v)", err)
	}
	if err := os.WriteFile(target, []byte("the customer is NOT eligible"), 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Get(ctx, d); !errors.Is(err, cas.ErrDigestMismatch) {
		t.Fatalf("got %v, want ErrDigestMismatch: a rewritten blob was served as genuine", err)
	}
}

func TestRefRoundTrip(t *testing.T) {
	d := cas.Sum([]byte("payload"))
	ref := d.Ref()
	if !strings.HasPrefix(ref, "cas://blake3:") {
		t.Fatalf("unexpected reference format %q", ref)
	}
	parsed, err := cas.ParseRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != d {
		t.Fatal("parsing a reference did not reproduce the digest")
	}
}

func TestParseRefRejectsMalformed(t *testing.T) {
	good := cas.Sum([]byte("x")).Ref()
	for name, ref := range map[string]string{
		"empty":            "",
		"no scheme":        strings.TrimPrefix(good, "cas://"),
		"wrong scheme":     "https://" + strings.TrimPrefix(good, "cas://"),
		"no algorithm":     "cas://" + strings.TrimPrefix(good, "cas://blake3:"),
		"unknown algo":     "cas://md5:" + strings.TrimPrefix(good, "cas://blake3:"),
		"not hex":          "cas://blake3:zzzz",
		"wrong length":     "cas://blake3:abcd",
		"trailing garbage": good + "!!",
	} {
		if _, err := cas.ParseRef(ref); err == nil {
			t.Errorf("%s: %q was accepted", name, ref)
		}
	}
}

func TestPutRejectsNothingAndHandlesEmpty(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	d, err := s.Put(ctx, nil)
	if err != nil {
		t.Fatalf("storing an empty payload should work: %v", err)
	}
	got, err := s.Get(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bytes back for an empty blob", len(got))
	}
}

func TestNewFileStoreRequiresDir(t *testing.T) {
	if _, err := cas.NewFileStore(""); err == nil {
		t.Fatal("expected an error for an empty directory")
	}
}
