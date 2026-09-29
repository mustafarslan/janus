package s3_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/cas"
	s3 "github.com/mustafarslan/janus/pkg/evidence/cas/s3"
	"github.com/mustafarslan/janus/pkg/evidence/objstore/objstoretest"
)

// The S3 backend is exercised against a real endpoint rather than a mock,
// because the behaviour that matters — how a provider reports a missing key,
// whether path-style addressing works, what a re-put does — is exactly what a
// mock would get to invent.

func s3Store(t *testing.T) *s3.Store {
	t.Helper()
	bucket := objstoretest.BucketName("janus-cas", time.Now().UnixNano())
	return s3.New(objstoretest.Client(t, bucket, false))
}

func TestS3RoundTrip(t *testing.T) {
	s := s3Store(t)
	ctx := context.Background()

	body := []byte(strings.Repeat("a retrieved document ", 200))
	d, err := s.Put(ctx, body)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %d bytes back, stored %d", len(got), len(body))
	}

	present, err := s.Has(ctx, d)
	if err != nil || !present {
		t.Fatalf("Has returned (%v, %v), want (true, nil)", present, err)
	}
}

func TestS3PutIsIdempotent(t *testing.T) {
	s := s3Store(t)
	ctx := context.Background()
	body := []byte("stored twice, kept once")

	first, err := s.Put(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Put(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("the same bytes produced two addresses: %s and %s", first, second)
	}
}

func TestS3MissingBlob(t *testing.T) {
	s := s3Store(t)
	_, err := s.Get(context.Background(), cas.Sum([]byte("never stored")))
	if !errors.Is(err, cas.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}

	present, err := s.Has(context.Background(), cas.Sum([]byte("also never stored")))
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("Has reported a blob that was never stored")
	}
}

func TestS3DescribeNamesTheBucket(t *testing.T) {
	s := s3Store(t)
	if !strings.HasPrefix(s.Describe(), "s3:") {
		t.Fatalf("Describe returned %q", s.Describe())
	}
}
