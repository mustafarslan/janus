// Package s3 keeps content-addressed blobs in S3-compatible object storage.
//
// # Why this is not in pkg/evidence/cas
//
// It was, and that single import put an S3 client inside `janus-verify`.
//
// The chain was one edge long: `cmd/janus-verify` → `pkg/evidence/verify` →
// `pkg/evidence/cas` → `pkg/evidence/objstore` → the AWS SDK. The verifier reads
// a directory of segments and a key set and performs no offload, but the
// dependency is a property of the import graph rather than of what runs, so the
// bill of materials the project publishes listed 18 AWS modules out of 23 — 78% of
// the dependency surface of the one binary this project asks people not to
// trust.
//
// Moving the implementation one package down cost nothing to do and is worth
// naming rather than hiding: `cas.Store` was already an interface, and this type
// had no production caller at all. The offline verifier now links what it reads.
package s3

import (
	"context"
	"errors"
	"fmt"

	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/objstore"
)

// Store keeps blobs in S3-compatible object storage.
//
// Keys are the digest itself, sharded by its first byte the same way the
// filesystem store shards directories. That keeps listings usable and, more
// importantly, means the key names carry no business meaning: an object key in
// a bucket an operator can list should not reveal which customer a document
// belongs to.
type Store struct {
	client *objstore.Client
}

// These are the reason this package can live outside cas without weakening
// anything: the interfaces are the contract, and a compile failure here is what
// says so.
var (
	_ cas.Store   = (*Store)(nil)
	_ cas.Located = (*Store)(nil)
)

// New wraps an object store client.
func New(client *objstore.Client) *Store { return &Store{client: client} }

// Jurisdiction implements cas.Located, forwarding what the bucket's operator
// declared.
func (s *Store) Jurisdiction() string { return s.client.Jurisdiction() }

// Describe implements cas.Store.
func (s *Store) Describe() string { return "s3:" + s.client.Bucket() }

func (s *Store) key(d cas.Digest) string {
	hexDigest := d.String()[len(cas.Algorithm)+1:]
	return "blobs/" + hexDigest[:2] + "/" + hexDigest
}

// Put stores b unless it is already present.
func (s *Store) Put(ctx context.Context, b []byte) (cas.Digest, error) {
	d := cas.Sum(b)
	// Content addressing makes a second write redundant rather than harmful,
	// but skipping it saves a round trip on retried steps and on the common
	// case of the same prompt appearing in many sagas.
	present, err := s.client.Exists(ctx, s.key(d))
	if err != nil {
		return d, err
	}
	if present {
		return d, nil
	}
	err = s.client.Put(ctx, s.key(d), b, objstore.PutOptions{
		ContentType: "application/octet-stream",
		Metadata:    map[string]string{"janus-digest": d.String()},
	})
	if err != nil {
		return d, err
	}
	return d, nil
}

// Get fetches a blob and verifies it against its address.
func (s *Store) Get(ctx context.Context, d cas.Digest) ([]byte, error) {
	body, err := s.client.Get(ctx, s.key(d))
	if err != nil {
		if errors.Is(err, objstore.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", cas.ErrNotFound, d)
		}
		return nil, err
	}
	if err := cas.Verify(d, body); err != nil {
		return nil, err
	}
	return body, nil
}

// Has reports presence without fetching.
func (s *Store) Has(ctx context.Context, d cas.Digest) (bool, error) {
	return s.client.Exists(ctx, s.key(d))
}
