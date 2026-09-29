package cas

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FileStore keeps blobs on a local filesystem, sharded by the first byte of the
// digest so no directory grows unbounded.
//
// This is the store an air-gapped single-node deployment uses, and the one the
// tests use. It is not a cache in front of object storage; it is a complete
// backend.
type FileStore struct {
	root string
}

// NewFileStore returns a store rooted at dir, creating it if needed.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("cas: FileStore requires a directory")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &FileStore{root: dir}, nil
}

// Describe implements Store.
func (s *FileStore) Describe() string { return "file:" + s.root }

// path returns the on-disk location of a digest.
func (s *FileStore) path(d Digest) string {
	hexDigest := d.String()[len(Algorithm)+1:]
	return filepath.Join(s.root, hexDigest[:2], hexDigest)
}

// Put writes b, if it is not already there.
func (s *FileStore) Put(_ context.Context, b []byte) (Digest, error) {
	d := Sum(b)
	final := s.path(d)

	if _, err := os.Stat(final); err == nil {
		// Already stored. Content addressing makes this a no-op rather than an
		// overwrite, so a retried step costs nothing and cannot change history.
		return d, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return d, err
	}

	if err := os.MkdirAll(filepath.Dir(final), 0o750); err != nil {
		return d, err
	}

	// Write to a temporary name and rename into place. A reader must never see
	// a blob that is only partly written, because it would fail its digest
	// check and look like corruption rather than a write in progress.
	tmp, err := os.CreateTemp(filepath.Dir(final), ".tmp-*")
	if err != nil {
		return d, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return d, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return d, err
	}
	if err := tmp.Close(); err != nil {
		return d, err
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return d, err
	}
	if err := os.Rename(tmpName, final); err != nil {
		return d, err
	}
	return d, nil
}

// Get reads a blob and verifies it against its address.
func (s *FileStore) Get(_ context.Context, d Digest) ([]byte, error) {
	body, err := os.ReadFile(s.path(d))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, d)
		}
		return nil, err
	}
	if err := Verify(d, body); err != nil {
		return nil, err
	}
	return body, nil
}

// Has reports presence without reading the blob.
func (s *FileStore) Has(_ context.Context, d Digest) (bool, error) {
	_, err := os.Stat(s.path(d))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
