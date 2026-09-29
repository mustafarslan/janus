// Package objstoretest wires tests up to a real S3-compatible endpoint.
//
// It lives apart from objstore so that importing the client does not drag the
// testing package into a production binary.
package objstoretest

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/objstore"
)

// Environment variables that point the integration tests at object storage.
const (
	// EnvEndpoint is the S3 endpoint, e.g. http://127.0.0.1:9000 for MinIO.
	EnvEndpoint = "JANUS_S3_ENDPOINT"
	// EnvAccessKey and EnvSecretKey are static credentials.
	EnvAccessKey = "JANUS_S3_ACCESS_KEY"
	EnvSecretKey = "JANUS_S3_SECRET_KEY"
	// EnvRequire makes an unreachable store a failure instead of a skip. CI
	// sets it so that a broken service container cannot look like a clean run.
	EnvRequire = "JANUS_S3_REQUIRED"
)

// Client returns a client against a scratch bucket, or skips the test.
//
// Skipping keeps `go test ./...` useful on a laptop with no object storage
// running. That is only safe because CI sets JANUS_S3_REQUIRED, which turns the
// skip into a failure — otherwise a misconfigured pipeline would report green
// while never exercising the WORM tier at all, which is exactly the kind of
// silent gap this package exists to prevent.
func Client(t *testing.T, bucket string, objectLock bool) *objstore.Client {
	t.Helper()

	endpoint := os.Getenv(EnvEndpoint)
	required := os.Getenv(EnvRequire) != ""
	if endpoint == "" {
		if required {
			t.Fatalf("%s is set but %s is empty: object storage was required and is not configured",
				EnvRequire, EnvEndpoint)
		}
		t.Skipf("set %s (and run `make dev`) to exercise object storage", EnvEndpoint)
	}

	access := os.Getenv(EnvAccessKey)
	secret := os.Getenv(EnvSecretKey)
	if access == "" {
		access = "janus"
	}
	if secret == "" {
		secret = "januspassword"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := objstore.New(ctx, objstore.Config{
		Endpoint:     endpoint,
		Region:       "us-east-1",
		Bucket:       bucket,
		AccessKey:    access,
		SecretKey:    secret,
		UsePathStyle: true,
	})
	if err != nil {
		t.Fatalf("build object store client: %v", err)
	}
	if err := c.EnsureBucket(ctx, objectLock); err != nil {
		if required {
			t.Fatalf("prepare bucket %s: %v", bucket, err)
		}
		t.Skipf("object storage at %s is not usable: %v", endpoint, err)
	}
	return c
}

// BucketName builds a unique bucket name for a test run.
//
// Object Lock can only be enabled when a bucket is created, and a locked object
// cannot be removed, so tests cannot clean up after themselves and must not
// share a bucket with each other or with a previous run.
func BucketName(prefix string, n int64) string {
	return fmt.Sprintf("%s-%d", prefix, n)
}
