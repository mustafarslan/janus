// Package objstore is the S3-compatible object storage client shared by the
// content-addressed blob store and the WORM tier.
//
// It exists as its own package because those two need the same client
// configured differently, and because a bank's deployment will point it at
// MinIO, an on-premises appliance, or a sovereign-cloud endpoint rather than at
// AWS. Everything is behind a small surface so that swapping the provider is a
// configuration change.
package objstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Config describes how to reach an object store.
type Config struct {
	// Endpoint is the S3 endpoint. Leave empty for AWS; set it for MinIO or an
	// on-premises appliance.
	Endpoint string
	// Region is required by the protocol even when the provider ignores it.
	Region string
	// Bucket holds the objects.
	Bucket string
	// AccessKey and SecretKey are static credentials. Leaving both empty falls
	// back to the ambient credential chain (instance role, environment, shared
	// config), which is what a real deployment should use.
	AccessKey string
	SecretKey string
	// Jurisdiction is the region code the operator declares this bucket's bytes
	// rest in — the same vocabulary as a retention schedule and a tenant
	// binding (EU, DE, UK).
	//
	// It is a declaration, not a measurement. Janus cannot determine where an
	// S3 endpoint physically is, and an AWS region name is a weak corroborator
	// at best. What the field is for is refusing to write a pinned tenant's
	// evidence to a store nobody has declared to be in that jurisdiction: it
	// makes the operator state it, in configuration, where an auditor can read
	// it and a mismatch is refused.
	Jurisdiction string
	// UsePathStyle addresses buckets as /bucket/key rather than by subdomain.
	// MinIO and most on-premises gateways need this.
	UsePathStyle bool
	// Prefix is prepended to every key, so one bucket can hold several kinds of
	// artefact — segments and blobs, say.
	//
	// Not several tenants. A prefix separates key names and nothing else: one
	// bucket policy, one credential, one Object Lock configuration, one
	// deletion blast radius. Tenants get buckets.
	Prefix string
}

// Client is a thin wrapper over the S3 API.
type Client struct {
	api          *s3.Client
	bucket       string
	prefix       string
	jurisdiction string
}

// New builds a client from cfg.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("objstore: Bucket is required")
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if cfg.AccessKey != "" || cfg.SecretKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("objstore: load config: %w", err)
	}

	api := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.UsePathStyle
	})
	return &Client{api: api, bucket: cfg.Bucket, prefix: cfg.Prefix,
		jurisdiction: cfg.Jurisdiction}, nil
}

// Jurisdiction returns the region code the operator declared for this bucket.
func (c *Client) Jurisdiction() string { return c.jurisdiction }

// Bucket returns the bucket name.
func (c *Client) Bucket() string { return c.bucket }

// Key returns the full object key for a relative name.
func (c *Client) Key(name string) string {
	if c.prefix == "" {
		return name
	}
	return c.prefix + "/" + name
}

// PutOptions configures a single write.
type PutOptions struct {
	// RetainUntil, when set, applies an Object Lock retention to the object.
	RetainUntil time.Time
	// ComplianceMode selects COMPLIANCE rather than GOVERNANCE retention.
	//
	// The difference is the whole point of the WORM tier: under GOVERNANCE a
	// sufficiently privileged user can shorten or remove the lock, while under
	// COMPLIANCE nobody can — not the account root, not the provider. Only
	// COMPLIANCE satisfies a non-rewriteable, non-erasable storage requirement
	// such as SEC 17a-4(f).
	ComplianceMode bool
	// ContentType labels the object.
	ContentType string
	// Metadata is attached as user metadata.
	Metadata map[string]string
}

// Put writes an object.
func (c *Client) Put(ctx context.Context, name string, body []byte, opts PutOptions) error {
	in := &s3.PutObjectInput{
		Bucket:   aws.String(c.bucket),
		Key:      aws.String(c.Key(name)),
		Body:     newReadSeeker(body),
		Metadata: opts.Metadata,
	}
	if opts.ContentType != "" {
		in.ContentType = aws.String(opts.ContentType)
	}
	if !opts.RetainUntil.IsZero() {
		in.ObjectLockRetainUntilDate = aws.Time(opts.RetainUntil.UTC())
		if opts.ComplianceMode {
			in.ObjectLockMode = types.ObjectLockModeCompliance
		} else {
			in.ObjectLockMode = types.ObjectLockModeGovernance
		}
	}
	if _, err := c.api.PutObject(ctx, in); err != nil {
		return fmt.Errorf("objstore: put %s: %w", c.Key(name), err)
	}
	return nil
}

// Get reads an object.
func (c *Client) Get(ctx context.Context, name string) ([]byte, error) {
	out, err := c.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.Key(name)),
	})
	if err != nil {
		if IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, c.Key(name))
		}
		return nil, fmt.Errorf("objstore: get %s: %w", c.Key(name), err)
	}
	defer func() { _ = out.Body.Close() }()
	return io.ReadAll(out.Body)
}

// ObjectInfo reports an object's size, lock state, and version.
type ObjectInfo struct {
	Size           int64
	RetainUntil    time.Time
	ComplianceMode bool
	VersionID      string
	Metadata       map[string]string
	// ETag identifies this version of the object's content, and is what
	// PutIfMatch compares against. It is quoted, as the protocol returns it, and
	// is passed back unmodified rather than trimmed: a caller that unquotes it
	// has produced a value the store will refuse.
	ETag string
}

// Head fetches an object's metadata.
func (c *Client) Head(ctx context.Context, name string) (ObjectInfo, error) {
	out, err := c.api.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.Key(name)),
	})
	if err != nil {
		if IsNotFound(err) {
			return ObjectInfo{}, fmt.Errorf("%w: %s", ErrNotFound, c.Key(name))
		}
		return ObjectInfo{}, fmt.Errorf("objstore: head %s: %w", c.Key(name), err)
	}
	info := ObjectInfo{Metadata: out.Metadata}
	if out.ContentLength != nil {
		info.Size = *out.ContentLength
	}
	if out.ObjectLockRetainUntilDate != nil {
		info.RetainUntil = out.ObjectLockRetainUntilDate.UTC()
	}
	info.ComplianceMode = out.ObjectLockMode == types.ObjectLockModeCompliance
	if out.VersionId != nil {
		info.VersionID = *out.VersionId
	}
	info.ETag = aws.ToString(out.ETag)
	return info, nil
}

// Exists reports whether an object is present.
func (c *Client) Exists(ctx context.Context, name string) (bool, error) {
	_, err := c.Head(ctx, name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return false, err
}

// Delete removes an object.
//
// On a versioned bucket — which Object Lock requires — this does not destroy
// anything: it writes a delete marker that hides the object from a plain read
// while every version, including any locked one, remains. Code that means "make
// this record go away" must use DeleteVersion.
func (c *Client) Delete(ctx context.Context, name string) error {
	_, err := c.api.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.Key(name)),
	})
	if err != nil {
		return fmt.Errorf("objstore: delete %s: %w", c.Key(name), err)
	}
	return nil
}

// DeleteVersion permanently removes one version of an object. This is the
// operation an Object Lock retention actually refuses, and therefore the only
// one that tests whether a WORM configuration is real.
func (c *Client) DeleteVersion(ctx context.Context, name, versionID string) error {
	_, err := c.api.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:    aws.String(c.bucket),
		Key:       aws.String(c.Key(name)),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return fmt.Errorf("objstore: delete version %s of %s: %w", versionID, c.Key(name), err)
	}
	return nil
}

// GetVersion reads one specific version of an object, bypassing any delete
// marker that may be hiding it.
func (c *Client) GetVersion(ctx context.Context, name, versionID string) ([]byte, error) {
	out, err := c.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    aws.String(c.bucket),
		Key:       aws.String(c.Key(name)),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		if IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s version %s", ErrNotFound, c.Key(name), versionID)
		}
		return nil, fmt.Errorf("objstore: get %s version %s: %w", c.Key(name), versionID, err)
	}
	defer func() { _ = out.Body.Close() }()
	return io.ReadAll(out.Body)
}

// EnsureBucket creates the bucket if it is absent.
//
// objectLock can only be enabled at creation time, and it cannot be turned on
// for a bucket that already exists — so a deployment that forgets it has to
// start a new bucket. EnsureBucket reports that rather than quietly proceeding
// with a bucket that cannot hold WORM objects.
func (c *Client) EnsureBucket(ctx context.Context, objectLock bool) error {
	_, err := c.api.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(c.bucket)})
	if err == nil {
		if objectLock {
			return c.requireObjectLock(ctx)
		}
		return nil
	}
	if !IsNotFound(err) {
		return fmt.Errorf("objstore: head bucket %s: %w", c.bucket, err)
	}

	in := &s3.CreateBucketInput{Bucket: aws.String(c.bucket)}
	if objectLock {
		in.ObjectLockEnabledForBucket = aws.Bool(true)
	}
	if _, err := c.api.CreateBucket(ctx, in); err != nil {
		return fmt.Errorf("objstore: create bucket %s: %w", c.bucket, err)
	}
	return nil
}

// requireObjectLock fails unless the bucket can hold locked objects.
func (c *Client) requireObjectLock(ctx context.Context) error {
	out, err := c.api.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: aws.String(c.bucket),
	})
	if err != nil {
		return fmt.Errorf("objstore: bucket %s does not report an Object Lock configuration, "+
			"so it cannot hold WORM evidence; Object Lock can only be enabled when a bucket is "+
			"created, so this needs a new bucket: %w", c.bucket, err)
	}
	if out.ObjectLockConfiguration == nil ||
		out.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		return fmt.Errorf("objstore: bucket %s exists but Object Lock is not enabled, "+
			"and it cannot be enabled after creation; use a new bucket", c.bucket)
	}
	return nil
}

// ErrNotFound means the object or bucket does not exist.
var ErrNotFound = errors.New("objstore: not found")

// IsNotFound reports whether err is a 404 from the object store.
func IsNotFound(err error) bool {
	if errors.Is(err, ErrNotFound) {
		return true
	}
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nsb *types.NoSuchBucket
	if errors.As(err, &nsb) {
		return true
	}
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	// MinIO and some gateways return a bare HTTP 404 rather than a typed error.
	var respErr interface {
		HTTPStatusCode() int
	}
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusNotFound {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NoSuchBucket", "NotFound":
			return true
		}
	}
	return false
}

// IsRetentionViolation reports whether err is the object store refusing to
// delete or overwrite something under an Object Lock retention. This is the
// error the WORM tier wants to see when it tries to prove the lock works.
func IsRetentionViolation(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDenied", "InvalidRequest", "MethodNotAllowed", "ObjectLockConfigurationNotFoundError":
			return true
		}
	}
	var respErr interface {
		HTTPStatusCode() int
	}
	if errors.As(err, &respErr) {
		switch respErr.HTTPStatusCode() {
		case http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusConflict:
			return true
		}
	}
	return false
}
