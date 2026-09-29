package objstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// ErrPreconditionFailed is the object store refusing a conditional write
// because the condition did not hold: the key already existed when the caller
// required absence, or its ETag had moved when the caller required a specific
// one.
//
// It is a normal outcome rather than a fault. For a lease it is the *answer* —
// somebody else holds it — which is why it is a distinguishable error and not
// folded into a generic write failure.
var ErrPreconditionFailed = errors.New("objstore: precondition failed")

// PutIfAbsent writes an object only if the key does not exist, and reports the
// new ETag.
//
// This is one half of a lease. `If-None-Match: *` makes creation exclusive: of
// two processes racing to take the same lease, exactly one gets 200 and the
// other gets 412, decided by the store rather than by either of them.
func (c *Client) PutIfAbsent(ctx context.Context, name string, body []byte, opts PutOptions) (string, error) {
	return c.conditionalPut(ctx, name, body, opts, aws.String("*"), nil)
}

// PutIfMatch overwrites an object only if its current ETag is the one supplied,
// and reports the new ETag.
//
// This is the other half, and it is what makes a lease *renewable* rather than
// merely exclusive. A holder renews by writing its own ETag back; a process that
// lost the lease while it was not looking finds its ETag stale and is refused.
// Two processes trying to steal an expired lease race safely: both read the same
// ETag, one wins the compare-and-swap, the other gets 412.
//
// Item 46 recorded only `If-None-Match` as probed. `If-Match` is what a writer
// that must keep holding a lease needs, and `ProbeConditionalWrites` checks both
// rather than assuming a store that has one has the other.
func (c *Client) PutIfMatch(ctx context.Context, name string, body []byte, etag string, opts PutOptions) (string, error) {
	if etag == "" {
		return "", fmt.Errorf("objstore: put-if-match %s: empty etag", c.Key(name))
	}
	return c.conditionalPut(ctx, name, body, opts, nil, aws.String(etag))
}

func (c *Client) conditionalPut(ctx context.Context, name string, body []byte, opts PutOptions, ifNoneMatch, ifMatch *string) (string, error) {
	in := &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(c.Key(name)),
		Body:        newReadSeeker(body),
		Metadata:    opts.Metadata,
		IfNoneMatch: ifNoneMatch,
		IfMatch:     ifMatch,
	}
	if opts.ContentType != "" {
		in.ContentType = aws.String(opts.ContentType)
	}
	out, err := c.api.PutObject(ctx, in)
	if err != nil {
		if IsPreconditionFailed(err) {
			return "", fmt.Errorf("%w: %s", ErrPreconditionFailed, c.Key(name))
		}
		return "", fmt.Errorf("objstore: conditional put %s: %w", c.Key(name), err)
	}
	return aws.ToString(out.ETag), nil
}

// IsPreconditionFailed reports whether err is a refused conditional write.
//
// Classified the same defensive way as IsNotFound in this package: a typed
// error, a bare HTTP status, and an API error code, because MinIO, AWS and the
// gateways in between do not agree on which one they return.
func IsPreconditionFailed(err error) bool {
	if errors.Is(err, ErrPreconditionFailed) {
		return true
	}
	var respErr interface{ HTTPStatusCode() int }
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusPreconditionFailed {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "PreconditionFailed", "ConditionalRequestConflict":
			return true
		}
	}
	return false
}

// ProbeResult records what one conditional-write behaviour did.
type ProbeResult struct {
	// What was attempted, in words an operator can act on.
	What string
	// Want is what a store that fences must do.
	Want string
	// OK is whether it did.
	OK bool
	// Got describes what happened when it did not.
	Got string
}

// ProbeConditionalWrites writes and rewrites a throwaway key to find out whether
// this bucket actually enforces conditional writes.
//
// **It exists because a fence that silently does not fence is the hollow control
// in its purest form.** Conditional writes are a recent addition to S3 and a
// version-dependent one in MinIO, and the failure mode when they are absent is
// not an error: the store accepts every write and two writers both believe they
// hold the lease. So the answer is taken from the bucket at arm time, from this
// bucket, rather than from a version number or from what worked once on
// somebody's laptop.
//
// The caller is expected to refuse to start when this returns anything but all
// four passing. The rule: a control is what it does here,
// not what the vendor's documentation says it does.
func (c *Client) ProbeConditionalWrites(ctx context.Context, name string) ([]ProbeResult, error) {
	star := aws.String("*")
	// Each write must differ from the last, and that is not a detail.
	//
	// An ETag is derived from content: writing the same bytes again leaves it
	// unchanged, so an etag a caller has been holding stays *current* rather
	// than going stale, and a compare-and-swap against it succeeds. A probe
	// that wrote one constant would find row 4 accepted and conclude the store
	// does not fence, when what it had actually built was a renewal that never
	// moved anything.
	//
	// **The same trap is load-bearing for the lease itself**: a lease document
	// whose bytes do not change on every renewal can be overwritten by a holder
	// that was fenced out, because its etag never stopped matching. Whatever
	// writes `tenure/lease.json` must vary it — an expiry timestamp does this
	// naturally, which is why the lease carries one.
	nth := 0
	body := func() []byte {
		nth++
		return fmt.Appendf(nil, `{"janus-fence-probe":%d}`, nth)
	}

	// Best effort: a leftover probe key from a crashed arm would make row 1 fail
	// for the wrong reason.
	_ = c.Delete(ctx, name)

	var out []ProbeResult
	etag, err := c.conditionalPut(ctx, name, body(), PutOptions{ContentType: "application/json"}, star, nil)
	out = append(out, ProbeResult{
		What: "If-None-Match:* on an absent key", Want: "accepted",
		OK: err == nil, Got: errText(err),
	})
	if err != nil {
		// Nothing below can be interpreted without a key that exists.
		return out, nil
	}
	defer func() { _ = c.Delete(ctx, name) }()

	_, err = c.conditionalPut(ctx, name, body(), PutOptions{}, star, nil)
	out = append(out, ProbeResult{
		What: "If-None-Match:* on a key that exists", Want: "refused (412)",
		OK: errors.Is(err, ErrPreconditionFailed), Got: errText(err),
	})

	_, err = c.conditionalPut(ctx, name, body(), PutOptions{}, nil, aws.String(etag))
	out = append(out, ProbeResult{
		What: "If-Match on the current etag", Want: "accepted",
		OK: err == nil, Got: errText(err),
	})

	// Row 3 just moved the object, so `etag` is now genuinely stale — which is
	// the realistic shape of the losing case and better than a fabricated value:
	// this is a holder that renewed once and then had the lease taken while it
	// was not looking. If row 3 was refused the object never moved and this row
	// cannot mean anything, which is why it says so rather than passing.
	if err != nil {
		out = append(out, ProbeResult{
			What: "If-Match on a stale etag", Want: "refused (412)",
			OK: false, Got: "not reached: the renew above was refused, so no etag went stale",
		})
		return out, nil
	}
	_, err = c.conditionalPut(ctx, name, body(), PutOptions{}, nil, aws.String(etag))
	out = append(out, ProbeResult{
		What: "If-Match on a stale etag", Want: "refused (412)",
		OK: errors.Is(err, ErrPreconditionFailed), Got: errText(err),
	})
	return out, nil
}

// ProbeOK reports whether every row passed, and names the first that did not.
func ProbeOK(rows []ProbeResult) (bool, string) {
	// A failing row first, whatever the count. The probe stops early when a row
	// fails, so reporting the count would hide the reason behind an arithmetic
	// complaint — which is what it did the first time this ran against a bucket
	// that did not exist: "the probe produced 1 rows, want 4", when what row 1
	// actually said was NoSuchBucket.
	for _, r := range rows {
		if !r.OK {
			return false, fmt.Sprintf("%s: want %s, got %s", r.What, r.Want, r.Got)
		}
	}
	if len(rows) != 4 {
		return false, fmt.Sprintf("the probe produced %d rows and none of them failed, "+
			"which means it did not finish; want 4", len(rows))
	}
	return true, ""
}

func errText(err error) string {
	if err == nil {
		return "accepted"
	}
	if errors.Is(err, ErrPreconditionFailed) {
		return "refused (412)"
	}
	return err.Error()
}
