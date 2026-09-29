package orchd

import (
	"context"
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence/replica"
	"google.golang.org/grpc"
)

// RemoteSource is a primary reached over gRPC.
//
// It implements `replica.Source` exactly, which is the point: the follower's
// three rules were established against that interface with a `LocalSource`
// behind it, and this changes where the bytes come from and nothing else. A
// transport that offered a different shape would be a second place for those
// rules to be re-decided, and the rules are the part that was hard.
type RemoteSource struct {
	rpc janusv1.OrchestratorServiceClient
	// max is the chunk size asked for. The server caps it further, which is its
	// business rather than this client's.
	max uint32
}

// NewRemoteSource wraps a connection to a primary.
func NewRemoteSource(conn grpc.ClientConnInterface) *RemoteSource {
	return &RemoteSource{rpc: janusv1.NewOrchestratorServiceClient(conn), max: 1 << 20}
}

// Head reports what the primary says it has durably acknowledged.
//
// The chain is carried as raw bytes and its length is checked here rather than
// trusted. A short or absent chain is what a field dropped in transit looks
// like, and the follower refuses a head it cannot check for divergence — so
// this fails at the boundary where the cause is still visible, instead of
// producing a head that fails later for a reason nobody can trace.
func (r *RemoteSource) Head(ctx context.Context) (replica.Head, error) {
	resp, err := r.rpc.ReplicationHead(ctx, &janusv1.ReplicationHeadRequest{})
	if err != nil {
		return replica.Head{}, err
	}
	var head replica.Head
	head.Seq = resp.GetSeq()
	raw := resp.GetChain()
	if head.Seq > 0 && len(raw) != len(head.Chain) {
		return replica.Head{}, fmt.Errorf(
			"orchd: the primary stated sequence %d with a %d-byte chain hash, want %d",
			head.Seq, len(raw), len(head.Chain))
	}
	copy(head.Chain[:], raw)
	return head, nil
}

// Segments lists the primary's segment ids.
func (r *RemoteSource) Segments(ctx context.Context) ([]uint64, error) {
	resp, err := r.rpc.ReplicationSegments(ctx, &janusv1.ReplicationSegmentsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetSegmentIds(), nil
}

// Read returns a slice of one segment.
func (r *RemoteSource) Read(ctx context.Context, id uint64, off int64, max int) (replica.Chunk, error) {
	want := r.max
	if max > 0 && uint32(max) < want {
		want = uint32(max)
	}
	resp, err := r.rpc.ReplicationRead(ctx, &janusv1.ReplicationReadRequest{
		SegmentId: id, Offset: off, MaxBytes: want,
	})
	if err != nil {
		return replica.Chunk{}, err
	}
	return replica.Chunk{Bytes: resp.GetData(), Length: resp.GetSegmentLength()}, nil
}

// compile-time proof that the wire shape is the tested shape.
var _ replica.Source = (*RemoteSource)(nil)
