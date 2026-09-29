package orchd

import (
	"context"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence/replica"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The replication surface: the primary's half of replication.
//
// It is three read-only calls and it is deliberately thin. Everything that can
// be got wrong about replication — the acknowledgement bound, the torn tail, a
// cursor that must not pass an unsealed segment — belongs to the follower, and
// was established against `replica.Source` before any of this existed. What is
// here serves that interface over the wire and adds no judgement of its own.
//
// A primary that made judgements would be the place those rules get quietly
// re-decided. The clearest example is the segment list: filtering it to
// "complete" segments looks like helpfulness and would remove the follower's
// only chance to apply rule three.

// maxReplicationChunk caps one response regardless of what a caller asks for.
//
// A follower asking for a gigabyte would otherwise make this daemon read a
// gigabyte into memory on the goroutine serving it — which is a way for a
// replica to take down the primary it is replicating, and the primary is the
// thing that must not fall over.
const maxReplicationChunk = 4 << 20

// ReplicationHead reports what this daemon has durably acknowledged.
func (s *Server) ReplicationHead(_ context.Context, _ *janusv1.ReplicationHeadRequest) (
	*janusv1.ReplicationHeadResponse, error) {

	st := s.app.Stats()
	chain := st.LastChain
	return &janusv1.ReplicationHeadResponse{Seq: st.LastSeq, Chain: chain[:]}, nil
}

// ReplicationSegments lists this daemon's segment ids.
func (s *Server) ReplicationSegments(ctx context.Context, _ *janusv1.ReplicationSegmentsRequest) (
	*janusv1.ReplicationSegmentsResponse, error) {

	ids, err := s.replicaSource().Segments(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing segments: %v", err)
	}
	return &janusv1.ReplicationSegmentsResponse{SegmentIds: ids}, nil
}

// ReplicationRead returns a slice of one segment.
func (s *Server) ReplicationRead(ctx context.Context, req *janusv1.ReplicationReadRequest) (
	*janusv1.ReplicationReadResponse, error) {

	if req.GetOffset() < 0 {
		return nil, status.Error(codes.InvalidArgument, "offset must not be negative")
	}
	max := int(req.GetMaxBytes())
	if max <= 0 || max > maxReplicationChunk {
		max = maxReplicationChunk
	}
	chunk, err := s.replicaSource().Read(ctx, req.GetSegmentId(), req.GetOffset(), max)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reading segment %d: %v", req.GetSegmentId(), err)
	}
	return &janusv1.ReplicationReadResponse{
		Data: chunk.Bytes, SegmentLength: chunk.Length,
	}, nil
}

// replicaSource serves this daemon's own directory.
//
// The head comes from this process's appender because this process holds the
// writer lock: it is the only thing in the system entitled to say what has been
// acknowledged, and a replication protocol whose head came from anywhere else
// would be quoting a belief.
func (s *Server) replicaSource() *replica.LocalSource {
	return replica.FromAppender(s.dir, s.app)
}
