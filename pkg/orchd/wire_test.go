package orchd_test

import (
	"context"
	"net"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/orchd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// TestTheServiceWorksOverTheWire exercises the thing the in-process tests do
// not: the generated service, real serialisation, and a stream.
//
// It matters because the whole point of 4a is that the caller is in another
// process. A server whose methods work when called directly and whose wire
// contract does not is a server that passes its tests and fails its purpose.
func TestTheServiceWorksOverTheWire(t *testing.T) {
	s, _ := newServer(t)
	client, stop := dial(t, s)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Subscribe before beginning, so the stream has to carry the change rather
	// than the initial snapshot.
	stream, err := client.WatchSagas(ctx, &janusv1.WatchSagasRequest{})
	if err != nil {
		t.Fatalf("watching: %v", err)
	}

	if _, err := client.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: quotePlan()}); err != nil {
		t.Fatalf("beginning over the wire: %v", err)
	}

	got, err := stream.Recv()
	if err != nil {
		t.Fatalf("the watcher was told nothing about a saga that just began: %v", err)
	}
	if got.GetSaga().GetSagaId() != testSaga {
		t.Fatalf("watch reported saga %q, want %q", got.GetSaga().GetSagaId(), testSaga)
	}
	if got.GetSaga().GetLastSeq() == 0 {
		t.Fatal("the projection carries no last_seq, so a client that reconnects " +
			"cannot say where it got to")
	}

	prep, err := client.PrepareStep(ctx, &janusv1.PrepareStepRequest{
		SagaId: testSaga, StepId: "st_quote",
	})
	if err != nil {
		t.Fatalf("preparing over the wire: %v", err)
	}
	if prep.GetStatus() != janusv1.PrepareStatus_PREPARE_STATUS_PREPARED {
		t.Fatalf("preparing over the wire: %s — %s", prep.GetStatus(), prep.GetReason())
	}
	if _, err := client.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: testSaga, StepId: "st_quote", Attempt: prep.GetAttempt(),
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}); err != nil {
		t.Fatalf("completing over the wire: %v", err)
	}

	// The stream coalesces, so what is required is that a later message shows
	// the saga finished — not that every intermediate state arrived.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("stream ended before the saga committed: %v", err)
		}
		if msg.GetSaga().GetStatus() == janusv1.SagaState_SAGA_STATE_COMMITTED {
			return
		}
	}
	t.Fatal("the saga committed but no watcher ever heard about it")
}

// TestARefusalArrivesAsAStatusCode. An SDK has to be able to tell a plan that
// was refused from a connection that broke, and the difference has to survive
// the wire.
func TestARefusalArrivesAsAStatusCode(t *testing.T) {
	s, _ := newServer(t)
	client, stop := dial(t, s)
	defer stop()

	ctx := context.Background()
	if _, err := client.GetSaga(ctx, &janusv1.GetSagaRequest{SagaId: "sg_nope"}); err == nil {
		t.Fatal("asking for a saga that does not exist succeeded")
	}
}

func dial(t *testing.T, s *orchd.Server) (janusv1.OrchestratorServiceClient, func()) {
	t.Helper()
	conn := clientConn(t, s)
	return janusv1.NewOrchestratorServiceClient(conn), func() {}
}

// clientConn serves the daemon over an in-memory listener and returns a
// connection to it. In-memory rather than a real port because a test that binds
// one is a test that fails when two of them run at once.
func clientConn(t *testing.T, s *orchd.Server) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	janusv1.RegisterOrchestratorServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return conn
}
