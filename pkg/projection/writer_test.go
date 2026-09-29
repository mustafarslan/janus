package projection_test

import (
	"errors"
	"testing"

	"github.com/mustafarslan/janus/pkg/projection"
)

// TestOnlyOneProjectorMayFoldAStore.
//
// The question is who is allowed to write a projection. The answer is one
// projector, and it is enforced rather than assumed, because the alternative is
// two processes folding one store and the failure is silent: both would be
// applying events to the same rows in an order neither of them chose.
//
// The mechanism is a PostgreSQL advisory lock held on a connection the store
// keeps for nothing else. That detail is the mechanism, not an implementation
// note — an advisory lock belongs to a session, so a lock taken through a
// connection pool can be dropped when the pool recycles the connection, leaving
// a projector that believes it is the writer and is not.
func TestOnlyOneProjectorMayFoldAStore(t *testing.T) {
	first, ctx, dsn := newStoreDSN(t)
	dir, _ := contendingLog(t)

	if _, err := projection.NewProjector(first, dir).CatchUp(ctx); err != nil {
		t.Fatalf("the first projector could not fold: %v", err)
	}

	// A second store on the same schema: a second process, pointed at one
	// projection.
	second, err := projection.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projection.NewProjector(second, dir).CatchUp(ctx); err == nil {
		second.Close()
		t.Fatal("two projectors folded one store")
	} else if !errors.Is(err, projection.ErrNotTheWriter) {
		second.Close()
		t.Fatalf("expected a writer-lock refusal, got: %v", err)
	}

	// Reading is not writing. A process that only reads the projection is the
	// console's case, and it must not need the lock.
	if _, _, err := second.Head(ctx); err != nil {
		second.Close()
		t.Errorf("a non-writing store could not read the projection: %v", err)
	}
	second.Close()

	// The lock dies with the connection that holds it, so releasing the first
	// store hands the store on rather than wedging it until somebody restarts
	// PostgreSQL.
	first.Close()

	third, err := projection.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if _, err := projection.NewProjector(third, dir).CatchUp(ctx); err != nil {
		t.Fatalf("the store stayed locked after its writer closed: %v", err)
	}
}

// TestAStoreBelongsToOneLog.
//
// The writer lock stops two projectors folding one store at the same time. It
// cannot see two doing it at different times — a daemon stopped, another one
// started against a different evidence directory and the same schema. That
// interleaves two histories into a projection describing neither, and nothing
// about it looks wrong: the rows are internally consistent, the head advances,
// and every query answers.
//
// So the store records which log it was folded from, as the chain hash of that
// log's first record. A path would have been easier and is not an identity: the
// same log is at different paths in a container and on a laptop, and two
// different logs can occupy one path on two machines.
func TestAStoreBelongsToOneLog(t *testing.T) {
	store, ctx := newStore(t)

	first, _ := contendingLog(t)
	if _, err := projection.NewProjector(store, first).CatchUp(ctx); err != nil {
		t.Fatal(err)
	}

	second, _ := contendingLog(t)
	_, err := projection.NewProjector(store, second).CatchUp(ctx)
	if err == nil {
		t.Fatal("a projection folded a second, unrelated log into rows built from the first")
	}
	if !errors.Is(err, projection.ErrWrongLog) {
		t.Fatalf("expected a wrong-log refusal, got: %v", err)
	}

	// The same log is of course still fine.
	if _, err := projection.NewProjector(store, first).CatchUp(ctx); err != nil {
		t.Errorf("the projection refused the log it was built from: %v", err)
	}
}

// TestARebuildReleasesTheLogBinding: a rebuild is a rederivation from nothing,
// so the store is free to belong to whatever log is being folded into it. A
// binding that survived a rebuild would make "point this projection at a
// different deployment" impossible without a DBA.
func TestARebuildReleasesTheLogBinding(t *testing.T) {
	store, ctx := newStore(t)

	first, _ := contendingLog(t)
	if _, err := projection.NewProjector(store, first).CatchUp(ctx); err != nil {
		t.Fatal(err)
	}

	second, _ := contendingLog(t)
	if _, err := projection.NewProjector(store, second).Rebuild(ctx); err != nil {
		t.Fatalf("a rebuild onto a different log was refused: %v", err)
	}
	if _, err := projection.NewProjector(store, first).CatchUp(ctx); !errors.Is(err, projection.ErrWrongLog) {
		t.Errorf("after rebuilding onto the second log the store still accepts the first: %v", err)
	}
}
