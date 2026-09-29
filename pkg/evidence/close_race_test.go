package evidence_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
)

// TestCloseDuringConcurrentAppends: Append is documented for concurrent use and
// Close says nothing about needing quiet, so the two overlap in any real
// service. Before this was fixed, a producer could pass the closing check, be
// delayed in encryption or a blob-store round trip, and then send on a channel
// Close had already closed — panicking the process whose entire job is to fail
// closed rather than fall over.
//
// Every append must therefore either succeed or return an error. Nothing may
// panic.
func TestCloseDuringConcurrentAppends(t *testing.T) {
	for attempt := range 20 {
		func() {
			signer := mustSigner(t)
			a, _ := newAppender(t, signer, func(o *evidence.Options) {
				// A small queue makes producers park in the send, which is the
				// interleaving that used to panic.
				o.QueueDepth = 4
			})

			var wg sync.WaitGroup
			for range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range 40 {
						_, err := a.Append(context.Background(), evidence.Request{
							Kind:        evidence.KindStepResult,
							SagaID:      "sg_race",
							Participant: evidence.ParticipantRef{ID: "ag"},
							Payload:     []byte(`{"racing":true}`),
						})
						if err != nil && !errors.Is(err, evidence.ErrClosed) {
							t.Errorf("attempt %d: unexpected error: %v", attempt, err)
							return
						}
					}
				}()
			}

			// Close while the producers are mid-flight.
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				_ = a.Close()
			}()

			wg.Wait()
			<-closed
		}()
	}
}

// TestAppendAfterCloseIsAnError rather than a panic or a silent success.
func TestAppendAfterCloseIsAnError(t *testing.T) {
	signer := mustSigner(t)
	a, _ := newAppender(t, signer, nil)
	appendN(t, a, 3, "sg")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	for range 10 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, Participant: evidence.ParticipantRef{ID: "ag"},
			Payload: []byte(`{}`),
		}); !errors.Is(err, evidence.ErrClosed) {
			t.Fatalf("got %v, want ErrClosed", err)
		}
	}
}

// TestConcurrentCloseIsSafe: two shutdown paths racing must not double-close.
func TestConcurrentCloseIsSafe(t *testing.T) {
	signer := mustSigner(t)
	a, _ := newAppender(t, signer, nil)
	appendN(t, a, 5, "sg")

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.Close()
		}()
	}
	wg.Wait()
}
