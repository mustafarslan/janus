package orchd

import (
	"context"
	"fmt"
	"log"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
)

// declareStandbyKeys records the keys a promoted replica may sign with.
//
// Idempotent by reading the log first: a daemon restarted with the same flag
// records nothing, because a second identical declaration would be a rotation
// that did not happen — and a log full of them would make the real ones harder
// to find.
//
// It runs at start-up, while this primary is healthy, and that timing is the
// whole point. See Options.StandbyKeys.
func (s *Server) declareStandbyKeys(set keys.PublicKeySet) error {
	if len(set) == 0 {
		return nil
	}
	// The keys the log already trusts, so this can tell a new declaration from a
	// repeat. Read from the log rather than remembered, because the daemon that
	// made the first declaration may not be this process.
	known, err := evidence.TrustedWriterKeys(s.dir, s.liveRead()...)
	if err != nil {
		return fmt.Errorf("orchd: reading the log's declared writer keys: %w", err)
	}

	by := evidence.ParticipantRef{ID: "sys_orchd", Kind: "SYSTEM", Principal: "pr_operator"}
	for id, pub := range set {
		if id == s.app.KeyID() {
			// Declaring the key already signing this log would record a
			// rotation to itself. janus-keys refuses the same thing.
			continue
		}
		if _, ok := known[id]; ok {
			continue
		}
		if _, err := s.app.RecordWriterKey(context.Background(), evidence.WriterKeyDeclaration{
			Kind: evidence.WriterKeyTrusted, KeyID: id, PublicKey: pub,
		}, by); err != nil {
			return fmt.Errorf("orchd: declaring standby key %s: %w", id, err)
		}
		log.Printf("orchd: declared standby writer key %s; a replica promoted later may "+
			"sign with it and still verify from this log's root", id)
	}
	return nil
}
