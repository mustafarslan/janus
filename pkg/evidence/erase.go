package evidence

import (
	"context"
	"fmt"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/crypto"
)

// Erase honours a data subject's erasure request by destroying their key and
// recording that it happened.
//
// # Why the key is destroyed before the event is written
//
// One of the two has to go first, and the failure windows are not symmetric.
//
// Recording first and dying before the shred would leave the log asserting an
// erasure that did not occur — the audit trail would be lying, and lying in the
// direction that matters most, because a data subject would have been told their
// data was gone while it was still readable.
//
// Shredding first and dying before the event leaves the key genuinely destroyed
// with no event explaining why the content is unreadable. That is a gap, but it
// is a gap in the direction of more erasure rather than less, and it is
// recoverable: the key ring keeps a durable tombstone naming the subject, the
// reason, the approver, and the time, so the missing event can be reconciled
// afterwards from a record that was written before the key was touched.
//
// So: shred, then record.
func Erase(ctx context.Context, app *Appender, ring crypto.KeyRing, subject, reason, approvedBy string) (Ref, crypto.ShredReceipt, error) {
	if app == nil || ring == nil {
		return Ref{}, crypto.ShredReceipt{}, fmt.Errorf("evidence: Erase needs an appender and a key ring")
	}
	if subject == "" {
		return Ref{}, crypto.ShredReceipt{}, fmt.Errorf("evidence: Erase needs a data subject")
	}

	receipt, err := ring.Shred(subject, reason, approvedBy, time.Now().UTC())
	if err != nil {
		return Ref{}, crypto.ShredReceipt{}, err
	}

	payload, err := receipt.Payload()
	if err != nil {
		return Ref{}, receipt, fmt.Errorf("evidence: render shred receipt: %w", err)
	}

	// The SHRED event itself carries no personal data beyond the subject
	// identifier already present throughout the log, and is deliberately not
	// encrypted: it is the explanation for why other records cannot be read,
	// so it has to remain readable after the erasure it describes.
	ref, err := app.Append(ctx, Request{
		Kind:        KindShred,
		Participant: ParticipantRef{ID: "janus-evidence", Kind: "SYSTEM"},
		Payload:     payload,
		Labels:      map[string]string{"subject": subject, "approved_by": approvedBy},
	})
	if err != nil {
		return Ref{}, receipt, fmt.Errorf(
			"evidence: key for %s was destroyed but the SHRED event could not be written (%w); "+
				"the key ring holds a tombstone with the details, and the event must be reconciled from it",
			subject, err)
	}
	return ref, receipt, nil
}

// OpenPayload decrypts a stored payload if it is encrypted, and returns it
// unchanged if it is not.
//
// Everything it needs comes from the record itself, which is the point: a
// reader holding the log and the key ring can decrypt without being told
// anything else.
//
// A destroyed key is reported as crypto.ErrKeyDestroyed rather than as
// corruption. The distinction matters to whoever is reading: the record is
// intact, the chain still verifies over it, and the content is deliberately
// gone. Treating that as damage would send someone hunting for a fault that is
// actually a fulfilled erasure request.
func OpenPayload(sealer *crypto.Sealer, payload []byte, h EventHeader) ([]byte, error) {
	if !crypto.IsEncrypted(payload) {
		return payload, nil
	}
	if sealer == nil {
		return nil, fmt.Errorf("evidence: payload at seq %d is encrypted and no sealer was supplied", h.Seq)
	}
	if h.Subject == "" {
		return nil, fmt.Errorf("evidence: payload at seq %d is encrypted but the record names no data subject, "+
			"so no key can be selected for it", h.Seq)
	}
	return sealer.Open(payload, crypto.Context{
		Subject: h.Subject,
		SagaID:  h.SagaID,
		StepID:  h.StepID,
		Kind:    string(h.Kind),
	})
}
