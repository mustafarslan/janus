package a2a

import "net/http"

// The JTP header set for plain HTTP.
//
// They are propagation, not authority. A message carrying Janus-Saga-Id says
// which saga the sender believes this belongs to; nothing downstream may treat
// that as permission, because a header is whatever the sender wrote. What the
// headers buy is that the two sides, and the log, agree on what to call this
// piece of work — which is what makes an evidence search across two agents
// answerable at all.
const (
	HeaderSagaID         = "Janus-Saga-Id"
	HeaderStepID         = "Janus-Step-Id"
	HeaderEffectClass    = "Janus-Effect-Class"
	HeaderIdempotencyKey = "Janus-Idempotency-Key"
	HeaderEvidenceRef    = "Janus-Evidence-Ref"
)

// Context is the Janus framing carried on one message.
type Context struct {
	SagaID         string
	StepID         string
	EffectClass    string
	IdempotencyKey string
	EvidenceRef    string
}

// ContextFrom reads the framing off a request.
func ContextFrom(h http.Header) Context {
	return Context{
		SagaID:         h.Get(HeaderSagaID),
		StepID:         h.Get(HeaderStepID),
		EffectClass:    h.Get(HeaderEffectClass),
		IdempotencyKey: h.Get(HeaderIdempotencyKey),
		EvidenceRef:    h.Get(HeaderEvidenceRef),
	}
}

// Apply writes the framing onto an outgoing request.
//
// Called by the agent making the call, not by anything in Janus. Only the agent
// knows which saga its outbound request belongs to; a proxy in the path does
// not, and one that guessed would file evidence under a saga nobody chose. So
// an agent working inside a saga sets the framing on every call it makes out —
// JTP §3 rule 1:
//
//	a2a.Context{SagaID: sagaID, StepID: stepID}.Apply(req.Header)
//
// Empty fields are left off rather than sent empty. A header present with no
// value is a claim that there is a saga and it has no id, which reads in a log
// as something worse than absence.
func (c Context) Apply(h http.Header) {
	for name, value := range map[string]string{
		HeaderSagaID:         c.SagaID,
		HeaderStepID:         c.StepID,
		HeaderEffectClass:    c.EffectClass,
		HeaderIdempotencyKey: c.IdempotencyKey,
		HeaderEvidenceRef:    c.EvidenceRef,
	} {
		if value != "" {
			h.Set(name, value)
		}
	}
}

// Labels renders the framing for an evidence event, so "every message of saga
// X" is answerable without parsing payloads.
func (c Context) Labels() map[string]string {
	out := map[string]string{}
	if c.SagaID != "" {
		out["saga_id"] = c.SagaID
	}
	if c.StepID != "" {
		out["step_id"] = c.StepID
	}
	if c.EffectClass != "" {
		out["effect_class"] = c.EffectClass
	}
	return out
}
