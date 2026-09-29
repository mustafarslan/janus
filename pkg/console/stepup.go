package console

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/identity"
	"github.com/mustafarslan/janus/pkg/saga"
)

// The browser half of a step-up.
//
// Everything that decides anything was built in 5b: the assertion is verified
// against a trust store folded out of the log, and the challenge it must have
// been signed over is *derived* from the approval — a digest of the saga, step,
// requirement and attempt — so an assertion captured at one payment cannot be
// presented at another. What was missing was a way for a person to produce one.
//
// This file is that way, and it is deliberately thin. Two things:
//
//   - an endpoint that tells the browser which challenge to sign, and
//   - a form field the signed result comes back in.
//
// Nothing here is trusted. The challenge is a public deterministic function of
// the approval, so publishing it gives away nothing; the assertion that comes
// back is checked by pkg/identity before the answer is composed, against a
// binding this process recomputes rather than reads from the request. A browser
// that lies produces a refused approval, not a wrong one.

// StepUpChallenge is what a browser needs to ask an authenticator for an
// assertion bound to one approval.
type StepUpChallenge struct {
	SagaID        string `json:"saga_id"`
	StepID        string `json:"step_id"`
	RequirementID string `json:"requirement_id"`
	// Attempt is the server's, never the caller's. An approval is for one
	// attempt (a retry runs the participant again and deserves its own
	// decision), and letting a page name the attempt would let it obtain a
	// challenge for a decision that is not the one in front of the person.
	Attempt uint32 `json:"attempt"`
	// Challenge is base64url, unpadded — the encoding WebAuthn puts in
	// clientDataJSON, so the browser passes the decoded bytes and the server
	// compares the encoded string without either side re-encoding.
	Challenge string `json:"challenge"`
	// RequiresStepUp says whether the gate demands one. A page can then ask for
	// an assertion only where one is wanted, rather than prompting for a
	// security key at every approval and training people to tap through it.
	RequiresStepUp bool `json:"requires_step_up"`
}

// stepUpChallenge answers "what would an assertion for this approval have to be
// signed over".
//
// It is a GET with no side effects and nothing secret in it. That is worth
// saying plainly rather than leaving a reader to wonder whether publishing a
// challenge weakens anything: the challenge is a deterministic public function
// of the approval, which is exactly what makes it re-derivable by a verifier
// replaying the log years later. A random challenge would be a secret, and a
// secret would have to be recorded and then trusted.
func (s *Server) stepUpChallenge(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ch, err := s.console.StepUpFor(q.Get("saga_id"), q.Get("step_id"), q.Get("requirement_id"))
	status := http.StatusInternalServerError
	if errors.Is(err, ErrNotAnswerable) {
		status = http.StatusConflict
	}
	writeJSON(w, ch, err, status)
}

// StepUpFor derives the challenge for one pending approval.
//
// It refuses anything that is not actually waiting, for the same reason
// Answer does: a challenge for a decision already made would let a browser
// collect an assertion nobody can use, and the person would find out only when
// the approval was rejected.
func (c *Console) StepUpFor(sagaID, stepID, requirementID string) (*StepUpChallenge, error) {
	if sagaID == "" || stepID == "" || requirementID == "" {
		return nil, fmt.Errorf("%w: a challenge is for one saga, step and requirement",
			ErrNotAnswerable)
	}
	state, err := saga.ReplaySaga(c.dir, sagaID)
	if err != nil {
		return nil, fmt.Errorf("console: read saga %s: %w", sagaID, err)
	}
	st, ok := state.Steps[stepID]
	if !ok {
		return nil, fmt.Errorf("%w: saga %s has no step %s", ErrNotAnswerable, sagaID, stepID)
	}
	if !saga.HeldByGate(st) {
		return nil, fmt.Errorf("%w: step %s/%s is not waiting for an answer",
			ErrNotAnswerable, sagaID, stepID)
	}

	phase := saga.PhaseUnderDecision(st)
	var requirement *janusv1.GateRequirement
	for _, req := range st.Gates {
		if req.GetId() == requirementID && req.GetPhase() == phase {
			requirement = req
			break
		}
	}
	if requirement == nil {
		return nil, fmt.Errorf("%w: step %s/%s is not waiting on a requirement called %q",
			ErrNotAnswerable, sagaID, stepID, requirementID)
	}
	if requirement.GetGate() != janusv1.GateType_GATE_TYPE_HUMAN {
		return nil, fmt.Errorf("%w: %q is answered by the participants it names, not by a person",
			ErrNotAnswerable, requirementID)
	}

	binding := identity.Binding{
		SagaID: sagaID, StepID: stepID, RequirementID: requirementID,
		Attempt: saga.AttemptUnderDecision(st, phase),
	}
	return &StepUpChallenge{
		SagaID:         sagaID,
		StepID:         stepID,
		RequirementID:  requirementID,
		Attempt:        binding.Attempt,
		Challenge:      base64.RawURLEncoding.EncodeToString(binding.Challenge()),
		RequiresStepUp: requirement.GetHuman().GetRequireStepUp(),
	}, nil
}

// assertionFrom builds what the approver presented, from the header the proxy
// set and the field the browser filled in.
//
// Returns nil when there is nothing to present, which is the pre-item-21
// behaviour: the console records what the authenticating layer asserted, and
// says so in auth_ref. A partial assertion is not built — a step-up with no
// token establishes that somebody with a registered credential was present,
// not who they are, and pkg/identity refuses it rather than reconciling.
func (s *Server) assertionFrom(r *http.Request, stepUpField string) (*identity.Assertion, error) {
	token := ""
	if s.opts.IDTokenHeader != "" {
		token = strings.TrimSpace(r.Header.Get(s.opts.IDTokenHeader))
	}
	blob := strings.TrimSpace(stepUpField)
	if token == "" && blob == "" {
		return nil, nil
	}
	// A step-up with no token is not rejected here. It is built as it stands
	// and refused by pkg/identity, which is the one place that decides what an
	// assertion has to contain — a second opinion in this file would be a
	// second rule to keep in step, and the first thing two rules do is drift.
	// Nothing reaches the log either way: the verification runs before the
	// answer is composed.
	a := &identity.Assertion{IDToken: token, RolesClaim: s.opts.RolesClaim}
	if blob != "" {
		var stepUp identity.StepUp
		if err := json.Unmarshal([]byte(blob), &stepUp); err != nil {
			return nil, fmt.Errorf("%w: the step-up field is not readable: %w",
				ErrNotAnswerable, err)
		}
		a.StepUp = &stepUp
	}
	return a, nil
}
