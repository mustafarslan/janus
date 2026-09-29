package orchd

import (
	"context"
	"errors"
	"fmt"
	"slices"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/callersig"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Who is calling.
//
// The daemon took every caller at its word: an answer's actor, a step's
// reporter and a saga's principal were whatever the message said. Now a
// participant signs what it asks to have recorded, with a key its registered
// manifest declares, and the signature goes into the record. These are the
// checks, one per thing a caller can claim.

// signingRegistry is the registry the caller checks read (see Server.signing).
func (s *Server) signingRegistry(ctx context.Context) (*registry.Registry, error) {
	s.signingMu.Lock()
	defer s.signingMu.Unlock()
	if s.signing == nil {
		reg, err := s.registryNow(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "reading the registry to check who is "+
				"calling: %v", err)
		}
		s.signing = reg
	}
	return s.signing, nil
}

// forgetRegistry drops the cached registry after this process records a
// registry event.
func (s *Server) forgetRegistry() {
	s.signingMu.Lock()
	s.signing = nil
	s.signingMu.Unlock()
}

// declared is what a participant's manifest says about who may sign as it.
type declared struct {
	keys      []string
	kind      string
	principal string
	found     bool
}

// declaredFor reads a participant's manifest: the version a saga pinned, when
// there is one -- a saga is admitted against a version and judged by it (I8), so
// a rotation mid-saga does not strand it -- and otherwise the active version.
func declaredFor(reg *registry.Registry, participant, pinned string) declared {
	var e *registry.Entry
	var ok bool
	if pinned != "" {
		e, ok = reg.Resolve(participant, pinned)
	} else {
		e, ok = reg.Active(participant)
	}
	if !ok || e.Manifest == nil {
		return declared{}
	}
	id := e.Manifest.Identity
	return declared{keys: id.PublicKeys, kind: id.Kind, principal: id.Principal, found: true}
}

// withoutActiveVersion reports whether a participant is in the registry but has
// no version that may act now. A suspended or retired participant is not one
// that declares no key: before this check the daemon read "no ACTIVE version" as
// "no key to check", and took an unsigned answer in the name of a validator
// whose key had just been suspended as compromised (the 2026-09-29 audit, M-1).
func withoutActiveVersion(reg *registry.Registry, participant string) bool {
	if _, ok := reg.Active(participant); ok {
		return false
	}
	return len(reg.Versions(participant)) > 0
}

// pinsOf reads the manifest versions a saga was admitted against, from its
// SAGA_BEGIN. The projection does not carry them; the record does.
func (s *Server) pinsOf(sagaID string) (map[string]string, error) {
	events, err := saga.LoadEvents(s.dir, sagaID)
	if err != nil || len(events) == 0 {
		return nil, err
	}
	var begin janusv1.SagaBegin
	if err := proto.Unmarshal(events[0].Payload, &begin); err != nil {
		return nil, err
	}
	return begin.GetManifestPins(), nil
}

// checkSigned applies the rule: a participant that declares a key must sign
// with it; one that declares none may go unsigned only if this daemon allows
// keyless participants at all.
func (s *Server) checkSigned(who string, d declared, sig *janusv1.ParticipantSignature,
	canonical []byte, what string) error {

	if len(d.keys) == 0 && (sig == nil || len(sig.GetSignature()) == 0) {
		if s.requireSigned {
			return status.Errorf(codes.Unauthenticated,
				"%s on behalf of %q is unsigned, and this daemon requires every caller to sign; "+
					"%q's manifest declares no key to sign with (identity.public_keys)", what, who, who)
		}
		return nil
	}
	if err := callersig.Verify(sig, who, d.keys, canonical); err != nil {
		code := codes.PermissionDenied
		if errors.Is(err, callersig.ErrUnsigned) {
			code = codes.Unauthenticated
		}
		return status.Errorf(code, "%s on behalf of %q is not %q's to make: %v; a participant "+
			"that declares a key signs what it asks to have recorded with it", what, who, who, err)
	}
	return nil
}

// checkAnswer: an answer is signed by the participant it is from, or, for a
// person's answer, by a participant allowed to relay one.
func (s *Server) checkAnswer(reg *registry.Registry, pins map[string]string,
	a *janusv1.GateAnswer) error {

	canonical := callersig.Answer(a)
	// The fold counts an actor naming a person as that person, whatever else it
	// names (saga.actorIdentity). Reading the participant here instead let an
	// agent sign as itself and record "alice approved". So an
	// actor is a participant or a person, never both.
	if a.GetActor().GetHumanSubject() != "" && a.GetActor().GetParticipant().GetId() != "" {
		return status.Error(codes.InvalidArgument,
			"an answer's actor names both a participant and a person; it is one or the other, "+
				"and a person's answer is signed by the participant relaying it")
	}
	if who := a.GetActor().GetParticipant().GetId(); who != "" {
		if pins[who] == "" && withoutActiveVersion(reg, who) {
			return status.Errorf(codes.PermissionDenied,
				"%q has no active version in the registry -- it is suspended, retired or not yet "+
					"activated -- and a participant that may not act may not answer", who)
		}
		return s.checkSigned(who, declaredFor(reg, who, pins[who]), a.GetSignature(), canonical,
			"an answer to "+fmt.Sprintf("%q", a.GetRequirementId()))
	}
	if a.GetActor().GetHumanSubject() == "" {
		return nil // the state machine refuses an answer that names nobody
	}
	sig := a.GetSignature()
	relayer := sig.GetParticipantId()
	switch {
	case len(s.humanRelayers) > 0 && !slices.Contains(s.humanRelayers, relayer):
		return status.Errorf(codes.PermissionDenied,
			"a person's answer (%q) was relayed by %q, and this daemon accepts a person's answer "+
				"only from %v; an agent that could record a person's approval in its own name "+
				"would be authoring its own permission", a.GetActor().GetHumanSubject(),
			relayer, s.humanRelayers)
	case len(s.humanRelayers) == 0 && !s.requireSigned && (sig == nil || len(sig.GetSignature()) == 0):
		return nil
	}
	// A suspended relayer needs no check of its own here: its keys resolve to
	// nothing, so a signature by it fails verification below, and an unsigned
	// relay names no relayer to check.
	d := declaredFor(reg, relayer, pins[relayer])
	if d.found && d.kind != "SYSTEM" && d.kind != "HUMAN" {
		return status.Errorf(codes.PermissionDenied,
			"a person's answer was relayed by %q, a participant of kind %s; only a SYSTEM or "+
				"HUMAN participant relays what a person decided", relayer, d.kind)
	}
	return s.checkSigned(relayer, d, sig, canonical, "a person's answer")
}

// checkStepCaller: a declaration or a result is signed by the step's
// participant, against the manifest version the saga pinned for it.
func (s *Server) checkStepCaller(ctx context.Context, sagaID, participant string,
	sig *janusv1.ParticipantSignature, canonical []byte, what string) error {

	reg, err := s.signingRegistry(ctx)
	if err != nil {
		return err
	}
	pins, err := s.pinsOf(sagaID)
	if err != nil {
		return status.Errorf(codes.Internal, "reading saga %q's pins: %v", sagaID, err)
	}
	return s.checkSigned(participant, declaredFor(reg, participant, pins[participant]), sig,
		canonical, what)
}

// checkBegin: a saga is begun by one of its own participants, signing, whose
// manifest names the principal the intent claims to act for.
func (s *Server) checkBegin(reg *registry.Registry, begin *janusv1.SagaBegin,
	sig *janusv1.ParticipantSignature) error {

	signer := sig.GetParticipantId()
	if signer == "" {
		if s.requireSigned {
			return status.Error(codes.Unauthenticated,
				"a saga begin is unsigned, and this daemon requires every caller to sign; one of "+
					"the plan's participants signs the saga it begins")
		}
		return nil
	}
	inPlan := slices.ContainsFunc(begin.GetPlan(), func(st *janusv1.PlannedStep) bool {
		return st.GetParticipant() == signer
	})
	if !inPlan {
		return status.Errorf(codes.PermissionDenied,
			"saga %q is signed by %q, which is not one of its participants", begin.GetSagaId(), signer)
	}
	d := declaredFor(reg, signer, begin.GetManifestPins()[signer])
	if d.principal != begin.GetIntent().GetPrincipal() {
		return status.Errorf(codes.PermissionDenied,
			"saga %q claims to act for %q and is signed by %q, whose manifest names %q; a "+
				"participant cannot begin work in another principal's name",
			begin.GetSagaId(), begin.GetIntent().GetPrincipal(), signer, d.principal)
	}
	return s.checkSigned(signer, d, sig, callersig.Begin(begin), "a saga begin")
}
