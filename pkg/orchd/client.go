package orchd

import (
	"context"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/callersig"
	"github.com/mustafarslan/janus/pkg/evidence"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// Client is the thin side of the service boundary.
//
// It exists so that the things that used to open an evidence directory — the
// console first, the SDKs next — can ask the process that owns it instead,
// without every one of them growing its own knowledge of the wire. It holds no
// state and makes no decisions: a method here is one RPC.
type Client struct {
	rpc janusv1.OrchestratorServiceClient
	// signers are the participants this client may sign as, and acting the one
	// it signs declarations, results, saga begins and relayed human answers as.
	// A client holding one signer acts as it without being told.
	signers map[string]callersig.Signer
	acting  string
}

// NewClient wraps a connection. The caller owns the connection, because the
// caller knows when it is finished with it and this does not.
func NewClient(conn grpc.ClientConnInterface) *Client {
	return &Client{rpc: janusv1.NewOrchestratorServiceClient(conn)}
}

// WithSigners returns a client that signs as these participants. A daemon
// checks each signature against the keys the participant's manifest declares,
// and records it; a client with no signer sends nothing signed, which
// is accepted only for a participant that declares no key.
func (c *Client) WithSigners(signers ...callersig.Signer) *Client {
	out := *c
	out.signers = make(map[string]callersig.Signer, len(c.signers)+len(signers))
	for id, s := range c.signers {
		out.signers[id] = s
	}
	for _, s := range signers {
		out.signers[s.Participant] = s
	}
	return &out
}

// As returns a client that signs as one participant: the step's, for the
// declarations and results it sends, or the relayer, for a person's answers.
func (c *Client) As(participant string) *Client {
	out := *c
	out.acting = participant
	return &out
}

// actingSigner is who this client signs as when a message does not say.
func (c *Client) actingSigner() (callersig.Signer, bool) {
	if c.acting != "" {
		s, ok := c.signers[c.acting]
		return s, ok
	}
	if len(c.signers) == 1 {
		for _, s := range c.signers {
			return s, true
		}
	}
	return callersig.Signer{}, false
}

// RecordAnswer sends one gate answer and returns where it landed.
//
// The returned reference is the daemon's, taken from its own append. That is
// the point of returning it at all: the console can show the person who
// approved exactly which record their approval became, in a log the console
// cannot write to.
func (c *Client) RecordAnswer(ctx context.Context, answer *janusv1.GateAnswer) (
	evidence.Ref, error) {

	// A validator signs its own answer; a person's is signed by whoever relays it.
	signer, ok := c.signers[answer.GetActor().GetParticipant().GetId()]
	if !ok && answer.GetActor().GetHumanSubject() != "" {
		signer, ok = c.actingSigner()
	}
	if ok {
		answer = proto.Clone(answer).(*janusv1.GateAnswer)
		answer.Signature = signer.Sign(callersig.Answer(answer))
	}
	resp, err := c.rpc.RecordAnswer(ctx, &janusv1.RecordAnswerRequest{Answer: answer})
	if err != nil {
		return evidence.Ref{}, err
	}
	return refFromProto(resp.GetRef()), nil
}

// RegisterCredential enrols a WebAuthn authenticator for a person.
func (c *Client) RegisterCredential(ctx context.Context, credentialID, subject string,
	publicKeySPKI []byte) (evidence.Ref, error) {

	resp, err := c.rpc.RegisterCredential(ctx, &janusv1.RegisterCredentialRequest{
		CredentialId: credentialID, Subject: subject, PublicKey: publicKeySPKI,
	})
	if err != nil {
		return evidence.Ref{}, err
	}
	return refFromProto(resp.GetRef()), nil
}

// RevokeCredential withdraws a lost or stolen authenticator.
func (c *Client) RevokeCredential(ctx context.Context, credentialID, reason string) (
	evidence.Ref, error) {

	resp, err := c.rpc.RevokeCredential(ctx, &janusv1.RevokeCredentialRequest{
		CredentialId: credentialID, Reason: reason,
	})
	if err != nil {
		return evidence.Ref{}, err
	}
	return refFromProto(resp.GetRef()), nil
}

// RevokeIssuerKey withdraws one signing key of one OIDC issuer.
func (c *Client) RevokeIssuerKey(ctx context.Context, issuer, keyID, reason string) (
	evidence.Ref, error) {

	resp, err := c.rpc.RevokeIssuerKey(ctx, &janusv1.RevokeIssuerKeyRequest{
		Issuer: issuer, KeyId: keyID, Reason: reason,
	})
	if err != nil {
		return evidence.Ref{}, err
	}
	return refFromProto(resp.GetRef()), nil
}

// BeginSaga admits and records a plan.
func (c *Client) BeginSaga(ctx context.Context, begin *janusv1.SagaBegin) (
	evidence.Ref, error) {

	req := &janusv1.BeginSagaRequest{Begin: begin}
	if signer, ok := c.actingSigner(); ok {
		req.Signature = signer.Sign(callersig.Begin(begin))
	}
	resp, err := c.rpc.BeginSaga(ctx, req)
	if err != nil {
		return evidence.Ref{}, err
	}
	return refFromProto(resp.GetRef()), nil
}

// PrepareStep asks for a step to run, and says why not when the answer is no.
func (c *Client) PrepareStep(ctx context.Context, sagaID, stepID string,
	facts []*janusv1.Fact, spawns *janusv1.ChildSaga) (*janusv1.PrepareStepResponse, error) {

	req := &janusv1.PrepareStepRequest{SagaId: sagaID, StepId: stepID, Facts: facts, Spawns: spawns}
	if signer, ok := c.actingSigner(); ok {
		req.Signature = signer.Sign(callersig.Prepare(sagaID, stepID, facts, spawns))
	}
	return c.rpc.PrepareStep(ctx, req)
}

// CompleteStep reports what a participant did.
func (c *Client) CompleteStep(ctx context.Context, result *janusv1.StepResult) (
	*janusv1.CompleteStepResponse, error) {

	if signer, ok := c.actingSigner(); ok {
		result = proto.Clone(result).(*janusv1.StepResult)
		result.Signature = signer.Sign(callersig.Result(result))
	}
	return c.rpc.CompleteStep(ctx, &janusv1.CompleteStepRequest{Result: result})
}

// HoldEffect withholds an effect until its saga commits.
func (c *Client) HoldEffect(ctx context.Context, effect *janusv1.EffectHeld) (
	evidence.Ref, error) {

	resp, err := c.rpc.HoldEffect(ctx, &janusv1.HoldEffectRequest{Effect: effect})
	if err != nil {
		return evidence.Ref{}, err
	}
	return refFromProto(resp.GetRef()), nil
}

// DeliverEffects opens the stream this process serves targets on.
func (c *Client) DeliverEffects(ctx context.Context) (
	janusv1.OrchestratorService_DeliverEffectsClient, error) {

	return c.rpc.DeliverEffects(ctx)
}

// ReleaseEffects delivers what a committed saga was holding.
func (c *Client) ReleaseEffects(ctx context.Context, sagaID string) (uint32, error) {
	resp, err := c.rpc.ReleaseEffects(ctx, &janusv1.ReleaseEffectsRequest{SagaId: sagaID})
	if err != nil {
		return 0, err
	}
	return resp.GetReleased(), nil
}

// ResolveParticipant returns what a pinned manifest version declares, so a
// client can check its own declarations before it starts anything.
func (c *Client) ResolveParticipant(ctx context.Context, participantID, version string) (
	*janusv1.ResolveParticipantResponse, error) {

	return c.rpc.ResolveParticipant(ctx, &janusv1.ResolveParticipantRequest{
		ParticipantId: participantID, Version: version,
	})
}

// GetSaga reads the projection.
func (c *Client) GetSaga(ctx context.Context, sagaID string) (*janusv1.SagaProjection, error) {
	resp, err := c.rpc.GetSaga(ctx, &janusv1.GetSagaRequest{SagaId: sagaID})
	if err != nil {
		return nil, err
	}
	return resp.GetSaga(), nil
}

// refFromProto is deliberately partial: the chain hash is copied and the wall
// clock is not carried at all. A caller that needs the full record reads it out
// of the log, which is where the full record is.
func refFromProto(r *janusv1.EvidenceRef) evidence.Ref {
	out := evidence.Ref{
		EventID:   r.GetEventId(),
		Seq:       r.GetSeq(),
		SegmentID: r.GetSegmentId(),
		HLC:       r.GetHlc(),
	}
	copy(out.ChainHash[:], r.GetChainHash())
	return out
}
