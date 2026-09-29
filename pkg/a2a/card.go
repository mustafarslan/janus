// Package a2a is the agent-to-agent interception edge: the discovery surface a
// counterpart resolves Janus through, and the middleware that sits between two
// agents speaking A2A.
//
// It is deliberately thinner than janus-mcpd. At the tool edge, a call *is* an
// effect, so mcpd turns one into a saga step, gates it, and routes it through
// the outbox. At the agent edge a message is a message: what Janus adds is that
// both sides can say which saga and step a message belongs to, that the
// counterpart is somebody the registry knows, and that what was said is on the
// record. Turning agent messages into saga steps would be inventing a
// transaction where the two agents did not agree to have one.
package a2a

import (
	"encoding/json"
	"fmt"

	"github.com/mustafarslan/janus/pkg/registry"
)

// CapabilityJanusTransactions is the A2A extension a Janus-governed agent
// advertises. A counterpart that understands it knows the saga and
// step headers below will be honoured; one that does not sees an ordinary
// AgentCard and is unaffected.
const CapabilityJanusTransactions = "janus.transactions/v1"

// AgentCard is the A2A discovery document, served at /.well-known/agent.json.
//
// It is a *lossy* projection of the participant's signed manifest, and the loss
// is the point. An AgentCard is an unauthenticated document fetched over the
// network from whoever is answering that address; a manifest is signed, its
// version is immutable, and the registry records its lifecycle. Deferred item
// 15 states the rule: nothing may consume the AgentCard to make a gating
// decision.
//
// So this projection does not carry effect classes at all.
//
// That is a stronger position than carrying them and writing "do not gate on
// these" beside them, and it is the reason to prefer it: a field that exists is
// a field somebody will eventually read, and the person who reads this one
// would be deciding whether to hold a payment on the word of a document anybody
// can serve. What the card carries is enough to find the agent and to know it
// speaks the extension; what an effect class is worth knowing for, the registry
// answers, from the log, about a version somebody pinned.
type AgentCard struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Version     string `json:"version"`
	// Provider is the legal principal the participant acts for. It is on the
	// card because "who is answerable for this agent" is exactly what a
	// counterpart is entitled to ask before it starts talking, and unlike an
	// effect class it is not something a gate decides on.
	Provider AgentProvider `json:"provider"`
	// Capabilities are the A2A extensions this agent speaks.
	Capabilities []string `json:"capabilities"`
	// Skills are the actions the manifest declares, by name only.
	Skills []AgentSkill `json:"skills"`
	// ManifestURL points at the superset: the Janus manifest served
	// alongside this card, which is where the answers this document
	// deliberately does not give come from.
	ManifestURL string `json:"manifest_url"`
	// ManifestVersion and ManifestAddress name exactly which declaration this
	// card was projected from, so a reader can ask the registry about that one
	// rather than about whatever is current.
	ManifestVersion string `json:"manifest_version"`
	ManifestAddress string `json:"manifest_address"`
}

// AgentProvider is who is answerable.
type AgentProvider struct {
	Organization string `json:"organization"`
}

// AgentSkill is one advertised action.
//
// A name and nothing else. The manifest's idempotency recipe, limits,
// compensation and effect class are all absent by design — see the note on
// AgentCard.
type AgentSkill struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CardFor projects an active manifest into an AgentCard.
//
// It refuses a version that is not ACTIVE. A suspended agent still has a
// manifest and the registry will still answer questions about it, but
// advertising it invites traffic that admission would refuse — and a discovery
// document is an invitation.
func CardFor(entry *registry.Entry, baseURL string) (*AgentCard, error) {
	if entry == nil || entry.Manifest == nil {
		return nil, fmt.Errorf("a2a: no manifest to project")
	}
	if entry.State != registry.StateActive {
		return nil, fmt.Errorf("a2a: %s@%s is %s, so it is not advertised; a discovery "+
			"document is an invitation, and this version is one admission would refuse",
			entry.ParticipantID, entry.Version, entry.State)
	}

	card := &AgentCard{
		Name:            entry.ParticipantID,
		Description:     fmt.Sprintf("%s, governed by Janus", entry.ParticipantID),
		URL:             baseURL,
		Version:         entry.Version,
		Provider:        AgentProvider{Organization: entry.Manifest.Identity.Principal},
		Capabilities:    []string{CapabilityJanusTransactions},
		ManifestURL:     baseURL + "/.well-known/janus-manifest.json",
		ManifestVersion: entry.Version,
		ManifestAddress: entry.ContentAddress,
	}
	for _, action := range entry.Manifest.Actions {
		card.Skills = append(card.Skills, AgentSkill{ID: action.Name, Name: action.Name})
	}
	return card, nil
}

// Speaks reports whether a card advertises the Janus extension.
//
// It is used to decide whether to propagate saga headers to a counterpart, and
// for nothing else. Believing a card about what an agent *does* is the mistake
// this package refuses to make; believing it about which wire format the agent
// understands costs nothing, because a counterpart that lied would only be
// asking to be sent headers it then ignores.
func (c *AgentCard) Speaks(capability string) bool {
	for _, have := range c.Capabilities {
		if have == capability {
			return true
		}
	}
	return false
}

// ParseCard reads a counterpart's card.
func ParseCard(raw []byte) (*AgentCard, error) {
	var card AgentCard
	if err := json.Unmarshal(raw, &card); err != nil {
		return nil, fmt.Errorf("a2a: unreadable agent card: %w", err)
	}
	if card.Name == "" {
		return nil, fmt.Errorf("a2a: agent card names no agent")
	}
	return &card, nil
}
