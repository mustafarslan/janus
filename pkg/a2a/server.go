package a2a

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/registry"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// The discovery surface.
//
// Three read paths, and every one of them derives its answer from the evidence
// log on the request rather than from anything held here. That is the same
// trade the console makes and for the same reason: a discovery
// service with its own copy of the registry is a second system of record that
// will eventually disagree with the first, and the disagreement surfaces as a
// counterpart being told about a version that was withdrawn an hour ago.

// ServerOptions configures the discovery surface.
type ServerOptions struct {
	// Dir is the evidence directory the registry is folded from.
	Dir string
	// Participant and Version are what this endpoint advertises.
	Participant string
	Version     string
	// BaseURL is where this agent is reachable, as it should appear on the card.
	BaseURL string
}

// Server serves the discovery documents and the registry watch.
type Server struct{ opts ServerOptions }

// NewServer returns the discovery surface.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Dir == "" || opts.Participant == "" || opts.Version == "" {
		return nil, fmt.Errorf("a2a: a discovery endpoint needs an evidence directory and " +
			"the participant and version it advertises")
	}
	return &Server{opts: opts}, nil
}

// Handler routes the discovery surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent.json", s.card)
	mux.HandleFunc("GET /.well-known/janus-manifest.json", s.manifest)
	mux.HandleFunc("GET /registry/watch", s.watch)
	return mux
}

// card serves the lossy projection.
func (s *Server) card(w http.ResponseWriter, _ *http.Request) {
	entry, err := s.resolve()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	card, err := CardFor(entry, s.opts.BaseURL)
	if err != nil {
		// A version that is not active is not advertised, and 404 is the honest
		// answer: there is no card here. Serving one with a "suspended" field
		// would invite a counterpart to decide for itself whether that matters.
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, card)
}

// manifest serves the superset the card points at.
//
// The whole manifest, verbatim, including the effect classes the card leaves
// out. There is no contradiction in that: this document is what the registry
// holds and what was signed, and a reader who fetched it still has not checked
// anything — the check is asking the registry about a pinned version, which is
// what Verifier does. What this gives a counterpart is the ability to read the
// declaration before deciding to pin it.
func (s *Server) manifest(w http.ResponseWriter, _ *http.Request) {
	entry, err := s.resolve()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, entry.Manifest)
}

// watch streams registry events after a sequence.
//
// Polled rather than pushed, and by sequence rather than by subscription,
// because "everything after sequence N" is how every other reader in this
// system works and it is the only form that survives a disconnect: a consumer
// that reconnects says where it got to, and no state has to be held here on its
// behalf.
func (s *Server) watch(w http.ResponseWriter, r *http.Request) {
	after, err := parseAfter(r.URL.Query().Get("after"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	events, err := registry.LoadEvents(s.opts.Dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	for _, event := range events {
		if event.Seq <= after {
			continue
		}
		var msg janusv1.RegistryEvent
		if err := proto.Unmarshal(event.Payload, &msg); err != nil {
			continue
		}
		raw, merr := protojson.Marshal(&msg)
		if merr != nil {
			continue
		}
		// One object per line, each carrying its own sequence. A consumer that
		// stops halfway has still consumed a prefix it can name.
		_ = enc.Encode(watchLine{Seq: event.Seq, Event: json.RawMessage(raw)})
	}
}

type watchLine struct {
	Seq   uint64          `json:"seq"`
	Event json.RawMessage `json:"event"`
}

func (s *Server) resolve() (*registry.Entry, error) {
	events, err := registry.LoadEvents(s.opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("reading the registry: %w", err)
	}
	reg, err := registry.Fold(events)
	if err != nil {
		return nil, fmt.Errorf("folding the registry: %w", err)
	}
	entry, ok := reg.Resolve(s.opts.Participant, s.opts.Version)
	if !ok {
		return nil, fmt.Errorf("%s@%s is not registered", s.opts.Participant, s.opts.Version)
	}
	return entry, nil
}

func parseAfter(raw string) (uint64, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("after must be a sequence number: %w", err)
	}
	return n, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
