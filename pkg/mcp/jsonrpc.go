// Package mcp implements the Janus interception edge for the Model Context
// Protocol: the agent↔tool leg.
//
// The design commitment here is interception rather than
// reimplementation. An agent connects to janus-mcpd exactly as it would connect
// to the tool server, and janus-mcpd connects onward to the real server
// unchanged. Neither side is modified, neither side needs to know Janus exists,
// and messages are forwarded byte for byte — the bytes that are hashed into the
// evidence log are the same bytes that crossed the wire, not a re-serialisation
// of them.
//
// Phase 0 observes and records. Classifying a call by effect class and refusing
// to forward an ungated irreversible one is Phase 3; the classification is
// computed and recorded here so that the gate has something to act on when it
// arrives.
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxFrameBytes bounds one JSON-RPC message. A peer that sends more is
// misbehaving, and unbounded buffering would be a denial-of-service vector.
const maxFrameBytes = 16 << 20

// Frame is one JSON-RPC message with its bytes preserved exactly as received.
//
// Raw is what gets hashed and forwarded; the parsed fields are only used for
// routing and classification. Keeping the two separate means a quirk of Go's
// JSON encoder can never change what the log says was sent.
type Frame struct {
	Raw    json.RawMessage
	ID     json.RawMessage
	Method string
	Params json.RawMessage
	IsResp bool
	IsErr  bool
}

// envelope is the subset of JSON-RPC 2.0 the proxy needs to understand.
type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// Reader decodes a stream of JSON-RPC messages.
type Reader struct {
	dec *json.Decoder
}

// NewReader wraps r as a JSON-RPC message stream. MCP's stdio transport is a
// sequence of JSON values, so a streaming decoder handles both the
// newline-delimited form and any incidental whitespace.
func NewReader(r io.Reader) *Reader {
	return &Reader{dec: json.NewDecoder(bufio.NewReaderSize(r, 64<<10))}
}

// Next returns the next frame, or io.EOF at the end of the stream.
func (r *Reader) Next() (Frame, error) {
	var raw json.RawMessage
	if err := r.dec.Decode(&raw); err != nil {
		return Frame{}, err
	}
	if len(raw) > maxFrameBytes {
		return Frame{}, fmt.Errorf("mcp: message of %d bytes exceeds the %d byte limit", len(raw), maxFrameBytes)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// Forward-compatibility: a message this proxy cannot parse is still
		// recorded and still forwarded. Refusing to pass on a message we merely
		// do not understand would make Janus a compatibility hazard.
		return Frame{Raw: raw}, nil
	}
	return Frame{
		Raw:    raw,
		ID:     env.ID,
		Method: env.Method,
		Params: env.Params,
		IsResp: env.Method == "" && (env.Result != nil || env.Error != nil),
		IsErr:  env.Error != nil,
	}, nil
}

// Writer forwards frames verbatim.
type Writer struct {
	w  *bufio.Writer
	nl bool
}

// NewWriter wraps w. Each frame is followed by a newline, which is what MCP's
// stdio transport expects and what makes the stream readable in a log.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: bufio.NewWriterSize(w, 64<<10), nl: true}
}

// Write forwards one frame and flushes, because a buffered response that never
// reaches the peer is a hang.
func (w *Writer) Write(f Frame) error {
	if _, err := w.w.Write(f.Raw); err != nil {
		return err
	}
	if w.nl {
		if err := w.w.WriteByte('\n'); err != nil {
			return err
		}
	}
	return w.w.Flush()
}

// ToolCallName extracts the tool name from a tools/call request.
func ToolCallName(f Frame) (string, bool) {
	if f.Method != MethodToolsCall || len(f.Params) == 0 {
		return "", false
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(f.Params, &p); err != nil || p.Name == "" {
		return "", false
	}
	return p.Name, true
}

// IDKey renders a request id as a map key. JSON-RPC allows numbers, strings, or
// null, so the raw bytes are the only universally correct key.
func IDKey(id json.RawMessage) string {
	if len(id) == 0 {
		return ""
	}
	return string(id)
}

// MCP method names the proxy treats specially.
const (
	MethodInitialize = "initialize"
	MethodToolsList  = "tools/list"
	MethodToolsCall  = "tools/call"
	MethodPing       = "ping"
)

// ErrClosed reports a stream that ended normally.
var ErrClosed = errors.New("mcp: stream closed")
