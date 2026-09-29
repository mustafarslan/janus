package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// EchoServer is a minimal MCP tool server used to exercise the interception
// path. It exists so the spike can prove the "tool servers need zero change"
// claim against something that genuinely knows nothing about Janus.
//
// It offers two tools chosen to sit at opposite ends of the effect
// classification: echo is PURE, and wire.send stands in for the kind of
// irreversible action that Phase 3's gates exist to hold back.
type EchoServer struct {
	// ServerName is reported during initialize.
	ServerName string
}

// Tool descriptions returned by tools/list.
var echoTools = []map[string]any{
	{
		"name":        "echo",
		"description": "Return the text it was given. No external effect.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"text": map[string]any{"type": "string"}},
			"required":   []string{"text"},
		},
	},
	{
		"name":        "wire.send",
		"description": "Pretend to send a payment. Stands in for an irreversible effect.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"account": map[string]any{"type": "string"},
				"amount":  map[string]any{"type": "number"},
			},
			"required": []string{"account", "amount"},
		},
	},
}

// Serve reads requests from in and writes responses to out until in is closed.
func (s *EchoServer) Serve(in io.Reader, out io.Writer) error {
	name := s.ServerName
	if name == "" {
		name = "janus-toytool"
	}
	r := NewReader(in)
	w := NewWriter(out)

	for {
		f, err := r.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		// Notifications carry no id and expect no response.
		if len(f.ID) == 0 {
			continue
		}

		var result any
		var rpcErr *rpcError

		switch f.Method {
		case MethodInitialize:
			result = map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": name, "version": "0.1.0"},
			}
		case MethodToolsList:
			result = map[string]any{"tools": echoTools}
		case MethodPing:
			result = map[string]any{}
		case MethodToolsCall:
			result, rpcErr = s.callTool(f)
		default:
			rpcErr = &rpcError{Code: -32601, Message: "method not found: " + f.Method}
		}

		resp := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(f.ID)}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}
		raw, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		if err := w.Write(Frame{Raw: raw}); err != nil {
			return err
		}
	}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *EchoServer) callTool(f Frame) (any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(f.Params, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	switch p.Name {
	case "echo":
		var args struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, &rpcError{Code: -32602, Message: "invalid arguments: " + err.Error()}
		}
		return textResult(args.Text), nil

	case "wire.send":
		var args struct {
			Account string  `json:"account"`
			Amount  float64 `json:"amount"`
		}
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, &rpcError{Code: -32602, Message: "invalid arguments: " + err.Error()}
		}
		return textResult(fmt.Sprintf("pretended to send %.2f to %s", args.Amount, args.Account)), nil

	default:
		return nil, &rpcError{Code: -32602, Message: "unknown tool: " + p.Name}
	}
}

func textResult(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": false,
	}
}

// Request builds a JSON-RPC request frame, for tests and the demo client.
func Request(id int, method string, params any) (Frame, error) {
	obj := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		obj["params"] = params
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Raw: raw, ID: json.RawMessage(fmt.Sprintf("%d", id)), Method: method}, nil
}

// ToolCall builds a tools/call request frame.
func ToolCall(id int, tool string, args any) (Frame, error) {
	return Request(id, MethodToolsCall, map[string]any{"name": tool, "arguments": args})
}
