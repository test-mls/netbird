package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// MCPDeny asks RenderDenyResponse to answer an MCP JSON-RPC request in
// protocol instead of with an HTTP error. MCP clients treat a non-2xx answer
// to a POST as a transport failure, so the model never learns why; a tool
// result flagged isError reaches the model as a readable refusal.
type MCPDeny struct {
	// Batch is true when the request body was a JSON-RPC array.
	Batch bool
	// Requests lists every message of the body in order.
	Requests []MCPDeniedRequest
}

// MCPDeniedRequest is one JSON-RPC message of a denied body.
type MCPDeniedRequest struct {
	// ID is the raw JSON-RPC id. Messages without one are notifications and
	// get no response.
	ID json.RawMessage
	// Tool is the tool name when the message is a tools/call.
	Tool string
	// Denied marks the tools/call messages the caller may not make.
	Denied bool
}

const (
	maxRPCIDBytes     = 128
	mcpBatchRejectMsg = "request rejected: the batch contains a tool call your roles do not allow"
	// jsonRPCInvalidRequest is the JSON-RPC 2.0 "Invalid Request" code.
	jsonRPCInvalidRequest = -32600
)

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  *rpcToolResult  `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcToolResult struct {
	Content []rpcText `json:"content"`
	IsError bool      `json:"isError"`
}

type rpcText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// renderMCPDeny writes the JSON-RPC answer for d and reports whether it did.
// It writes nothing when no message carries a usable id, so the caller can
// fall back to the plain deny body.
func renderMCPDeny(w http.ResponseWriter, d *MCPDeny) bool {
	var responses []rpcResponse
	for _, req := range d.Requests {
		if !validRPCID(req.ID) {
			continue
		}
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
		if req.Denied {
			resp.Result = &rpcToolResult{IsError: true, Content: []rpcText{{
				Type: "text",
				Text: fmt.Sprintf("NetBird denied this tool call: your roles do not allow the MCP tool %q.", truncate(Scan(req.Tool), 128)),
			}}}
		} else {
			resp.Error = &rpcError{Code: jsonRPCInvalidRequest, Message: mcpBatchRejectMsg}
		}
		responses = append(responses, resp)
	}
	if len(responses) == 0 {
		return false
	}

	var body any = responses
	if !d.Batch {
		body = responses[0]
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
	return true
}

// validRPCID accepts the JSON-RPC id forms a client may send back: a number
// or a string, bounded in size. Anything else is not echoed.
func validRPCID(id json.RawMessage) bool {
	id = bytes.TrimSpace(id)
	if len(id) == 0 || len(id) > maxRPCIDBytes || !json.Valid(id) {
		return false
	}
	switch c := id[0]; {
	case c == '"':
		return true
	case c == '-' || (c >= '0' && c <= '9'):
		return true
	default:
		return false
	}
}
