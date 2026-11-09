package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func renderMCP(t *testing.T, mcp *MCPDeny) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	RenderDenyResponse(rec, "app_authz", &DenyReason{Code: "mcp_tool_forbidden", Message: "no", MCP: mcp}, http.StatusForbidden)
	return rec
}

func TestRenderMCPDenySingle(t *testing.T) {
	rec := renderMCP(t, &MCPDeny{Requests: []MCPDeniedRequest{{ID: json.RawMessage(`7`), Tool: "delete_ticket", Denied: true}}})

	require.Equal(t, http.StatusOK, rec.Code, "MCP clients need a 2xx to read the JSON-RPC body")
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "2.0", resp["jsonrpc"])
	assert.EqualValues(t, 7, resp["id"], "the id matches the request")
	result := resp["result"].(map[string]any)
	assert.Equal(t, true, result["isError"], "a tool error the model can read")
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	assert.Contains(t, text, `"delete_ticket"`)
}

func TestRenderMCPDenyBatch(t *testing.T) {
	rec := renderMCP(t, &MCPDeny{Batch: true, Requests: []MCPDeniedRequest{
		{ID: json.RawMessage(`"a"`), Tool: "list_tickets"},
		{ID: json.RawMessage(`"b"`), Tool: "delete_ticket", Denied: true},
		{Tool: "ping"}, // a notification gets no response
	}})

	require.Equal(t, http.StatusOK, rec.Code)
	var resp []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp, 2, "one response per message with an id")
	assert.Equal(t, "a", resp[0]["id"])
	assert.NotNil(t, resp[0]["error"], "the allowed call is rejected with the batch, as an error")
	assert.Equal(t, "b", resp[1]["id"])
	assert.Equal(t, true, resp[1]["result"].(map[string]any)["isError"])
}

func TestRenderMCPDenyFallsBack(t *testing.T) {
	rec := renderMCP(t, &MCPDeny{Requests: []MCPDeniedRequest{{Tool: "x", Denied: true}}})
	assert.Equal(t, http.StatusForbidden, rec.Code, "with no id to answer, the plain deny is used")

	rec = renderMCP(t, &MCPDeny{Requests: []MCPDeniedRequest{{ID: json.RawMessage(`{"evil":1}`), Tool: "x", Denied: true}}})
	assert.Equal(t, http.StatusForbidden, rec.Code, "ids that are not a number or string are never echoed")
}
