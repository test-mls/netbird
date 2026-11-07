package app_authz

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const methodToolsCall = "tools/call"

// reservedKeys are the JSON-RPC keys the tool check reads. A case variant of
// one would be ignored here but may be honoured by a case-insensitive
// upstream decoder, so it is rejected.
var reservedKeys = map[string]struct{}{"jsonrpc": {}, "id": {}, "method": {}, "params": {}, "name": {}}

var (
	errBodyNotInspected = errors.New("request body could not be inspected")
	errBodyNotJSONRPC   = errors.New("request body is not unambiguous JSON-RPC")
)

// toolCalls returns the tool names of every tools/call message in a POST
// body. A single message and a batch array are both accepted. Any body the
// proxy did not fully capture, or cannot parse as JSON-RPC without ambiguity,
// is an error so the caller can fail closed: a tools/call it cannot see is
// one it cannot authorize.
func toolCalls(method string, headers http.Header, body []byte, truncated bool) ([]string, error) {
	if method != http.MethodPost {
		return nil, nil
	}
	if truncated {
		return nil, errBodyNotInspected
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		if headers.Get("Content-Length") == "0" {
			return nil, nil
		}
		return nil, errBodyNotInspected
	}

	var raws []json.RawMessage
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &raws); err != nil {
			return nil, errBodyNotJSONRPC
		}
	} else {
		raws = []json.RawMessage{trimmed}
	}

	var tools []string
	for _, raw := range raws {
		tool, isCall, err := parseMessage(raw)
		if err != nil {
			return nil, err
		}
		if isCall {
			tools = append(tools, tool)
		}
	}
	return tools, nil
}

// parseMessage reports whether raw is a tools/call and, if so, its tool name.
func parseMessage(raw json.RawMessage) (string, bool, error) {
	fields, err := strictObject(raw)
	if err != nil {
		return "", false, err
	}
	methodRaw, ok := fields["method"]
	if !ok {
		// A response or an error object; nothing to authorize.
		return "", false, nil
	}
	var method string
	if err := json.Unmarshal(methodRaw, &method); err != nil {
		return "", false, errBodyNotJSONRPC
	}
	if method != methodToolsCall {
		return "", false, nil
	}
	paramsRaw, ok := fields["params"]
	if !ok {
		return "", true, nil
	}
	params, err := strictObject(paramsRaw)
	if err != nil {
		return "", false, err
	}
	var name string
	if nameRaw, ok := params["name"]; ok {
		if err := json.Unmarshal(nameRaw, &name); err != nil {
			return "", false, errBodyNotJSONRPC
		}
	}
	return name, true, nil
}

// strictObject decodes a JSON object into its fields with exact-case keys.
// encoding/json matches struct fields case-insensitively and keeps the last
// duplicate, while upstream servers in other languages may keep the first or
// match exactly. Rejecting duplicate keys, including keys that differ only in
// case, removes any reading of the message that differs from the upstream's.
func strictObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errBodyNotJSONRPC
	}
	fields := make(map[string]json.RawMessage)
	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, errBodyNotJSONRPC
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errBodyNotJSONRPC
		}
		folded := strings.ToLower(key)
		if _, dup := seen[folded]; dup {
			return nil, fmt.Errorf("%w: duplicate key %q", errBodyNotJSONRPC, key)
		}
		if _, reserved := reservedKeys[folded]; reserved && key != folded {
			return nil, fmt.Errorf("%w: key %q differs from %q only in case", errBodyNotJSONRPC, key, folded)
		}
		seen[folded] = struct{}{}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, errBodyNotJSONRPC
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, errBodyNotJSONRPC
	}
	if dec.More() {
		return nil, errBodyNotJSONRPC
	}
	return fields, nil
}
