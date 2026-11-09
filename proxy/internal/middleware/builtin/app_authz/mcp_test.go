package app_authz

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var postHeaders = http.Header{"Content-Length": {"1"}}

// lenientCall is how an upstream written with encoding/json reads a message:
// keys match case-insensitively and the last duplicate wins.
type lenientCall struct {
	Method string `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// checkAgreesWithLenientDecoder fails when parseBody accepted a body that a
// Go upstream would read as a different tools/call: that is a bypass.
func checkAgreesWithLenientDecoder(t *testing.T, body []byte) {
	t.Helper()
	parsed, err := parseBody(http.MethodPost, postHeaders, body, false)
	if err != nil {
		return
	}
	trimmed := bytes.TrimSpace(body)
	raws := []json.RawMessage{trimmed}
	if parsed.batch {
		raws = nil
		require.NoError(t, json.Unmarshal(trimmed, &raws))
	}
	require.Len(t, parsed.messages, len(raws))
	for i, raw := range raws {
		var lenient lenientCall
		if json.Unmarshal(raw, &lenient) != nil {
			continue
		}
		isCall := lenient.Method == methodToolsCall
		if isCall != parsed.messages[i].isCall {
			t.Fatalf("proxy and upstream disagree on whether %q is a tools/call", raw)
		}
		if isCall && lenient.Params.Name != parsed.messages[i].tool {
			t.Fatalf("proxy saw tool %q, upstream would call %q, in %q", parsed.messages[i].tool, lenient.Params.Name, raw)
		}
	}
}

func TestParseBodyRejectsUnicodeFoldedKeys(t *testing.T) {
	// U+017F (long s) folds to "s" in encoding/json, so a Go upstream reads
	// "paramſ" as "params", and the last duplicate wins.
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_x"},"paramſ":{"name":"delete_x"}}`)
	_, err := parseBody(http.MethodPost, postHeaders, body, false)
	assert.Error(t, err, "a key that folds to a reserved key must be refused")
	checkAgreesWithLenientDecoder(t, body)

	// U+212A (Kelvin sign) folds to "k"; no reserved key has a k, so it stays
	// an ordinary key and the message is accepted.
	body = []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_x","Key":1}}`)
	_, err = parseBody(http.MethodPost, postHeaders, body, false)
	assert.NoError(t, err)
}

func FuzzParseBody(f *testing.F) {
	for _, seed := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_x"}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`,
		`{"method":"tools/call","params":{"name":"a","Name":"b"}}`,
		`{"method":"tools/call","params":{"name":"a"},"paramſ":{"name":"b"}}`,
		`{"method":"tools/call","Method":"x"}`,
		`{"method":"tools/call","params":null}`,
		`{"id":1,"result":{}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		checkAgreesWithLenientDecoder(t, body)
	})
}
