package rypt

import (
	"strings"
	"testing"
)

// FuzzAPIError: no error body makes apiError panic or put an unsafe
// character, or the token, in the Error's text.
func FuzzAPIError(f *testing.F) {
	f.Add(400, []byte(`{"error":"not_found","message":"m","request_id":"r"}`), "hdr")
	f.Add(429, []byte(`{"error":"ops_cap_reached","cap":10,"resets_at":"2026-11-01T00:00:00Z"}`), "")
	f.Add(502, []byte("<html>\x1b[31m</html>"), "id\u202e")
	f.Add(400, []byte(`{"error":"x","message":"`+testToken+`"}`), testToken)
	c, err := NewClient(testToken)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, status int, body []byte, header string) {
		e := c.apiError(status, body, c.serverText(header))
		text := e.Error()
		assertPrintable(t, text)
		if strings.Contains(text, "\n") {
			t.Errorf("multi-line error %q", text)
		}
	})
}

// FuzzDecode: no response body makes decoding panic, and a body that is
// refused is never quoted.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"dek":"` + b64(make([]byte, 32)) + `","wrapped":"V1c="}`))
	f.Add([]byte(`{"dek":"!!!","wrapped":7}`))
	f.Add([]byte(`[{"id":"x","created_at":"2026-09-16T10:00:00Z"}]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, out := range []any{&wrapResponse{generated: true}, &unwrapResponse{}, &[]Key{}, &Billing{}} {
			b := append([]byte(nil), body...)
			err := (&reply{status: 200, body: b}).decode(out)
			if err != nil {
				msg := err.Error()
				assertPrintable(t, msg)
				if len(body) >= 8 && strings.Contains(msg, string(body)) {
					t.Errorf("the error quotes the body: %q", msg)
				}
			}
			for _, c := range b {
				if c != 0 {
					t.Fatal("the body was not cleared")
				}
			}
		}
	})
}
