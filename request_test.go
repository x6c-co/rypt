package rypt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAPIError(t *testing.T) {
	api := newFakeAPI(t)
	api.script(jsonReply(429, map[string]any{
		"error": "ops_cap_reached", "message": "monthly operation cap reached",
		"request_id": "rid-1", "cap": 10000, "resets_at": "2026-11-01T00:00:00Z",
	}))
	_, err := api.client().Encrypt(t.Context(), keyID, []byte("x"), nil)
	e := asError(t, err)
	want := &Error{
		Kind: KindAPI, StatusCode: 429, Code: CodeOpsCapReached, Message: "monthly operation cap reached",
		RequestID: "rid-1", Cap: 10000, ResetsAt: mustTime(t, "2026-11-01T00:00:00Z"), Attempts: 1,
	}
	if sprint(e) != sprint(want) {
		t.Errorf("got  %s\nwant %s", sprint(e), sprint(want))
	}
	const text = "rypt API error ops_cap_reached (HTTP 429): monthly operation cap reached; cap 10000, resets at 2026-11-01T00:00:00Z (request_id rid-1)"
	if e.Error() != text {
		t.Errorf("Error() = %q\nwant      %q", e.Error(), text)
	}
	if !IsCode(err, CodeOpsCapReached) || IsCode(err, CodeRateLimited) {
		t.Error("IsCode does not match the code")
	}
	if !IsCode(errors.Join(errors.New("context"), err), CodeOpsCapReached) {
		t.Error("IsCode does not see a wrapped error")
	}
	if IsCode(errors.New("ops_cap_reached"), CodeOpsCapReached) || IsCode(nil, "") {
		t.Error("IsCode matched something that is not an *Error")
	}
}

// TestAPIErrorFields: each field of the envelope is decoded on its own,
// and the x-request-id header stands in for a missing request_id.
func TestAPIErrorFields(t *testing.T) {
	c, _ := NewClient(testToken)
	cases := map[string]struct {
		body string
		want Error
	}{
		"not JSON":            {`<html>502</html>`, Error{Message: "unexpected HTTP 400 response", RequestID: "hdr"}},
		"no code":             {`{"message":"m","request_id":"r"}`, Error{Message: "unexpected HTTP 400 response", RequestID: "hdr"}},
		"code not a string":   {`{"error":5,"message":"m"}`, Error{Message: "unexpected HTTP 400 response", RequestID: "hdr"}},
		"envelope":            {`{"error":"not_found","message":"m","request_id":"r"}`, Error{Code: CodeNotFound, Message: "m", RequestID: "r"}},
		"message not string":  {`{"error":"not_found","message":{},"request_id":"r"}`, Error{Code: CodeNotFound, RequestID: "r"}},
		"no request_id":       {`{"error":"not_found","message":"m"}`, Error{Code: CodeNotFound, Message: "m", RequestID: "hdr"}},
		"cap negative":        {`{"error":"ops_cap_reached","cap":-1}`, Error{Code: CodeOpsCapReached, RequestID: "hdr"}},
		"cap string":          {`{"error":"ops_cap_reached","cap":"10"}`, Error{Code: CodeOpsCapReached, RequestID: "hdr"}},
		"resets_at bad":       {`{"error":"ops_cap_reached","resets_at":"soon"}`, Error{Code: CodeOpsCapReached, RequestID: "hdr"}},
		"unknown code passes": {`{"error":"new_code","message":"m"}`, Error{Code: "new_code", Message: "m", RequestID: "hdr"}},
	}
	for name, tc := range cases {
		got := c.apiError(400, []byte(tc.body), "hdr")
		tc.want.Kind, tc.want.StatusCode = KindAPI, 400
		if sprint(got) != sprint(&tc.want) {
			t.Errorf("%s:\n got %s\nwant %s", name, sprint(got), sprint(&tc.want))
		}
	}
}

func TestErrorText(t *testing.T) {
	cause := &transportError{err: io.EOF, text: "EOF"}
	cases := []struct {
		err  *Error
		want string
	}{
		{&Error{Kind: KindTransport, Attempts: 3, Err: cause}, "cannot reach the rypt API after 3 attempts: EOF"},
		{&Error{Kind: KindTransport, Attempts: 1}, "cannot reach the rypt API after 1 attempt"},
		{&Error{Kind: KindResponse, StatusCode: 200, Message: "dek is missing", RequestID: "r"}, "malformed rypt API response (HTTP 200): dek is missing (request_id r)"},
		{&Error{Kind: KindAPI, StatusCode: 502, Message: "unexpected HTTP 502 response"}, "rypt API error (HTTP 502): unexpected HTTP 502 response"},
		{&Error{Kind: KindAPI, StatusCode: 404, Code: CodeNotFound}, "rypt API error not_found (HTTP 404)"},
	}
	for _, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
	if !errors.Is(&Error{Kind: KindTransport, Err: cause}, io.EOF) {
		t.Error("errors.Is does not reach the transport error's cause")
	}
	for k, want := range map[ErrorKind]string{KindAPI: "api", KindTransport: "transport", KindResponse: "response", 9: "ErrorKind(9)"} {
		if k.String() != want {
			t.Errorf("%d.String() = %q", int(k), k.String())
		}
	}
}

// TestServerTextSanitized: control characters, escape sequences, invisible
// format characters and the token never reach an Error's text.
func TestServerTextSanitized(t *testing.T) {
	nasty := "visible-start\x1b[2J\x1b]0;pwned\x07\r\nFAKE: success\x00\u009b31m\u202Eevil\u200B\u2028" + testToken + " visible-end"
	cases := map[string]responder{
		"message":    apiErr(400, "invalid_request", nasty),
		"code":       apiErr(400, "invalid_request\x1b[31m\u202E", "m"),
		"request_id": jsonReply(400, map[string]any{"error": "invalid_request", "request_id": nasty}),
		"header": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-Id", "rid\x1b[31m-"+testToken)
			w.WriteHeader(400)
		},
		"status line": rawConn("HTTP/1.1 4\x1b[31m00 \x1b]0;t\x07Bad " + testToken + "\r\n\r\n"),
		"error page":  rawReply(400, "text/plain", nasty),
		"echoed header": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-Id", r.Header.Get("Authorization"))
			w.WriteHeader(403)
		},
	}
	for name, f := range cases {
		api := newFakeAPI(t)
		api.fallback = f
		_, err := api.client().Encrypt(t.Context(), keyID, []byte("x"), nil)
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		assertPrintable(t, err.Error())
		e := asError(t, err)
		for _, s := range []string{string(e.Code), e.Message, e.RequestID} {
			assertPrintable(t, s)
		}
		if name == "message" && (!strings.Contains(e.Message, "visible-start") || !strings.Contains(e.Message, "[redacted] visible-end")) {
			t.Errorf("the printable part of the message is missing: %q", e.Message)
		}
	}
}

func TestServerTextTruncated(t *testing.T) {
	api := newFakeAPI(t)
	api.fallback = apiErr(400, "invalid_request", strings.Repeat("é", 1000))
	_, err := api.client().ListKeys(t.Context())
	e := asError(t, err)
	if len(e.Message) > maxServerText || !strings.HasSuffix(e.Message, "...") {
		t.Errorf("message of %d bytes: %q", len(e.Message), e.Message)
	}
}

// TestNoRetry: errors that a retry cannot fix are returned at once.
func TestNoRetry(t *testing.T) {
	for name, f := range map[string]responder{
		"400":          apiErr(400, "invalid_request", "bad"),
		"429 rate":     apiErr(429, "rate_limited", "slow down"),
		"429 cap":      apiErr(429, "ops_cap_reached", "cap"),
		"500":          apiErr(500, "internal_error", "boom"),
		"501":          rawReply(501, "", ""),
		"505":          rawReply(505, "", ""),
		"301":          rawReply(301, "", ""),
		"truncated ok": truncatedBody(), // a transport error, but retried below only for safe calls
	} {
		api := newFakeAPI(t)
		api.fallback = f
		_, err := api.client().CreateKey(t.Context(), &CreateKeyParams{Name: "k", Tier: TierFree})
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if n := len(api.requests()); n != 1 {
			t.Errorf("%s: sent %d requests, want 1", name, n)
		}
	}
}

func TestTransportRetries(t *testing.T) {
	cases := []struct {
		name   string
		faults []responder
		ok     bool
		sent   int
	}{
		{"drop then success", []responder{dropConn()}, true, 2},
		{"truncated then success", []responder{truncatedBody()}, true, 2},
		{"drop drop then success", []responder{dropConn(), dropConn()}, true, 3},
		{"drop x3", []responder{dropConn(), dropConn(), dropConn()}, false, 3},
		{"drop then 503 then 404", []responder{dropConn(), apiErr(503, "unavailable", ""), apiErr(404, "not_found", "")}, false, 3},
		{"503 then 400 is final", []responder{apiErr(503, "unavailable", ""), apiErr(400, "invalid_request", "")}, false, 2},
	}
	for _, tc := range cases {
		api := newFakeAPI(t)
		api.script(tc.faults...)
		api.fallback = jsonReply(200, map[string]any{"ciphertext": b64([]byte("CT"))})
		_, err := api.client().Encrypt(t.Context(), keyID, []byte("x"), nil)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v", tc.name, err)
		}
		if n := len(api.requests()); n != tc.sent {
			t.Errorf("%s: sent %d requests, want %d", tc.name, n, tc.sent)
		}
		if !tc.ok && asError(t, err).Attempts != tc.sent {
			t.Errorf("%s: Attempts %d", tc.name, asError(t, err).Attempts)
		}
	}
}

// TestDialErrorRetried: a connection that cannot be made sent nothing, so
// even a call that is never repeated otherwise is retried.
func TestDialErrorRetried(t *testing.T) {
	c, err := NewClient(testToken, WithBaseURL(closedURL(t)), WithBackoff(noBackoff))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateKey(t.Context(), &CreateKeyParams{Name: "k", Tier: TierFree})
	e := asError(t, err)
	if e.Kind != KindTransport || e.StatusCode != 0 || e.Attempts != DefaultMaxAttempts {
		t.Errorf("got %s", sprint(e))
	}
	assertPrintable(t, e.Error())
}

func TestTLSErrorNotRetried(t *testing.T) {
	api := newFakeAPI(t)
	// The fake API speaks plain HTTP, so a TLS client gets a record header
	// error, which will not change on a retry.
	c, err := NewClient(testToken, WithBaseURL(strings.Replace(api.srv.URL, "http://127.0.0.1", "https://localhost", 1)), WithBackoff(noBackoff))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListKeys(t.Context())
	if e := asError(t, err); e.Kind != KindTransport || e.Attempts != 1 {
		t.Errorf("got %s", sprint(e))
	}
}

func TestContextCanceled(t *testing.T) {
	api := newFakeAPI(t)
	api.fallback = apiErr(503, "unavailable", "busy")
	c := api.client(WithBackoff(func(int) time.Duration { return time.Hour }))
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.ListKeys(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want context.DeadlineExceeded", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the backoff did not stop when the context ended")
	}

	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	if _, err := c.ListKeys(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
	if n := len(api.requests()); n != 1 {
		t.Errorf("sent %d requests, want 1", n)
	}
}

func TestResponseTooLarge(t *testing.T) {
	api := newFakeAPI(t)
	api.fallback = rawReply(200, "application/json", `{"ciphertext":"`+strings.Repeat("A", maxResponseBytes)+`"}`)
	_, err := api.client().Encrypt(t.Context(), keyID, []byte("x"), nil)
	if e := asError(t, err); e.Kind != KindResponse || e.Message != "response too large" {
		t.Errorf("got %v", err)
	}
	if n := len(api.requests()); n != 1 {
		t.Errorf("sent %d requests, want 1", n)
	}
}

func TestReadBody(t *testing.T) {
	for _, n := range []int{0, 1, 4095, 4096, 4097, 100000, maxResponseBytes} {
		for _, hint := range []int64{-1, int64(n)} {
			src := bytes.Repeat([]byte("x"), n)
			got, tooLarge, err := readBody(bytes.NewReader(src), hint)
			if err != nil || tooLarge || !bytes.Equal(got, src) {
				t.Errorf("n=%d hint=%d: %d bytes, tooLarge %v, err %v", n, hint, len(got), tooLarge, err)
			}
		}
	}
	_, tooLarge, _ := readBody(bytes.NewReader(make([]byte, maxResponseBytes+1)), -1)
	if !tooLarge {
		t.Error("a body over the limit is not too large")
	}
}

// TestMalformedSuccess: a success whose body is not what the API documents
// is a KindResponse error that does not quote the body.
func TestMalformedSuccess(t *testing.T) {
	dek := b64(bytes.Repeat([]byte{0x5a}, 32))
	cases := []struct {
		name string
		body string
		call func(context.Context, *Client) (any, error)
	}{
		{"encrypt not JSON", `<html>ok</html>`, encryptCall},
		{"encrypt empty body", ``, encryptCall},
		{"encrypt null", `null`, encryptCall},
		{"encrypt array", `["CT"]`, encryptCall},
		{"encrypt truncated", `{"ciphertext":"AAAA`, encryptCall},
		{"encrypt missing", `{}`, encryptCall},
		{"encrypt empty", `{"ciphertext":""}`, encryptCall},
		{"encrypt number", `{"ciphertext":7}`, encryptCall},
		{"encrypt not base64", `{"ciphertext":"!!"}`, encryptCall},
		{"encrypt unpadded", `{"ciphertext":"QQ"}`, encryptCall},
		{"decrypt missing", `{}`, decryptCall},
		{"generate missing dek", `{"wrapped":"V1c="}`, generateCall},
		{"generate null dek", `{"dek":null,"wrapped":"V1c="}`, generateCall},
		{"generate 16-byte dek", `{"dek":"` + b64(make([]byte, 16)) + `","wrapped":"V1c="}`, generateCall},
		{"generate 33-byte dek", `{"dek":"` + b64(make([]byte, 33)) + `","wrapped":"V1c="}`, generateCall},
		{"generate missing wrapped", `{"dek":"` + dek + `"}`, generateCall},
		{"generate empty wrapped", `{"dek":"` + dek + `","wrapped":""}`, generateCall},
		{"generate wrapped object", `{"dek":"` + dek + `","wrapped":{}}`, generateCall},
		{"wrap missing wrapped", `{}`, wrapCall},
		{"unwrap missing", `{}`, unwrapCall},
		{"unwrap string", `"dek"`, unwrapCall},
		{"unwrap dek number", `{"dek":1}`, unwrapCall},
		{"key bad time", `{"id":"x","created_at":"yesterday"}`, func(ctx context.Context, c *Client) (any, error) { return c.GetKey(ctx, keyID) }},
		{"list not array", `{"id":"x"}`, func(ctx context.Context, c *Client) (any, error) { return c.ListKeys(ctx) }},
		{"health not ok", `{"status":"starting"}`, func(ctx context.Context, c *Client) (any, error) { return nil, c.Health(ctx) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.fallback = rawReply(200, "application/json", tc.body)
			_, err := tc.call(t.Context(), api.client())
			e := asError(t, err)
			if e.Kind != KindResponse || e.StatusCode != 200 || e.RequestID != "raw-request" {
				t.Errorf("got %s", sprint(e))
			}
			if n := len(api.requests()); n != 1 {
				t.Errorf("sent %d requests, want 1", n)
			}
			for _, quoted := range []string{"html", "AAAA", dek[:8], "yesterday", "starting", "!!"} {
				if strings.Contains(e.Error(), quoted) {
					t.Errorf("the error quotes the body: %v", e)
				}
			}
		})
	}
}

func encryptCall(ctx context.Context, c *Client) (any, error) {
	return c.Encrypt(ctx, keyID, []byte("x"), nil)
}
func decryptCall(ctx context.Context, c *Client) (any, error) {
	return c.Decrypt(ctx, keyID, []byte("x"), nil)
}
func generateCall(ctx context.Context, c *Client) (any, error) {
	return c.GenerateDataKey(ctx, keyID, nil)
}
func wrapCall(ctx context.Context, c *Client) (any, error) {
	return c.Wrap(ctx, keyID, make([]byte, 32), nil)
}
func unwrapCall(ctx context.Context, c *Client) (any, error) {
	return c.Unwrap(ctx, keyID, []byte("W"), nil)
}

// TestDecodeClears: the response body is cleared after decoding, and a
// secret decoded from a malformed response is cleared too.
func TestDecodeClears(t *testing.T) {
	body := []byte(`{"dek":"` + b64(bytes.Repeat([]byte{0x5a}, 16)) + `","wrapped":""}`)
	res := wrapResponse{generated: true}
	err := (&reply{status: 200, body: body}).decode(&res)
	if err == nil {
		t.Fatal("decode accepted a 16-byte generated dek")
	}
	if !bytes.Equal(body, make([]byte, len(body))) {
		t.Error("the body was not cleared")
	}
	if len(res.DEK) != 16 || !bytes.Equal(res.DEK, make([]byte, 16)) {
		t.Errorf("the decoded dek was not cleared: %x", res.DEK)
	}

	body = []byte(`{"plaintext":"` + b64([]byte("secret")) + `"}`)
	var pt plaintextResponse
	if err := (&reply{status: 200, body: body}).decode(&pt); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, make([]byte, len(body))) {
		t.Error("the body was not cleared")
	}
	if string(pt.Plaintext) != "secret" {
		t.Errorf("plaintext %q", pt.Plaintext)
	}
}

// TestWrapClearsEchoedDEK: a data key the service sends back unasked is
// cleared, not returned.
func TestWrapClearsEchoedDEK(t *testing.T) {
	api := newFakeAPI(t)
	api.fallback = jsonReply(200, map[string]any{"dek": b64(bytes.Repeat([]byte{1}, 32)), "wrapped": b64([]byte("W"))})
	wrapped, err := api.client().Wrap(t.Context(), keyID, bytes.Repeat([]byte{1}, 32), nil)
	if err != nil || string(wrapped) != "W" {
		t.Errorf("Wrap = %q, %v", wrapped, err)
	}
}

func TestBinaryBody(t *testing.T) {
	cases := []struct {
		fields []binaryField
		want   string
	}{
		{nil, `{}`},
		{[]binaryField{{name: "aad", optional: true}}, `{}`},
		{[]binaryField{{name: "plaintext", value: []byte("hi")}, {name: "aad", optional: true}}, `{"plaintext":"aGk="}`},
		{[]binaryField{{name: "plaintext"}}, `{"plaintext":""}`},
		{[]binaryField{{name: "a", value: []byte{0xff, 0xfe}}, {name: "b", value: []byte("x"), optional: true}}, `{"a":"//4=","b":"eA=="}`},
	}
	for _, tc := range cases {
		got := binaryBody(tc.fields...)
		if string(got) != tc.want {
			t.Errorf("binaryBody = %s, want %s", got, tc.want)
		}
		if cap(got) < len(got) || cap(got) > len(got)+16 {
			t.Errorf("capacity %d for %d bytes", cap(got), len(got))
		}
	}
}

func TestIsUUID(t *testing.T) {
	for s, want := range map[string]bool{
		keyID:                                  true,
		strings.ToUpper(keyID):                 true,
		"00000000-0000-0000-0000-000000000000": true,
		"":                                     false,
		keyID[1:]:                              false,
		keyID + "a":                            false,
		strings.ReplaceAll(keyID, "-", "a"):    false,
		"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1g0": false,
		"0f1e2d3c-4b5a-6978-8796a-5b4c3d2e1f0": false,
	} {
		if isUUID(s) != want {
			t.Errorf("isUUID(%q) = %v", s, !want)
		}
	}
}
