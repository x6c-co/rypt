package rypt

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes caps how much of a response body is read.
const maxResponseBytes = 8 << 20

// retryPolicy says which failed attempts of a request may be repeated.
type retryPolicy int

const (
	// retryIfUnprocessed repeats a request only when it certainly was not
	// carried out: the connection could not be made, or the API answered
	// 503 unavailable. For requests whose repetition could do harm.
	retryIfUnprocessed retryPolicy = iota
	// retryIfTransient also repeats a request after a connection that
	// failed part-way and after HTTP 502, 503 and 504. For requests that
	// are safe to repeat.
	retryIfTransient
)

// request is one API call.
type request struct {
	method string
	path   string // the escaped path after the base URL, such as "/v1/keys"
	query  url.Values
	body   []byte // JSON, or nil for none
	retry  retryPolicy
	// noAuth leaves out the Authorization header.
	noAuth bool
}

// response is one complete HTTP response.
type response struct {
	status    int
	requestID string // x-request-id header, passed through serverText
	body      []byte
	tooLarge  bool // the body exceeded maxResponseBytes and was cut
}

// reply is the body of a successful response, for the caller to decode.
type reply struct {
	status    int
	body      []byte
	requestID string
	attempts  int
}

// malformed returns a KindResponse error. msg must be fixed text: it must
// never quote the body, which may hold a secret.
func (r *reply) malformed(msg string) *Error {
	return &Error{
		Kind:       KindResponse,
		StatusCode: r.status,
		Message:    msg,
		RequestID:  r.requestID,
		Attempts:   r.attempts,
	}
}

// checkedResponse is a response type that checks itself once decoded.
type checkedResponse interface {
	// problem describes, in fixed text, what is wrong with the decoded
	// response, or returns "" when nothing is.
	problem() string
}

// secretResponse is a response type that holds a secret, which is cleared
// when the response turns out to be malformed.
type secretResponse interface {
	clearSecrets()
}

// decode decodes the JSON body into out and then clears the body. A body
// that does not decode, or that out finds a problem with, is a KindResponse
// error.
func (r *reply) decode(out any) error {
	err := json.Unmarshal(r.body, out)
	clear(r.body)
	problem := ""
	if err != nil {
		problem = jsonProblem(err)
	} else if v, ok := out.(checkedResponse); ok {
		problem = v.problem()
	}
	if problem == "" {
		return nil
	}
	// A decoding error can come after a secret field was decoded.
	if v, ok := out.(secretResponse); ok {
		v.clearSecrets()
	}
	return r.malformed(problem)
}

// do sends req, decodes a successful response's JSON body into out unless
// out is nil, and clears the response body.
func (c *Client) do(ctx context.Context, req *request, out any) error {
	rep, err := c.send(ctx, req)
	if err != nil {
		return err
	}
	if out == nil {
		clear(rep.body)
		return nil
	}
	return rep.decode(out)
}

// send sends req until it gets a final answer, retrying as req.retry
// allows, and returns the body of a 2xx response. Any other final answer is
// an *Error. When ctx is done it stops and returns ctx.Err().
func (c *Client) send(ctx context.Context, req *request) (*reply, error) {
	endpoint := c.base.String() + req.path
	if len(req.query) > 0 {
		endpoint += "?" + req.query.Encode()
	}

	var last *Error
	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		if attempt > 1 {
			if err := sleep(ctx, c.backoff(attempt-1)); err != nil {
				return nil, err
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		resp, err := c.exchange(ctx, endpoint, req)
		if err != nil {
			// The caller's ctx decides cancellation. A Client.Timeout error
			// can also look like a deadline, but it is a transport failure.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			last = &Error{
				Kind:     KindTransport,
				Message:  "cannot reach the rypt API",
				Attempts: attempt,
				Err:      &transportError{err: err, text: c.serverText(err.Error())},
			}
			if !retryableErr(err, req.retry) {
				return nil, last
			}
			continue
		}

		if resp.status < 200 || resp.status > 299 {
			last = c.apiError(resp.status, resp.body, resp.requestID)
			clear(resp.body)
			last.Attempts = attempt
			if !retryableStatus(resp.status, last.Code, req.retry) {
				return nil, last
			}
			continue
		}
		rep := &reply{status: resp.status, body: resp.body, requestID: resp.requestID, attempts: attempt}
		if resp.tooLarge {
			clear(resp.body)
			return nil, rep.malformed("response too large")
		}
		return rep, nil
	}
	return nil, last
}

// transportError is the Err of a KindTransport Error. The text of a
// net/http error can quote bytes the server sent, such as a malformed status
// or header line, so it is passed through serverText; errors.Is and
// errors.As still reach err.
type transportError struct {
	err  error
	text string
}

func (e *transportError) Error() string { return e.text }
func (e *transportError) Unwrap() error { return e.err }

// exchange sends one request and reads the whole response. A failure to
// read the body is returned as an error, like a failure to connect.
func (c *Client) exchange(ctx context.Context, endpoint string, req *request) (*response, error) {
	var body io.Reader
	if req.body != nil {
		// A fresh reader for every attempt.
		body = bytes.NewReader(req.body)
	}
	hr, err := http.NewRequestWithContext(ctx, req.method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if !req.noAuth {
		hr.Header.Set("Authorization", "Bearer "+c.token)
	}
	if req.body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buf, tooLarge, err := readBody(resp.Body, resp.ContentLength)
	if err != nil {
		clear(buf)
		return nil, fmt.Errorf("reading the response: %w", err)
	}
	return &response{
		status:    resp.StatusCode,
		requestID: c.serverText(resp.Header.Get("X-Request-Id")),
		body:      buf,
		tooLarge:  tooLarge,
	}, nil
}

// readBody reads r to EOF, keeping at most maxResponseBytes+1 bytes. If r
// has more than maxResponseBytes bytes, it stops and reports tooLarge.
// sizeHint is the Content-Length, or -1. The buffer is grown by hand so
// that each outgrown buffer is cleared: the body may hold a secret.
func readBody(r io.Reader, sizeHint int64) (buf []byte, tooLarge bool, err error) {
	size := 4096
	if sizeHint >= 0 && sizeHint < maxResponseBytes {
		size = int(sizeHint) + 1 // one spare byte to reach EOF without growing
	}
	buf = make([]byte, 0, size)
	for {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), min(2*cap(buf), maxResponseBytes+1))
			copy(grown, buf)
			clear(buf)
			buf = grown
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if len(buf) > maxResponseBytes {
			return buf, true, nil
		}
		if err == io.EOF {
			return buf, false, nil
		}
		if err != nil {
			return buf, false, err
		}
	}
}

// sleep waits for d or until ctx is done, whichever comes first.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryableStatus reports whether a request that got an error response may
// be sent again. HTTP 429 is never retried: neither the monthly cap nor the
// rate limit clears in the time a retry waits.
func retryableStatus(status int, code ErrorCode, policy retryPolicy) bool {
	if status == http.StatusServiceUnavailable && code == CodeUnavailable {
		// The API sends this only for a request it did not carry out.
		return true
	}
	if policy != retryIfTransient {
		return false
	}
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryableErr reports whether a request whose exchange failed with err may
// be sent again. A failure to connect never sent the request, so it may
// always be repeated; any other failure may have happened after the API
// received the request. A certificate the client does not trust, or a
// server that does not speak TLS, fails the same way every time.
func retryableErr(err error, policy retryPolicy) bool {
	var (
		verifyErr  *tls.CertificateVerificationError
		recordErr  tls.RecordHeaderError
		unknownCA  x509.UnknownAuthorityError
		hostErr    x509.HostnameError
		invalidErr x509.CertificateInvalidError
		opErr      *net.OpError
	)
	switch {
	case errors.As(err, &verifyErr),
		errors.As(err, &recordErr),
		errors.As(err, &unknownCA),
		errors.As(err, &hostErr),
		errors.As(err, &invalidErr),
		errors.Is(err, http.ErrSchemeMismatch):
		return false
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return true
	}
	return policy == retryIfTransient
}

// jsonProblem describes a decoding error without its text, which can quote
// bytes of the body.
func jsonProblem(err error) string {
	var (
		typeErr   *json.UnmarshalTypeError
		b64Err    base64.CorruptInputError
		syntaxErr *json.SyntaxError
	)
	switch {
	case errors.As(err, &b64Err):
		return "a binary field is not valid base64"
	case errors.As(err, &typeErr) && typeErr.Field != "":
		// Field is a path of this package's JSON field names.
		return "field " + typeErr.Field + " has the wrong type"
	case errors.As(err, &typeErr):
		return "the response has the wrong JSON type"
	case errors.As(err, &syntaxErr), errors.Is(err, io.ErrUnexpectedEOF):
		return "the response is not valid JSON"
	}
	return "the response does not have the documented shape"
}

// apiError builds the KindAPI error for an error response. It decodes the
// API error envelope when the body is one; otherwise, as for an HTML page
// from a proxy, Code stays empty and Message is fixed text. headerID is the
// sanitized x-request-id header.
func (c *Client) apiError(status int, body []byte, headerID string) *Error {
	e := &Error{Kind: KindAPI, StatusCode: status, RequestID: headerID}

	// Each field is decoded on its own, so one of an unexpected type does
	// not lose the others.
	var env map[string]json.RawMessage
	if json.Unmarshal(body, &env) == nil {
		e.Code = ErrorCode(c.jsonText(env["error"]))
	}
	if e.Code == "" {
		e.Message = fmt.Sprintf("unexpected HTTP %d response", status)
		return e
	}
	e.Message = c.jsonText(env["message"])
	if id := c.jsonText(env["request_id"]); id != "" {
		e.RequestID = id
	}
	if t, err := time.Parse(time.RFC3339, c.jsonText(env["resets_at"])); err == nil {
		e.ResetsAt = t
	}
	var limit int64
	if json.Unmarshal(env["cap"], &limit) == nil && limit > 0 {
		e.Cap = limit
	}
	return e
}

// jsonText returns the value of a JSON string passed through serverText,
// or "" if raw is not a string.
func (c *Client) jsonText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return c.serverText(s)
}

// serverText makes server-supplied text safe to keep in an Error. Besides
// sanitizing it, it redacts the token, in case a server echoes it back; that
// happens before truncation so that no part of the token can survive.
func (c *Client) serverText(s string) string {
	return truncate(strings.ReplaceAll(clean(s), c.token, "[redacted]"))
}

// jsonBody encodes v as a request body. The types this package sends always
// encode, so an error means a bug.
func jsonBody(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("rypt: encoding the request: %w", err)
	}
	return b, nil
}

// binaryField is one field of a request body built by binaryBody.
type binaryField struct {
	name     string // a JSON field name that needs no escaping
	value    []byte
	optional bool // leave the field out when value is empty
}

// binaryBody returns a JSON object of fields, each value standard padded
// base64. It is built by hand rather than with encoding/json so that no
// copy of a plaintext or data key stays behind in encoding/json's buffer
// pool. The caller clears the result when the call is over.
func binaryBody(fields ...binaryField) []byte {
	n := 2
	for _, f := range fields {
		n += len(f.name) + 6 + base64.StdEncoding.EncodedLen(len(f.value))
	}
	b := make([]byte, 0, n)
	b = append(b, '{')
	for _, f := range fields {
		if f.optional && len(f.value) == 0 {
			continue
		}
		if len(b) > 1 {
			b = append(b, ',')
		}
		b = append(b, '"')
		b = append(b, f.name...)
		b = append(b, `":"`...)
		b = base64.StdEncoding.AppendEncode(b, f.value)
		b = append(b, '"')
	}
	return append(b, '}')
}

// isUUID reports whether s is a UUID in the 8-4-4-4-12 hexadecimal form,
// in either case, which is the form of every id in the API.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// idPath returns "/v1/<collection>/<id><suffix>" after checking that id is
// a UUID, so that an id can never change which endpoint a request reaches.
// what names the id in the error.
func idPath(collection, what, id, suffix string) (string, error) {
	if !isUUID(id) {
		return "", fmt.Errorf("rypt: the %s is not a UUID", what)
	}
	return "/v1/" + collection + "/" + id + suffix, nil
}
