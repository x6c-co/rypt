package rypt

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testToken has the shape of a real API token.
const testToken = "ry_K3pQ7xTa_9fLm2Qd8xWv4Nc6Bz1Hs0Yt3Rk5Jp7Gq"

// Ids used in requests and canned responses.
const (
	keyID       = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	containerID = "3e2d1c0b-9a87-4654-b321-0fedcba98765"
	firewallID  = "4c3b2a19-0817-4f6e-9d5c-3b2a19081726"
	tokenID     = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
	userID      = "5d4c3b2a-1908-4f7e-8d6c-5b4a39281706"
)

// recorded is one request the fake API received.
type recorded struct {
	method string
	path   string
	query  string
	header http.Header
	body   []byte
}

// responder answers one request to the fake API.
type responder func(w http.ResponseWriter, r *http.Request)

// fakeAPI is an httptest server that records requests and answers them
// with scripted responders, then with its fallback.
type fakeAPI struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	reqs     []recorded
	queue    []responder
	fallback responder
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, fallback: jsonReply(http.StatusOK, map[string]any{})}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Errorf("reading the request body: %v", err)
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, recorded{
		method: r.Method,
		path:   r.URL.EscapedPath(),
		query:  r.URL.RawQuery,
		header: r.Header.Clone(),
		body:   body,
	})
	next := f.fallback
	if len(f.queue) > 0 {
		next, f.queue = f.queue[0], f.queue[1:]
	}
	f.mu.Unlock()
	next(w, r)
}

// script queues responders for the next requests.
func (f *fakeAPI) script(rs ...responder) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, rs...)
}

// requests returns the requests received so far.
func (f *fakeAPI) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

// last returns the last request, failing the test if there was none.
func (f *fakeAPI) last() recorded {
	f.t.Helper()
	reqs := f.requests()
	if len(reqs) == 0 {
		f.t.Fatal("the fake API received no request")
	}
	return reqs[len(reqs)-1]
}

// client returns a client of the fake API that does not wait between
// retries.
func (f *fakeAPI) client(opts ...Option) *Client {
	f.t.Helper()
	opts = append([]Option{WithBaseURL(f.srv.URL), WithBackoff(noBackoff)}, opts...)
	c, err := NewClient(testToken, opts...)
	if err != nil {
		f.t.Fatalf("NewClient: %v", err)
	}
	return c
}

func noBackoff(int) time.Duration { return 0 }

// jsonReply answers with v encoded as JSON.
func jsonReply(status int, v any) responder {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-"+r.Method)
		w.WriteHeader(status)
		if v != nil {
			json.NewEncoder(w).Encode(v)
		}
	}
}

// rawReply answers with body as it is.
func rawReply(status int, contentType, body string) responder {
	return func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.Header().Set("X-Request-Id", "raw-request")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

// apiErr answers with the API's error envelope.
func apiErr(status int, code, message string) responder {
	return jsonReply(status, map[string]any{"error": code, "message": message, "request_id": "env-" + code})
}

// noContent answers 204 with no body.
func noContent() responder {
	return func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
}

// dropConn closes the connection without answering, after the request has
// been received.
func dropConn() responder {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		conn.Close()
	}
}

// truncatedBody promises more body than it sends, then closes.
func truncatedBody() responder {
	return rawConn("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"ciph")
}

// rawConn writes raw bytes to the connection and closes it.
func rawConn(raw string) responder {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		buf.WriteString(raw)
		buf.Flush()
	}
}

// closedURL returns the URL of a loopback port that nothing listens on.
func closedURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

// asError returns err as an *Error, failing the test if it is not one.
func asError(t *testing.T, err error) *Error {
	t.Helper()
	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("got error %T %v, want *Error", err, err)
	}
	return e
}

// assertPrintable fails the test if s has a control or invisible format
// character, or the test token.
func assertPrintable(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, testToken) {
		t.Errorf("the token appears in %q", s)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '\u202e' || r == '\u200b' || r == '\u2028' {
			t.Errorf("unsafe character %U in %q", r, s)
		}
	}
}

// formatJSON re-encodes a JSON document so that two documents can be
// compared regardless of field order and spacing.
func formatJSON(t *testing.T, doc []byte) string {
	t.Helper()
	if len(doc) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatalf("the request body is not JSON: %v: %q", err, doc)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func ptr[T any](v T) *T { return &v }

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func sprint(v any) string { return fmt.Sprintf("%+v", v) }
