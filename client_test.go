package rypt

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewClientToken(t *testing.T) {
	for _, token := range []string{"", "ry_abc\n", "ry_\x00abc", "ry_abc\x7f", "\r"} {
		if _, err := NewClient(token); err == nil {
			t.Errorf("NewClient(%q) succeeded", token)
		}
	}
	if _, err := NewClient(testToken); err != nil {
		t.Errorf("NewClient(valid token): %v", err)
	}
}

func TestNewClientOptions(t *testing.T) {
	for name, opt := range map[string]Option{
		"zero attempts":         WithMaxAttempts(0),
		"negative attempts":     WithMaxAttempts(-1),
		"user agent with CR LF": WithUserAgent("app\r\nX-Evil: 1"),
	} {
		if _, err := NewClient(testToken, opt); err == nil {
			t.Errorf("%s: NewClient succeeded", name)
		}
	}
}

func TestBaseURL(t *testing.T) {
	cases := []struct {
		raw  string
		want string // "" means the URL is refused
	}{
		{"", "https://api.rypt.dev"},
		{"https://api.rypt.dev", "https://api.rypt.dev"},
		{"https://api.rypt.dev/", "https://api.rypt.dev"},
		{"https://example.com/rypt/", "https://example.com/rypt"},
		{"https://example.com:8443", "https://example.com:8443"},
		{"https://localhost:8443", "https://localhost:8443"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"http://127.0.0.1", "http://127.0.0.1"},
		{"HTTP://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"http://[::1]:8080", "http://[::1]:8080"},
		{"http://[::1]", "http://[::1]"},
		{"http://api.rypt.dev", ""},
		// A name is looked up, so plain http to it could go anywhere.
		{"http://localhost", ""},
		{"http://localhost:8080", ""},
		{"http://LocalHost:8080", ""},
		{"http://localhost.:8080", ""},
		{"http://localhoſt", ""},
		{"http://localhost.example.com", ""},
		// Other spellings of loopback addresses, and other loopback addresses.
		{"http://127.0.0.2", ""},
		{"http://127.1", ""},
		{"http://2130706433", ""},
		{"http://[::ffff:127.0.0.1]", ""},
		{"http://[0:0:0:0:0:0:0:1]", ""},
		{"http://[::1%25lo]:8080", ""},
		{"ftp://api.rypt.dev", ""},
		{"api.rypt.dev", ""},
		{"https://", ""},
		{"https://user:pass@api.rypt.dev", ""},
		{"https://api.rypt.dev?x=1", ""},
		{"https://api.rypt.dev?", ""},
		{"https://api.rypt.dev#frag", ""},
		{"https:opaque", ""},
		{"https://api.rypt.dev/%zz", ""},
	}
	for _, tc := range cases {
		u, err := parseBaseURL(tc.raw)
		switch {
		case tc.want == "" && err == nil:
			t.Errorf("parseBaseURL(%q) = %s, want an error", tc.raw, u)
		case tc.want != "" && err != nil:
			t.Errorf("parseBaseURL(%q): %v", tc.raw, err)
		case tc.want != "" && u.String() != tc.want:
			t.Errorf("parseBaseURL(%q) = %s, want %s", tc.raw, u, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "pass") {
			t.Errorf("the error quotes the URL: %v", err)
		}
	}
	// The error for http://localhost says what is allowed instead.
	const want = "rypt: the base URL must use https unless the host is 127.0.0.1 or ::1"
	if _, err := parseBaseURL("http://localhost:8080"); err == nil || err.Error() != want {
		t.Errorf("parseBaseURL(http://localhost:8080): error %v, want %q", err, want)
	}
}

func TestBaseURLPath(t *testing.T) {
	api := newFakeAPI(t)
	api.fallback = jsonReply(200, []any{})
	c := api.client(WithBaseURL(api.srv.URL + "/prefix/"))
	if _, err := c.ListKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p := api.last().path; p != "/prefix/v1/keys" {
		t.Errorf("path %q, want /prefix/v1/keys", p)
	}
}

func TestUserAgent(t *testing.T) {
	api := newFakeAPI(t)
	api.fallback = jsonReply(200, []any{})
	if _, err := api.client().ListKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ua := api.last().header.Get("User-Agent"); ua != "rypt-go/dev" {
		t.Errorf("User-Agent %q, want rypt-go/dev", ua)
	}
}

// TestRedirectRefused: a redirect is returned as an error, and its target
// never sees the token.
func TestRedirectRefused(t *testing.T) {
	target := newFakeAPI(t)
	api := newFakeAPI(t)
	api.fallback = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}
	following := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	for name, c := range map[string]*Client{
		"default client":     api.client(),
		"WithHTTPClient":     api.client(WithHTTPClient(following)),
		"WithHTTPClient nil": api.client(WithHTTPClient(&http.Client{})),
	} {
		_, err := c.Encrypt(t.Context(), keyID, []byte("x"), nil)
		e := asError(t, err)
		if e.Kind != KindAPI || e.StatusCode != http.StatusTemporaryRedirect {
			t.Errorf("%s: got %v, want an HTTP 307 error", name, err)
		}
	}
	if n := len(target.requests()); n != 0 {
		t.Errorf("the redirect target received %d requests", n)
	}
	if following.CheckRedirect == nil {
		t.Error("WithHTTPClient changed the caller's client")
	}
}

func TestHTTPSOnlyProxy(t *testing.T) {
	proxy, _ := url.Parse("http://proxy.example:3128")
	next := func(*http.Request) (*url.URL, error) { return proxy, nil }
	f := httpsOnlyProxy(next)
	for scheme, want := range map[string]*url.URL{"https": proxy, "http": nil} {
		req, _ := http.NewRequest("GET", scheme+"://localhost/", nil)
		if got, _ := f(req); got != want {
			t.Errorf("%s: proxy %v, want %v", scheme, got, want)
		}
	}
	req, _ := http.NewRequest("GET", "https://api.rypt.dev/", nil)
	if got, _ := httpsOnlyProxy(nil)(req); got != nil {
		t.Errorf("nil next: proxy %v", got)
	}
}

func TestDefaultHTTPClient(t *testing.T) {
	c := defaultHTTPClient()
	if c.Timeout != DefaultTimeout {
		t.Errorf("timeout %v", c.Timeout)
	}
	if c.CheckRedirect == nil {
		t.Error("the default client follows redirects")
	}
}

func TestDefaultBackoff(t *testing.T) {
	for retry, max := range map[int]time.Duration{
		0: 250 * time.Millisecond, 1: 250 * time.Millisecond, 2: 500 * time.Millisecond,
		3: time.Second, 5: 4 * time.Second, 6: 5 * time.Second, 64: 5 * time.Second, 1 << 30: 5 * time.Second,
	} {
		for range 50 {
			if d := defaultBackoff(retry); d < max/2 || d > max {
				t.Fatalf("defaultBackoff(%d) = %v, want between %v and %v", retry, d, max/2, max)
			}
		}
	}
}

func TestMaxAttempts(t *testing.T) {
	api := newFakeAPI(t)
	api.fallback = apiErr(503, "unavailable", "busy")
	for _, n := range []int{1, 2, 5} {
		before := len(api.requests())
		_, err := api.client(WithMaxAttempts(n)).ListKeys(t.Context())
		if e := asError(t, err); e.Attempts != n {
			t.Errorf("Attempts %d, want %d", e.Attempts, n)
		}
		if sent := len(api.requests()) - before; sent != n {
			t.Errorf("WithMaxAttempts(%d) sent %d requests", n, sent)
		}
	}
}

func TestBackoffCalls(t *testing.T) {
	api := newFakeAPI(t)
	api.fallback = apiErr(503, "unavailable", "busy")
	var retries []int
	c := api.client(WithBackoff(func(retry int) time.Duration {
		retries = append(retries, retry)
		return 0
	}))
	c.ListKeys(t.Context())
	if got := sprint(retries); got != "[1 2]" {
		t.Errorf("backoff called with %s, want [1 2]", got)
	}
}
