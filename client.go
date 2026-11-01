package rypt

import (
	"errors"
	"math/rand/v2"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the production rypt API.
	DefaultBaseURL = "https://api.rypt.dev"

	// DefaultTimeout bounds each HTTP request made by a client that has no
	// [WithHTTPClient] option, including reading the response.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxAttempts is how many times a request is sent at most: one
	// try and up to two retries. See the package documentation for which
	// failures are retried.
	DefaultMaxAttempts = 3
)

// modulePath is this module's path, used to find its version for the
// User-Agent header.
const modulePath = "github.com/x6c-co/rypt"

// Client calls the rypt API. It is safe for concurrent use by multiple
// goroutines. Create one with [NewClient] and reuse it.
type Client struct {
	base        *url.URL
	token       string
	userAgent   string
	http        *http.Client
	maxAttempts int
	backoff     func(retry int) time.Duration
}

// An Option configures a [Client]. Pass options to [NewClient].
type Option func(*options)

type options struct {
	baseURL     string
	userAgent   string
	httpClient  *http.Client
	maxAttempts int
	backoff     func(retry int) time.Duration
}

// WithBaseURL sets the API base URL. The default is [DefaultBaseURL].
//
// The URL must use https, except that http is allowed when the host is
// 127.0.0.1 or ::1 (written [::1] in a URL), for a server under development.
// The name localhost needs https, because a name is looked up. The lookup
// can reach DNS when the hosts file does not list the name, or when DNS
// comes first in the lookup order. The resolver then asks for
// localhost.<search domain> first, so whoever controls that zone can answer
// with another machine, which would receive the token in clear text.
//
// The URL must have a host and no user info, query or fragment. It may have
// a path, which then prefixes every API path.
func WithBaseURL(baseURL string) Option {
	return func(o *options) { o.baseURL = baseURL }
}

// WithUserAgent names the application in the User-Agent header, for example
// "myapp/1.2.3". The client appends its own name and version.
func WithUserAgent(userAgent string) Option {
	return func(o *options) { o.userAgent = userAgent }
}

// WithHTTPClient sets the HTTP client that sends requests, for example to
// add instrumentation to its transport or to change its timeout.
//
// The client is copied, and the copy refuses redirects whatever the
// original's CheckRedirect says, so that the token is never sent to another
// URL. The default client also never sends plain-HTTP requests through a
// proxy, where the token would travel in clear text; a transport given here
// is responsible for its own proxy settings.
func WithHTTPClient(client *http.Client) Option {
	return func(o *options) { o.httpClient = client }
}

// WithMaxAttempts sets how many times a request is sent at most, counting
// the first try. 1 turns retries off. The default is [DefaultMaxAttempts].
func WithMaxAttempts(n int) Option {
	return func(o *options) { o.maxAttempts = n }
}

// WithBackoff sets the delay before each retry. backoff is called with 1
// before the first retry, 2 before the second, and so on. The default waits
// up to 250ms before the first retry and twice as long before each later
// one, to at most 5s, with random jitter that shortens each delay by up to
// half.
func WithBackoff(backoff func(retry int) time.Duration) Option {
	return func(o *options) { o.backoff = backoff }
}

// NewClient returns a client that authenticates with token, an API token or
// a console session token (see the package documentation).
//
// It returns an error if token is empty or contains a character that cannot
// be sent in an HTTP header, if the base URL is invalid, or if an option has
// an invalid value. It makes no request.
func NewClient(token string, opts ...Option) (*Client, error) {
	o := options{maxAttempts: DefaultMaxAttempts}
	for _, opt := range opts {
		opt(&o)
	}
	if token == "" {
		return nil, errors.New("rypt: the token is empty")
	}
	// Not a format check: a control character cannot go in an HTTP header,
	// and net/http would refuse every request.
	if strings.ContainsFunc(token, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, errors.New("rypt: the token contains control characters")
	}
	if strings.ContainsFunc(o.userAgent, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, errors.New("rypt: the user agent contains control characters")
	}
	if o.maxAttempts < 1 {
		return nil, errors.New("rypt: the maximum number of attempts must be at least 1")
	}
	base, err := parseBaseURL(o.baseURL)
	if err != nil {
		return nil, err
	}

	c := &Client{
		base:        base,
		token:       token,
		userAgent:   userAgent(o.userAgent),
		maxAttempts: o.maxAttempts,
		backoff:     o.backoff,
	}
	if o.httpClient != nil {
		hc := *o.httpClient
		hc.CheckRedirect = refuseRedirect
		c.http = &hc
	} else {
		c.http = defaultHTTPClient()
	}
	if c.backoff == nil {
		c.backoff = defaultBackoff
	}
	return c, nil
}

// parseBaseURL validates an API base URL as described in [WithBaseURL] and
// removes a trailing slash from its path. An empty URL is DefaultBaseURL.
func parseBaseURL(raw string) (*url.URL, error) {
	if raw == "" {
		raw = DefaultBaseURL
	}
	// The URL is not echoed in errors: it could carry a password.
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("rypt: invalid base URL")
	}
	switch {
	case u.Opaque != "":
		return nil, errors.New("rypt: invalid base URL")
	case u.User != nil:
		return nil, errors.New("rypt: the base URL must not contain user info")
	case strings.Contains(raw, "?"):
		// Checked on the raw string so that a bare "?" is refused too.
		return nil, errors.New("rypt: the base URL must not contain a query")
	case strings.Contains(raw, "#"):
		return nil, errors.New("rypt: the base URL must not contain a fragment")
	case u.Hostname() == "":
		return nil, errors.New("rypt: the base URL must have a host")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackAddress(u.Hostname()) {
			return nil, errors.New("rypt: the base URL must use https unless the host is 127.0.0.1 or ::1")
		}
	default:
		return nil, errors.New("rypt: the base URL must use https")
	}
	return &url.URL{
		Scheme:  u.Scheme,
		Host:    u.Host,
		Path:    strings.TrimRight(u.Path, "/"),
		RawPath: strings.TrimRight(u.RawPath, "/"),
	}, nil
}

// isLoopbackAddress reports whether host is one of the two addresses to
// which plain http is allowed. It deliberately matches these exact
// strings: not names, which are looked up and could resolve to another
// machine, and not other spellings or address ranges.
func isLoopbackAddress(host string) bool {
	return host == "127.0.0.1" || host == "::1"
}

// refuseRedirect makes an http.Client return a redirect response as it is,
// so that the token and body are never re-sent to another URL.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// defaultHTTPClient returns a client with a DefaultTimeout timeout that
// never follows redirects and never sends plain HTTP through a proxy.
func defaultHTTPClient() *http.Client {
	var transport *http.Transport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = t.Clone()
	} else {
		transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	transport.Proxy = httpsOnlyProxy(transport.Proxy)
	return &http.Client{
		Transport:     transport,
		Timeout:       DefaultTimeout,
		CheckRedirect: refuseRedirect,
	}
}

// httpsOnlyProxy returns a proxy function that uses next for https requests
// only. Plain http is only ever allowed to 127.0.0.1 or ::1, and through a
// proxy the token would travel in clear text. https requests still use
// HTTPS_PROXY, through a CONNECT tunnel that carries the TLS session.
func httpsOnlyProxy(next func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		if r.URL.Scheme != "https" || next == nil {
			return nil, nil
		}
		return next(r)
	}
}

// defaultBackoff returns up to 250ms before the first retry, doubling to at
// most 5s. Up to half of each delay is random jitter, so that many clients
// failing together do not retry together.
func defaultBackoff(retry int) time.Duration {
	d := 5 * time.Second
	if retry < 6 {
		d = min(d, 250*time.Millisecond<<max(retry-1, 0))
	}
	return d/2 + rand.N(d/2+1)
}

// userAgent returns the User-Agent header: the application's name, if
// given, then this module's name and version.
func userAgent(app string) string {
	ua := "rypt-go/" + moduleVersion()
	if app = strings.TrimSpace(app); app != "" {
		ua = app + " " + ua
	}
	return ua
}

// moduleVersion returns the version of this module in the running binary,
// or "dev" when it is not built as a dependency, as in its own tests.
func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	for _, dep := range info.Deps {
		if dep.Path == modulePath {
			if dep.Replace != nil {
				return "dev"
			}
			return dep.Version
		}
	}
	return "dev"
}
