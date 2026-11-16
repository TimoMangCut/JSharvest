package netsafe

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ProxyNone is the -proxy value that turns the proxy off whatever the
// environment says. An empty -proxy is "not given": the environment decides.
const ProxyNone = "none"

// Known limit: NO_PROXY / no_proxy are not read. A run goes through the one
// proxy it chose, but for loopback and the hosts of -host-resolver-rules
// (ProxyFunc).
//
// ProxyFrom picks the one proxy every client of a run goes through, in
// this order: the -proxy flag, JSHARVEST_PROXY, HTTPS_PROXY / https_proxy,
// HTTP_PROXY / http_proxy. -proxy none (ProxyNone) disables it. The second
// result names where the value came from. The URL needs a scheme and a
// host.
func ProxyFrom(flagVal string, env func(string) string) (*url.URL, string, error) {
	if env == nil {
		env = func(string) string { return "" }
	}
	type src struct{ name, val string }
	var cands []src
	if flagVal != "" {
		cands = append(cands, src{"-proxy", flagVal})
	}
	for _, k := range []string{"JSHARVEST_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		cands = append(cands, src{k, env(k)})
	}
	for _, c := range cands {
		v := strings.TrimSpace(c.val)
		if v == "" {
			continue
		}
		if strings.EqualFold(v, ProxyNone) {
			return nil, c.name, nil
		}
		if !strings.Contains(v, "://") {
			v = "http://" + v
		}
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			// Never the string as given: it may carry a credential.
			return nil, c.name, fmt.Errorf("%s: %q is not a proxy URL (http://host:port)", c.name, Redact(v))
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, c.name, fmt.Errorf("%s: proxy scheme %q is not supported", c.name, u.Scheme)
		}
		return u, c.name, nil
	}
	return nil, "", nil
}

// Redact drops the userinfo of a URL-looking string, parsed or not: what
// precedes the last "@" goes (a password may hold an "@").
func Redact(s string) string {
	i := strings.LastIndex(s, "@")
	if i < 0 {
		return s
	}
	if j := strings.Index(s, "://"); j >= 0 && j < i {
		return s[:j+3] + s[i+1:]
	}
	return s[i+1:]
}

// ProxyLine is the line a run prints when it has chosen a proxy: no
// credential in it.
func ProxyLine(u *url.URL) string {
	c := *u
	c.User = nil
	return "proxy: " + c.String()
}

// ProxyFunc is a transport's Proxy: the chosen proxy for every request,
// except a host the user's -host-resolver-rules map (they name where it
// goes; go there). nil for no proxy.
func ProxyFunc(u *url.URL, rules Rules) func(*http.Request) (*url.URL, error) {
	if u == nil {
		return nil
	}
	return func(r *http.Request) (*url.URL, error) {
		// Loopback is never sent through a proxy (Chrome's <-loopback>, Go's
		// own rule): localhost, *.localhost and a loopback literal.
		if loopbackHost(r.URL.Hostname()) {
			return nil, nil
		}
		h := r.URL.Host
		if r.URL.Port() == "" {
			h += ":80"
		}
		if len(rules) > 0 && rules.MapAddr(h) != h {
			return nil, nil
		}
		return u, nil
	}
}

// loopbackHost: localhost, *.localhost (RFC 6761) or a loopback literal in
// any number form.
func loopbackHost(h string) bool {
	l := strings.ToLower(strings.TrimRight(h, "."))
	if l == "localhost" || strings.HasSuffix(l, ".localhost") {
		return true
	}
	a, lit, err := LiteralHost(h)
	return lit && err == nil && a.Unmap().IsLoopback()
}
